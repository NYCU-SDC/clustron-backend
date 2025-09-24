package job

import (
	"clustron-backend/internal/jwt"
	"clustron-backend/internal/slurm"
	"context"
	handlerutil "github.com/NYCU-SDC/summer/pkg/handler"
	logutil "github.com/NYCU-SDC/summer/pkg/log"
	"github.com/NYCU-SDC/summer/pkg/pagination"
	"github.com/NYCU-SDC/summer/pkg/problem"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
	"net/http"
)

type store interface {
	GetJobs(ctx context.Context, userID uuid.UUID, page, size int, sortDirection, sortBy, filterBy, filterValue string) ([]slurm.JobResponse, int, error)
}

type slurmStore interface {
	GetJobs(ctx context.Context, userID uuid.UUID) (slurm.JobsResponse, error)
	CreateJob(ctx context.Context, userID uuid.UUID, req slurm.JobRequest) ([]slurm.JobResponse, error)
	GetPartitions(ctx context.Context, userID uuid.UUID) (slurm.PartitionResponse, error)
	CountJobStates(ctx context.Context, userID uuid.UUID) (slurm.JobStateResponse, error)
}

type Handler struct {
	logger            *zap.Logger
	tracer            trace.Tracer
	validator         *validator.Validate
	problemWriter     *problem.HttpWriter
	paginationFactory pagination.Factory[Response]

	store      store
	slurmStore slurmStore
}

func NewHandler(logger *zap.Logger, validator *validator.Validate, problemWriter *problem.HttpWriter, store store, slurmStore slurmStore) *Handler {
	return &Handler{
		logger:        logger,
		tracer:        otel.Tracer("slurm/handler"),
		validator:     validator,
		problemWriter: problemWriter,
		paginationFactory: pagination.Factory[Response]{
			MaxPageSize:     200,
			SortableColumns: []string{"id", "status", "partition", "user", "cpu", "memory"},
		},

		store:      store,
		slurmStore: slurmStore,
	}
}

func (h Handler) GetAllJobsHandler(w http.ResponseWriter, r *http.Request) {
	traceCtx, span := h.tracer.Start(r.Context(), "GetAllJobsHandler")
	defer span.End()
	logger := logutil.WithContext(traceCtx, h.logger)

	paginationParams, err := h.paginationFactory.GetRequest(r)
	if err != nil {
		logger.Warn("failed to get pagination params", zap.Error(err))
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	filterBy := r.URL.Query().Get("filterBy")
	filterValue := r.URL.Query().Get("filterValue")

	jwtUser, err := jwt.GetUserFromContext(traceCtx)
	if err != nil {
		logger.DPanic("Can't find user in context, this should never happen")
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	jobs, count, err := h.store.GetJobs(traceCtx, jwtUser.ID, paginationParams.Page, paginationParams.Size, paginationParams.Sort, paginationParams.SortBy, filterBy, filterValue)
	if err != nil {
		logger.Error("failed to get jobs", zap.Error(err))
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	response := make([]Response, len(jobs))
	for i, job := range jobs {
		response[i] = toResponse(job)
	}

	paginatedJobs := h.paginationFactory.NewResponse(response, count, paginationParams.Page, paginationParams.Size)
	handlerutil.WriteJSONResponse(w, http.StatusOK, paginatedJobs)
}

func (h Handler) CreateHandler(w http.ResponseWriter, r *http.Request) {
	traceCtx, span := h.tracer.Start(r.Context(), "CreateHandler")
	defer span.End()
	logger := logutil.WithContext(traceCtx, h.logger)

	jwtUser, err := jwt.GetUserFromContext(traceCtx)
	if err != nil {
		logger.DPanic("Can't find user in context, this should never happen")
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	var jobReq Request
	err = handlerutil.ParseAndValidateRequestBody(traceCtx, h.validator, r, &jobReq)
	if err != nil {
		logger.Warn("failed to parse and validate request body", zap.Error(err))
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	slurmJobRequest := jobReq.ToSlurmJobRequest()

	jobs, err := h.slurmStore.CreateJob(traceCtx, jwtUser.ID, slurmJobRequest)
	if err != nil {
		logger.Error("failed to get jobs", zap.Error(err))
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	handlerutil.WriteJSONResponse(w, http.StatusOK, jobs)
}

func (h Handler) GetPartitionsHandler(w http.ResponseWriter, r *http.Request) {
	traceCtx, span := h.tracer.Start(r.Context(), "GetPartitionsHandler")
	defer span.End()
	logger := logutil.WithContext(traceCtx, h.logger)

	jwtUser, err := jwt.GetUserFromContext(traceCtx)
	if err != nil {
		logger.DPanic("Can't find user in context, this should never happen")
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	partitions, err := h.slurmStore.GetPartitions(traceCtx, jwtUser.ID)
	if err != nil {
		logger.Error("failed to get partitions", zap.Error(err))
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	var partitionsResponse PartitionsResponse
	for _, p := range partitions.Partitions {
		partitionsResponse.Partitions = append(partitionsResponse.Partitions, p.Name)
	}

	handlerutil.WriteJSONResponse(w, http.StatusOK, partitionsResponse)
}

func (h Handler) GetJobStateHandler(w http.ResponseWriter, r *http.Request) {
	traceCtx, span := h.tracer.Start(r.Context(), "GetJobStateHandler")
	defer span.End()
	logger := logutil.WithContext(traceCtx, h.logger)

	jwtUser, err := jwt.GetUserFromContext(traceCtx)
	if err != nil {
		logger.DPanic("Can't find user in context, this should never happen")
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	jobState, err := h.slurmStore.CountJobStates(traceCtx, jwtUser.ID)
	if err != nil {
		logger.Error("failed to get job states", zap.Error(err))
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	handlerutil.WriteJSONResponse(w, http.StatusOK, jobState)
}
