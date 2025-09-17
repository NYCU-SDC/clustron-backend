package job

import (
	"clustron-backend/internal/jwt"
	"clustron-backend/internal/slurm"
	"context"
	handlerutil "github.com/NYCU-SDC/summer/pkg/handler"
	logutil "github.com/NYCU-SDC/summer/pkg/log"
	"github.com/NYCU-SDC/summer/pkg/problem"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
	"net/http"
)

type Store interface {
	GetJobs(ctx context.Context, userID uuid.UUID) ([]slurm.JobResponse, error)
	CreateJob(ctx context.Context, userID uuid.UUID, req slurm.JobRequest) ([]slurm.JobResponse, error)
	GetPartitions(ctx context.Context, userID uuid.UUID) (slurm.PartitionResponse, error)
	CountJobStates(ctx context.Context, userID uuid.UUID) (slurm.JobStateResponse, error)
}

type Handler struct {
	logger        *zap.Logger
	tracer        trace.Tracer
	validator     *validator.Validate
	problemWriter *problem.HttpWriter

	store Store
}

func NewHandler(logger *zap.Logger, validator *validator.Validate, problemWriter *problem.HttpWriter, store Store) *Handler {
	return &Handler{
		logger:        logger,
		tracer:        otel.Tracer("slurm/handler"),
		validator:     validator,
		problemWriter: problemWriter,

		store: store,
	}
}

func (h Handler) GetAllJobsHandler(w http.ResponseWriter, r *http.Request) {
	traceCtx, span := h.tracer.Start(r.Context(), "GetAllJobsHandler")
	defer span.End()
	logger := logutil.WithContext(traceCtx, h.logger)

	jwtUser, err := jwt.GetUserFromContext(traceCtx)
	if err != nil {
		logger.DPanic("Can't find user in context, this should never happen")
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	jobs, err := h.store.GetJobs(traceCtx, jwtUser.ID)
	if err != nil {
		logger.Error("failed to get jobs", zap.Error(err))
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	handlerutil.WriteJSONResponse(w, http.StatusOK, jobs)
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

	jobs, err := h.store.CreateJob(traceCtx, jwtUser.ID, slurmJobRequest)
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

	partitions, err := h.store.GetPartitions(traceCtx, jwtUser.ID)
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

	jobState, err := h.store.CountJobStates(traceCtx, jwtUser.ID)
	if err != nil {
		logger.Error("failed to get job states", zap.Error(err))
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	handlerutil.WriteJSONResponse(w, http.StatusOK, jobState)
}
