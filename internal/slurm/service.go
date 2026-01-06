package slurm

import (
	"bytes"
	"clustron-backend/internal/setting"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	logutil "github.com/NYCU-SDC/summer/pkg/log"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
	"io"
	"net/http"
	"strings"
)

type redisClient interface {
	GetSlurmJobs(ctx context.Context, userID uuid.UUID) (JobsResponse, error)
	SetSlurmJobs(ctx context.Context, userID uuid.UUID, jobs JobsResponse) error
	DeleteSlurmJobs(ctx context.Context, userID uuid.UUID) error
	GetSlurmJobStates(ctx context.Context, userID uuid.UUID) (JobStateResponse, error)
	SetSlurmJobStates(ctx context.Context, userID uuid.UUID, jobStates JobStateResponse) error
	DeleteSlurmJobStates(ctx context.Context, userID uuid.UUID) error
	GetSlurmPartitions(ctx context.Context) (PartitionResponse, error)
	SetSlurmPartitions(ctx context.Context, partitions PartitionResponse) error
}

type settingStore interface {
	GetLDAPUserInfoByUserID(ctx context.Context, userID uuid.UUID) (setting.LDAPUserInfo, error)
}

type Service struct {
	logger              *zap.Logger
	tracer              trace.Tracer
	slurmRestfulBaseURL string
	slurmTokenHelperURL string
	httpClient          *http.Client
	redisClient         redisClient

	settingStore settingStore
}

func NewService(logger *zap.Logger, slurmTokenHelperURL string, slurmRestfulBaseURL string, slurmVersion string, settingStore settingStore, redisClient redisClient) *Service {
	return &Service{
		logger:              logger,
		tracer:              otel.Tracer("slurm/service"),
		slurmRestfulBaseURL: fmt.Sprintf("%s/slurm/%s", slurmRestfulBaseURL, slurmVersion),
		slurmTokenHelperURL: slurmTokenHelperURL,
		httpClient:          &http.Client{},
		redisClient:         redisClient,

		settingStore: settingStore,
	}
}

func (s Service) GetJobs(ctx context.Context, userID uuid.UUID) (JobsResponse, error) {
	traceCtx, span := s.tracer.Start(ctx, "GetSlurmJobs")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	cachedJobs, err := s.redisClient.GetSlurmJobs(traceCtx, userID)
	if err == nil {
		logger.Info("got jobs from redis cache", zap.Any("jobs", cachedJobs))
		span.RecordError(err)
		return cachedJobs, nil
	}

	logger.Info("failed to get jobs from redis cache, fetching from slurm restful api", zap.Error(err))

	slurmToken, err := s.GetNewToken(traceCtx, userID)
	if err != nil {
		logger.Error("failed to get new token", zap.Error(err))
		span.RecordError(err)
		return JobsResponse{}, err
	}

	requestPath := fmt.Sprintf("%s/jobs", s.slurmRestfulBaseURL)

	httpRequest, err := http.NewRequest(http.MethodGet, requestPath, nil)
	if err != nil {
		logger.Error("failed to create http request", zap.Error(err))
		span.RecordError(err)
		return JobsResponse{}, err
	}

	httpRequest.Header.Add("X-SLURM-USER-TOKEN", slurmToken)

	response, err := s.httpClient.Do(httpRequest)
	if err != nil {
		logger.Error("failed to perform http request", zap.Error(err))
		span.RecordError(err)
		return JobsResponse{}, err
	}
	defer func() {
		if cerr := response.Body.Close(); cerr != nil {
			logger.Error("failed to close response body", zap.Error(cerr))
		}
	}()

	if response.StatusCode != http.StatusOK {
		err = fmt.Errorf("unexpected status code: %d", response.StatusCode)
		logger.Error("failed to get jobs", zap.Error(err))
		span.RecordError(err)
		return JobsResponse{}, err
	}

	var jobsResponse JobsResponse
	err = ParseResponse(traceCtx, response, &jobsResponse)
	if err != nil {
		logger.Error("failed to parse response", zap.Error(err))
		span.RecordError(err)
		return JobsResponse{}, err
	}

	err = s.redisClient.SetSlurmJobs(traceCtx, userID, jobsResponse)
	if err != nil {
		logger.Warn("failed to set jobs to redis cache", zap.Error(err))
		span.RecordError(err)
		return jobsResponse, nil
	}

	logger.Info("successfully got jobs", zap.Any("jobs", jobsResponse))

	return jobsResponse, nil
}

func (s Service) CreateJob(ctx context.Context, userID uuid.UUID, jobRequest JobRequest) ([]JobResponse, error) {
	traceCtx, span := s.tracer.Start(ctx, "CreateJob")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	slurmToken, err := s.GetNewToken(traceCtx, userID)
	if err != nil {
		logger.Error("failed to get new token", zap.Error(err))
		span.RecordError(err)
		return nil, err
	}

	requestPath := fmt.Sprintf("%s/job/submit", s.slurmRestfulBaseURL)

	submitJobRequest := SubmitJobRequest{
		Job: jobRequest,
	}

	requestBody, err := json.Marshal(submitJobRequest)
	if err != nil {
		logger.Error("failed to marshal job request", zap.Error(err))
		span.RecordError(err)
		return nil, err
	}

	httpRequest, err := http.NewRequest(http.MethodPost, requestPath, bytes.NewReader(requestBody))
	if err != nil {
		logger.Error("failed to create http request", zap.Error(err))
		span.RecordError(err)
		return nil, err
	}

	httpRequest.Header.Add("X-SLURM-USER-TOKEN", slurmToken)
	httpRequest.Header.Add("Content-Type", "application/json")

	response, err := s.httpClient.Do(httpRequest)
	if err != nil {
		logger.Error("failed to perform http request", zap.Error(err))
		span.RecordError(err)
		return nil, err
	}
	defer func() {
		if cerr := response.Body.Close(); cerr != nil {
			logger.Error("failed to close response body", zap.Error(cerr))
		}
	}()

	if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusCreated {

		var errorResponse ErrorResponse
		err := ParseResponse(traceCtx, response, &errorResponse)
		if err != nil {
			logger.Error("failed to parse error response", zap.Error(err))
			span.RecordError(err)
			return nil, err
		}
		err = fmt.Errorf("unexpected status code: %d", response.StatusCode)
		logger.Error("unexpected status code", zap.Error(err))
		span.RecordError(err)
		return nil, fmt.Errorf("unexpected status code: %d", response.StatusCode)
	}

	var jobsResponse JobsResponse
	err = ParseResponse(traceCtx, response, &jobsResponse)
	if err != nil {
		logger.Error("failed to parse response", zap.Error(err))
		span.RecordError(err)
		return nil, err
	}

	err = s.redisClient.DeleteSlurmJobs(traceCtx, userID)
	if err != nil && !errors.Is(err, redis.Nil) {
		logger.Warn("failed to delete jobs from redis cache", zap.Error(err))
		span.RecordError(err)
		return jobsResponse.Jobs, nil
	}

	err = s.redisClient.DeleteSlurmJobStates(traceCtx, userID)
	if err != nil && !errors.Is(err, redis.Nil) {
		logger.Warn("failed to delete job states from redis cache", zap.Error(err))
		span.RecordError(err)
		return jobsResponse.Jobs, nil
	}

	logger.Info("successfully got jobs", zap.Any("jobs", jobsResponse))

	return jobsResponse.Jobs, nil
}

func (s Service) GetPartitions(ctx context.Context, userID uuid.UUID) (PartitionResponse, error) {
	traceCtx, span := s.tracer.Start(ctx, "GetSlurmPartitions")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	cachePartitions, err := s.redisClient.GetSlurmPartitions(traceCtx)
	if err == nil {
		logger.Info("got partitions from redis cache", zap.Any("partitions", cachePartitions))
		span.RecordError(err)
		return cachePartitions, nil
	}

	logger.Info("failed to get partitions from redis cache, fetching from slurm restful api", zap.Error(err))

	slurmToken, err := s.GetNewToken(traceCtx, userID)
	if err != nil {
		logger.Error("failed to get new token", zap.Error(err))
		span.RecordError(err)
		return PartitionResponse{}, err
	}

	requestPath := fmt.Sprintf("%s/partitions", s.slurmRestfulBaseURL)

	httpRequest, err := http.NewRequest(http.MethodGet, requestPath, nil)
	if err != nil {
		logger.Error("failed to create http request", zap.Error(err))
		span.RecordError(err)
		return PartitionResponse{}, err
	}

	httpRequest.Header.Add("X-SLURM-USER-TOKEN", slurmToken)

	response, err := s.httpClient.Do(httpRequest)
	if err != nil {
		logger.Error("failed to perform http request", zap.Error(err))
		span.RecordError(err)
		return PartitionResponse{}, err
	}
	defer func() {
		if cerr := response.Body.Close(); cerr != nil {
			logger.Error("failed to close response body", zap.Error(cerr))
		}
	}()

	if response.StatusCode != http.StatusOK {
		err = fmt.Errorf("unexpected status code: %d", response.StatusCode)
		logger.Error("failed to get partitions", zap.Error(err))
		span.RecordError(err)
		return PartitionResponse{}, err
	}

	var partitionResponse PartitionResponse
	err = ParseResponse(traceCtx, response, &partitionResponse)
	if err != nil {
		logger.Error("failed to parse response", zap.Error(err))
		span.RecordError(err)
		return PartitionResponse{}, err
	}

	err = s.redisClient.SetSlurmPartitions(traceCtx, partitionResponse)
	if err != nil {
		logger.Warn("failed to set partitions to redis cache", zap.Error(err))
		span.RecordError(err)
		return partitionResponse, nil
	}

	logger.Info("successfully got partitions", zap.Any("partitions", partitionResponse))
	return partitionResponse, nil
}

func (s Service) CountJobStates(ctx context.Context, userID uuid.UUID) (JobStateResponse, error) {
	traceCtx, span := s.tracer.Start(ctx, "CountJobStates")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	cachedJobStates, err := s.redisClient.GetSlurmJobStates(traceCtx, userID)
	if err == nil {
		logger.Info("got job states from redis cache", zap.Any("job_states", cachedJobStates))
		span.RecordError(err)
		return cachedJobStates, nil
	}

	logger.Info("failed to get job states from redis cache, fetching from slurm restful api", zap.Error(err))

	slurmToken, err := s.GetNewToken(traceCtx, userID)
	if err != nil {
		logger.Error("failed to get new token", zap.Error(err))
		span.RecordError(err)
		return JobStateResponse{}, err
	}

	requestPath := fmt.Sprintf("%s/jobs", s.slurmRestfulBaseURL)

	httpRequest, err := http.NewRequest(http.MethodGet, requestPath, nil)
	if err != nil {
		logger.Error("failed to create http request", zap.Error(err))
		span.RecordError(err)
		return JobStateResponse{}, err
	}

	httpRequest.Header.Add("X-SLURM-USER-TOKEN", slurmToken)

	response, err := s.httpClient.Do(httpRequest)
	if err != nil {
		logger.Error("failed to perform http request", zap.Error(err))
		span.RecordError(err)
		return JobStateResponse{}, err
	}
	defer func() {
		if cerr := response.Body.Close(); cerr != nil {
			logger.Error("failed to close response body", zap.Error(cerr))
		}
	}()
	if response.StatusCode != http.StatusOK {
		err = fmt.Errorf("unexpected status code: %d", response.StatusCode)
		logger.Error("failed to get jobs", zap.Error(err))
		span.RecordError(err)
		return JobStateResponse{}, err
	}

	var jobsResponse JobsResponse
	err = ParseResponse(traceCtx, response, &jobsResponse)
	if err != nil {
		logger.Error("failed to parse response", zap.Error(err))
		span.RecordError(err)
		return JobStateResponse{}, err
	}

	jobStateResponse := JobStateResponse{}
	stateMap := map[string]*int{
		"PENDING":   &jobStateResponse.Pending,
		"RUNNING":   &jobStateResponse.Running,
		"COMPLETED": &jobStateResponse.Completed,
		"CANCELLED": &jobStateResponse.Cancelled,
		"FAILED":    &jobStateResponse.Failed,
		"TIMEOUT":   &jobStateResponse.Timeout,
	}

	jobStates := jobsResponse.GetStates()
	for _, states := range jobStates {
		founded := false
		for _, state := range states {
			if countPtr, exists := stateMap[state]; exists {
				*countPtr++
				founded = true
				break
			}
		}
		if !founded {
			jobStateResponse.Unknown++
		}
	}

	err = s.redisClient.SetSlurmJobStates(traceCtx, userID, jobStateResponse)
	if err != nil {
		logger.Warn("failed to set job states to redis cache", zap.Error(err))
		span.RecordError(err)
		return jobStateResponse, nil
	}

	logger.Info("successfully got job states", zap.Any("job_states", jobStateResponse))

	return jobStateResponse, nil
}

func (s Service) GetNewToken(ctx context.Context, userID uuid.UUID) (string, error) {
	traceCtx, span := s.tracer.Start(ctx, "GetNewToken")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	ldapUserInfo, err := s.settingStore.GetLDAPUserInfoByUserID(ctx, userID)
	if err != nil {
		logger.Error("failed to get setting by user id", zap.Error(err))
		span.RecordError(err)
		return "", err
	}

	requestPath := fmt.Sprintf("%s/api/token/%s", s.slurmTokenHelperURL, ldapUserInfo.Username)
	logger.Info("requesting new slurm token", zap.String("path", requestPath))

	httpReq, err := http.NewRequest(http.MethodGet, requestPath, nil)
	if err != nil {
		logger.Error("failed to create http request", zap.Error(err))
		span.RecordError(err)
		return "", err
	}

	response, err := s.httpClient.Do(httpReq)
	if err != nil {
		logger.Error("failed to perform http request", zap.Error(err))
		span.RecordError(err)
		return "", err
	}
	defer func() {
		if cerr := response.Body.Close(); cerr != nil {
			logger.Error("failed to close response body", zap.Error(cerr))
		}
	}()

	if response.StatusCode != http.StatusOK {
		err = fmt.Errorf("unexpected status code: %d", response.StatusCode)
		logger.Error("failed to get new token", zap.Error(err))
		span.RecordError(err)
		return "", err
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		logger.Error("failed to read response body", zap.Error(err))
		span.RecordError(err)
		return "", err
	}

	tokenString := strings.Trim(string(body), "\n")

	logger.Info("successfully got new slurm token", zap.String("token", tokenString))

	return tokenString, nil
}

func ParseResponse(ctx context.Context, r *http.Response, s interface{}) error {
	_, span := otel.Tracer("slurm/service").Start(ctx, "ParseResponse")
	defer span.End()

	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		span.RecordError(err)
		return err
	}
	defer func() {
		err := r.Body.Close()
		if err != nil {
			fmt.Println("Error closing response body:", err)
		}
	}()

	err = json.Unmarshal(bodyBytes, s)
	if err != nil {
		span.RecordError(err)
		return err
	}

	return nil
}
