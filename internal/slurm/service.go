package slurm

import (
	"bytes"
	"clustron-backend/internal/setting"
	"context"
	"encoding/json"
	"fmt"
	logutil "github.com/NYCU-SDC/summer/pkg/log"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
	"io"
	"net/http"
	"strings"
)

type settingStore interface {
	GetSettingByUserID(ctx context.Context, userID uuid.UUID) (setting.Setting, error)
}

type Service struct {
	logger              *zap.Logger
	tracer              trace.Tracer
	slurmRestfulBaseURL string
	slurmTokenHelperURL string
	httpClient          *http.Client

	settingStore settingStore
}

func NewService(logger *zap.Logger, slurmTokenHelperURL string, slurmRestfulBaseURL string, slurmVersion string, settingStore settingStore) *Service {
	return &Service{
		logger:              logger,
		tracer:              otel.Tracer("slurm/service"),
		slurmRestfulBaseURL: fmt.Sprintf("%s/slurm/%s", slurmRestfulBaseURL, slurmVersion),
		slurmTokenHelperURL: slurmTokenHelperURL,
		httpClient:          &http.Client{},

		settingStore: settingStore,
	}
}

func (s Service) GetJobs(ctx context.Context, userID uuid.UUID) (JobsResponse, error) {
	traceCtx, span := s.tracer.Start(ctx, "GetJobs")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	slurmToken, err := s.GetNewToken(traceCtx, userID)
	if err != nil {
		logger.Error("failed to get new token", zap.Error(err))
		span.RecordError(err)
		return JobsResponse{}, err
	}

	requestPath := fmt.Sprintf("%s/jobs", s.slurmRestfulBaseURL)

	httpRequest, err := http.NewRequest(http.MethodGet, requestPath, nil)
	if err != nil {
		logger.Error("failed to create http request", zap.Error(err), zap.String("path", requestPath))
		span.RecordError(err)
		return JobsResponse{}, err
	}

	httpRequest.Header.Add("X-SLURM-USER-TOKEN", slurmToken)

	response, err := s.httpClient.Do(httpRequest)
	if err != nil {
		logger.Error("failed to perform http request", zap.Error(err), zap.String("path", requestPath))
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
		logger.Error("failed to get jobs", zap.Error(err), zap.String("path", requestPath))
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

	logger.Info("successfully got jobs", zap.Any("jobs", jobsResponse))

	return jobsResponse.Jobs, nil
}

func (s Service) GetPartitions(ctx context.Context, userID uuid.UUID) (PartitionResponse, error) {
	traceCtx, span := s.tracer.Start(ctx, "GetPartitions")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

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

	logger.Info("successfully got partitions", zap.Any("partitions", partitionResponse))
	return partitionResponse, nil
}

func (s Service) CountJobStates(ctx context.Context, userID uuid.UUID) (JobStateResponse, error) {
	traceCtx, span := s.tracer.Start(ctx, "CountJobStates")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

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

	return jobStateResponse, nil
}

func (s Service) GetNewToken(ctx context.Context, userID uuid.UUID) (string, error) {
	traceCtx, span := s.tracer.Start(ctx, "GetNewToken")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	userSetting, err := s.settingStore.GetSettingByUserID(ctx, userID)
	if err != nil {
		logger.Error("failed to get setting by user id", zap.Error(err))
		span.RecordError(err)
		return "", err
	}

	requestPath := fmt.Sprintf("%s/api/token/%s", s.slurmTokenHelperURL, userSetting.LinuxUsername.String)
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
