package slurm

import (
	"clustron-backend/internal/setting"
	"context"
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
	logger     *zap.Logger
	tracer     trace.Tracer
	slurmURL   string
	httpClient *http.Client

	settingStore settingStore
}

func NewService(logger *zap.Logger, slurmURL string, settingStore settingStore) *Service {
	return &Service{
		logger:     logger,
		tracer:     otel.Tracer("slurm/service"),
		slurmURL:   slurmURL,
		httpClient: &http.Client{},

		settingStore: settingStore,
	}
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

	requestPath := fmt.Sprintf("%s/api/token/%s", s.slurmURL, userSetting.LinuxUsername.String)
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
