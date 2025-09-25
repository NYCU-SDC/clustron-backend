package redis

import (
	"bytes"
	"clustron-backend/internal/slurm"
	"context"
	"encoding/gob"
	"errors"
	"fmt"
	logutil "github.com/NYCU-SDC/summer/pkg/log"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
	"time"
)

type Service struct {
	logger *zap.Logger
	tracer trace.Tracer
	client *redis.Client
}

func NewService(logger *zap.Logger, redisURL string) *Service {
	return &Service{
		logger: logger,
		tracer: otel.Tracer("redis/service"),
		client: redis.NewClient(&redis.Options{
			Addr: redisURL,
		}),
	}
}

func (s *Service) GetSlurmJobs(ctx context.Context, userID uuid.UUID) (slurm.JobsResponse, error) {
	traceCtx, span := s.tracer.Start(ctx, "GetSlurmJobs")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	var jobs slurm.JobsResponse
	jobsBytes, err := s.client.Get(traceCtx, fmt.Sprintf("slurm:jobs:%s", userID.String())).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return jobs, redis.Nil
		}
		logger.Error("Failed to get jobs from Redis", zap.Error(err))
		span.RecordError(err)
		return jobs, err
	}

	err = gob.NewDecoder(bytes.NewBuffer(jobsBytes)).Decode(&jobs)
	if err != nil {
		logger.Error("Failed to decode jobs", zap.Error(err))
		span.RecordError(err)
		return jobs, err
	}

	return jobs, nil
}

func (s *Service) SetSlurmJobs(ctx context.Context, userID uuid.UUID, jobs slurm.JobsResponse) error {
	traceCtx, span := s.tracer.Start(ctx, "SetSlurmJobs")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	var buf bytes.Buffer
	err := gob.NewEncoder(&buf).Encode(jobs)
	if err != nil {
		logger.Error("Failed to encode jobs", zap.Error(err))
		span.RecordError(err)
		return err
	}

	err = s.client.Set(traceCtx, fmt.Sprintf("slurm:jobs:%s", userID.String()), buf.Bytes(), 2*time.Minute).Err()
	if err != nil {
		logger.Error("Failed to set jobs to Redis", zap.Error(err))
		span.RecordError(err)
		return err
	}

	return nil
}

func (s *Service) DeleteSlurmJobs(ctx context.Context, userID uuid.UUID) error {
	traceCtx, span := s.tracer.Start(ctx, "DeleteSlurmJobs")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	err := s.client.Del(traceCtx, fmt.Sprintf("slurm:jobs:%s", userID.String())).Err()
	if err != nil {
		logger.Error("Failed to delete jobs from Redis", zap.Error(err))
		span.RecordError(err)
		return err
	}

	return nil
}

func (s *Service) GetSlurmJobStates(ctx context.Context, userID uuid.UUID) (slurm.JobStateResponse, error) {
	traceCtx, span := s.tracer.Start(ctx, "GetSlurmJobStates")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	var jobStates slurm.JobStateResponse
	jobStatesBytes, err := s.client.Get(traceCtx, fmt.Sprintf("slurm:job_states:%s", userID.String())).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return jobStates, redis.Nil
		}
		logger.Error("Failed to get job states from Redis", zap.Error(err))
		span.RecordError(err)
		return jobStates, err
	}

	err = gob.NewDecoder(bytes.NewBuffer(jobStatesBytes)).Decode(&jobStates)
	if err != nil {
		logger.Error("Failed to decode job states", zap.Error(err))
		span.RecordError(err)
		return jobStates, err
	}

	return jobStates, nil
}

func (s *Service) SetSlurmJobStates(ctx context.Context, userID uuid.UUID, jobStates slurm.JobStateResponse) error {
	traceCtx, span := s.tracer.Start(ctx, "SetSlurmJobStates")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	var buf bytes.Buffer
	err := gob.NewEncoder(&buf).Encode(jobStates)
	if err != nil {
		logger.Error("Failed to encode job states", zap.Error(err))
		span.RecordError(err)
		return err
	}

	err = s.client.Set(traceCtx, fmt.Sprintf("slurm:job_states:%s", userID.String()), buf.Bytes(), 2*time.Minute).Err()
	if err != nil {
		logger.Error("Failed to set job states to Redis", zap.Error(err))
		span.RecordError(err)
		return err
	}

	return nil
}

func (s *Service) DeleteSlurmJobStates(ctx context.Context, userID uuid.UUID) error {
	traceCtx, span := s.tracer.Start(ctx, "DeleteSlurmJobStates")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	err := s.client.Del(traceCtx, fmt.Sprintf("slurm:job_states:%s", userID.String())).Err()
	if err != nil {
		logger.Error("Failed to delete job states from Redis", zap.Error(err))
		span.RecordError(err)
		return err
	}

	return nil
}

func (s *Service) GetSlurmPartitions(ctx context.Context) (slurm.PartitionResponse, error) {
	traceCtx, span := s.tracer.Start(ctx, "GetSlurmPartitions")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	var partitions slurm.PartitionResponse
	partitionsBytes, err := s.client.Get(traceCtx, "slurm:partitions").Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return partitions, redis.Nil
		}
		logger.Error("Failed to get partitions from Redis", zap.Error(err))
		span.RecordError(err)
		return partitions, err
	}

	err = gob.NewDecoder(bytes.NewBuffer(partitionsBytes)).Decode(&partitions)
	if err != nil {
		logger.Error("Failed to decode partitions", zap.Error(err))
		span.RecordError(err)
		return partitions, err
	}

	return partitions, nil
}

func (s *Service) SetSlurmPartitions(ctx context.Context, partitions slurm.PartitionResponse) error {
	traceCtx, span := s.tracer.Start(ctx, "SetSlurmPartitions")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	var buf bytes.Buffer
	err := gob.NewEncoder(&buf).Encode(partitions)
	if err != nil {
		logger.Error("Failed to encode partitions", zap.Error(err))
		span.RecordError(err)
		return err
	}

	err = s.client.Set(traceCtx, "slurm:partitions", buf.Bytes(), 0).Err()
	if err != nil {
		logger.Error("Failed to set partitions to Redis", zap.Error(err))
		span.RecordError(err)
		return err
	}

	return nil
}
