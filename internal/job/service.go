package job

import (
	"clustron-backend/internal/slurm"
	"context"
	logutil "github.com/NYCU-SDC/summer/pkg/log"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
	"sort"
)

type Service struct {
	logger     *zap.Logger
	tracer     trace.Tracer
	slurmStore slurmStore
}

func NewService(logger *zap.Logger, slurmStore slurmStore) *Service {
	return &Service{
		logger:     logger,
		tracer:     otel.Tracer("job/service"),
		slurmStore: slurmStore,
	}
}

func (s Service) GetJobs(ctx context.Context, userID uuid.UUID, page, size int, sortDirection, sortBy, filterBy, filterValue string) ([]slurm.JobResponse, int, error) {
	traceCtx, span := s.tracer.Start(ctx, "GetJobs")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	jobs, err := s.slurmStore.GetJobs(traceCtx, userID)
	if err != nil {
		logger.Error("failed to get jobs from slurm store", zap.Error(err))
		span.RecordError(err)
		return nil, 0, err
	}

	jobsContent := jobs.Jobs

	if filterBy != "" && filterValue != "" {
		var filteredJobs []slurm.JobResponse
		for _, job := range jobsContent {
			switch filterBy {
			case "status":
				if job.JobState[0] == filterValue {
					filteredJobs = append(filteredJobs, job)
				}
			case "partition":
				if job.Partition == filterValue {
					filteredJobs = append(filteredJobs, job)
				}
			case "resource":
				if filterValue == "cpu" {
					if job.CPUs.Number > 0 {
						filteredJobs = append(filteredJobs, job)
					}
				}
			}
		}
		jobsContent = filteredJobs
	}

	totalCount := len(jobsContent)

	compare := map[string]func(a, b slurm.JobResponse) bool{
		"id":        func(a, b slurm.JobResponse) bool { return a.JobID < b.JobID },
		"status":    func(a, b slurm.JobResponse) bool { return a.JobState[0] < b.JobState[0] },
		"partition": func(a, b slurm.JobResponse) bool { return a.Partition < b.Partition },
		"user":      func(a, b slurm.JobResponse) bool { return a.Username < b.Username },
		"cpu":       func(a, b slurm.JobResponse) bool { return a.CPUs.Number < b.CPUs.Number },
		"memory": func(a, b slurm.JobResponse) bool {
			return a.MemoryPerCPU.Number*a.CPUs.Number < b.MemoryPerCPU.Number*b.CPUs.Number
		},
	}

	sort.Slice(jobsContent, func(i, j int) bool {
		if sortDirection == "asc" {
			return compare[sortBy](jobsContent[i], jobsContent[j])
		}
		return !compare[sortBy](jobsContent[i], jobsContent[j])
	})

	paginatedJobs := jobsContent[page*size : min((page+1)*size, totalCount)]

	return paginatedJobs, totalCount, nil
}
