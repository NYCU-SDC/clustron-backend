package internal

import (
	"context"

	"go.uber.org/zap"
)

type SagaStep struct {
	Name       string
	Action     func(ctx context.Context) error
	Compensate func(ctx context.Context) error
}

type Saga struct {
	Steps  []SagaStep
	logger *zap.Logger
}

func NewSaga(logger *zap.Logger) *Saga {
	return &Saga{
		logger: logger,
	}
}

func (s *Saga) AddStep(step SagaStep) {
	s.Steps = append(s.Steps, step)
}

func (s *Saga) Execute(ctx context.Context) error {
	var executedSteps []SagaStep
	for _, step := range s.Steps {
		if err := step.Action(ctx); err != nil {
			s.logger.Error("Saga step failed", zap.String("step", step.Name), zap.Error(err))

			for i := len(executedSteps) - 1; i >= 0; i-- {
				if executedSteps[i].Compensate == nil {
					continue
				}
				if rollbackErr := executedSteps[i].Compensate(ctx); rollbackErr != nil {
					s.logger.Error("Compensation step failed", zap.String("step", executedSteps[i].Name), zap.Error(rollbackErr))
					return rollbackErr
				}
			}
			return err
		}
		executedSteps = append(executedSteps, step)
	}

	return nil
}
