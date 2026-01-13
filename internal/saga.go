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
	Steps         []SagaStep
	executedSteps []SagaStep
	logger        *zap.Logger
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
	for _, step := range s.Steps {
		if err := step.Action(ctx); err != nil {
			s.logger.Error("Saga step failed", zap.String("step", step.Name), zap.Error(err))

			for i := len(s.executedSteps) - 1; i >= 0; i-- {
				if s.executedSteps[i].Compensate == nil {
					continue
				}
				if rollbackErr := s.executedSteps[i].Compensate(ctx); rollbackErr != nil {
					s.logger.Error("Compensation step failed", zap.String("step", s.executedSteps[i].Name), zap.Error(rollbackErr))
					return rollbackErr
				}
			}
			return err
		}
		s.executedSteps = append(s.executedSteps, step)
	}

	return nil
}

func (s *Saga) Rollback() {
	for i := len(s.executedSteps) - 1; i >= 0; i-- {
		if s.executedSteps[i].Compensate == nil {
			continue
		}
		if err := s.executedSteps[i].Compensate(context.Background()); err != nil {
			s.logger.Error("Compensation step failed during manual rollback", zap.String("step", s.executedSteps[i].Name), zap.Error(err))
		}
	}
}
