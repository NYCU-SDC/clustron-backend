package internal

import (
	"context"
	"errors"
	"testing"

	"go.uber.org/zap"
)

// On action failure, every previously-executed step is compensated in reverse
// order, and Execute returns the original action error (not nil, not a
// compensation error).
func TestSaga_RollsBackInReverseOnActionFailure(t *testing.T) {
	var order []string
	wantErr := errors.New("action boom")

	s := NewSaga(zap.NewNop())
	s.AddStep(SagaStep{
		Name:       "step1",
		Action:     func(context.Context) error { return nil },
		Compensate: func(context.Context) error { order = append(order, "comp1"); return nil },
	})
	s.AddStep(SagaStep{
		Name:       "step2",
		Action:     func(context.Context) error { return nil },
		Compensate: func(context.Context) error { order = append(order, "comp2"); return nil },
	})
	s.AddStep(SagaStep{
		Name:   "step3",
		Action: func(context.Context) error { return wantErr },
	})

	err := s.Execute(context.Background())
	if !errors.Is(err, wantErr) {
		t.Fatalf("want original action error, got %v", err)
	}
	if len(order) != 2 || order[0] != "comp2" || order[1] != "comp1" {
		t.Fatalf("want reverse-order compensation [comp2 comp1], got %v", order)
	}
}

// A failing compensation must not prevent the remaining steps from being
// compensated (best-effort rollback). Regression test for the early-return bug.
func TestSaga_BestEffortRollbackContinuesAfterCompensationFailure(t *testing.T) {
	var compensated []string
	wantErr := errors.New("action boom")

	s := NewSaga(zap.NewNop())
	s.AddStep(SagaStep{
		Name:       "step1",
		Action:     func(context.Context) error { return nil },
		Compensate: func(context.Context) error { compensated = append(compensated, "comp1"); return nil },
	})
	s.AddStep(SagaStep{
		Name:   "step2",
		Action: func(context.Context) error { return nil },
		Compensate: func(context.Context) error {
			compensated = append(compensated, "comp2")
			return errors.New("compensation boom")
		},
	})
	s.AddStep(SagaStep{
		Name:   "step3",
		Action: func(context.Context) error { return wantErr },
	})

	err := s.Execute(context.Background())
	if !errors.Is(err, wantErr) {
		t.Fatalf("want original action error, got %v", err)
	}
	// comp2 fails, but comp1 must still be attempted.
	if len(compensated) != 2 || compensated[0] != "comp2" || compensated[1] != "comp1" {
		t.Fatalf("want both compensations attempted [comp2 comp1], got %v", compensated)
	}
}
