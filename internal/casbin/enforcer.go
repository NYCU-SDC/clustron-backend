package casbin

import (
	"clustron-backend/internal/config"
	"context"
	"github.com/casbin/casbin/v2"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

type UserStore interface {
	GetRoleByID(ctx context.Context, userID uuid.UUID) (string, error)
}

type Enforcer struct {
	enforcer *casbin.Enforcer
}

func NewEnforcer(logger *zap.Logger, config config.Config) *Enforcer {
	// Create a new enforcer with the model and adapter
	e, err := casbin.NewEnforcer(config.CasbinModelSource, config.CasbinPolicySource)
	if err != nil {
		logger.Fatal("Failed to create enforcer", zap.Error(err))
		return nil
	}

	return &Enforcer{
		enforcer: e,
	}
}

func (e *Enforcer) Enforce(userID string, obj string, act string) (bool, error) {
	return e.enforcer.Enforce(userID, obj, act)
}
