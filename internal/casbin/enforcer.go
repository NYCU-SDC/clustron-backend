package casbin

import (
	"clustron-backend/internal/config"
	"context"
	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
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
	modelText := `
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub) && keyMatch2(r.obj, p.obj) && regexMatch(r.act, p.act)
`
	m, err := model.NewModelFromString(modelText)
	if err != nil {
		logger.Fatal("Failed to create Casbin model", zap.Error(err))
	}

	// Create a new enforcer with the model and adapter
	e, err := casbin.NewEnforcer(m, config.CasbinPolicySource)
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
