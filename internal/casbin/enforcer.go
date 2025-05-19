package casbin

import (
	"context"
	"github.com/casbin/casbin/v2"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

type UserStore interface {
	GetRoleByID(ctx context.Context, userID uuid.UUID) (string, error)
}

type Enforcer struct {
	logger   *zap.Logger
	enforcer *casbin.Enforcer
}

func NewEnforcer(logger *zap.Logger, userStore UserStore) *Enforcer {

	// Load the model and policy from files
	e, err := casbin.NewEnforcer("path/to/model.conf", "path/to/policy.csv")
	if err != nil {
		logger.Fatal("Failed to create enforcer", zap.Error(err))
		return nil
	}

	e.AddFunction("getLevel", func(args ...interface{}) (interface{}, error) {
		roleLevel := map[string]int{
			"admin":     3,
			"organizer": 2,
			"user":      1,
		}

		userID := args[0].(uuid.UUID)

		role, err := userStore.GetRoleByID(context.Background(), userID)
		if err != nil {
			return nil, err
		}

		if level, ok := roleLevel[role]; ok {
			return level, nil
		}
		return 0, nil
	})

	return &Enforcer{
		enforcer: e,
	}
}
