package auth

import (
	"github.com/casbin/casbin/v2"
	"go.uber.org/zap"
)

type Enforcer struct {
	logger   *zap.Logger
	enforcer *casbin.Enforcer
}

func NewEnforcer(logger *zap.Logger) *Enforcer {

	// Load the model and policy from files
	e, err := casbin.NewEnforcer("path/to/model.conf", "path/to/policy.csv")
	if err != nil {
		logger.Fatal("Failed to create enforcer", zap.Error(err))
		return nil
	}

	e.AddFunction("getLevel", func(args ...interface{}) (interface{}, error) {
		// Custom function logic here
		// TODO: Implement the logic to get the level based on user and group
		// user := args[0].(string)
		// group := args[1].(string)

		// Example logic: return the level based on user and group

		// return group, nil

		return nil, nil
	})

	return &Enforcer{
		enforcer: e,
	}
}
