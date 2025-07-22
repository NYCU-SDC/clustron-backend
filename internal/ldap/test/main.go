package main

import (
	"clustron-backend/internal/ldap"
	logutil "github.com/NYCU-SDC/summer/pkg/log"
	"go.uber.org/zap"
)

var AppName = "no-app-name"

var Version = "no-version"

var BuildTime = "no-build-time"

var CommitHash = "no-commit-hash"

func main() {
	cfg := &ldap.Config{
		Debug:       true,
		LDAPHost:    "100.72.107.26",
		LDAPPort:    "389",
		LDAPBaseDN:  "dc=clustron,dc=prj,dc=internal,dc=sdc,dc=nycu,dc=club",
		LDAPBindDN:  "cn=admin,dc=clustron,dc=prj,dc=internal,dc=sdc,dc=nycu,dc=club",
		LDAPBindPwd: "password",
	}

	appMetadata := []zap.Field{
		zap.String("app_name", AppName),
		zap.String("version", Version),
		zap.String("build_time", BuildTime),
		zap.String("commit_hash", CommitHash),
	}

	logger, err := initLogger(appMetadata)
	if err != nil {
		panic("failed to create logger: " + err.Error())
	}

	client, err := ldap.NewClient(cfg, logger)
	if err != nil {
		logger.Error("failed to create LDAP client", zap.Error(err))
		return
	}

	err = client.CreateGroup("testgroup", "1001", []string{})
	if err != nil {
		logger.Error("failed to create group", zap.Error(err))
	} else {
		logger.Info("group created successfully")
	}

	err = client.CreateUser("testuser", "TestUser", "1000", "testtest", "10002")
	if err != nil {
		logger.Error("failed to create user", zap.Error(err))
	} else {
		logger.Info("user created successfully")
	}

	err = client.AddUserToGroup("testgroup", "testuser")
	if err != nil {
		logger.Error("failed to add user to group", zap.Error(err))
	} else {
		logger.Info("user added to group successfully")
	}

	err = client.AddUserToGroup("testgroup", "test")
	if err != nil {
		logger.Error("failed to add user to group", zap.Error(err))
	} else {
		logger.Info("user added to group successfully")
	}

	err = client.RemoveUserFromGroup("testgroup", "testuser")
	if err != nil {
		logger.Error("failed to remove user from group", zap.Error(err))
	} else {
		logger.Info("user removed from group successfully")
	}

	err = client.DeleteUser("testuser")
	if err != nil {
		logger.Error("failed to delete user", zap.Error(err))
	} else {
		logger.Info("user deleted successfully")
	}

	err = client.DeleteGroup("testgroup")
	if err != nil {
		logger.Error("failed to delete group", zap.Error(err))
	} else {
		logger.Info("group deleted successfully")
	}

}

func initLogger(appMetadata []zap.Field) (*zap.Logger, error) {
	var err error
	var logger *zap.Logger
	logger, err = logutil.ZapDevelopmentConfig().Build()
	if err != nil {
		return nil, err
	}
	logger.Info("Running in debug mode", appMetadata...)
	defer func() {
		err := logger.Sync()
		if err != nil {
			zap.S().Errorw("Failed to sync logger", zap.Error(err))
		}
	}()

	return logger, nil
}
