package setup

import (
	"go.uber.org/zap"
	"os"
	"strings"
)

func NewTestLogger() (*zap.Logger, error) {
	cfg := zap.NewDevelopmentConfig()

	levelStr := strings.ToLower(os.Getenv("TEST_LOG_LEVEL"))
	switch levelStr {
	case "debug":
		cfg.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
	case "info":
		cfg.Level = zap.NewAtomicLevelAt(zap.InfoLevel)
	case "warn":
		cfg.Level = zap.NewAtomicLevelAt(zap.WarnLevel)
	case "error":
		cfg.Level = zap.NewAtomicLevelAt(zap.ErrorLevel)
	default:
		cfg.Level = zap.NewAtomicLevelAt(zap.InfoLevel)
	}

	cfg.EncoderConfig.TimeKey = ""
	cfg.EncoderConfig.LevelKey = "level"
	cfg.EncoderConfig.MessageKey = "msg"
	cfg.EncoderConfig.CallerKey = "caller"
	logger, err := cfg.Build()
	if err != nil {
		return nil, err
	}

	return logger, err
}
