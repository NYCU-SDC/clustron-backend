package setup

import (
	"go.uber.org/zap"
	"os"
)

func NewTestLogger() (*zap.Logger, error) {
	cfg := zap.NewDevelopmentConfig()
	if os.Getenv("TEST_DEBUG") == "1" {
		cfg.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
	} else {
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
