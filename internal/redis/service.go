package redis

import (
	"github.com/redis/go-redis/v9"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

type Service struct {
	logger *zap.Logger
	tracer trace.Tracer
	client *redis.Client
}

func NewService(logger *zap.Logger, redisURL string) *Service {
	return &Service{
		logger: logger,
		tracer: otel.Tracer("redis/service"),
		client: redis.NewClient(&redis.Options{
			Addr: redisURL,
		}),
	}
}
