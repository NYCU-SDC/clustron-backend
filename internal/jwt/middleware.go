package jwt

import (
	"clustron-backend/internal"
	"context"
	handlerutil "github.com/NYCU-SDC/summer/pkg/handler"
	logutil "github.com/NYCU-SDC/summer/pkg/log"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
	"net/http"
)

type Verifier interface {
	Parse(ctx context.Context, tokenString string) (User, error)
}

type Middleware struct {
	logger *zap.Logger
	tracer trace.Tracer

	verifier Verifier
}

func NewMiddleware(verifier Verifier, logger *zap.Logger) Middleware {
	name := "middleware/jwt"
	tracer := otel.Tracer(name)

	return Middleware{
		tracer:   tracer,
		logger:   logger,
		verifier: verifier,
	}
}

func (m Middleware) HandlerFunc(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		traceCtx, span := m.tracer.Start(r.Context(), "JWTMiddleware")
		defer span.End()
		logger := logutil.WithContext(traceCtx, m.logger)

		token := r.Header.Get("Authorization")
		if token == "" {
			logger.Warn("Authorization header required")
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		user, err := m.verifier.Parse(traceCtx, token)
		if err != nil {
			logger.Warn("Authorization header invalid", zap.Error(err))
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		logger.Debug("Authorization header valid")
		r = r.WithContext(context.WithValue(traceCtx, internal.UserContextKey, user))
		next.ServeHTTP(w, r)
	}
}

func GetUserFromContext(ctx context.Context) (User, error) {
	user, ok := ctx.Value(internal.UserContextKey).(User)
	if !ok {
		return User{}, handlerutil.ErrInternalServer
	}
	return user, nil
}
