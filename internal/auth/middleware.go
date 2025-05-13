package auth

import (
	"github.com/NYCU-SDC/clustron-backend/internal/jwt"
	logutil "github.com/NYCU-SDC/summer/pkg/log"
	"github.com/casbin/casbin/v2"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
	"net/http"
)

type Middleware struct {
	logger   *zap.Logger
	tracer   trace.Tracer
	enforcer *casbin.Enforcer
}

func NewMiddleware(logger *zap.Logger, tracer trace.Tracer, enforcer *casbin.Enforcer) *Middleware {
	return &Middleware{
		logger:   logger,
		tracer:   tracer,
		enforcer: enforcer,
	}
}

func (m *Middleware) HandlerFunc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		traceCtx, span := m.tracer.Start(r.Context(), "AuthMiddleware")
		defer span.End()
		logger := logutil.WithContext(traceCtx, m.logger)

		// Extract the user from the request context
		user, err := jwt.GetUserFromContext(r.Context())
		if err != nil {
			logger.Error("Failed to get user from context", zap.Error(err))
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Check if the user has the required permissions
		ok, err := m.enforcer.Enforce(user.Role, r.URL.Path, r.Method)
		if err != nil {
			logger.Error("Failed to enforce permissions", zap.Error(err))
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		if !ok {
			logger.Warn("User does not have permission", zap.String("user_id", user.ID), zap.String("role", user.Role))
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		m.logger.Info("Authenticated user", zap.String("user_id", user.ID), zap.String("role", user.Role))

		// Call the next handler
		next.ServeHTTP(w, r)
	})
}
