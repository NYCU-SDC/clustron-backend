package auth

import (
	"clustron-backend/internal"
	"clustron-backend/internal/jwt"
	logutil "github.com/NYCU-SDC/summer/pkg/log"
	"github.com/NYCU-SDC/summer/pkg/problem"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
	"net/http"
)

//go:generate mockery --name CasbinEnforcer
type CasbinEnforcer interface {
	Enforce(role, path, method string) (bool, error)
}

type Middleware struct {
	logger *zap.Logger
	tracer trace.Tracer

	enforcer CasbinEnforcer

	problemWriter *problem.HttpWriter
}

func NewMiddleware(logger *zap.Logger, enforcer CasbinEnforcer, problemWriter *problem.HttpWriter) *Middleware {
	return &Middleware{
		logger:   logger,
		tracer:   otel.Tracer("auth/middleware"),
		enforcer: enforcer,

		problemWriter: problemWriter,
	}
}

func (m *Middleware) HandlerFunc(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
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
			logger.Warn("User does not have permission", zap.String("user_id", user.ID.String()), zap.String("role", user.Role), zap.String("path", r.URL.Path), zap.String("method", r.Method))
			m.problemWriter.WriteError(traceCtx, w, internal.ErrPermissionDenied, logger)
			return
		}

		m.logger.Info("Authenticated user", zap.String("user_id", user.ID.String()), zap.String("role", user.Role))

		// Call the next handler
		next.ServeHTTP(w, r)
	}
}
