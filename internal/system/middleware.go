package system

import (
	"clustron-backend/internal/user"
	"net/http"
	"strings"

	"go.uber.org/zap"
)

type Middleware struct {
	logger  *zap.Logger
	service *user.Service
}

func NewMiddleware(logger *zap.Logger, service *user.Service) *Middleware {
	return &Middleware{
		logger:  logger,
		service: service,
	}
}

func (m *Middleware) EnsureSystemSetupMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		allowedPaths := []string{
			"/api/system/info",
			"/api/login",
			"/api/oauth",
			"/api/internal/login",
		}

		for _, path := range allowedPaths {
			if strings.HasPrefix(r.URL.Path, path) {
				next.ServeHTTP(w, r)
				return
			}
		}

		isSetup, err := m.service.HasAdmin(r.Context())
		if err != nil {
			m.logger.Error("failed to check system setup status", zap.Error(err))
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		if !isSetup {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, err := w.Write([]byte(`{"code": "system_not_setup", "message": "System is not initialized yet. Please register the first admin user."}`))
			if err != nil {
				return
			}
			return
		}

		next.ServeHTTP(w, r)
	})
}
