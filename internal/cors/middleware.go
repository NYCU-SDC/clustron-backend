package cors

import (
	corsutil "github.com/NYCU-SDC/summer/pkg/cors"
	"go.uber.org/zap"
	"net/http"
)

type Middleware struct {
	logger       *zap.Logger
	allowOrigins []string
}

func NewMiddleware(logger *zap.Logger, allowOrigins []string) Middleware {
	return Middleware{
		logger:       logger,
		allowOrigins: allowOrigins,
	}
}

func (m Middleware) HandlerFunc(next http.HandlerFunc) http.HandlerFunc {
	return corsutil.CORSMiddleware(next, m.logger, m.allowOrigins)
}
