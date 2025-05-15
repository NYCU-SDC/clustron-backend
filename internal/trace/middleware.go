package trace

import (
	traceutil "github.com/NYCU-SDC/summer/pkg/trace"
	"go.uber.org/zap"
	"net/http"
)

type Middleware struct {
	logger *zap.Logger
	debug  bool
}

func NewMiddleware(logger *zap.Logger, debug bool) *Middleware {
	return &Middleware{
		logger: logger,
		debug:  debug,
	}
}

func (m Middleware) TraceMiddleWare(next http.HandlerFunc) http.HandlerFunc {
	return traceutil.TraceMiddleware(next, m.logger)
}

func (m Middleware) RecoverMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return traceutil.RecoverMiddleware(next, m.logger, m.debug)
}
