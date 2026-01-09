package system

import (
	"clustron-backend/internal/user"
	"net/http"

	handlerutil "github.com/NYCU-SDC/summer/pkg/handler"
	"github.com/NYCU-SDC/summer/pkg/problem"
	"go.uber.org/zap"
)

type Handler struct {
	logger        *zap.Logger
	service       *user.Service
	problemWriter *problem.HttpWriter
}

func NewHandler(logger *zap.Logger, service *user.Service, problemWriter *problem.HttpWriter) *Handler {
	return &Handler{
		logger:        logger,
		service:       service,
		problemWriter: problemWriter,
	}
}

type SystemInfoResponse struct {
	AdminAccountCreated bool `json:"adminAccountCreated"`
}

func (h *Handler) GetSystemInfoHandler(w http.ResponseWriter, r *http.Request) {
	adminExists, err := h.service.HasAdmin(r.Context())
	if err != nil {
		h.problemWriter.WriteError(r.Context(), w, err, h.logger)
		return
	}

	handlerutil.WriteJSONResponse(w, http.StatusOK, SystemInfoResponse{
		AdminAccountCreated: adminExists,
	})
}
