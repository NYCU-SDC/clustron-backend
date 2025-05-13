package jwt

import (
	"context"
	handlerutil "github.com/NYCU-SDC/summer/pkg/handler"
	logutil "github.com/NYCU-SDC/summer/pkg/log"
	"github.com/NYCU-SDC/summer/pkg/problem"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
	"net/http"
)

//go:generate mockery --name JWTIssuer
type JWTIssuer interface {
	New(ctx context.Context, user User) (string, error)
	GetUserByRefreshToken(ctx context.Context, refreshToken uuid.UUID) (User, error)
	GenerateRefreshToken(ctx context.Context, user User) (RefreshToken, error)
	InactivateRefreshToken(ctx context.Context, refreshToken uuid.UUID) error
}

type Response struct {
	AccessToken    string `json:"accessToken"`
	ExpirationTime int64  `json:"expirationTime"`
	RefreshToken   string `json:"refreshToken"`
}

type Handler struct {
	logger *zap.Logger
	tracer trace.Tracer

	validator     *validator.Validate
	problemWriter *problem.HttpWriter

	jwtIssuer JWTIssuer
}

func NewHandler(
	logger *zap.Logger,
	validator *validator.Validate,
	problemWriter *problem.HttpWriter,
	jwtIssuer JWTIssuer) *Handler {
	return &Handler{
		validator:     validator,
		logger:        logger,
		problemWriter: problemWriter,
		tracer:        otel.Tracer("auth/handler"),
		jwtIssuer:     jwtIssuer,
	}
}

func (h *Handler) RefreshToken(w http.ResponseWriter, r *http.Request) {
	traceCtx, span := h.tracer.Start(r.Context(), "AuthHandler")
	defer span.End()
	logger := logutil.WithContext(traceCtx, h.logger)

	// Validate the request and extract the refresh token
	pathRefreshToken := r.PathValue("refreshToken")
	if pathRefreshToken == "" {
		h.problemWriter.WriteError(traceCtx, w, handlerutil.NewNotFoundError("refresh_token", "refreshToken", pathRefreshToken, "missing refresh token"), logger)
		return
	}
	refreshTokenID, err := handlerutil.ParseUUID(pathRefreshToken)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	// Get the user associated with the refresh token
	jwtUser, err := h.jwtIssuer.GetUserByRefreshToken(traceCtx, refreshTokenID)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	// Generate a new JWT and refresh token
	jwtToken, err := h.jwtIssuer.New(traceCtx, jwtUser)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	newRefreshToken, err := h.jwtIssuer.GenerateRefreshToken(traceCtx, jwtUser)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	// Inactivate the old refresh token
	err = h.jwtIssuer.InactivateRefreshToken(traceCtx, refreshTokenID)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	handlerutil.WriteJSONResponse(w, http.StatusOK, Response{
		AccessToken:    jwtToken,
		ExpirationTime: newRefreshToken.ExpirationDate.Time.Unix(),
		RefreshToken:   newRefreshToken.ID.String(),
	})

}
