package auth

import (
	"clustron-backend/internal/config"
	"encoding/json"
	"errors"
	handlerutil "github.com/NYCU-SDC/summer/pkg/handler"
	logutil "github.com/NYCU-SDC/summer/pkg/log"
	"github.com/NYCU-SDC/summer/pkg/problem"
	"github.com/go-playground/validator/v10"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"net/http"
)

type Handler struct {
	Validator   *validator.Validate
	Logger      *zap.Logger
	Tracer      trace.Tracer
	OauthConfig *oauth2.Config
}

func NewHandler(validator *validator.Validate, logger *zap.Logger, config config.Config) *Handler {
	return &Handler{
		Validator: validator,
		Logger:    logger,
		Tracer:    otel.Tracer("auth/handler"),
		OauthConfig: &oauth2.Config{
			ClientID:     config.OauthClientID,
			ClientSecret: config.OauthClientSecret,
			RedirectURL:  "http://" + config.Host + ":" + config.Port + " /api/oauth2/google/callback",
			Scopes: []string{
				"https://www.googleapis.com/auth/userinfo.email",
				"https://www.googleapis.com/auth/userinfo.profile",
			},
			Endpoint: google.Endpoint,
		},
	}
}

func (h *Handler) Oauth2WithGoogle(w http.ResponseWriter, r *http.Request) {
	traceCtx, span := h.Tracer.Start(r.Context(), "AuthHandler")
	defer span.End()
	logger := logutil.WithContext(traceCtx, h.Logger)

	url := h.OauthConfig.AuthCodeURL("state", oauth2.AccessTypeOffline)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)

	logger.Info("Redirecting to Google OAuth2", zap.String("url", url))
}

func (h *Handler) Callback(w http.ResponseWriter, r *http.Request) {
	traceCtx, span := h.Tracer.Start(r.Context(), "AuthHandler")
	defer span.End()
	logger := logutil.WithContext(traceCtx, h.Logger)

	if r.URL.Query().Get("state") != "state" {
		problem.WriteError(traceCtx, w, errors.New("state did not match"), logger)
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		problem.WriteError(traceCtx, w, errors.New("missing code"), logger)
		return
	}

	token, err := h.OauthConfig.Exchange(traceCtx, code)
	if err != nil {
		problem.WriteError(traceCtx, w, errors.New("failed to exchange token"), logger)
		return
	}

	client := h.OauthConfig.Client(traceCtx, token)
	resp, err := client.Get("https://www.googleapis.com/oauth2/v3/userinfo")
	if err != nil {
		problem.WriteError(traceCtx, w, errors.New("failed to get user info"), logger)
		return
	}
	defer resp.Body.Close()

	var userInfo GoogleUserInfo
	err = json.NewDecoder(resp.Body).Decode(&userInfo)
	if err != nil {
		problem.WriteError(traceCtx, w, errors.New("failed to decode user info"), logger)
		return
	}

	handlerutil.WriteJSONResponse(w, http.StatusOK, userInfo)
}

type GoogleUserInfo struct {
	Sub           string `json:"sub"`
	Name          string `json:"name"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
	Picture       string `json:"picture"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Locale        string `json:"locale"`
}
