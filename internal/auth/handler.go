package auth

import (
	"clustron-backend/internal/config"
	"clustron-backend/internal/jwt"
	"clustron-backend/internal/user"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	handlerutil "github.com/NYCU-SDC/summer/pkg/handler"
	logutil "github.com/NYCU-SDC/summer/pkg/log"
	"github.com/NYCU-SDC/summer/pkg/problem"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"io"
	"net/http"
	"net/url"
)

type googleUserInfo struct {
	Sub           string `json:"sub"`
	Name          string `json:"name"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
	Picture       string `json:"picture"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Locale        string `json:"locale"`
}

type Response struct {
	AccessToken    string `json:"accessToken"`
	ExpirationTime int64  `json:"expirationTime"`
	RefreshToken   string `json:"refreshToken"`
}

type JWTIssuer interface {
	New(ctx context.Context, user jwt.User) (string, error)
	Parse(ctx context.Context, tokenString string) (jwt.User, error)
	GetUserByRefreshToken(ctx context.Context, refreshToken uuid.UUID) (jwt.User, error)
	GenerateRefreshToken(ctx context.Context, user jwt.User) (jwt.RefreshToken, error)
	InactivateRefreshToken(ctx context.Context, refreshToken uuid.UUID) error
}

type UserStore interface {
	Create(ctx context.Context, username string, email string) (user.User, error)
	ExistsByEmail(ctx context.Context, email string) (bool, error)
	GetByEmail(ctx context.Context, email string) (user.User, error)
}

type Handler struct {
	validator   *validator.Validate
	logger      *zap.Logger
	tracer      trace.Tracer
	oauthConfig *oauth2.Config
	userStore   UserStore
	jwtIssuer   JWTIssuer
}

func NewHandler(validator *validator.Validate, logger *zap.Logger, config config.Config, userStore UserStore, jwtIssuer JWTIssuer) *Handler {
	return &Handler{
		validator: validator,
		logger:    logger,
		tracer:    otel.Tracer("auth/handler"),
		userStore: userStore,
		jwtIssuer: jwtIssuer,
		oauthConfig: &oauth2.Config{
			ClientID:     config.OauthClientID,
			ClientSecret: config.OauthClientSecret,
			RedirectURL:  "http://" + config.Host + ":" + config.Port + "/api/oauth2/google/callback",
			Scopes: []string{
				"https://www.googleapis.com/auth/userinfo.email",
				"https://www.googleapis.com/auth/userinfo.profile",
			},
			Endpoint: google.Endpoint,
		},
	}
}

func (h *Handler) Oauth2WithGoogle(w http.ResponseWriter, r *http.Request) {
	traceCtx, span := h.tracer.Start(r.Context(), "AuthHandler")
	defer span.End()
	logger := logutil.WithContext(traceCtx, h.logger)

	c := r.URL.Query().Get("c")
	var state string
	if c == "" {
		state = url.QueryEscape("http://localhost:8080/api/oauth2/debug/token")
	} else {
		state = url.QueryEscape(c)
	}

	authURL := h.oauthConfig.AuthCodeURL(state, oauth2.AccessTypeOffline)
	http.Redirect(w, r, authURL, http.StatusTemporaryRedirect)

	logger.Info("Redirecting to Google OAuth2", zap.String("url", authURL))
}

func (h *Handler) Callback(w http.ResponseWriter, r *http.Request) {
	traceCtx, span := h.tracer.Start(r.Context(), "AuthHandler")
	defer span.End()
	logger := logutil.WithContext(traceCtx, h.logger)

	code := r.URL.Query().Get("code")
	if code == "" {
		problem.WriteError(traceCtx, w, errors.New("missing code"), logger)
		return
	}

	state := r.URL.Query().Get("state")
	callbackURL, _ := url.QueryUnescape(state)

	token, err := h.oauthConfig.Exchange(traceCtx, code)
	if err != nil {
		problem.WriteError(traceCtx, w, errors.New("failed to exchange token"), logger)
		return
	}

	client := h.oauthConfig.Client(traceCtx, token)
	resp, err := client.Get("https://www.googleapis.com/oauth2/v3/userinfo")
	if err != nil {
		problem.WriteError(traceCtx, w, errors.New("failed to get user info"), logger)
		return
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			problem.WriteError(traceCtx, w, errors.New("failed to close response body"), logger)
		}
	}(resp.Body)

	var userInfo googleUserInfo
	err = json.NewDecoder(resp.Body).Decode(&userInfo)
	if err != nil {
		problem.WriteError(traceCtx, w, errors.New("failed to decode user info"), logger)
		return
	}

	exists, err := h.userStore.ExistsByEmail(traceCtx, userInfo.Email)
	if err != nil {
		problem.WriteError(traceCtx, w, err, logger)
		return
	}

	var jwtUser user.User
	if !exists {
		jwtUser, err = h.userStore.Create(traceCtx, userInfo.Name, userInfo.Email)
		if err != nil {
			problem.WriteError(traceCtx, w, err, logger)
			return
		}
	} else {
		jwtUser, err = h.userStore.GetByEmail(traceCtx, userInfo.Email)
		if err != nil {
			problem.WriteError(traceCtx, w, err, logger)
			return
		}
	}

	// Generate JWT token
	jwtToken, err := h.jwtIssuer.New(traceCtx, jwt.User(jwtUser))
	if err != nil {
		problem.WriteError(traceCtx, w, err, logger)
		return
	}

	refreshToken, err := h.jwtIssuer.GenerateRefreshToken(traceCtx, jwt.User(jwtUser))
	if err != nil {
		problem.WriteError(traceCtx, w, err, logger)
		return
	}

	redirectWithToken := fmt.Sprintf("%s?token=%s&refresh_token=%s", callbackURL, jwtToken, refreshToken.ID.String())
	http.Redirect(w, r, redirectWithToken, http.StatusTemporaryRedirect)
}

func (h *Handler) RefreshToken(w http.ResponseWriter, r *http.Request) {
	traceCtx, span := h.tracer.Start(r.Context(), "AuthHandler")
	defer span.End()
	logger := logutil.WithContext(traceCtx, h.logger)

	// Validate the request and extract the refresh token
	pathRefreshToken := r.PathValue("refresh_token")
	if pathRefreshToken == "" {
		problem.WriteError(traceCtx, w, errors.New("missing refresh token"), logger)
		return
	}
	refreshTokenID, err := handlerutil.ParseUUID(pathRefreshToken)
	if err != nil {
		problem.WriteError(traceCtx, w, err, logger)
		return
	}

	// Get the user associated with the refresh token
	jwtUser, err := h.jwtIssuer.GetUserByRefreshToken(traceCtx, refreshTokenID)
	if err != nil {
		problem.WriteError(traceCtx, w, err, logger)
		return
	}

	// Generate a new JWT and refresh token
	jwtToken, err := h.jwtIssuer.New(traceCtx, jwtUser)
	if err != nil {
		problem.WriteError(traceCtx, w, err, logger)
		return
	}

	newRefreshToken, err := h.jwtIssuer.GenerateRefreshToken(traceCtx, jwtUser)
	if err != nil {
		problem.WriteError(traceCtx, w, err, logger)
		return
	}

	// Inactivate the old refresh token
	err = h.jwtIssuer.InactivateRefreshToken(traceCtx, refreshTokenID)
	if err != nil {
		problem.WriteError(traceCtx, w, err, logger)
		return
	}

	handlerutil.WriteJSONResponse(w, http.StatusOK, Response{
		AccessToken:    jwtToken,
		ExpirationTime: newRefreshToken.ExpirationDate.Time.Unix(),
		RefreshToken:   newRefreshToken.ID.String(),
	})

}

func (h *Handler) DebugToken(w http.ResponseWriter, r *http.Request) {
	traceCtx, span := h.tracer.Start(r.Context(), "DebugToken")
	defer span.End()
	logger := logutil.WithContext(traceCtx, h.logger)

	token := r.URL.Query().Get("token")
	if token == "" {
		problem.WriteError(traceCtx, w, errors.New("missing token"), logger)
		return
	}

	jwtUser, err := h.jwtIssuer.Parse(traceCtx, token)
	if err != nil {
		problem.WriteError(traceCtx, w, err, logger)
		return
	}

	handlerutil.WriteJSONResponse(w, http.StatusOK, jwtUser)
}
