package auth

import (
	"clustron-backend/internal"
	"clustron-backend/internal/auth/oauthProvider"
	"clustron-backend/internal/config"
	"clustron-backend/internal/jwt"
	"clustron-backend/internal/user"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	handlerutil "github.com/NYCU-SDC/summer/pkg/handler"
	logutil "github.com/NYCU-SDC/summer/pkg/log"
	"github.com/NYCU-SDC/summer/pkg/problem"
	"github.com/go-playground/validator/v10"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
	"net/http"
	"net/url"
)

type JWTIssuer interface {
	New(ctx context.Context, user jwt.User) (string, error)
	Parse(ctx context.Context, tokenString string) (jwt.User, error)
	GenerateRefreshToken(ctx context.Context, user jwt.User) (jwt.RefreshToken, error)
}

type UserStore interface {
	Create(ctx context.Context, username string, email string, studentID string) (user.User, error)
	ExistsByEmail(ctx context.Context, email string) (bool, error)
	GetByEmail(ctx context.Context, email string) (user.User, error)
	FindOrCreate(ctx context.Context, username string, email string, studentID string) (user.User, error)
}

type OAuthProvider interface {
	Name() string
	Config() *oauth2.Config
	Exchange(ctx context.Context, code string) (*oauth2.Token, error)
	GetUserInfo(ctx context.Context, token *oauth2.Token) (oauthProvider.UserInfo, error)
}

type callBackInfo struct {
	code       string
	oauthError string
	callback   url.URL
	redirectTo string
}

type Handler struct {
	config config.Config
	logger *zap.Logger
	tracer trace.Tracer

	validator     *validator.Validate
	problemWriter *problem.HttpWriter

	userStore UserStore
	jwtIssuer JWTIssuer
	provider  map[string]OAuthProvider
}

func NewHandler(
	config config.Config,
	logger *zap.Logger,
	validator *validator.Validate,
	problemWriter *problem.HttpWriter,
	userStore UserStore,
	jwtIssuer JWTIssuer) *Handler {

	googleProvider := oauthProvider.NewGoogleConfig(
		config.GoogleOauthClientID,
		config.GoogleOauthClientSecret,
		fmt.Sprintf("%s/api/oauth/google/callback", config.BaseURL))

	nycuProvider := oauthProvider.NewNYCUConfig(
		config.NYCUOauthClientID,
		config.NYCUOauthClientSecret,
		fmt.Sprintf("%s/api/oauth/nycu/callback", config.BaseURL))

	return &Handler{
		config: config,
		logger: logger,
		tracer: otel.Tracer("auth/handler"),

		validator:     validator,
		problemWriter: problemWriter,

		userStore: userStore,
		jwtIssuer: jwtIssuer,
		provider: map[string]OAuthProvider{
			"google": googleProvider,
			"nycu":   nycuProvider,
		},
	}
}

// Oauth2Start initiates the OAuth2 flow by redirecting the user to the provider's authorization URL
func (h *Handler) Oauth2Start(w http.ResponseWriter, r *http.Request) {
	traceCtx, span := h.tracer.Start(r.Context(), "Oauth2Start")
	defer span.End()
	logger := logutil.WithContext(traceCtx, h.logger)

	providerName := r.PathValue("provider")
	provider := h.provider[providerName]
	if provider == nil {
		h.problemWriter.WriteError(traceCtx, w, fmt.Errorf("%w: provider not found: %s", internal.ErrProviderNotFound, providerName), logger)
		return
	}

	callback := r.URL.Query().Get("c")
	redirectTo := r.URL.Query().Get("r")
	if callback == "" {
		callback = fmt.Sprintf("%s/api/oauth/debug/token", h.config.BaseURL)
	}
	if redirectTo != "" {
		callback = fmt.Sprintf("%s?r=%s", callback, redirectTo)
	}
	state := base64.StdEncoding.EncodeToString([]byte(callback))

	authURL := provider.Config().AuthCodeURL(state, oauth2.AccessTypeOffline)
	http.Redirect(w, r, authURL, http.StatusTemporaryRedirect)

	logger.Info("Redirecting to Google OAuth2", zap.String("url", authURL))
}

// Callback handles the OAuth2 callback from the provider
func (h *Handler) Callback(w http.ResponseWriter, r *http.Request) {
	traceCtx, span := h.tracer.Start(r.Context(), "Callback")
	defer span.End()
	logger := logutil.WithContext(traceCtx, h.logger)

	providerName := r.PathValue("provider")
	provider := h.provider[providerName]
	if provider == nil {
		h.problemWriter.WriteError(traceCtx, w, fmt.Errorf("%w: provider not found: %s", internal.ErrProviderNotFound, providerName), logger)
		return
	}

	// Get the OAuth2 code and state from the request
	callbackInfo, err := h.getCallBackInfo(r.URL)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, fmt.Errorf("%w: %v", internal.ErrInvalidCallbackInfo, err), logger)
		return
	}

	callback := callbackInfo.callback.String()
	code := callbackInfo.code
	redirectTo := callbackInfo.redirectTo
	oauthError := callbackInfo.oauthError

	if oauthError != "" {
		http.Redirect(w, r, fmt.Sprintf("%s?error=%s", callback, oauthError), http.StatusTemporaryRedirect)
		return
	}

	token, err := provider.Exchange(traceCtx, code)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, fmt.Errorf("%w: %v", internal.ErrInvalidExchangeToken, err), logger)
		return
	}

	userInfo, err := provider.GetUserInfo(traceCtx, token)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	// Check if the user exists in the database, if not, create a new user
	jwtUser, err := h.userStore.FindOrCreate(traceCtx, userInfo.Name, userInfo.Email, userInfo.StudentID)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	// Generate JWT token
	jwtToken, refreshTokenID, err := h.generateJWT(traceCtx, jwtUser)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	var redirectWithToken string
	if redirectTo != "" {
		redirectWithToken = fmt.Sprintf("%s?token=%s&refreshToken=%s&r=%s", callback, jwtToken, refreshTokenID, redirectTo)
	} else {
		redirectWithToken = fmt.Sprintf("%s?token=%s&refreshToken=%s", callback, jwtToken, refreshTokenID)
	}

	http.Redirect(w, r, redirectWithToken, http.StatusTemporaryRedirect)
}

func (h *Handler) DebugToken(w http.ResponseWriter, r *http.Request) {
	traceCtx, span := h.tracer.Start(r.Context(), "DebugToken")
	defer span.End()
	logger := logutil.WithContext(traceCtx, h.logger)

	e := r.URL.Query().Get("error")
	if e != "" {
		h.problemWriter.WriteError(traceCtx, w, handlerutil.ErrForbidden, logger)
		return
	}

	token := r.URL.Query().Get("token")
	if token == "" {
		h.problemWriter.WriteError(traceCtx, w, errors.New("missing token"), logger)
		return
	}

	jwtUser, err := h.jwtIssuer.Parse(traceCtx, token)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	handlerutil.WriteJSONResponse(w, http.StatusOK, jwtUser)
}

func (h *Handler) generateJWT(ctx context.Context, user user.User) (string, string, error) {
	traceCtx, span := h.tracer.Start(ctx, "generateJWT")
	defer span.End()

	jwtToken, err := h.jwtIssuer.New(traceCtx, jwt.User(user))
	if err != nil {
		return "", "", err
	}

	refreshToken, err := h.jwtIssuer.GenerateRefreshToken(traceCtx, jwt.User(user))
	if err != nil {
		return "", "", err
	}

	return jwtToken, refreshToken.ID.String(), nil
}

func (h *Handler) getCallBackInfo(url *url.URL) (callBackInfo, error) {

	code := url.Query().Get("code")
	state := url.Query().Get("state")
	oauthError := url.Query().Get("error") // Check if there was an error during the OAuth2 process

	callbackURL, err := base64.StdEncoding.DecodeString(state)
	if err != nil {
		return callBackInfo{}, err
	}

	callback, err := url.Parse(string(callbackURL))
	if err != nil {
		return callBackInfo{}, err
	}

	redirectTo := callback.Query().Get("r")
	callback.RawQuery = ""

	return callBackInfo{
		code:       code,
		oauthError: oauthError,
		callback:   *callback,
		redirectTo: redirectTo,
	}, nil

}
