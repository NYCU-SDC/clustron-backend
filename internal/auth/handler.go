package auth

import (
	"clustron-backend/internal"
	"clustron-backend/internal/auth/oauthprovider"
	"clustron-backend/internal/config"
	"clustron-backend/internal/jwt"
	"clustron-backend/internal/setting"
	"clustron-backend/internal/user"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	handlerutil "github.com/NYCU-SDC/summer/pkg/handler"
	logutil "github.com/NYCU-SDC/summer/pkg/log"
	"github.com/NYCU-SDC/summer/pkg/problem"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
	"net/http"
	"net/url"
	"time"
)

type JWTIssuer interface {
	New(ctx context.Context, user jwt.User) (string, error)
	Parse(ctx context.Context, tokenString string) (jwt.User, error)
	GenerateRefreshToken(ctx context.Context, user jwt.User) (jwt.RefreshToken, error)
}

type JWTStore interface {
	InactivateRefreshTokensByUserID(ctx context.Context, userID uuid.UUID) error
}

type UserStore interface {
	GetByID(ctx context.Context, userID uuid.UUID) (user.User, error)
}

type SettingStore interface {
	FindOrCreateSetting(ctx context.Context, userID uuid.UUID, fullName pgtype.Text) (setting.Setting, error)
}

type Store interface {
	FindOrCreate(ctx context.Context, email, identifier string, providerType ProviderType) (LoginInfo, error)
	GetEmailByUserID(ctx context.Context, userID uuid.UUID) (string, error)
}

type OAuthProvider interface {
	Name() string
	Config() *oauth2.Config
	Exchange(ctx context.Context, code string) (*oauth2.Token, error)
	GetUserInfo(ctx context.Context, token *oauth2.Token) (oauthprovider.UserInfo, error)
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

	userStore    UserStore
	jwtIssuer    JWTIssuer
	jwtStore     JWTStore
	settingStore SettingStore
	store        Store
	provider     map[string]OAuthProvider
}

func NewHandler(
	config config.Config,
	logger *zap.Logger,
	validator *validator.Validate,
	problemWriter *problem.HttpWriter,
	userStore UserStore,
	jwtIssuer JWTIssuer,
	jwtStore JWTStore,
	store Store,
	settingStore SettingStore) *Handler {

	googleProvider := oauthprovider.NewGoogleConfig(
		config.GoogleOauthClientID,
		config.GoogleOauthClientSecret,
		fmt.Sprintf("%s/api/oauth/google/callback", config.BaseURL))

	nycuProvider := oauthprovider.NewNYCUConfig(
		config.NYCUOauthClientID,
		config.NYCUOauthClientSecret,
		fmt.Sprintf("%s/api/oauth/nycu/callback", config.BaseURL))

	return &Handler{
		config: config,
		logger: logger,
		tracer: otel.Tracer("auth/handler"),

		validator:     validator,
		problemWriter: problemWriter,

		userStore:    userStore,
		jwtIssuer:    jwtIssuer,
		jwtStore:     jwtStore,
		settingStore: settingStore,
		store:        store,
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
	loginInfo, err := h.store.FindOrCreate(traceCtx, userInfo.GetUserInfo().Email, userInfo.GetUserInfo().ID, ProviderTypesMap[provider.Name()])
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	// Create a new setting for the user
	_, err = h.settingStore.FindOrCreateSetting(traceCtx, loginInfo.UserID, pgtype.Text{String: userInfo.GetUserInfo().Name, Valid: true})
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	// Get user with loginInfo
	loginUser, err := h.userStore.GetByID(traceCtx, loginInfo.UserID)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	// Generate JWT token
	jwtToken, refreshTokenID, err := h.generateJWT(traceCtx, loginUser)
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

	// Clear the query parameters from the callback URL, due to "?" symbol in original URL
	redirectTo := callback.Query().Get("r")
	callback.RawQuery = ""

	return callBackInfo{
		code:       code,
		oauthError: oauthError,
		callback:   *callback,
		redirectTo: redirectTo,
	}, nil
}

func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	traceCtx, span := h.tracer.Start(r.Context(), "Logout")
	defer span.End()
	logger := logutil.WithContext(traceCtx, h.logger)

	jwtUser, err := jwt.GetUserFromContext(r.Context())
	if err != nil {
		logger.DPanic("Can't find user in context, this should never happen")
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	// Invalidate the refresh token associated with the user
	err = h.jwtStore.InactivateRefreshTokensByUserID(traceCtx, jwtUser.ID)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	// Clean the client side cookie
	accessTokenCookie := &http.Cookie{
		Name:     "accessToken",
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		SameSite: http.SameSiteLaxMode,
	}
	refreshTokenCookie := &http.Cookie{
		Name:     "refreshToken",
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(w, accessTokenCookie)
	http.SetCookie(w, refreshTokenCookie)

	handlerutil.WriteJSONResponse(w, http.StatusOK, map[string]string{"message": "Logged out successfully"})
}
