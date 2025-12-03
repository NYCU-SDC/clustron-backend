package auth

import (
	"clustron-backend/internal"
	"clustron-backend/internal/auth/oauthprovider"
	"clustron-backend/internal/config"
	"clustron-backend/internal/jwt"
	"clustron-backend/internal/setting"
	"clustron-backend/internal/user"
	"context"
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
	NewState(ctx context.Context, service, environment, callbackURL, redirectURL, state string) (string, error)
	ParseState(ctx context.Context, tokenString string) (string, string, error)
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
	FindOrCreateInfo(ctx context.Context, email, identifier string, providerType ProviderType) (LoginInfo, error)
	CreateInfo(ctx context.Context, userID uuid.UUID, providerType ProviderType, email, identifier string) (LoginInfo, error)
	GetTokenByID(ctx context.Context, id uuid.UUID) (LoginToken, error)
	CreateToken(ctx context.Context, callback string, userID uuid.UUID) (LoginToken, error)
	InactivateToken(ctx context.Context, id uuid.UUID) error
	DeleteExpiredTokens(ctx context.Context) error
}

type OAuthProvider interface {
	Name() string
	Config() *oauth2.Config
	Exchange(ctx context.Context, code string) (*oauth2.Token, error)
	GetUserInfo(ctx context.Context, token *oauth2.Token) (oauthprovider.UserInfoStore, error)
}

type InternalLoginRequest struct {
	UserID string `json:"user_id" validate:"required,uuid"`
}

type InternalLoginResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type BindLoginInfoResponse struct {
	Url string `json:"url"`
}

type callbackInfo struct {
	code        string
	oauthError  string
	callback    url.URL
	redirectTo  string
	bindingUser uuid.UUID
}

type Handler struct {
	config      config.Config
	logger      *zap.Logger
	tracer      trace.Tracer
	environment string
	appName     string

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
	environment string,
	appName string,
	validator *validator.Validate,
	problemWriter *problem.HttpWriter,
	userStore UserStore,
	jwtIssuer JWTIssuer,
	jwtStore JWTStore,
	store Store,
	settingStore SettingStore) *Handler {

	var (
		googleProvider OAuthProvider
		nycuProvider   OAuthProvider
	)
	if config.OAuthProxyBaseURL != "" {
		googleProvider = oauthprovider.NewGoogleConfig(
			config.GoogleOauthClientID,
			config.GoogleOauthClientSecret,
			fmt.Sprintf("%s/api/auth/google/callback", config.OAuthProxyBaseURL))
		nycuProvider = oauthprovider.NewNYCUConfig(
			config.NYCUOauthClientID,
			config.NYCUOauthClientSecret,
			fmt.Sprintf("%s/api/auth/google/callback", config.OAuthProxyBaseURL))
	} else {
		googleProvider = oauthprovider.NewGoogleConfig(
			config.GoogleOauthClientID,
			config.GoogleOauthClientSecret,
			fmt.Sprintf("%s/api/oauth/google/callback", config.BaseURL))

		nycuProvider = oauthprovider.NewNYCUConfig(
			config.NYCUOauthClientID,
			config.NYCUOauthClientSecret,
			fmt.Sprintf("%s/api/oauth/nycu/callback", config.BaseURL))
	}

	return &Handler{
		config:      config,
		logger:      logger,
		tracer:      otel.Tracer("auth/handler"),
		environment: environment,
		appName:     appName,

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

	redirectTo := r.URL.Query().Get("c")
	frontendRedirectTo := r.URL.Query().Get("r")
	if redirectTo == "" {
		redirectTo = fmt.Sprintf("%s/api/oauth/debug/token", h.config.BaseURL)
	}
	if frontendRedirectTo != "" {
		redirectTo = fmt.Sprintf("%s?r=%s", redirectTo, frontendRedirectTo)
	}

	token, err := h.store.CreateToken(traceCtx, redirectTo, uuid.Nil)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	callback := fmt.Sprintf("%s/api/oauth/%s/callback", h.config.BaseURL, provider.Name())

	proxyState, err := h.jwtIssuer.NewState(traceCtx, h.appName, h.environment, callback, redirectTo, token.ID.String())
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, fmt.Errorf("%w: %v", internal.ErrNewStateFailed, err), logger)
		return
	}

	authURL := provider.Config().AuthCodeURL(proxyState, oauth2.AccessTypeOffline)
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
	callbackInfo, err := h.getCallBackInfo(traceCtx, r.URL)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, fmt.Errorf("%w: %v", internal.ErrInvalidCallbackInfo, err), logger)
		return
	}

	err = h.store.DeleteExpiredTokens(traceCtx)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	callback := callbackInfo.callback.String()
	code := callbackInfo.code
	redirectTo := callbackInfo.redirectTo
	oauthError := callbackInfo.oauthError
	bindingUser := callbackInfo.bindingUser

	if oauthError != "" {
		http.Redirect(w, r, fmt.Sprintf("%s?error=%s", callback, oauthError), http.StatusTemporaryRedirect)
		return
	}

	token, err := provider.Exchange(traceCtx, code)
	if err != nil {
		logger.Error("Failed to exchange code for token", zap.Error(err))
		http.Redirect(w, r, fmt.Sprintf("%s?error=%s", callback, err), http.StatusTemporaryRedirect)
		return
	}

	userInfo, err := provider.GetUserInfo(traceCtx, token)
	if err != nil {
		logger.Error("Failed to get user info", zap.Error(err))
		http.Redirect(w, r, fmt.Sprintf("%s?error=%s", callback, err), http.StatusTemporaryRedirect)
		return
	}

	// Check if the user is binding to an existing user
	var loginInfo LoginInfo
	if bindingUser != uuid.Nil {
		loginInfo, err = h.store.CreateInfo(traceCtx, bindingUser, ProviderTypesMap[provider.Name()], userInfo.GetUserInfo().Email, userInfo.GetUserInfo().ID)
		if err != nil {
			logger.Error("Failed to create user info", zap.Error(err))
			http.Redirect(w, r, fmt.Sprintf("%s?error=%s", callback, err), http.StatusTemporaryRedirect)
			return
		}
	} else {
		// Check if the user exists in the database, if not, create a new user
		loginInfo, err = h.store.FindOrCreateInfo(traceCtx, userInfo.GetUserInfo().Email, userInfo.GetUserInfo().ID, ProviderTypesMap[provider.Name()])
		if err != nil {
			logger.Error("Failed to find or create user info", zap.Error(err))
			http.Redirect(w, r, fmt.Sprintf("%s?error=%s", callback, err), http.StatusTemporaryRedirect)
			return
		}
	}

	// Get user with loginInfo
	loginUser, err := h.userStore.GetByID(traceCtx, loginInfo.UserID)
	if err != nil {
		logger.Error("Failed to get user by ID", zap.Error(err))
		http.Redirect(w, r, fmt.Sprintf("%s?error=%s", callback, err), http.StatusTemporaryRedirect)
		return
	}

	// Generate JWT token
	jwtToken, refreshTokenID, err := h.generateJWT(traceCtx, loginUser)
	if err != nil {
		logger.Error("Failed to generate JWT", zap.Error(err))
		http.Redirect(w, r, fmt.Sprintf("%s?error=%s", callback, err), http.StatusTemporaryRedirect)
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

// BindLoginInfo binds the login information to the request context
func (h *Handler) BindLoginInfo(w http.ResponseWriter, r *http.Request) {
	traceCtx, span := h.tracer.Start(r.Context(), "BindLoginInfo")
	defer span.End()
	logger := logutil.WithContext(traceCtx, h.logger)

	jwtUser, err := jwt.GetUserFromContext(traceCtx)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, handlerutil.ErrUnauthorized, logger)
		return
	}

	providerName := r.PathValue("provider")
	provider := h.provider[providerName]
	if provider == nil {
		h.problemWriter.WriteError(traceCtx, w, fmt.Errorf("%w: provider not found: %s", internal.ErrProviderNotFound, providerName), logger)
		return
	}

	redirectTo := r.URL.Query().Get("c")
	frontendRedirectTo := r.URL.Query().Get("r")
	if redirectTo == "" {
		redirectTo = fmt.Sprintf("%s/api/oauth/debug/token", h.config.BaseURL)
	}
	if frontendRedirectTo != "" {
		redirectTo = fmt.Sprintf("%s?r=%s", redirectTo, frontendRedirectTo)
	}

	token, err := h.store.CreateToken(traceCtx, redirectTo, jwtUser.ID)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	callback := fmt.Sprintf("%s/api/oauth/%s/callback", h.config.BaseURL, provider.Name())

	proxyState, err := h.jwtIssuer.NewState(traceCtx, h.appName, h.environment, callback, redirectTo, token.ID.String())
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, fmt.Errorf("%w: %v", internal.ErrNewStateFailed, err), logger)
		return
	}

	authURL := provider.Config().AuthCodeURL(proxyState, oauth2.AccessTypeOffline)

	result := &BindLoginInfoResponse{
		Url: authURL,
	}

	handlerutil.WriteJSONResponse(w, http.StatusOK, result)
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

func (h *Handler) InternalLogin(w http.ResponseWriter, r *http.Request) {
	traceCtx, span := h.tracer.Start(r.Context(), "InternalLogin")
	defer span.End()
	logger := logutil.WithContext(traceCtx, h.logger)

	var request InternalLoginRequest
	err := handlerutil.ParseAndValidateRequestBody(traceCtx, h.validator, r, &request)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	userID, err := handlerutil.ParseUUID(request.UserID)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	loginUser, err := h.userStore.GetByID(traceCtx, userID)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	jwtToken, refreshToken, err := h.generateJWT(traceCtx, loginUser)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	response := &InternalLoginResponse{
		AccessToken:  jwtToken,
		RefreshToken: refreshToken,
	}

	handlerutil.WriteJSONResponse(w, http.StatusOK, response)

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

func (h *Handler) getCallBackInfo(ctx context.Context, url *url.URL) (callbackInfo, error) {
	code := url.Query().Get("code")
	state := url.Query().Get("state")
	oauthError := url.Query().Get("error") // Check if there was an error during the OAuth2 process

	redirect, tokenStr, err := h.jwtIssuer.ParseState(ctx, state)
	if err != nil {
		return callbackInfo{}, fmt.Errorf("%w: invalid state parameter", internal.ErrInvalidCallbackInfo)
	}

	tokenID, err := handlerutil.ParseUUID(tokenStr)
	if err != nil {
		return callbackInfo{}, fmt.Errorf("%w: invalid token ID", internal.ErrInvalidCallbackInfo)
	}

	token, err := h.store.GetTokenByID(ctx, tokenID)
	if err != nil {
		return callbackInfo{}, err
	}

	err = h.store.InactivateToken(ctx, tokenID)
	if err != nil {
		return callbackInfo{}, err
	}

	frontendRedirect, err := url.Parse(redirect)
	if err != nil {
		return callbackInfo{}, err
	}

	// Clear the query parameters from the callback URL, due to "?" symbol in original URL
	redirectTo := frontendRedirect.Query().Get("r")
	frontendRedirect.RawQuery = ""

	// Extract the binding user ID from the token
	var bindingUser uuid.UUID
	if !token.UserID.Valid {
		bindingUser = uuid.Nil
	} else {
		bindingUser = token.UserID.Bytes
	}

	return callbackInfo{
		code:        code,
		oauthError:  oauthError,
		callback:    *frontendRedirect,
		redirectTo:  redirectTo,
		bindingUser: bindingUser,
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
