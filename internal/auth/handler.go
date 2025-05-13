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

type OAuthUserInfo struct {
	Sub           string `json:"sub"`
	Name          string `json:"name"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
	Picture       string `json:"picture"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Locale        string `json:"locale"`
}

type JWTIssuer interface {
	New(ctx context.Context, user jwt.User) (string, error)
	Parse(ctx context.Context, tokenString string) (jwt.User, error)
	GenerateRefreshToken(ctx context.Context, user jwt.User) (jwt.RefreshToken, error)
}

type UserStore interface {
	Create(ctx context.Context, username string, email string, studentID string) (user.User, error)
	ExistsByEmail(ctx context.Context, email string) (bool, error)
	GetByEmail(ctx context.Context, email string) (user.User, error)
}

type OAuthProvider interface {
	Name() string
	Config() *oauth2.Config
	Exchange(ctx context.Context, code string) (*oauth2.Token, error)
	GetUserInfo(ctx context.Context, token *oauth2.Token) (oauthProvider.UserInfo, error)
}

type Handler struct {
	validator     *validator.Validate
	logger        *zap.Logger
	config        config.Config
	tracer        trace.Tracer
	userStore     UserStore
	jwtIssuer     JWTIssuer
	problemWriter *problem.HttpWriter
	provider      map[string]OAuthProvider
}

func NewHandler(validator *validator.Validate,
	logger *zap.Logger,
	config config.Config,
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
		validator:     validator,
		logger:        logger,
		config:        config,
		tracer:        otel.Tracer("auth/handler"),
		userStore:     userStore,
		jwtIssuer:     jwtIssuer,
		problemWriter: problemWriter,
		provider: map[string]OAuthProvider{
			"google": googleProvider,
			"nycu":   nycuProvider,
		},
	}
}

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
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	oauthError := r.URL.Query().Get("error") // Check if there was an error during the OAuth2 process
	callbackURL, _ := base64.StdEncoding.DecodeString(state)
	callback, _ := url.Parse(string(callbackURL))
	redirectTo := callback.Query().Get("r")
	callback.RawQuery = ""

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
	jwtUser, err := h.findOrCreateUser(traceCtx, userInfo)
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

func (h *Handler) findOrCreateUser(ctx context.Context, userInfo oauthProvider.UserInfo) (user.User, error) {
	traceCtx, span := h.tracer.Start(ctx, "findOrCreateUser")
	defer span.End()

	exists, err := h.userStore.ExistsByEmail(traceCtx, userInfo.Email)
	if err != nil {
		span.RecordError(err)
		return user.User{}, err
	}
	var jwtUser user.User
	if !exists {
		jwtUser, err = h.userStore.Create(traceCtx, userInfo.Name, userInfo.Email, userInfo.StudentID)
		if err != nil {
			span.RecordError(err)
			return user.User{}, err
		}
	} else {
		jwtUser, err = h.userStore.GetByEmail(traceCtx, userInfo.Email)
		if err != nil {
			return user.User{}, err
		}
	}

	return jwtUser, nil
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
