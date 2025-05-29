package oauthprovider

import (
	"context"
	"encoding/json"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"io"
)

type GoogleConfig struct {
	config *oauth2.Config
}

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

func NewGoogleConfig(clientID, clientSecret, redirectURL string) *GoogleConfig {
	return &GoogleConfig{
		config: &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  redirectURL,
			Scopes: []string{
				"https://www.googleapis.com/auth/userinfo.email",
				"https://www.googleapis.com/auth/userinfo.profile",
			},
			Endpoint: google.Endpoint,
		},
	}
}

func (g *GoogleConfig) Name() string {
	return "google"
}

func (g *GoogleConfig) Config() *oauth2.Config {
	return g.config
}

func (g *GoogleConfig) Exchange(ctx context.Context, code string) (*oauth2.Token, error) {
	return g.config.Exchange(ctx, code)
}

func (g *GoogleConfig) GetUserInfo(ctx context.Context, token *oauth2.Token) (UserInfo, error) {
	client := g.config.Client(ctx, token)
	resp, err := client.Get("https://www.googleapis.com/oauth2/v3/userinfo")
	if err != nil {
		return UserInfo{}, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			return
		}
	}(resp.Body)

	var userInfo googleUserInfo
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return UserInfo{}, err
	}

	return UserInfo{
		ID:    userInfo.Sub,
		Name:  userInfo.Name,
		Email: userInfo.Email,
	}, nil
}
