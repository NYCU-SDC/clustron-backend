package oauthprovider

import (
	"context"
	"encoding/json"
	"io"
	"strconv"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

type GithubConfig struct {
	config *oauth2.Config
}

type githubUserResponse struct {
	ID    int64  `json:"id"`
	Login string `json:"login"`
	Name  string `json:"name"`
	Email string `json:"email"`
}

type GithubUserInfo struct {
	UserInfo
}

func (g *GithubUserInfo) GetUserInfo() UserInfo { return g.UserInfo }

func (g *GithubUserInfo) SetUserInfo(userInfo UserInfo) {
	g.UserInfo = userInfo
}

func NewGithubConfig(clientID, clientSecret, redirectURL string) *GithubConfig {
	return &GithubConfig{
		config: &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  redirectURL,
			Scopes: []string{
				"read:user",
				"user:email",
			},
			Endpoint: github.Endpoint,
		},
	}
}

func (g *GithubConfig) Name() string { return "github" }

func (g *GithubConfig) Config() *oauth2.Config { return g.config }

func (g *GithubConfig) Exchange(ctx context.Context, code string) (*oauth2.Token, error) {
	return g.config.Exchange(ctx, code)
}

func (g *GithubConfig) GetUserInfo(ctx context.Context, token *oauth2.Token) (UserInfoStore, error) {
	client := g.config.Client(ctx, token)
	resp, err := client.Get("https://api.github.com/user")
	if err != nil {
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			return
		}
	}(resp.Body)

	var userInfo githubUserResponse
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return nil, err
	}

	displayName := userInfo.Name
	if displayName == "" {
		displayName = userInfo.Login
	}

	return &GithubUserInfo{
		UserInfo: UserInfo{
			ID:    strconv.FormatInt(userInfo.ID, 10),
			Email: userInfo.Email,
			Name:  displayName,
		},
	}, nil
}
