package oauthProvider

import (
	"context"
	"encoding/json"
	"fmt"
	"golang.org/x/oauth2"
	"io"
	"net/http"
	"net/url"
	"strings"
)

type NYCUProfile struct {
	Username string `json:"username"`
	Email    string `json:"email"`
}

type NYCUConfig struct {
	config *oauth2.Config
}

type NYCUUserInfo struct {
	Sub           string `json:"sub"`
	Name          string `json:"name"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
	Picture       string `json:"picture"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Locale        string `json:"locale"`
}

func NewNYCUConfig(clientID, clientSecret, redirectURL string) *NYCUConfig {
	return &NYCUConfig{
		config: &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  redirectURL,
			Scopes: []string{
				"profile",
			},
			Endpoint: oauth2.Endpoint{
				AuthURL:  "https://id.nycu.edu.tw/o/authorize/",
				TokenURL: "https://id.nycu.edu.tw/o/token/",
			},
		},
	}
}

func (n *NYCUConfig) Name() string {
	return "nycu"
}

func (n *NYCUConfig) Config() *oauth2.Config {
	return n.config
}

func (n *NYCUConfig) Exchange(ctx context.Context, code string) (*oauth2.Token, error) {
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("client_id", n.config.ClientID)
	data.Set("client_secret", n.config.ClientSecret)
	data.Set("redirect_uri", n.config.RedirectURL)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.config.Endpoint.TokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			return
		}
	}(resp.Body)

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("token exchange failed: %s (body: %s)", resp.Status, string(body))
	}

	var token oauth2.Token
	if err := json.NewDecoder(resp.Body).Decode(&token); err != nil {
		return nil, err
	}

	return &token, nil
	//return n.config.Exchange(ctx, code, oauth2.SetAuthURLParam("client_id", n.config.ClientID), oauth2.SetAuthURLParam("client_secret", n.config.ClientSecret))
}

func (n *NYCUConfig) GetUserInfo(ctx context.Context, token *oauth2.Token) (UserInfo, error) {
	client := n.config.Client(ctx, token)

	// Fetch user info from NYCU OAuth Service
	profileResp, err := client.Get("https://id.nycu.edu.tw/api/profile")
	if err != nil {
		return UserInfo{}, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			return
		}
	}(profileResp.Body)

	var profile NYCUProfile
	err = json.NewDecoder(profileResp.Body).Decode(&profile)
	if err != nil {
		return UserInfo{}, err
	}

	return UserInfo{
		ID:        profile.Username,
		StudentID: profile.Username,
		Email:     profile.Email,
	}, nil
}
