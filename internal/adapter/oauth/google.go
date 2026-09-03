// Package oauth implements usecase.GoogleOAuthProvider against Google's real
// OAuth 2.0 endpoints.
package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/adriano-linux/auth-service-go/internal/usecase"
)

const (
	googleAuthorizeEndpoint = "https://accounts.google.com/o/oauth2/v2/auth"
	googleTokenEndpoint     = "https://oauth2.googleapis.com/token"
	googleUserinfoEndpoint  = "https://www.googleapis.com/oauth2/v3/userinfo"
)

type GoogleProvider struct {
	clientID     string
	clientSecret string
	redirectURI  string
	httpClient   *http.Client
}

func NewGoogleProvider(clientID, clientSecret, redirectURI string) *GoogleProvider {
	return &GoogleProvider{
		clientID:     clientID,
		clientSecret: clientSecret,
		redirectURI:  redirectURI,
		httpClient:   &http.Client{Timeout: 10 * time.Second},
	}
}

func (p *GoogleProvider) AuthorizeURL(state string) string {
	q := url.Values{
		"client_id":     {p.clientID},
		"redirect_uri":  {p.redirectURI},
		"response_type": {"code"},
		"scope":         {"openid email profile"},
		"state":         {state},
		"prompt":        {"select_account"},
	}
	return googleAuthorizeEndpoint + "?" + q.Encode()
}

type googleTokenResponse struct {
	AccessToken string `json:"access_token"`
	Error       string `json:"error"`
	ErrorDesc   string `json:"error_description"`
}

type googleUserinfoResponse struct {
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
}

func (p *GoogleProvider) Exchange(ctx context.Context, code string) (usecase.GoogleIdentity, error) {
	token, err := p.exchangeCodeForToken(ctx, code)
	if err != nil {
		return usecase.GoogleIdentity{}, err
	}

	info, err := p.fetchUserinfo(ctx, token)
	if err != nil {
		return usecase.GoogleIdentity{}, err
	}

	return usecase.GoogleIdentity{
		Email:         info.Email,
		EmailVerified: info.EmailVerified,
		Name:          info.Name,
	}, nil
}

func (p *GoogleProvider) exchangeCodeForToken(ctx context.Context, code string) (string, error) {
	form := url.Values{
		"code":          {code},
		"client_id":     {p.clientID},
		"client_secret": {p.clientSecret},
		"redirect_uri":  {p.redirectURI},
		"grant_type":    {"authorization_code"},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, googleTokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("building google token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("calling google token endpoint: %w", err)
	}
	defer resp.Body.Close()

	var tok googleTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil {
		return "", fmt.Errorf("decoding google token response: %w", err)
	}
	if resp.StatusCode != http.StatusOK || tok.AccessToken == "" {
		return "", fmt.Errorf("google token exchange failed (status %d): %s %s", resp.StatusCode, tok.Error, tok.ErrorDesc)
	}

	return tok.AccessToken, nil
}

func (p *GoogleProvider) fetchUserinfo(ctx context.Context, accessToken string) (googleUserinfoResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, googleUserinfoEndpoint, nil)
	if err != nil {
		return googleUserinfoResponse{}, fmt.Errorf("building google userinfo request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return googleUserinfoResponse{}, fmt.Errorf("calling google userinfo endpoint: %w", err)
	}
	defer resp.Body.Close()

	var info googleUserinfoResponse
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return googleUserinfoResponse{}, fmt.Errorf("decoding google userinfo response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return googleUserinfoResponse{}, fmt.Errorf("google userinfo request failed with status %d", resp.StatusCode)
	}

	return info, nil
}
