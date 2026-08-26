package handler

import "github.com/adriano-linux/auth-service-go/internal/usecase"

// tokenPairResponse is shared by login and refresh — same shape, per RFC 6749's token
// response conventions.
type tokenPairResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
}

func toTokenPairResponse(pair *usecase.TokenPair) tokenPairResponse {
	return tokenPairResponse{
		AccessToken:  pair.AccessToken,
		RefreshToken: pair.RefreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    pair.ExpiresIn,
	}
}
