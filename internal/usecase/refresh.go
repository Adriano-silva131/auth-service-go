package usecase

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/adriano-linux/auth-service-go/internal/domain"
)

type RefreshAccessToken struct {
	users  UserRepository
	tokens RefreshTokenRepository
	issuer TokenIssuer
}

func NewRefreshAccessToken(users UserRepository, tokens RefreshTokenRepository, issuer TokenIssuer) *RefreshAccessToken {
	return &RefreshAccessToken{users: users, tokens: tokens, issuer: issuer}
}

// Handle rotates the refresh token on every successful call: the presented token is
// revoked and a brand-new pair is issued, mitigating refresh-token replay.
func (uc *RefreshAccessToken) Handle(ctx context.Context, plaintextRefreshToken string) (*TokenPair, error) {
	hash := uc.issuer.HashRefreshTokenValue(plaintextRefreshToken)

	stored, err := uc.tokens.FindByTokenHash(ctx, hash)
	if err != nil {
		if errors.Is(err, domain.ErrRefreshTokenInvalid) {
			return nil, domain.ErrRefreshTokenInvalid
		}
		return nil, fmt.Errorf("loading refresh token: %w", err)
	}

	if !stored.IsValid(time.Now().UTC()) {
		return nil, domain.ErrRefreshTokenInvalid
	}

	user, err := uc.users.FindByID(ctx, stored.UserID)
	if err != nil {
		return nil, fmt.Errorf("loading user for refresh token: %w", err)
	}

	if err := uc.tokens.Revoke(ctx, stored.ID); err != nil {
		return nil, fmt.Errorf("revoking used refresh token: %w", err)
	}

	return issueTokenPairFor(ctx, uc.tokens, uc.issuer, user)
}
