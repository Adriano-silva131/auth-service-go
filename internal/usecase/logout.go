package usecase

import (
	"context"
	"errors"
	"fmt"

	"github.com/adriano-linux/auth-service-go/internal/domain"
)

type Logout struct {
	tokens RefreshTokenRepository
	issuer TokenIssuer
}

func NewLogout(tokens RefreshTokenRepository, issuer TokenIssuer) *Logout {
	return &Logout{tokens: tokens, issuer: issuer}
}

// Handle is idempotent: an unknown or already-revoked token is not an error — the
// caller's intent (this token must no longer work) is already satisfied.
func (uc *Logout) Handle(ctx context.Context, plaintextRefreshToken string) error {
	hash := uc.issuer.HashRefreshTokenValue(plaintextRefreshToken)

	stored, err := uc.tokens.FindByTokenHash(ctx, hash)
	if err != nil {
		if errors.Is(err, domain.ErrRefreshTokenInvalid) {
			return nil
		}
		return fmt.Errorf("loading refresh token: %w", err)
	}

	if err := uc.tokens.Revoke(ctx, stored.ID); err != nil {
		return fmt.Errorf("revoking refresh token: %w", err)
	}
	return nil
}
