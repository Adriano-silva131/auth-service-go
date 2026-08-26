package usecase

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/adriano-linux/auth-service-go/internal/domain"
)

type LoginInput struct {
	Email    string
	Password string
}

type Login struct {
	users  UserRepository
	tokens RefreshTokenRepository
	hasher PasswordHasher
	issuer TokenIssuer
}

func NewLogin(users UserRepository, tokens RefreshTokenRepository, hasher PasswordHasher, issuer TokenIssuer) *Login {
	return &Login{users: users, tokens: tokens, hasher: hasher, issuer: issuer}
}

func (uc *Login) Handle(ctx context.Context, in LoginInput) (*TokenPair, error) {
	user, err := uc.users.FindByEmail(ctx, normalizeEmail(in.Email))
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			return nil, domain.ErrInvalidCredentials
		}
		return nil, fmt.Errorf("loading user: %w", err)
	}

	if user.PasswordHash == nil || !uc.hasher.Matches(*user.PasswordHash, in.Password) {
		return nil, domain.ErrInvalidCredentials
	}

	return issueTokenPairFor(ctx, uc.tokens, uc.issuer, user)
}

func issueTokenPairFor(ctx context.Context, tokens RefreshTokenRepository, issuer TokenIssuer, user *domain.User) (*TokenPair, error) {
	accessToken, expiresIn, err := issuer.IssueAccessToken(user)
	if err != nil {
		return nil, fmt.Errorf("issuing access token: %w", err)
	}

	plaintext, hash, err := issuer.NewRefreshTokenValue()
	if err != nil {
		return nil, fmt.Errorf("generating refresh token: %w", err)
	}

	now := time.Now().UTC()
	refreshToken := &domain.RefreshToken{
		ID:        uuid.New(),
		UserID:    user.ID,
		TokenHash: hash,
		ExpiresAt: now.Add(issuer.RefreshTokenTTL()),
		CreatedAt: now,
	}
	if err := tokens.Insert(ctx, refreshToken); err != nil {
		return nil, fmt.Errorf("persisting refresh token: %w", err)
	}

	return &TokenPair{AccessToken: accessToken, RefreshToken: plaintext, ExpiresIn: expiresIn}, nil
}
