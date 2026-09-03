package usecase

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/adriano-linux/auth-service-go/internal/domain"
)

const maxVerificationAttempts = 5

type VerifyCodeInput struct {
	Email string
	Code  string
}

type VerifyCode struct {
	codes  VerificationCodeRepository
	users  UserRepository
	tokens RefreshTokenRepository
	issuer TokenIssuer
}

func NewVerifyCode(codes VerificationCodeRepository, users UserRepository, tokens RefreshTokenRepository, issuer TokenIssuer) *VerifyCode {
	return &VerifyCode{codes: codes, users: users, tokens: tokens, issuer: issuer}
}

func (uc *VerifyCode) Handle(ctx context.Context, in VerifyCodeInput) (*TokenPair, error) {
	email := normalizeEmail(in.Email)

	record, err := uc.codes.FindLatestByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, domain.ErrCodeNotFound) {
			return nil, domain.ErrCodeInvalid
		}
		return nil, fmt.Errorf("loading verification code: %w", err)
	}

	if record.ConsumedAt != nil || time.Now().UTC().After(record.ExpiresAt) {
		return nil, domain.ErrCodeInvalid
	}
	if record.Attempts >= maxVerificationAttempts {
		return nil, domain.ErrTooManyAttempts
	}

	if hashVerificationCode(in.Code) != record.CodeHash {
		if err := uc.codes.IncrementAttempts(ctx, record.ID); err != nil {
			return nil, fmt.Errorf("recording failed attempt: %w", err)
		}
		return nil, domain.ErrCodeInvalid
	}

	if err := uc.codes.MarkConsumed(ctx, record.ID); err != nil {
		return nil, fmt.Errorf("consuming verification code: %w", err)
	}

	user, err := uc.users.FindByEmail(ctx, email)
	if err != nil {
		if !errors.Is(err, domain.ErrUserNotFound) {
			return nil, fmt.Errorf("loading user: %w", err)
		}
		// New account, created passwordless (PasswordHash stays nil) — the
		// same pattern the users table already reserves for social login.
		// No name is collected in this flow; email stands in until the user
		// sets one.
		now := time.Now().UTC()
		user = &domain.User{
			ID:        uuid.New(),
			Email:     email,
			Name:      email,
			Roles:     []string{domain.RoleCustomer},
			CreatedAt: now,
			UpdatedAt: now,
		}
		if err := uc.users.Insert(ctx, user); err != nil {
			return nil, fmt.Errorf("creating user: %w", err)
		}
	}

	return issueTokenPairFor(ctx, uc.tokens, uc.issuer, user)
}
