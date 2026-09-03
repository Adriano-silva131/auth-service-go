package usecase

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/adriano-linux/auth-service-go/internal/domain"
)

type CompleteGoogleOAuthInput struct {
	Code  string
	State string
}

type CompleteGoogleOAuthResult struct {
	Tokens     *TokenPair
	RedirectTo string
}

type CompleteGoogleOAuth struct {
	provider GoogleOAuthProvider
	signer   *oauthStateSigner
	users    UserRepository
	tokens   RefreshTokenRepository
	issuer   TokenIssuer
}

func NewCompleteGoogleOAuth(provider GoogleOAuthProvider, stateSecret string, users UserRepository, tokens RefreshTokenRepository, issuer TokenIssuer) *CompleteGoogleOAuth {
	return &CompleteGoogleOAuth{provider: provider, signer: newOAuthStateSigner(stateSecret), users: users, tokens: tokens, issuer: issuer}
}

func (uc *CompleteGoogleOAuth) Handle(ctx context.Context, in CompleteGoogleOAuthInput) (*CompleteGoogleOAuthResult, error) {
	redirectTo, err := uc.signer.verify(in.State)
	if err != nil {
		return nil, domain.ErrOAuthStateInvalid
	}

	identity, err := uc.provider.Exchange(ctx, in.Code)
	if err != nil {
		return nil, fmt.Errorf("exchanging google authorization code: %w", err)
	}
	if !identity.EmailVerified {
		return nil, domain.ErrOAuthEmailNotVerified
	}

	email := normalizeEmail(identity.Email)
	user, err := uc.users.FindByEmail(ctx, email)
	if err != nil {
		if !errors.Is(err, domain.ErrUserNotFound) {
			return nil, fmt.Errorf("loading user: %w", err)
		}
		now := time.Now().UTC()
		name := identity.Name
		if name == "" {
			name = email
		}
		user = &domain.User{
			ID:        uuid.New(),
			Email:     email,
			Name:      name,
			Roles:     []string{domain.RoleCustomer},
			CreatedAt: now,
			UpdatedAt: now,
		}
		if err := uc.users.Insert(ctx, user); err != nil {
			return nil, fmt.Errorf("creating user: %w", err)
		}
	}

	pair, err := issueTokenPairFor(ctx, uc.tokens, uc.issuer, user)
	if err != nil {
		return nil, err
	}

	return &CompleteGoogleOAuthResult{Tokens: pair, RedirectTo: redirectTo}, nil
}
