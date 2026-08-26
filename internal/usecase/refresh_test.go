package usecase_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/adriano-linux/auth-service-go/internal/domain"
	"github.com/adriano-linux/auth-service-go/internal/usecase"
)

func seedUserWithRefreshToken(users *fakeUserRepo, tokens *fakeRefreshTokenRepo, issuer *fakeIssuer, expired bool) (*domain.User, string) {
	user := &domain.User{ID: uuid.New(), Email: "user@example.com", Name: "User"}
	users.byEmail[user.Email] = user
	users.byID[user.ID] = user

	plaintext, hash, _ := issuer.NewRefreshTokenValue()
	expiresAt := time.Now().UTC().Add(30 * 24 * time.Hour)
	if expired {
		expiresAt = time.Now().UTC().Add(-1 * time.Hour)
	}
	tokens.byHash[hash] = &domain.RefreshToken{
		ID: uuid.New(), UserID: user.ID, TokenHash: hash, ExpiresAt: expiresAt, CreatedAt: time.Now().UTC(),
	}
	return user, plaintext
}

func TestRefresh_RotatesTokenOnSuccess(t *testing.T) {
	users := newFakeUserRepo()
	tokens := newFakeRefreshTokenRepo()
	issuer := &fakeIssuer{}
	_, oldPlaintext := seedUserWithRefreshToken(users, tokens, issuer, false)

	uc := usecase.NewRefreshAccessToken(users, tokens, issuer)

	pair, err := uc.Handle(context.Background(), oldPlaintext)
	require.NoError(t, err)
	assert.NotEqual(t, oldPlaintext, pair.RefreshToken)

	oldHash := issuer.HashRefreshTokenValue(oldPlaintext)
	assert.NotNil(t, tokens.byHash[oldHash].RevokedAt, "old refresh token must be revoked after rotation")

	_, err = uc.Handle(context.Background(), oldPlaintext)
	assert.ErrorIs(t, err, domain.ErrRefreshTokenInvalid, "a revoked token must not be usable again")
}

func TestRefresh_RejectsExpiredToken(t *testing.T) {
	users := newFakeUserRepo()
	tokens := newFakeRefreshTokenRepo()
	issuer := &fakeIssuer{}
	_, plaintext := seedUserWithRefreshToken(users, tokens, issuer, true)

	uc := usecase.NewRefreshAccessToken(users, tokens, issuer)

	_, err := uc.Handle(context.Background(), plaintext)
	assert.ErrorIs(t, err, domain.ErrRefreshTokenInvalid)
}

func TestRefresh_RejectsUnknownToken(t *testing.T) {
	uc := usecase.NewRefreshAccessToken(newFakeUserRepo(), newFakeRefreshTokenRepo(), &fakeIssuer{})

	_, err := uc.Handle(context.Background(), "never-issued")
	assert.ErrorIs(t, err, domain.ErrRefreshTokenInvalid)
}
