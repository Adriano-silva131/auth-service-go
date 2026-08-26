package usecase_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/adriano-linux/auth-service-go/internal/usecase"
)

func TestLogout_RevokesToken(t *testing.T) {
	users := newFakeUserRepo()
	tokens := newFakeRefreshTokenRepo()
	issuer := &fakeIssuer{}
	_, plaintext := seedUserWithRefreshToken(users, tokens, issuer, false)

	uc := usecase.NewLogout(tokens, issuer)

	require.NoError(t, uc.Handle(context.Background(), plaintext))

	refreshUC := usecase.NewRefreshAccessToken(users, tokens, issuer)
	_, err := refreshUC.Handle(context.Background(), plaintext)
	assert.Error(t, err, "a logged-out refresh token must no longer work")
}

func TestLogout_IsIdempotentForUnknownToken(t *testing.T) {
	uc := usecase.NewLogout(newFakeRefreshTokenRepo(), &fakeIssuer{})

	err := uc.Handle(context.Background(), "never-issued")
	assert.NoError(t, err)
}
