package usecase_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/adriano-linux/auth-service-go/internal/domain"
	"github.com/adriano-linux/auth-service-go/internal/usecase"
)

func requestRealCode(t *testing.T, codes *fakeVerificationCodeRepo, email string) string {
	t.Helper()
	sender := &fakeCodeSender{}
	require.NoError(t, usecase.NewRequestCode(codes, sender).Handle(context.Background(), usecase.RequestCodeInput{Email: email}))
	return sender.sentCode
}

func TestVerifyCode_CreatesNewUserAndReturnsTokenPairOnFirstLogin(t *testing.T) {
	codes := newFakeVerificationCodeRepo()
	users := newFakeUserRepo()
	tokens := newFakeRefreshTokenRepo()
	code := requestRealCode(t, codes, "new.user@example.com")

	uc := usecase.NewVerifyCode(codes, users, tokens, &fakeIssuer{})
	pair, err := uc.Handle(context.Background(), usecase.VerifyCodeInput{Email: "new.user@example.com", Code: code})

	require.NoError(t, err)
	assert.NotEmpty(t, pair.AccessToken)
	created, err := users.FindByEmail(context.Background(), "new.user@example.com")
	require.NoError(t, err)
	assert.Nil(t, created.PasswordHash, "passwordless account must have no password hash")
	assert.Contains(t, created.Roles, domain.RoleCustomer)
}

func TestVerifyCode_LogsInExistingUserWithoutDuplicating(t *testing.T) {
	codes := newFakeVerificationCodeRepo()
	users := newFakeUserRepo()
	tokens := newFakeRefreshTokenRepo()
	existing := &domain.User{ID: uuid.New(), Email: "returning@example.com", Name: "Returning", Roles: []string{domain.RoleCustomer}}
	users.byEmail[existing.Email] = existing
	users.byID[existing.ID] = existing
	code := requestRealCode(t, codes, "returning@example.com")

	uc := usecase.NewVerifyCode(codes, users, tokens, &fakeIssuer{})
	pair, err := uc.Handle(context.Background(), usecase.VerifyCodeInput{Email: "returning@example.com", Code: code})

	require.NoError(t, err)
	assert.Equal(t, fmt.Sprintf("access-token-for-%s", existing.ID), pair.AccessToken)
	assert.Len(t, users.byEmail, 1, "must not create a second account for the same email")
}

func TestVerifyCode_RejectsWrongCode(t *testing.T) {
	codes := newFakeVerificationCodeRepo()
	users := newFakeUserRepo()
	requestRealCode(t, codes, "user@example.com")

	uc := usecase.NewVerifyCode(codes, users, newFakeRefreshTokenRepo(), &fakeIssuer{})
	_, err := uc.Handle(context.Background(), usecase.VerifyCodeInput{Email: "user@example.com", Code: "000000"})

	assert.ErrorIs(t, err, domain.ErrCodeInvalid)
	assert.Equal(t, 1, codes.byID[0].Attempts, "a failed attempt must be recorded")
}

func TestVerifyCode_RejectsExpiredCode(t *testing.T) {
	codes := newFakeVerificationCodeRepo()
	users := newFakeUserRepo()
	code := requestRealCode(t, codes, "user@example.com")
	codes.byID[0].ExpiresAt = time.Now().UTC().Add(-time.Minute)

	uc := usecase.NewVerifyCode(codes, users, newFakeRefreshTokenRepo(), &fakeIssuer{})
	_, err := uc.Handle(context.Background(), usecase.VerifyCodeInput{Email: "user@example.com", Code: code})

	assert.ErrorIs(t, err, domain.ErrCodeInvalid)
}

func TestVerifyCode_RejectsAlreadyConsumedCode(t *testing.T) {
	codes := newFakeVerificationCodeRepo()
	users := newFakeUserRepo()
	code := requestRealCode(t, codes, "user@example.com")
	now := time.Now().UTC()
	codes.byID[0].ConsumedAt = &now

	uc := usecase.NewVerifyCode(codes, users, newFakeRefreshTokenRepo(), &fakeIssuer{})
	_, err := uc.Handle(context.Background(), usecase.VerifyCodeInput{Email: "user@example.com", Code: code})

	assert.ErrorIs(t, err, domain.ErrCodeInvalid)
}

func TestVerifyCode_LocksOutAfterTooManyAttempts(t *testing.T) {
	codes := newFakeVerificationCodeRepo()
	users := newFakeUserRepo()
	code := requestRealCode(t, codes, "user@example.com")
	codes.byID[0].Attempts = 5

	uc := usecase.NewVerifyCode(codes, users, newFakeRefreshTokenRepo(), &fakeIssuer{})
	_, err := uc.Handle(context.Background(), usecase.VerifyCodeInput{Email: "user@example.com", Code: code})

	assert.ErrorIs(t, err, domain.ErrTooManyAttempts)
}

func TestVerifyCode_RejectsWhenNoCodeWasEverRequested(t *testing.T) {
	uc := usecase.NewVerifyCode(newFakeVerificationCodeRepo(), newFakeUserRepo(), newFakeRefreshTokenRepo(), &fakeIssuer{})

	_, err := uc.Handle(context.Background(), usecase.VerifyCodeInput{Email: "nobody@example.com", Code: "123456"})

	assert.ErrorIs(t, err, domain.ErrCodeInvalid)
}
