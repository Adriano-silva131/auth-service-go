package usecase_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/adriano-linux/auth-service-go/internal/domain"
	"github.com/adriano-linux/auth-service-go/internal/usecase"
)

type fakeRefreshTokenRepo struct {
	byHash map[string]*domain.RefreshToken
}

func newFakeRefreshTokenRepo() *fakeRefreshTokenRepo {
	return &fakeRefreshTokenRepo{byHash: make(map[string]*domain.RefreshToken)}
}

func (f *fakeRefreshTokenRepo) Insert(ctx context.Context, t *domain.RefreshToken) error {
	f.byHash[t.TokenHash] = t
	return nil
}

func (f *fakeRefreshTokenRepo) FindByTokenHash(ctx context.Context, tokenHash string) (*domain.RefreshToken, error) {
	t, ok := f.byHash[tokenHash]
	if !ok {
		return nil, domain.ErrRefreshTokenInvalid
	}
	return t, nil
}

func (f *fakeRefreshTokenRepo) Revoke(ctx context.Context, id uuid.UUID) error {
	for _, t := range f.byHash {
		if t.ID == id {
			now := time.Now().UTC()
			t.RevokedAt = &now
		}
	}
	return nil
}

// fakeIssuer issues deterministic, inspectable "tokens" instead of real JWTs/random
// bytes, so tests can assert on exactly what was issued without parsing a real JWT.
type fakeIssuer struct {
	seq int
	ttl time.Duration
}

func (f *fakeIssuer) IssueAccessToken(u *domain.User) (string, int, error) {
	return fmt.Sprintf("access-token-for-%s", u.ID), 300, nil
}

func (f *fakeIssuer) NewRefreshTokenValue() (string, string, error) {
	f.seq++
	plaintext := fmt.Sprintf("refresh-token-%d", f.seq)
	return plaintext, f.HashRefreshTokenValue(plaintext), nil
}

func (f *fakeIssuer) HashRefreshTokenValue(plaintext string) string {
	sum := sha256.Sum256([]byte(plaintext))
	return hex.EncodeToString(sum[:])
}

func (f *fakeIssuer) RefreshTokenTTL() time.Duration {
	if f.ttl == 0 {
		return 30 * 24 * time.Hour
	}
	return f.ttl
}

func TestLogin_ReturnsTokenPairOnValidCredentials(t *testing.T) {
	users := newFakeUserRepo()
	tokens := newFakeRefreshTokenRepo()
	hash, _ := fakeHasher{}.Hash("supersecret")
	user := &domain.User{ID: uuid.New(), Email: "user@example.com", PasswordHash: &hash, Name: "User", CreatedAt: time.Now(), UpdatedAt: time.Now()}
	users.byEmail[user.Email] = user
	users.byID[user.ID] = user

	uc := usecase.NewLogin(users, tokens, fakeHasher{}, &fakeIssuer{})

	pair, err := uc.Handle(context.Background(), usecase.LoginInput{Email: "user@example.com", Password: "supersecret"})

	require.NoError(t, err)
	assert.Equal(t, fmt.Sprintf("access-token-for-%s", user.ID), pair.AccessToken)
	assert.NotEmpty(t, pair.RefreshToken)
	assert.Len(t, tokens.byHash, 1)
}

func TestLogin_RejectsWrongPassword(t *testing.T) {
	users := newFakeUserRepo()
	tokens := newFakeRefreshTokenRepo()
	hash, _ := fakeHasher{}.Hash("supersecret")
	user := &domain.User{ID: uuid.New(), Email: "user@example.com", PasswordHash: &hash, Name: "User"}
	users.byEmail[user.Email] = user

	uc := usecase.NewLogin(users, tokens, fakeHasher{}, &fakeIssuer{})

	_, err := uc.Handle(context.Background(), usecase.LoginInput{Email: "user@example.com", Password: "wrong"})
	assert.ErrorIs(t, err, domain.ErrInvalidCredentials)
}

func TestLogin_RejectsUnknownEmail(t *testing.T) {
	uc := usecase.NewLogin(newFakeUserRepo(), newFakeRefreshTokenRepo(), fakeHasher{}, &fakeIssuer{})

	_, err := uc.Handle(context.Background(), usecase.LoginInput{Email: "nobody@example.com", Password: "whatever"})
	assert.ErrorIs(t, err, domain.ErrInvalidCredentials)
}

func TestLogin_RejectsUserWithNoPassword(t *testing.T) {
	users := newFakeUserRepo()
	user := &domain.User{ID: uuid.New(), Email: "social@example.com", PasswordHash: nil, Name: "Social User"}
	users.byEmail[user.Email] = user

	uc := usecase.NewLogin(users, newFakeRefreshTokenRepo(), fakeHasher{}, &fakeIssuer{})

	_, err := uc.Handle(context.Background(), usecase.LoginInput{Email: "social@example.com", Password: "anything"})
	assert.ErrorIs(t, err, domain.ErrInvalidCredentials)
}
