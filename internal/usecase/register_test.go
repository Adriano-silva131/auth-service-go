package usecase_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/adriano-linux/auth-service-go/internal/domain"
	"github.com/adriano-linux/auth-service-go/internal/usecase"
)

type fakeUserRepo struct {
	byEmail   map[string]*domain.User
	byID      map[uuid.UUID]*domain.User
	insertErr error
}

func newFakeUserRepo() *fakeUserRepo {
	return &fakeUserRepo{byEmail: make(map[string]*domain.User), byID: make(map[uuid.UUID]*domain.User)}
}

func (f *fakeUserRepo) ExistsByEmail(ctx context.Context, email string) (bool, error) {
	_, ok := f.byEmail[email]
	return ok, nil
}

func (f *fakeUserRepo) Insert(ctx context.Context, u *domain.User) error {
	if f.insertErr != nil {
		return f.insertErr
	}
	f.byEmail[u.Email] = u
	f.byID[u.ID] = u
	return nil
}

func (f *fakeUserRepo) FindByEmail(ctx context.Context, email string) (*domain.User, error) {
	u, ok := f.byEmail[email]
	if !ok {
		return nil, domain.ErrUserNotFound
	}
	return u, nil
}

func (f *fakeUserRepo) FindByID(ctx context.Context, id uuid.UUID) (*domain.User, error) {
	u, ok := f.byID[id]
	if !ok {
		return nil, domain.ErrUserNotFound
	}
	return u, nil
}

func (f *fakeUserRepo) AddRole(ctx context.Context, userID uuid.UUID, role string) (*domain.User, error) {
	u, ok := f.byID[userID]
	if !ok {
		return nil, domain.ErrUserNotFound
	}
	for _, r := range u.Roles {
		if r == role {
			return u, nil
		}
	}
	u.Roles = append(u.Roles, role)
	return u, nil
}

type fakeHasher struct{}

func (fakeHasher) Hash(password string) (string, error) { return "hashed:" + password, nil }
func (fakeHasher) Matches(hash, password string) bool   { return hash == "hashed:"+password }

func TestRegister_CreatesUserWithLowercasedEmail(t *testing.T) {
	repo := newFakeUserRepo()
	uc := usecase.NewRegister(repo, fakeHasher{})

	user, err := uc.Handle(context.Background(), usecase.RegisterInput{
		Email: "  User@Example.com ", Password: "supersecret", Name: "User",
	})

	require.NoError(t, err)
	assert.Equal(t, "user@example.com", user.Email)
	require.NotNil(t, user.PasswordHash)
	assert.Equal(t, "hashed:supersecret", *user.PasswordHash)
	assert.Equal(t, []string{domain.RoleCustomer}, user.Roles)
}

func TestRegister_RejectsDuplicateEmail(t *testing.T) {
	repo := newFakeUserRepo()
	uc := usecase.NewRegister(repo, fakeHasher{})
	ctx := context.Background()

	_, err := uc.Handle(ctx, usecase.RegisterInput{Email: "dup@example.com", Password: "supersecret", Name: "A"})
	require.NoError(t, err)

	_, err = uc.Handle(ctx, usecase.RegisterInput{Email: "DUP@example.com", Password: "anotherpass", Name: "B"})
	assert.ErrorIs(t, err, domain.ErrEmailAlreadyExists)
}
