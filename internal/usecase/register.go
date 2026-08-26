package usecase

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/adriano-linux/auth-service-go/internal/domain"
)

type RegisterInput struct {
	Email    string
	Password string
	Name     string
}

type Register struct {
	users  UserRepository
	hasher PasswordHasher
}

func NewRegister(users UserRepository, hasher PasswordHasher) *Register {
	return &Register{users: users, hasher: hasher}
}

func (uc *Register) Handle(ctx context.Context, in RegisterInput) (*domain.User, error) {
	email := normalizeEmail(in.Email)

	exists, err := uc.users.ExistsByEmail(ctx, email)
	if err != nil {
		return nil, fmt.Errorf("checking existing user: %w", err)
	}
	if exists {
		return nil, domain.ErrEmailAlreadyExists
	}

	hash, err := uc.hasher.Hash(in.Password)
	if err != nil {
		return nil, fmt.Errorf("hashing password: %w", err)
	}

	now := time.Now().UTC()
	user := &domain.User{
		ID:           uuid.New(),
		Email:        email,
		PasswordHash: &hash,
		Name:         in.Name,
		Roles:        []string{domain.RoleCustomer},
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	if err := uc.users.Insert(ctx, user); err != nil {
		return nil, fmt.Errorf("inserting user: %w", err)
	}

	return user, nil
}

func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}
