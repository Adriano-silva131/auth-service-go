package usecase

import (
	"context"
	"errors"

	"github.com/google/uuid"

	"github.com/adriano-linux/auth-service-go/internal/domain"
)

type BulkCreateItem struct {
	Email    string
	Password string
	Name     string
}

type CreatedUser struct {
	ID    uuid.UUID
	Email string
}

type SkippedUser struct {
	Email  string
	Reason string
}

type BulkCreateResult struct {
	Created []CreatedUser
	Skipped []SkippedUser
}

// CreateUsersBulk exists to provision synthetic test users for k6 load testing —
// duplicates are reported per-item in Skipped rather than failing the whole batch,
// so re-running the load-test setup script is safe.
type CreateUsersBulk struct {
	register *Register
}

func NewCreateUsersBulk(register *Register) *CreateUsersBulk {
	return &CreateUsersBulk{register: register}
}

func (uc *CreateUsersBulk) Handle(ctx context.Context, items []BulkCreateItem) BulkCreateResult {
	result := BulkCreateResult{}

	for _, item := range items {
		user, err := uc.register.Handle(ctx, RegisterInput{Email: item.Email, Password: item.Password, Name: item.Name})
		if err != nil {
			reason := "unknown error"
			if errors.Is(err, domain.ErrEmailAlreadyExists) {
				reason = "email already registered"
			}
			result.Skipped = append(result.Skipped, SkippedUser{Email: item.Email, Reason: reason})
			continue
		}
		result.Created = append(result.Created, CreatedUser{ID: user.ID, Email: user.Email})
	}

	return result
}
