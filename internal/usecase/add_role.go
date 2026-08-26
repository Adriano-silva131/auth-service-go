package usecase

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"github.com/adriano-linux/auth-service-go/internal/domain"
)

type AddRoleInput struct {
	UserID uuid.UUID
	Role   string
}

type AddRole struct {
	users UserRepository
}

func NewAddRole(users UserRepository) *AddRole {
	return &AddRole{users: users}
}

// Handle only allows upgrading to SELLER — CUSTOMER is granted automatically at
// registration and isn't something a caller adds later.
func (uc *AddRole) Handle(ctx context.Context, in AddRoleInput) (*domain.User, error) {
	if in.Role != domain.RoleSeller {
		return nil, domain.ErrInvalidRole
	}

	user, err := uc.users.AddRole(ctx, in.UserID, in.Role)
	if err != nil {
		return nil, fmt.Errorf("adding role: %w", err)
	}
	return user, nil
}
