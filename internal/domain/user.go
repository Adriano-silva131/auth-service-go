package domain

import (
	"time"

	"github.com/google/uuid"
)

// User's PasswordHash is nullable: a user created via a future social login
// (e.g. Google, planned once the frontend exists) will have no password at all.
type User struct {
	ID           uuid.UUID
	Email        string
	PasswordHash *string
	Name         string
	Roles        []string
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// Roles are additive, not exclusive — a single account can hold both at once (e.g. a
// buyer who also sells), so there is no separate account type to switch between.
const (
	RoleCustomer = "CUSTOMER"
	RoleSeller   = "SELLER"
)
