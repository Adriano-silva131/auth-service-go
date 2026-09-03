package domain

import (
	"time"

	"github.com/google/uuid"
)

type VerificationCode struct {
	ID         uuid.UUID
	Email      string
	CodeHash   string
	ExpiresAt  time.Time
	ConsumedAt *time.Time
	Attempts   int
	CreatedAt  time.Time
}
