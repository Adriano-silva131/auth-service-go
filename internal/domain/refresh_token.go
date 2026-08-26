package domain

import (
	"time"

	"github.com/google/uuid"
)

// RefreshToken stores only a hash of the opaque token value handed to the client —
// the plaintext token is never persisted, so a database leak alone can't be used to
// impersonate a session (same rationale as password hashing).
type RefreshToken struct {
	ID        uuid.UUID
	UserID    uuid.UUID
	TokenHash string
	ExpiresAt time.Time
	RevokedAt *time.Time
	CreatedAt time.Time
}

func (t *RefreshToken) IsValid(now time.Time) bool {
	return t.RevokedAt == nil && now.Before(t.ExpiresAt)
}
