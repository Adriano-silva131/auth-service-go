package postgres

import (
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/adriano-linux/auth-service-go/internal/domain"
)

// userModel and refreshTokenModel carry the GORM struct tags — kept out of internal/domain
// so the domain package stays free of persistence concerns (no external imports).

type userModel struct {
	ID           uuid.UUID `gorm:"type:uuid;primaryKey"`
	Email        string    `gorm:"uniqueIndex;not null"`
	PasswordHash *string
	Name         string         `gorm:"not null"`
	Roles        pq.StringArray `gorm:"type:text[];not null"`
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

func (userModel) TableName() string { return "users" }

func fromDomainUser(u *domain.User) userModel {
	return userModel{
		ID:           u.ID,
		Email:        u.Email,
		PasswordHash: u.PasswordHash,
		Name:         u.Name,
		Roles:        pq.StringArray(u.Roles),
		CreatedAt:    u.CreatedAt,
		UpdatedAt:    u.UpdatedAt,
	}
}

func toDomainUser(m *userModel) *domain.User {
	return &domain.User{
		ID:           m.ID,
		Email:        m.Email,
		PasswordHash: m.PasswordHash,
		Name:         m.Name,
		Roles:        []string(m.Roles),
		CreatedAt:    m.CreatedAt,
		UpdatedAt:    m.UpdatedAt,
	}
}

type refreshTokenModel struct {
	ID        uuid.UUID `gorm:"type:uuid;primaryKey"`
	UserID    uuid.UUID `gorm:"type:uuid;not null;index"`
	TokenHash string    `gorm:"uniqueIndex;not null"`
	ExpiresAt time.Time `gorm:"not null"`
	RevokedAt *time.Time
	CreatedAt time.Time
}

func (refreshTokenModel) TableName() string { return "refresh_tokens" }

func fromDomainRefreshToken(t *domain.RefreshToken) refreshTokenModel {
	return refreshTokenModel{
		ID:        t.ID,
		UserID:    t.UserID,
		TokenHash: t.TokenHash,
		ExpiresAt: t.ExpiresAt,
		RevokedAt: t.RevokedAt,
		CreatedAt: t.CreatedAt,
	}
}

func toDomainRefreshToken(m *refreshTokenModel) *domain.RefreshToken {
	return &domain.RefreshToken{
		ID:        m.ID,
		UserID:    m.UserID,
		TokenHash: m.TokenHash,
		ExpiresAt: m.ExpiresAt,
		RevokedAt: m.RevokedAt,
		CreatedAt: m.CreatedAt,
	}
}
