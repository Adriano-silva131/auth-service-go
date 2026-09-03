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

type verificationCodeModel struct {
	ID         uuid.UUID `gorm:"type:uuid;primaryKey"`
	Email      string    `gorm:"not null;index"`
	CodeHash   string    `gorm:"not null"`
	ExpiresAt  time.Time `gorm:"not null"`
	ConsumedAt *time.Time
	Attempts   int `gorm:"not null;default:0"`
	CreatedAt  time.Time
}

func (verificationCodeModel) TableName() string { return "verification_codes" }

func fromDomainVerificationCode(c *domain.VerificationCode) verificationCodeModel {
	return verificationCodeModel{
		ID:         c.ID,
		Email:      c.Email,
		CodeHash:   c.CodeHash,
		ExpiresAt:  c.ExpiresAt,
		ConsumedAt: c.ConsumedAt,
		Attempts:   c.Attempts,
		CreatedAt:  c.CreatedAt,
	}
}

func toDomainVerificationCode(m *verificationCodeModel) *domain.VerificationCode {
	return &domain.VerificationCode{
		ID:         m.ID,
		Email:      m.Email,
		CodeHash:   m.CodeHash,
		ExpiresAt:  m.ExpiresAt,
		ConsumedAt: m.ConsumedAt,
		Attempts:   m.Attempts,
		CreatedAt:  m.CreatedAt,
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
