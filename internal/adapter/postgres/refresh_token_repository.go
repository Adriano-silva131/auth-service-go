package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/adriano-linux/auth-service-go/internal/domain"
)

type RefreshTokenRepository struct {
	db *gorm.DB
}

func NewRefreshTokenRepository(db *gorm.DB) *RefreshTokenRepository {
	return &RefreshTokenRepository{db: db}
}

func (r *RefreshTokenRepository) Insert(ctx context.Context, t *domain.RefreshToken) error {
	m := fromDomainRefreshToken(t)
	if err := r.db.WithContext(ctx).Create(&m).Error; err != nil {
		return fmt.Errorf("inserting refresh token: %w", err)
	}
	return nil
}

func (r *RefreshTokenRepository) FindByTokenHash(ctx context.Context, tokenHash string) (*domain.RefreshToken, error) {
	var m refreshTokenModel
	err := r.db.WithContext(ctx).Where("token_hash = ?", tokenHash).First(&m).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, domain.ErrRefreshTokenInvalid
		}
		return nil, fmt.Errorf("finding refresh token: %w", err)
	}
	return toDomainRefreshToken(&m), nil
}

func (r *RefreshTokenRepository) Revoke(ctx context.Context, id uuid.UUID) error {
	err := r.db.WithContext(ctx).Model(&refreshTokenModel{}).
		Where("id = ?", id).
		Update("revoked_at", gorm.Expr("now()")).Error
	if err != nil {
		return fmt.Errorf("revoking refresh token: %w", err)
	}
	return nil
}
