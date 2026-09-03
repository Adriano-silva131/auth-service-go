package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/adriano-linux/auth-service-go/internal/domain"
)

type VerificationCodeRepository struct {
	db *gorm.DB
}

func NewVerificationCodeRepository(db *gorm.DB) *VerificationCodeRepository {
	return &VerificationCodeRepository{db: db}
}

func (r *VerificationCodeRepository) Insert(ctx context.Context, c *domain.VerificationCode) error {
	m := fromDomainVerificationCode(c)
	if err := r.db.WithContext(ctx).Create(&m).Error; err != nil {
		return fmt.Errorf("inserting verification code: %w", err)
	}
	return nil
}

func (r *VerificationCodeRepository) FindLatestByEmail(ctx context.Context, email string) (*domain.VerificationCode, error) {
	var m verificationCodeModel
	err := r.db.WithContext(ctx).
		Where("email = ?", email).
		Order("created_at DESC").
		First(&m).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, domain.ErrCodeNotFound
		}
		return nil, fmt.Errorf("finding verification code by email: %w", err)
	}
	return toDomainVerificationCode(&m), nil
}

func (r *VerificationCodeRepository) IncrementAttempts(ctx context.Context, id uuid.UUID) error {
	err := r.db.WithContext(ctx).Model(&verificationCodeModel{}).
		Where("id = ?", id).
		UpdateColumn("attempts", gorm.Expr("attempts + 1")).Error
	if err != nil {
		return fmt.Errorf("incrementing verification code attempts: %w", err)
	}
	return nil
}

func (r *VerificationCodeRepository) MarkConsumed(ctx context.Context, id uuid.UUID) error {
	now := time.Now().UTC()
	err := r.db.WithContext(ctx).Model(&verificationCodeModel{}).
		Where("id = ?", id).
		UpdateColumn("consumed_at", now).Error
	if err != nil {
		return fmt.Errorf("marking verification code consumed: %w", err)
	}
	return nil
}
