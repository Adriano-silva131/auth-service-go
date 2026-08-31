package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/adriano-linux/auth-service-go/internal/domain"
)

type UserRepository struct {
	db *gorm.DB
}

func NewUserRepository(db *gorm.DB) *UserRepository {
	return &UserRepository{db: db}
}

func (r *UserRepository) ExistsByEmail(ctx context.Context, email string) (bool, error) {
	var count int64
	err := r.db.WithContext(ctx).Model(&userModel{}).Where("email = ?", email).Count(&count).Error
	if err != nil {
		return false, fmt.Errorf("checking user existence: %w", err)
	}
	return count > 0, nil
}

func (r *UserRepository) Insert(ctx context.Context, u *domain.User) error {
	m := fromDomainUser(u)
	if err := r.db.WithContext(ctx).Create(&m).Error; err != nil {
		return fmt.Errorf("inserting user: %w", err)
	}
	return nil
}

// AddRole is idempotent: adding a role the user already has is a no-op rather than an
// error, so callers don't need to check current roles before calling it. Kept as a raw
// atomic UPDATE ... RETURNING (rather than a GORM read-modify-write) so a concurrent call
// can't race and drop an append.
func (r *UserRepository) AddRole(ctx context.Context, userID uuid.UUID, role string) (*domain.User, error) {
	var m userModel
	result := r.db.WithContext(ctx).Raw(`
		UPDATE users
		SET roles = CASE WHEN ? = ANY(roles) THEN roles ELSE array_append(roles, ?) END,
		    updated_at = now()
		WHERE id = ?
		RETURNING id, email, password_hash, name, roles, created_at, updated_at
	`, role, role, userID).Scan(&m)
	if result.Error != nil {
		return nil, fmt.Errorf("adding role: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return nil, domain.ErrUserNotFound
	}
	return toDomainUser(&m), nil
}

func (r *UserRepository) FindByEmail(ctx context.Context, email string) (*domain.User, error) {
	var m userModel
	err := r.db.WithContext(ctx).Where("email = ?", email).First(&m).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, domain.ErrUserNotFound
		}
		return nil, fmt.Errorf("finding user by email: %w", err)
	}
	return toDomainUser(&m), nil
}

func (r *UserRepository) FindByID(ctx context.Context, id uuid.UUID) (*domain.User, error) {
	var m userModel
	err := r.db.WithContext(ctx).Where("id = ?", id).First(&m).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, domain.ErrUserNotFound
		}
		return nil, fmt.Errorf("finding user by id: %w", err)
	}
	return toDomainUser(&m), nil
}
