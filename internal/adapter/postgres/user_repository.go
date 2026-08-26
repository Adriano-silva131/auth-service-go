package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/adriano-linux/auth-service-go/internal/domain"
)

type UserRepository struct {
	pool *pgxpool.Pool
}

func NewUserRepository(pool *pgxpool.Pool) *UserRepository {
	return &UserRepository{pool: pool}
}

func (r *UserRepository) ExistsByEmail(ctx context.Context, email string) (bool, error) {
	var exists bool
	err := r.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM users WHERE email = $1)`, email).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("checking user existence: %w", err)
	}
	return exists, nil
}

func (r *UserRepository) Insert(ctx context.Context, u *domain.User) error {
	_, err := r.pool.Exec(ctx, `
		INSERT INTO users (id, email, password_hash, name, roles, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`, u.ID, u.Email, u.PasswordHash, u.Name, u.Roles, u.CreatedAt, u.UpdatedAt)
	if err != nil {
		return fmt.Errorf("inserting user: %w", err)
	}
	return nil
}

// AddRole is idempotent: adding a role the user already has is a no-op rather than an
// error, so callers don't need to check current roles before calling it.
func (r *UserRepository) AddRole(ctx context.Context, userID uuid.UUID, role string) (*domain.User, error) {
	row := r.pool.QueryRow(ctx, `
		UPDATE users
		SET roles = CASE WHEN $2 = ANY(roles) THEN roles ELSE array_append(roles, $2) END,
		    updated_at = now()
		WHERE id = $1
		RETURNING id, email, password_hash, name, roles, created_at, updated_at
	`, userID, role)
	return scanUser(row)
}

func (r *UserRepository) FindByEmail(ctx context.Context, email string) (*domain.User, error) {
	row := r.pool.QueryRow(ctx, `
		SELECT id, email, password_hash, name, roles, created_at, updated_at FROM users WHERE email = $1
	`, email)
	return scanUser(row)
}

func (r *UserRepository) FindByID(ctx context.Context, id uuid.UUID) (*domain.User, error) {
	row := r.pool.QueryRow(ctx, `
		SELECT id, email, password_hash, name, roles, created_at, updated_at FROM users WHERE id = $1
	`, id)
	return scanUser(row)
}

func scanUser(row pgx.Row) (*domain.User, error) {
	var u domain.User
	err := row.Scan(&u.ID, &u.Email, &u.PasswordHash, &u.Name, &u.Roles, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrUserNotFound
		}
		return nil, fmt.Errorf("scanning user row: %w", err)
	}
	return &u, nil
}
