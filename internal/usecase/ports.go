package usecase

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/adriano-linux/auth-service-go/internal/domain"
)

type UserRepository interface {
	ExistsByEmail(ctx context.Context, email string) (bool, error)
	Insert(ctx context.Context, u *domain.User) error
	FindByEmail(ctx context.Context, email string) (*domain.User, error)
	FindByID(ctx context.Context, id uuid.UUID) (*domain.User, error)
	AddRole(ctx context.Context, userID uuid.UUID, role string) (*domain.User, error)
}

type RefreshTokenRepository interface {
	Insert(ctx context.Context, t *domain.RefreshToken) error
	FindByTokenHash(ctx context.Context, tokenHash string) (*domain.RefreshToken, error)
	Revoke(ctx context.Context, id uuid.UUID) error
}

// PasswordHasher isolates the hashing algorithm (bcrypt) from the usecase layer.
type PasswordHasher interface {
	Hash(password string) (string, error)
	Matches(hash, password string) bool
}

// TokenIssuer signs access tokens and mints opaque refresh token values.
type TokenIssuer interface {
	IssueAccessToken(u *domain.User) (token string, expiresIn int, err error)
	NewRefreshTokenValue() (plaintext string, hash string, err error)
	HashRefreshTokenValue(plaintext string) string
	RefreshTokenTTL() time.Duration
}

// TokenPair is the shape returned to clients by login/refresh.
type TokenPair struct {
	AccessToken  string
	RefreshToken string
	ExpiresIn    int
}
