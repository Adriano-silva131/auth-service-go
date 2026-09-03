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

type VerificationCodeRepository interface {
	Insert(ctx context.Context, c *domain.VerificationCode) error
	// FindLatestByEmail returns domain.ErrCodeNotFound when none exists.
	FindLatestByEmail(ctx context.Context, email string) (*domain.VerificationCode, error)
	IncrementAttempts(ctx context.Context, id uuid.UUID) error
	MarkConsumed(ctx context.Context, id uuid.UUID) error
}

// CodeSender delivers a verification code to the user — email in production,
// console logging in local dev when no SMTP is configured.
type CodeSender interface {
	SendVerificationCode(ctx context.Context, email, code string) error
}

// GoogleIdentity is what Google vouches for once the code-for-token exchange
// succeeds. EmailVerified comes straight from Google — a Google account can
// exist on an unverified email, and that's not enough to trust for login.
type GoogleIdentity struct {
	Email         string
	EmailVerified bool
	Name          string
}

// GoogleOAuthProvider builds the consent-screen URL and performs the
// authorization-code-for-token exchange server-to-server with Google. Because
// the exchange is authenticated with our client secret, the identity it
// returns is trusted without needing to separately verify a JWT signature.
type GoogleOAuthProvider interface {
	AuthorizeURL(state string) string
	Exchange(ctx context.Context, code string) (GoogleIdentity, error)
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
