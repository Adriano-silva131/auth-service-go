//go:build integration

package integration

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/adriano-linux/auth-service-go/internal/adapter/hash"
	authjwt "github.com/adriano-linux/auth-service-go/internal/adapter/jwt"
	pg "github.com/adriano-linux/auth-service-go/internal/adapter/postgres"
	"github.com/adriano-linux/auth-service-go/internal/usecase"
)

// TestAuthFlow_RealPostgres exercises register -> login -> refresh (rotation) ->
// logout -> refresh-fails against a real Postgres container running this repo's own
// migrations, the Go equivalent of payment-service-go's PaymentRepository integration
// test.
func TestAuthFlow_RealPostgres(t *testing.T) {
	ctx := context.Background()

	container, err := postgres.Run(ctx, "postgres:16-alpine",
		postgres.WithDatabase("authdb"),
		postgres.WithUsername("orderdb"),
		postgres.WithPassword("postgres"),
		testcontainers.WithWaitStrategyAndDeadline(60*time.Second,
			wait.ForLog("database system is ready to accept connections").WithOccurrence(2)),
		postgres.WithInitScripts(
			"../../migrations/000001_create_users_table.up.sql",
			"../../migrations/000002_create_refresh_tokens_table.up.sql",
			"../../migrations/000003_add_roles_to_users.up.sql",
		),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = container.Terminate(ctx) })

	connStr, err := container.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)

	db, err := pg.NewGormDB(ctx, connStr)
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	t.Cleanup(func() { _ = sqlDB.Close() })

	userRepo := pg.NewUserRepository(db)
	tokenRepo := pg.NewRefreshTokenRepository(db)
	hasher := hash.NewBcryptHasher()

	dir := t.TempDir()
	key, err := authjwt.LoadOrGenerateKeyPair(filepath.Join(dir, "private.pem"), filepath.Join(dir, "public.pem"))
	require.NoError(t, err)
	kid, err := authjwt.Thumbprint(&key.PublicKey)
	require.NoError(t, err)
	issuer := authjwt.NewIssuer(key, kid, "orderhub-auth-service", 300*time.Second, 30*24*time.Hour)

	registerUC := usecase.NewRegister(userRepo, hasher)
	loginUC := usecase.NewLogin(userRepo, tokenRepo, hasher, issuer)
	refreshUC := usecase.NewRefreshAccessToken(userRepo, tokenRepo, issuer)
	logoutUC := usecase.NewLogout(tokenRepo, issuer)

	user, err := registerUC.Handle(ctx, usecase.RegisterInput{Email: "integration@example.com", Password: "supersecret", Name: "Integration"})
	require.NoError(t, err)

	pair, err := loginUC.Handle(ctx, usecase.LoginInput{Email: "integration@example.com", Password: "supersecret"})
	require.NoError(t, err)
	require.NotEmpty(t, pair.AccessToken)
	require.NotEmpty(t, pair.RefreshToken)

	rotated, err := refreshUC.Handle(ctx, pair.RefreshToken)
	require.NoError(t, err)
	require.NotEqual(t, pair.RefreshToken, rotated.RefreshToken)

	_, err = refreshUC.Handle(ctx, pair.RefreshToken)
	require.Error(t, err, "the pre-rotation refresh token must no longer work")

	require.NoError(t, logoutUC.Handle(ctx, rotated.RefreshToken))
	_, err = refreshUC.Handle(ctx, rotated.RefreshToken)
	require.Error(t, err, "a logged-out refresh token must no longer work")

	loaded, err := userRepo.FindByID(ctx, user.ID)
	require.NoError(t, err)
	require.Equal(t, "integration@example.com", loaded.Email)
}
