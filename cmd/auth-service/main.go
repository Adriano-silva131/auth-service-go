// Command auth-service is the composition root: wiring only, no business logic.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/adriano-linux/auth-service-go/internal/adapter/hash"
	httptransport "github.com/adriano-linux/auth-service-go/internal/adapter/http"
	"github.com/adriano-linux/auth-service-go/internal/adapter/http/handler"
	authjwt "github.com/adriano-linux/auth-service-go/internal/adapter/jwt"
	"github.com/adriano-linux/auth-service-go/internal/adapter/postgres"
	"github.com/adriano-linux/auth-service-go/internal/config"
	"github.com/adriano-linux/auth-service-go/internal/usecase"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))

	if err := run(); err != nil {
		slog.Error("fatal startup error", "error", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pool, err := postgres.NewPool(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()

	userRepo := postgres.NewUserRepository(pool)
	refreshTokenRepo := postgres.NewRefreshTokenRepository(pool)
	hasher := hash.NewBcryptHasher()

	privateKey, err := authjwt.LoadOrGenerateKeyPair(cfg.JWTPrivateKeyPath, cfg.JWTPublicKeyPath)
	if err != nil {
		return err
	}
	kid, err := authjwt.Thumbprint(&privateKey.PublicKey)
	if err != nil {
		return err
	}

	issuer := authjwt.NewIssuer(
		privateKey, kid, cfg.Issuer,
		time.Duration(cfg.AccessTokenTTLSeconds)*time.Second,
		time.Duration(cfg.RefreshTokenTTLSeconds)*time.Second,
	)

	registerUC := usecase.NewRegister(userRepo, hasher)
	loginUC := usecase.NewLogin(userRepo, refreshTokenRepo, hasher, issuer)
	refreshUC := usecase.NewRefreshAccessToken(userRepo, refreshTokenRepo, issuer)
	logoutUC := usecase.NewLogout(refreshTokenRepo, issuer)
	bulkCreateUC := usecase.NewCreateUsersBulk(registerUC)
	addRoleUC := usecase.NewAddRole(userRepo)

	jwksHandler, err := handler.NewJWKSHandler(authjwt.BuildJWKSet(&privateKey.PublicKey, kid))
	if err != nil {
		return err
	}

	verifier := authjwt.NewVerifier(&privateKey.PublicKey)

	router := httptransport.NewRouter(httptransport.RouterDeps{
		Register:    handler.NewRegisterHandler(registerUC),
		Login:       handler.NewLoginHandler(loginUC),
		Refresh:     handler.NewRefreshHandler(refreshUC),
		Logout:      handler.NewLogoutHandler(logoutUC),
		JWKS:        jwksHandler,
		BulkCreate:  handler.NewBulkCreateHandler(bulkCreateUC),
		AddRole:     handler.NewAddRoleHandler(addRoleUC),
		Health:      handler.NewHealthHandler(pool),
		AdminAPIKey: cfg.AdminAPIKey,
		Verifier:    verifier,
	})

	server := &http.Server{
		Addr:    ":" + cfg.HTTPPort,
		Handler: router,
	}

	serverErr := make(chan error, 1)
	go func() {
		slog.Info("http server listening", "port", cfg.HTTPPort)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErr <- err
		}
	}()

	select {
	case <-ctx.Done():
		slog.Info("shutdown signal received")
	case err := <-serverErr:
		return err
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return server.Shutdown(shutdownCtx)
}
