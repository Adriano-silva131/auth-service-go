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
	"github.com/adriano-linux/auth-service-go/internal/adapter/logging"
	"github.com/adriano-linux/auth-service-go/internal/adapter/mail"
	"github.com/adriano-linux/auth-service-go/internal/adapter/oauth"
	oteladapter "github.com/adriano-linux/auth-service-go/internal/adapter/otel"
	"github.com/adriano-linux/auth-service-go/internal/adapter/postgres"
	"github.com/adriano-linux/auth-service-go/internal/config"
	"github.com/adriano-linux/auth-service-go/internal/usecase"
)

// codeSender chooses SMTP delivery when configured, console logging
// otherwise — see adapter/mail for why local dev needs a fallback.
func codeSender(cfg *config.Config) usecase.CodeSender {
	if cfg.SMTPHost == "" {
		slog.Warn("SMTP_HOST not set — verification codes will be logged, not emailed")
		return mail.NewConsoleSender()
	}
	return mail.NewSMTPSender(cfg.SMTPHost, cfg.SMTPPort, cfg.SMTPUsername, cfg.SMTPPassword, cfg.MailFrom)
}

func main() {
	slog.SetDefault(slog.New(logging.NewTraceHandler(slog.NewJSONHandler(os.Stdout, nil))))

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

	shutdownTracing, err := oteladapter.Setup(ctx, cfg.OtelExporterOtlpEndpoint, cfg.OtelServiceName, cfg.OtelTracesSampleRate)
	if err != nil {
		return err
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := shutdownTracing(shutdownCtx); err != nil {
			slog.Error("error shutting down tracer provider", "error", err)
		}
	}()

	db, err := postgres.NewGormDB(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	sqlDB, err := db.DB()
	if err != nil {
		return err
	}
	defer sqlDB.Close()

	userRepo := postgres.NewUserRepository(db)
	refreshTokenRepo := postgres.NewRefreshTokenRepository(db)
	verificationCodeRepo := postgres.NewVerificationCodeRepository(db)
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
	requestCodeUC := usecase.NewRequestCode(verificationCodeRepo, codeSender(cfg))
	verifyCodeUC := usecase.NewVerifyCode(verificationCodeRepo, userRepo, refreshTokenRepo, issuer)

	googleProvider := oauth.NewGoogleProvider(cfg.GoogleClientID, cfg.GoogleClientSecret, cfg.GoogleRedirectURI)
	startGoogleOAuthUC := usecase.NewStartGoogleOAuth(googleProvider, cfg.GoogleClientSecret)
	completeGoogleOAuthUC := usecase.NewCompleteGoogleOAuth(googleProvider, cfg.GoogleClientSecret, userRepo, refreshTokenRepo, issuer)

	jwksHandler, err := handler.NewJWKSHandler(authjwt.BuildJWKSet(&privateKey.PublicKey, kid))
	if err != nil {
		return err
	}

	verifier := authjwt.NewVerifier(&privateKey.PublicKey)

	router := httptransport.NewRouter(httptransport.RouterDeps{
		Register:            handler.NewRegisterHandler(registerUC),
		Login:               handler.NewLoginHandler(loginUC),
		Refresh:             handler.NewRefreshHandler(refreshUC),
		Logout:              handler.NewLogoutHandler(logoutUC),
		RequestCode:         handler.NewRequestCodeHandler(requestCodeUC),
		VerifyCode:          handler.NewVerifyCodeHandler(verifyCodeUC),
		StartGoogleOAuth:    handler.NewStartGoogleOAuthHandler(startGoogleOAuthUC),
		CompleteGoogleOAuth: handler.NewCompleteGoogleOAuthHandler(completeGoogleOAuthUC),
		JWKS:                jwksHandler,
		BulkCreate:          handler.NewBulkCreateHandler(bulkCreateUC),
		AddRole:             handler.NewAddRoleHandler(addRoleUC),
		Health:              handler.NewHealthHandler(db),
		AdminAPIKey:         cfg.AdminAPIKey,
		Verifier:            verifier,
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
