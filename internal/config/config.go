package config

import (
	"fmt"

	"github.com/caarlos0/env/v11"
)

type Config struct {
	HTTPPort string `env:"HTTP_PORT" envDefault:"8090"`

	DatabaseURL string `env:"DATABASE_URL,required"`

	JWTPrivateKeyPath string `env:"JWT_PRIVATE_KEY_PATH" envDefault:"./keys/private.pem"`
	JWTPublicKeyPath  string `env:"JWT_PUBLIC_KEY_PATH" envDefault:"./keys/public.pem"`

	AccessTokenTTLSeconds  int `env:"ACCESS_TOKEN_TTL_SECONDS" envDefault:"300"`
	RefreshTokenTTLSeconds int `env:"REFRESH_TOKEN_TTL_SECONDS" envDefault:"2592000"`

	Issuer string `env:"AUTH_ISSUER" envDefault:"orderhub-auth-service"`

	AdminAPIKey string `env:"ADMIN_API_KEY,required"`

	// SMTP is optional: SMTPHost empty means the passwordless flow logs the
	// verification code instead of emailing it (see adapter/mail).
	SMTPHost     string `env:"SMTP_HOST"`
	SMTPPort     string `env:"SMTP_PORT" envDefault:"587"`
	SMTPUsername string `env:"SMTP_USERNAME"`
	SMTPPassword string `env:"SMTP_PASSWORD"`
	MailFrom     string `env:"MAIL_FROM" envDefault:"no-reply@orderhub.local"`

	// Google OAuth — the code-for-token exchange happens here, not in
	// order-hub-store, so this is the only service that ever holds the
	// client secret. GoogleRedirectURI must point at order-hub-store's own
	// callback route (order-hub-store sets the session cookie, so the
	// browser has to land back on its origin) and must match, byte for
	// byte, what's registered in Google Cloud Console.
	GoogleClientID     string `env:"GOOGLE_CLIENT_ID"`
	GoogleClientSecret string `env:"GOOGLE_CLIENT_SECRET"`
	GoogleRedirectURI  string `env:"GOOGLE_REDIRECT_URI" envDefault:"http://localhost:3001/api/auth/google/callback"`

	OtelExporterOtlpEndpoint string  `env:"OTEL_EXPORTER_OTLP_ENDPOINT" envDefault:"http://otel-collector:4317"`
	OtelServiceName          string  `env:"OTEL_SERVICE_NAME" envDefault:"auth-service"`
	OtelTracesSampleRate     float64 `env:"OTEL_TRACES_SAMPLE_RATE" envDefault:"1.0"`
}

func Load() (*Config, error) {
	cfg := &Config{}
	if err := env.Parse(cfg); err != nil {
		return nil, fmt.Errorf("loading config from environment: %w", err)
	}
	return cfg, nil
}
