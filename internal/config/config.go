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
