package httpadapter

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	"github.com/adriano-linux/auth-service-go/internal/adapter/http/handler"
	authjwt "github.com/adriano-linux/auth-service-go/internal/adapter/jwt"
)

// noTraceRoutes are excluded from tracing — pure infrastructure traffic (liveness/
// readiness probes, Prometheus scraping) with no diagnostic value in a trace backend.
var noTraceRoutes = map[string]bool{
	"/healthz": true,
	"/readyz":  true,
	"/metrics": true,
}

func tracingMiddleware() func(http.Handler) http.Handler {
	return otelhttp.NewMiddleware("auth-service",
		otelhttp.WithFilter(func(r *http.Request) bool {
			return !noTraceRoutes[r.URL.Path]
		}),
		otelhttp.WithSpanNameFormatter(func(operation string, r *http.Request) string {
			return r.Method + " " + r.URL.Path
		}),
	)
}

type RouterDeps struct {
	Register   *handler.RegisterHandler
	Login      *handler.LoginHandler
	Refresh    *handler.RefreshHandler
	Logout     *handler.LogoutHandler
	JWKS       *handler.JWKSHandler
	BulkCreate *handler.BulkCreateHandler
	AddRole    *handler.AddRoleHandler
	Health     *handler.HealthHandler

	AdminAPIKey string
	Verifier    *authjwt.Verifier
}

func NewRouter(deps RouterDeps) http.Handler {
	r := chi.NewRouter()
	r.Use(Recoverer, tracingMiddleware(), RequestLogger)

	r.Get("/healthz", deps.Health.Liveness)
	r.Get("/readyz", deps.Health.Readiness)
	r.Handle("/metrics", promhttp.Handler())

	r.Get("/.well-known/jwks.json", deps.JWKS.ServeHTTP)

	r.Route("/auth", func(r chi.Router) {
		r.Post("/register", deps.Register.ServeHTTP)
		r.Post("/login", deps.Login.ServeHTTP)
		r.Post("/refresh", deps.Refresh.ServeHTTP)
		r.Post("/logout", deps.Logout.ServeHTTP)
	})

	r.Route("/admin", func(r chi.Router) {
		r.Use(AdminAPIKey(deps.AdminAPIKey))
		r.Post("/users/bulk", deps.BulkCreate.ServeHTTP)
	})

	r.Route("/users", func(r chi.Router) {
		r.Use(RequireAuth(deps.Verifier))
		r.Post("/me/roles", deps.AddRole.ServeHTTP)
	})

	return r
}
