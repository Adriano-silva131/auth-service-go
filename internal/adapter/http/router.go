package httpadapter

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/adriano-linux/auth-service-go/internal/adapter/http/handler"
	authjwt "github.com/adriano-linux/auth-service-go/internal/adapter/jwt"
)

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
	r.Use(Recoverer, RequestLogger)

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
