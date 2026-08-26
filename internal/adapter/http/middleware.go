// Package httpadapter is named to avoid shadowing the stdlib "net/http" package that
// every file here (and every importer) also needs.
package httpadapter

import (
	"crypto/subtle"
	"log/slog"
	"net/http"
	"strings"
	"time"

	authjwt "github.com/adriano-linux/auth-service-go/internal/adapter/jwt"
)

// RequireAuth validates the bearer access token and puts the authenticated user's ID on
// the request context — the first (and so far only) route in this service that needs the
// caller's own identity rather than acting on a token/email supplied in the request body.
// The context key lives in the jwt package (not here) so handler.* can read it back
// without importing this package, which already imports handler.* and would cycle.
func RequireAuth(verifier *authjwt.Verifier) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tokenString, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
			if !ok || tokenString == "" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			userID, err := verifier.VerifySubject(tokenString)
			if err != nil {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			ctx := authjwt.ContextWithUserID(r.Context(), userID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequestLogger logs method, path, status and duration for every request.
func RequestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}

		next.ServeHTTP(sw, r)

		slog.InfoContext(r.Context(), "http request",
			"method", r.Method, "path", r.URL.Path, "status", sw.status, "duration", time.Since(start))
	})
}

// Recoverer converts a panic in any handler into a 500 instead of crashing the process.
func Recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				slog.ErrorContext(r.Context(), "panic recovered", "error", rec)
				w.WriteHeader(http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// AdminAPIKey protects the bulk-user-creation route with a static shared-secret header
// — this is a load-testing provisioning utility, not a full admin panel, so a constant-
// time header comparison is the right amount of protection (see README for context).
func AdminAPIKey(expectedKey string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			provided := r.Header.Get("X-Admin-Api-Key")
			if provided == "" || subtle.ConstantTimeCompare([]byte(provided), []byte(expectedKey)) != 1 {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}
