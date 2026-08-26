package handler

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/adriano-linux/auth-service-go/internal/adapter/jwt"
)

// JWKSHandler serves a precomputed JWK Set — the key pair is fixed for the process
// lifetime (see jwt.LoadOrGenerateKeyPair), so there's nothing to recompute per request.
type JWKSHandler struct {
	body []byte
}

func NewJWKSHandler(set jwt.JWKSet) (*JWKSHandler, error) {
	body, err := json.Marshal(set)
	if err != nil {
		return nil, fmt.Errorf("marshalling JWK set: %w", err)
	}
	return &JWKSHandler{body: body}, nil
}

func (h *JWKSHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(h.body)
}
