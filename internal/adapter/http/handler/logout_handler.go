package handler

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/adriano-linux/auth-service-go/internal/usecase"
)

type logoutRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type LogoutHandler struct {
	logout *usecase.Logout
}

func NewLogoutHandler(logout *usecase.Logout) *LogoutHandler {
	return &LogoutHandler{logout: logout}
}

func (h *LogoutHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var req logoutRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.RefreshToken == "" {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	if err := h.logout.Handle(r.Context(), req.RefreshToken); err != nil {
		slog.ErrorContext(r.Context(), "logout failed", "error", err)
	}

	w.WriteHeader(http.StatusNoContent)
}
