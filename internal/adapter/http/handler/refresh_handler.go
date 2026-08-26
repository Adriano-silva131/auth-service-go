package handler

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/go-playground/validator/v10"

	"github.com/adriano-linux/auth-service-go/internal/domain"
	"github.com/adriano-linux/auth-service-go/internal/usecase"
)

type refreshRequest struct {
	RefreshToken string `json:"refresh_token" validate:"required"`
}

type RefreshHandler struct {
	refresh  *usecase.RefreshAccessToken
	validate *validator.Validate
}

func NewRefreshHandler(refresh *usecase.RefreshAccessToken) *RefreshHandler {
	return &RefreshHandler{refresh: refresh, validate: validator.New()}
}

func (h *RefreshHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var req refreshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := h.validate.Struct(req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	pair, err := h.refresh.Handle(r.Context(), req.RefreshToken)
	if err != nil {
		if errors.Is(err, domain.ErrRefreshTokenInvalid) {
			writeError(w, http.StatusUnauthorized, "invalid or expired refresh token")
			return
		}
		slog.ErrorContext(r.Context(), "refresh failed", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to refresh token")
		return
	}

	writeJSON(w, http.StatusOK, toTokenPairResponse(pair))
}
