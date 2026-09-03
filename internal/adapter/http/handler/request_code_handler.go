package handler

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/go-playground/validator/v10"

	"github.com/adriano-linux/auth-service-go/internal/usecase"
)

type requestCodeRequest struct {
	Email string `json:"email" validate:"required,email"`
}

type RequestCodeHandler struct {
	requestCode *usecase.RequestCode
	validate    *validator.Validate
}

func NewRequestCodeHandler(uc *usecase.RequestCode) *RequestCodeHandler {
	return &RequestCodeHandler{requestCode: uc, validate: validator.New()}
}

func (h *RequestCodeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var req requestCodeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := h.validate.Struct(req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := h.requestCode.Handle(r.Context(), usecase.RequestCodeInput{Email: req.Email}); err != nil {
		slog.ErrorContext(r.Context(), "request code failed", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to send verification code")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
