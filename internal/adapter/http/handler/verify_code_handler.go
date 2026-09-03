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

type verifyCodeRequest struct {
	Email string `json:"email" validate:"required,email"`
	Code  string `json:"code" validate:"required,len=6,numeric"`
}

type VerifyCodeHandler struct {
	verifyCode *usecase.VerifyCode
	validate   *validator.Validate
}

func NewVerifyCodeHandler(uc *usecase.VerifyCode) *VerifyCodeHandler {
	return &VerifyCodeHandler{verifyCode: uc, validate: validator.New()}
}

func (h *VerifyCodeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var req verifyCodeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := h.validate.Struct(req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	pair, err := h.verifyCode.Handle(r.Context(), usecase.VerifyCodeInput{Email: req.Email, Code: req.Code})
	if err != nil {
		if errors.Is(err, domain.ErrCodeInvalid) || errors.Is(err, domain.ErrTooManyAttempts) {
			writeError(w, http.StatusUnauthorized, "invalid or expired code")
			return
		}
		slog.ErrorContext(r.Context(), "verify code failed", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to verify code")
		return
	}

	writeJSON(w, http.StatusOK, toTokenPairResponse(pair))
}
