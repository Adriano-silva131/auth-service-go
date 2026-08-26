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

type loginRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

type LoginHandler struct {
	login    *usecase.Login
	validate *validator.Validate
}

func NewLoginHandler(login *usecase.Login) *LoginHandler {
	return &LoginHandler{login: login, validate: validator.New()}
}

func (h *LoginHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := h.validate.Struct(req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	pair, err := h.login.Handle(r.Context(), usecase.LoginInput{Email: req.Email, Password: req.Password})
	if err != nil {
		if errors.Is(err, domain.ErrInvalidCredentials) {
			writeError(w, http.StatusUnauthorized, "invalid credentials")
			return
		}
		slog.ErrorContext(r.Context(), "login failed", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to log in")
		return
	}

	writeJSON(w, http.StatusOK, toTokenPairResponse(pair))
}
