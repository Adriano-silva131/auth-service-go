package handler

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/go-playground/validator/v10"

	authjwt "github.com/adriano-linux/auth-service-go/internal/adapter/jwt"
	"github.com/adriano-linux/auth-service-go/internal/domain"
	"github.com/adriano-linux/auth-service-go/internal/usecase"
)

type addRoleRequest struct {
	Role string `json:"role" validate:"required"`
}

type addRoleResponse struct {
	ID    string   `json:"id"`
	Roles []string `json:"roles"`
}

type AddRoleHandler struct {
	addRole  *usecase.AddRole
	validate *validator.Validate
}

func NewAddRoleHandler(addRole *usecase.AddRole) *AddRoleHandler {
	return &AddRoleHandler{addRole: addRole, validate: validator.New()}
}

func (h *AddRoleHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	userID, ok := authjwt.UserIDFromContext(r.Context())
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	var req addRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := h.validate.Struct(req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	user, err := h.addRole.Handle(r.Context(), usecase.AddRoleInput{UserID: userID, Role: req.Role})
	if err != nil {
		if errors.Is(err, domain.ErrInvalidRole) {
			writeError(w, http.StatusBadRequest, "invalid role")
			return
		}
		if errors.Is(err, domain.ErrUserNotFound) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		slog.ErrorContext(r.Context(), "add role failed", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to add role")
		return
	}

	writeJSON(w, http.StatusOK, addRoleResponse{ID: user.ID.String(), Roles: user.Roles})
}
