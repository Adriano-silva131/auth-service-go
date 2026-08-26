package handler

import (
	"encoding/json"
	"net/http"

	"github.com/go-playground/validator/v10"

	"github.com/adriano-linux/auth-service-go/internal/usecase"
)

type bulkCreateItemRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,min=8"`
	Name     string `json:"name" validate:"required"`
}

type bulkCreateRequest struct {
	Users []bulkCreateItemRequest `json:"users" validate:"required,min=1,dive"`
}

type createdUserResponse struct {
	ID    string `json:"id"`
	Email string `json:"email"`
}

type skippedUserResponse struct {
	Email  string `json:"email"`
	Reason string `json:"reason"`
}

type bulkCreateResponse struct {
	Created []createdUserResponse `json:"created"`
	Skipped []skippedUserResponse `json:"skipped"`
}

func toBulkCreateResponse(result usecase.BulkCreateResult) bulkCreateResponse {
	resp := bulkCreateResponse{
		Created: make([]createdUserResponse, len(result.Created)),
		Skipped: make([]skippedUserResponse, len(result.Skipped)),
	}
	for i, c := range result.Created {
		resp.Created[i] = createdUserResponse{ID: c.ID.String(), Email: c.Email}
	}
	for i, s := range result.Skipped {
		resp.Skipped[i] = skippedUserResponse{Email: s.Email, Reason: s.Reason}
	}
	return resp
}

// BulkCreateHandler exists to provision synthetic users for k6 load testing — see
// usecase.CreateUsersBulk. Mounted behind the AdminAPIKey middleware in router.go.
type BulkCreateHandler struct {
	bulkCreate *usecase.CreateUsersBulk
	validate   *validator.Validate
}

func NewBulkCreateHandler(bulkCreate *usecase.CreateUsersBulk) *BulkCreateHandler {
	return &BulkCreateHandler{bulkCreate: bulkCreate, validate: validator.New()}
}

func (h *BulkCreateHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var req bulkCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := h.validate.Struct(req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	items := make([]usecase.BulkCreateItem, len(req.Users))
	for i, u := range req.Users {
		items[i] = usecase.BulkCreateItem{Email: u.Email, Password: u.Password, Name: u.Name}
	}

	result := h.bulkCreate.Handle(r.Context(), items)

	writeJSON(w, http.StatusCreated, toBulkCreateResponse(result))
}
