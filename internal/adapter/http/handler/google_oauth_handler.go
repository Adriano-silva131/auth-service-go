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

type StartGoogleOAuthHandler struct {
	start *usecase.StartGoogleOAuth
}

func NewStartGoogleOAuthHandler(uc *usecase.StartGoogleOAuth) *StartGoogleOAuthHandler {
	return &StartGoogleOAuthHandler{start: uc}
}

// ServeHTTP is a plain browser redirect straight into Google's consent
// screen — order-hub-store's own /api/auth/google route just forwards the
// browser here rather than building the URL itself, so all Google config
// (client ID included) lives only in this service.
func (h *StartGoogleOAuthHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	redirectTo := r.URL.Query().Get("redirect_to")
	if redirectTo == "" {
		redirectTo = "/"
	}

	authorizeURL, err := h.start.Handle(usecase.StartGoogleOAuthInput{RedirectTo: redirectTo})
	if err != nil {
		slog.ErrorContext(r.Context(), "starting google oauth failed", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to start google sign-in")
		return
	}

	http.Redirect(w, r, authorizeURL, http.StatusFound)
}

type completeGoogleOAuthRequest struct {
	Code  string `json:"code" validate:"required"`
	State string `json:"state" validate:"required"`
}

type completeGoogleOAuthResponse struct {
	tokenPairResponse
	RedirectTo string `json:"redirect_to"`
}

type CompleteGoogleOAuthHandler struct {
	complete *usecase.CompleteGoogleOAuth
	validate *validator.Validate
}

func NewCompleteGoogleOAuthHandler(uc *usecase.CompleteGoogleOAuth) *CompleteGoogleOAuthHandler {
	return &CompleteGoogleOAuthHandler{complete: uc, validate: validator.New()}
}

// ServeHTTP is called server-to-server by order-hub-store's own callback
// route (never directly by the browser) — it hands over the code Google
// issued and gets back a token pair plus the original redirect target.
func (h *CompleteGoogleOAuthHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var req completeGoogleOAuthRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := h.validate.Struct(req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	result, err := h.complete.Handle(r.Context(), usecase.CompleteGoogleOAuthInput{Code: req.Code, State: req.State})
	if err != nil {
		switch {
		case errors.Is(err, domain.ErrOAuthStateInvalid):
			writeError(w, http.StatusBadRequest, "invalid or expired oauth state")
		case errors.Is(err, domain.ErrOAuthEmailNotVerified):
			writeError(w, http.StatusUnauthorized, "google account email is not verified")
		default:
			slog.ErrorContext(r.Context(), "completing google oauth failed", "error", err)
			writeError(w, http.StatusInternalServerError, "failed to authenticate with google")
		}
		return
	}

	writeJSON(w, http.StatusOK, completeGoogleOAuthResponse{
		tokenPairResponse: toTokenPairResponse(result.Tokens),
		RedirectTo:        result.RedirectTo,
	})
}
