package usecase_test

import (
	"context"
	"errors"
	"net/url"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/adriano-linux/auth-service-go/internal/domain"
	"github.com/adriano-linux/auth-service-go/internal/usecase"
)

const testStateSecret = "test-secret"

// validState produces a genuinely signed state by driving StartGoogleOAuth,
// the same way order-hub-store would receive one to carry through the round
// trip to Google and back — avoids reaching into the signer privately.
func validState(t *testing.T, redirectTo string) string {
	t.Helper()
	authorizeURL, err := usecase.NewStartGoogleOAuth(&fakeGoogleProvider{}, testStateSecret).Handle(usecase.StartGoogleOAuthInput{RedirectTo: redirectTo})
	require.NoError(t, err)

	parsed, err := url.Parse(authorizeURL)
	require.NoError(t, err)
	return parsed.Query().Get("state")
}

func TestCompleteGoogleOAuth_CreatesNewUserAndReturnsTokenPairAndRedirectTo(t *testing.T) {
	users := newFakeUserRepo()
	tokens := newFakeRefreshTokenRepo()
	provider := &fakeGoogleProvider{identity: usecase.GoogleIdentity{Email: "new.user@example.com", EmailVerified: true, Name: "New User"}}
	state := validState(t, "/checkout")

	uc := usecase.NewCompleteGoogleOAuth(provider, testStateSecret, users, tokens, &fakeIssuer{})
	result, err := uc.Handle(context.Background(), usecase.CompleteGoogleOAuthInput{Code: "authorization-code", State: state})

	require.NoError(t, err)
	assert.NotEmpty(t, result.Tokens.AccessToken)
	assert.Equal(t, "/checkout", result.RedirectTo)
	created, err := users.FindByEmail(context.Background(), "new.user@example.com")
	require.NoError(t, err)
	assert.Nil(t, created.PasswordHash, "google-created account must have no password hash")
	assert.Equal(t, "New User", created.Name)
	assert.Contains(t, created.Roles, domain.RoleCustomer)
}

func TestCompleteGoogleOAuth_LogsInExistingUserWithoutDuplicating(t *testing.T) {
	users := newFakeUserRepo()
	tokens := newFakeRefreshTokenRepo()
	existing := &domain.User{ID: uuid.New(), Email: "returning@example.com", Name: "Returning", Roles: []string{domain.RoleCustomer}}
	users.byEmail[existing.Email] = existing
	users.byID[existing.ID] = existing
	provider := &fakeGoogleProvider{identity: usecase.GoogleIdentity{Email: "returning@example.com", EmailVerified: true, Name: "Returning"}}
	state := validState(t, "/")

	uc := usecase.NewCompleteGoogleOAuth(provider, testStateSecret, users, tokens, &fakeIssuer{})
	_, err := uc.Handle(context.Background(), usecase.CompleteGoogleOAuthInput{Code: "authorization-code", State: state})

	require.NoError(t, err)
	assert.Len(t, users.byEmail, 1, "must not create a second account for the same email")
}

func TestCompleteGoogleOAuth_RejectsUnverifiedEmail(t *testing.T) {
	provider := &fakeGoogleProvider{identity: usecase.GoogleIdentity{Email: "unverified@example.com", EmailVerified: false}}
	state := validState(t, "/")

	uc := usecase.NewCompleteGoogleOAuth(provider, testStateSecret, newFakeUserRepo(), newFakeRefreshTokenRepo(), &fakeIssuer{})
	_, err := uc.Handle(context.Background(), usecase.CompleteGoogleOAuthInput{Code: "authorization-code", State: state})

	assert.ErrorIs(t, err, domain.ErrOAuthEmailNotVerified)
}

func TestCompleteGoogleOAuth_RejectsTamperedState(t *testing.T) {
	provider := &fakeGoogleProvider{identity: usecase.GoogleIdentity{Email: "user@example.com", EmailVerified: true}}
	// Signed with a different secret than the one CompleteGoogleOAuth verifies
	// against — simulates a forged or replayed-across-environments state.
	stateSignedElsewhere, err := usecase.NewStartGoogleOAuth(provider, "a-different-secret").Handle(usecase.StartGoogleOAuthInput{RedirectTo: "/"})
	require.NoError(t, err)
	parsed, err := url.Parse(stateSignedElsewhere)
	require.NoError(t, err)
	state := parsed.Query().Get("state")

	uc := usecase.NewCompleteGoogleOAuth(provider, testStateSecret, newFakeUserRepo(), newFakeRefreshTokenRepo(), &fakeIssuer{})
	_, err = uc.Handle(context.Background(), usecase.CompleteGoogleOAuthInput{Code: "authorization-code", State: state})

	assert.ErrorIs(t, err, domain.ErrOAuthStateInvalid)
}

func TestCompleteGoogleOAuth_RejectsMalformedState(t *testing.T) {
	uc := usecase.NewCompleteGoogleOAuth(&fakeGoogleProvider{}, testStateSecret, newFakeUserRepo(), newFakeRefreshTokenRepo(), &fakeIssuer{})

	_, err := uc.Handle(context.Background(), usecase.CompleteGoogleOAuthInput{Code: "authorization-code", State: "not-a-real-state"})

	assert.ErrorIs(t, err, domain.ErrOAuthStateInvalid)
}

func TestCompleteGoogleOAuth_PropagatesExchangeFailure(t *testing.T) {
	provider := &fakeGoogleProvider{exchangeErr: errors.New("google token endpoint unreachable")}
	state := validState(t, "/")

	uc := usecase.NewCompleteGoogleOAuth(provider, testStateSecret, newFakeUserRepo(), newFakeRefreshTokenRepo(), &fakeIssuer{})
	_, err := uc.Handle(context.Background(), usecase.CompleteGoogleOAuthInput{Code: "authorization-code", State: state})

	require.Error(t, err)
	assert.NotErrorIs(t, err, domain.ErrOAuthStateInvalid)
}
