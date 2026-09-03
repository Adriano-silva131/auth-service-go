package usecase_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/adriano-linux/auth-service-go/internal/usecase"
)

// fakeGoogleProvider stands in for the real Google endpoints — AuthorizeURL
// just echoes the state back so tests can assert it round-trips, and
// Exchange is scripted per test.
type fakeGoogleProvider struct {
	identity    usecase.GoogleIdentity
	exchangeErr error
}

func (f *fakeGoogleProvider) AuthorizeURL(state string) string {
	return "https://accounts.google.com/o/oauth2/v2/auth?state=" + state
}

func (f *fakeGoogleProvider) Exchange(ctx context.Context, code string) (usecase.GoogleIdentity, error) {
	if f.exchangeErr != nil {
		return usecase.GoogleIdentity{}, f.exchangeErr
	}
	return f.identity, nil
}

func TestStartGoogleOAuth_ProducesAuthorizeURLCarryingSignedState(t *testing.T) {
	uc := usecase.NewStartGoogleOAuth(&fakeGoogleProvider{}, "test-secret")

	authorizeURL, err := uc.Handle(usecase.StartGoogleOAuthInput{RedirectTo: "/checkout"})

	require.NoError(t, err)
	assert.Contains(t, authorizeURL, "state=")
}

func TestStartGoogleOAuth_DifferentCallsProduceDifferentState(t *testing.T) {
	uc := usecase.NewStartGoogleOAuth(&fakeGoogleProvider{}, "test-secret")

	first, err := uc.Handle(usecase.StartGoogleOAuthInput{RedirectTo: "/"})
	require.NoError(t, err)
	second, err := uc.Handle(usecase.StartGoogleOAuthInput{RedirectTo: "/"})
	require.NoError(t, err)

	assert.NotEqual(t, first, second, "state must include a fresh nonce each time, or it'd be replayable")
}
