package usecase

import "fmt"

type StartGoogleOAuthInput struct {
	RedirectTo string
}

type StartGoogleOAuth struct {
	provider GoogleOAuthProvider
	signer   *oauthStateSigner
}

func NewStartGoogleOAuth(provider GoogleOAuthProvider, stateSecret string) *StartGoogleOAuth {
	return &StartGoogleOAuth{provider: provider, signer: newOAuthStateSigner(stateSecret)}
}

func (uc *StartGoogleOAuth) Handle(in StartGoogleOAuthInput) (string, error) {
	state, err := uc.signer.sign(in.RedirectTo)
	if err != nil {
		return "", fmt.Errorf("signing oauth state: %w", err)
	}
	return uc.provider.AuthorizeURL(state), nil
}
