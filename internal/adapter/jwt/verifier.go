package jwt

import (
	"context"
	"crypto/rsa"
	"fmt"

	jwtlib "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Verifier validates access tokens issued by Issuer, using the same RSA key pair. This
// service only ever needs to verify its own tokens (e.g. for the "become a seller"
// endpoint below), not third-party ones, so there's no need to fetch a JWKS.
type Verifier struct {
	publicKey *rsa.PublicKey
}

func NewVerifier(publicKey *rsa.PublicKey) *Verifier {
	return &Verifier{publicKey: publicKey}
}

// VerifySubject validates the token's signature and expiry and returns its "sub" claim
// (the authenticated user's ID).
func (v *Verifier) VerifySubject(tokenString string) (uuid.UUID, error) {
	token, err := jwtlib.Parse(tokenString, func(t *jwtlib.Token) (any, error) {
		return v.publicKey, nil
	}, jwtlib.WithValidMethods([]string{"RS256"}))
	if err != nil || !token.Valid {
		return uuid.Nil, fmt.Errorf("invalid token: %w", err)
	}

	claims, ok := token.Claims.(jwtlib.MapClaims)
	if !ok {
		return uuid.Nil, fmt.Errorf("invalid token claims")
	}

	sub, ok := claims["sub"].(string)
	if !ok {
		return uuid.Nil, fmt.Errorf("token missing sub claim")
	}

	userID, err := uuid.Parse(sub)
	if err != nil {
		return uuid.Nil, fmt.Errorf("invalid sub claim: %w", err)
	}
	return userID, nil
}

type contextKey int

const userIDContextKey contextKey = iota

// ContextWithUserID and UserIDFromContext carry the authenticated user's ID from
// RequireAuth (in the http adapter) to handlers, without either package importing
// the other.
func ContextWithUserID(ctx context.Context, userID uuid.UUID) context.Context {
	return context.WithValue(ctx, userIDContextKey, userID)
}

func UserIDFromContext(ctx context.Context) (uuid.UUID, bool) {
	userID, ok := ctx.Value(userIDContextKey).(uuid.UUID)
	return userID, ok
}
