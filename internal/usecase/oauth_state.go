package usecase

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const oauthStateTTL = 10 * time.Minute

type oauthStateSigner struct {
	secret []byte
}

func newOAuthStateSigner(secret string) *oauthStateSigner {
	return &oauthStateSigner{secret: []byte(secret)}
}

type oauthStateClaims struct {
	Nonce      string `json:"n"`
	RedirectTo string `json:"r"`
	IssuedAt   int64  `json:"t"`
}

func (s *oauthStateSigner) sign(redirectTo string) (string, error) {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("generating oauth state nonce: %w", err)
	}

	claims := oauthStateClaims{
		Nonce:      base64.RawURLEncoding.EncodeToString(nonce),
		RedirectTo: redirectTo,
		IssuedAt:   time.Now().UTC().Unix(),
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("encoding oauth state: %w", err)
	}

	encoded := base64.RawURLEncoding.EncodeToString(payload)
	return encoded + "." + s.sig(encoded), nil
}

func (s *oauthStateSigner) verify(state string) (string, error) {
	encoded, sig, ok := strings.Cut(state, ".")
	if !ok {
		return "", errors.New("malformed oauth state")
	}
	if !hmac.Equal([]byte(sig), []byte(s.sig(encoded))) {
		return "", errors.New("oauth state signature mismatch")
	}

	payload, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("decoding oauth state: %w", err)
	}
	var claims oauthStateClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", fmt.Errorf("parsing oauth state: %w", err)
	}
	if time.Since(time.Unix(claims.IssuedAt, 0).UTC()) > oauthStateTTL {
		return "", errors.New("oauth state expired")
	}

	return claims.RedirectTo, nil
}

func (s *oauthStateSigner) sig(encoded string) string {
	mac := hmac.New(sha256.New, s.secret)
	mac.Write([]byte(encoded))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
