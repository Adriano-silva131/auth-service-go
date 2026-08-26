package jwt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"time"

	jwtlib "github.com/golang-jwt/jwt/v5"

	"github.com/adriano-linux/auth-service-go/internal/domain"
)

const refreshTokenBytes = 32

// Issuer implements usecase.TokenIssuer: RS256-signed access tokens (verifiable via the
// JWKS endpoint built from the same key pair) plus opaque, hash-stored refresh tokens.
type Issuer struct {
	privateKey      *rsa.PrivateKey
	kid             string
	issuer          string
	accessTokenTTL  time.Duration
	refreshTokenTTL time.Duration
}

func NewIssuer(privateKey *rsa.PrivateKey, kid, issuerName string, accessTokenTTL, refreshTokenTTL time.Duration) *Issuer {
	return &Issuer{
		privateKey:      privateKey,
		kid:             kid,
		issuer:          issuerName,
		accessTokenTTL:  accessTokenTTL,
		refreshTokenTTL: refreshTokenTTL,
	}
}

func (i *Issuer) IssueAccessToken(u *domain.User) (string, int, error) {
	now := time.Now().UTC()
	expiresIn := int(i.accessTokenTTL.Seconds())

	claims := jwtlib.MapClaims{
		"sub":   u.ID.String(),
		"email": u.Email,
		"name":  u.Name,
		"roles": u.Roles,
		"iat":   now.Unix(),
		"exp":   now.Add(i.accessTokenTTL).Unix(),
		"iss":   i.issuer,
	}

	token := jwtlib.NewWithClaims(jwtlib.SigningMethodRS256, claims)
	token.Header["kid"] = i.kid

	signed, err := token.SignedString(i.privateKey)
	if err != nil {
		return "", 0, fmt.Errorf("signing access token: %w", err)
	}
	return signed, expiresIn, nil
}

func (i *Issuer) NewRefreshTokenValue() (plaintext string, hash string, err error) {
	buf := make([]byte, refreshTokenBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", "", fmt.Errorf("generating random refresh token: %w", err)
	}
	plaintext = base64.RawURLEncoding.EncodeToString(buf)
	return plaintext, i.HashRefreshTokenValue(plaintext), nil
}

func (i *Issuer) HashRefreshTokenValue(plaintext string) string {
	sum := sha256.Sum256([]byte(plaintext))
	return hex.EncodeToString(sum[:])
}

func (i *Issuer) RefreshTokenTTL() time.Duration {
	return i.refreshTokenTTL
}
