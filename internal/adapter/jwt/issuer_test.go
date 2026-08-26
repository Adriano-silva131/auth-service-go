package jwt_test

import (
	"crypto/rsa"
	"encoding/base64"
	"math/big"
	"path/filepath"
	"testing"
	"time"

	jwtlib "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	authjwt "github.com/adriano-linux/auth-service-go/internal/adapter/jwt"
	"github.com/adriano-linux/auth-service-go/internal/domain"
)

func TestLoadOrGenerateKeyPair_GeneratesThenLoadsSameKey(t *testing.T) {
	dir := t.TempDir()
	privPath := filepath.Join(dir, "private.pem")
	pubPath := filepath.Join(dir, "public.pem")

	key1, err := authjwt.LoadOrGenerateKeyPair(privPath, pubPath)
	require.NoError(t, err)
	require.FileExists(t, privPath)
	require.FileExists(t, pubPath)

	key2, err := authjwt.LoadOrGenerateKeyPair(privPath, pubPath)
	require.NoError(t, err)

	assert.True(t, key1.Equal(key2), "second call must load the same key, not generate a new one")
}

func TestIssueAccessToken_VerifiesAgainstItsOwnJWKS(t *testing.T) {
	dir := t.TempDir()
	key, err := authjwt.LoadOrGenerateKeyPair(filepath.Join(dir, "private.pem"), filepath.Join(dir, "public.pem"))
	require.NoError(t, err)

	kid, err := authjwt.Thumbprint(&key.PublicKey)
	require.NoError(t, err)

	issuer := authjwt.NewIssuer(key, kid, "orderhub-auth-service", 300*time.Second, 30*24*time.Hour)
	user := &domain.User{ID: uuid.New(), Email: "user@example.com", Name: "User", Roles: []string{domain.RoleCustomer}}

	token, expiresIn, err := issuer.IssueAccessToken(user)
	require.NoError(t, err)
	assert.Equal(t, 300, expiresIn)

	jwkSet := authjwt.BuildJWKSet(&key.PublicKey, kid)
	require.Len(t, jwkSet.Keys, 1)
	pub := jwkToRSAPublicKey(t, jwkSet.Keys[0])

	parsed, err := jwtlib.Parse(token, func(tok *jwtlib.Token) (any, error) {
		assert.Equal(t, kid, tok.Header["kid"])
		return pub, nil
	}, jwtlib.WithValidMethods([]string{"RS256"}))
	require.NoError(t, err)
	require.True(t, parsed.Valid)

	claims := parsed.Claims.(jwtlib.MapClaims)
	assert.Equal(t, user.ID.String(), claims["sub"])
	assert.Equal(t, user.Email, claims["email"])
	assert.Equal(t, "orderhub-auth-service", claims["iss"])
	assert.Equal(t, []any{domain.RoleCustomer}, claims["roles"])
}

func TestVerifier_VerifySubject_AcceptsTokenIssuedByIssuer(t *testing.T) {
	dir := t.TempDir()
	key, err := authjwt.LoadOrGenerateKeyPair(filepath.Join(dir, "private.pem"), filepath.Join(dir, "public.pem"))
	require.NoError(t, err)

	kid, err := authjwt.Thumbprint(&key.PublicKey)
	require.NoError(t, err)

	issuer := authjwt.NewIssuer(key, kid, "orderhub-auth-service", 300*time.Second, 30*24*time.Hour)
	user := &domain.User{ID: uuid.New(), Email: "user@example.com", Name: "User", Roles: []string{domain.RoleCustomer}}

	token, _, err := issuer.IssueAccessToken(user)
	require.NoError(t, err)

	verifier := authjwt.NewVerifier(&key.PublicKey)
	subject, err := verifier.VerifySubject(token)

	require.NoError(t, err)
	assert.Equal(t, user.ID, subject)
}

func TestVerifier_VerifySubject_RejectsTokenFromAnotherKeyPair(t *testing.T) {
	dir := t.TempDir()
	key, err := authjwt.LoadOrGenerateKeyPair(filepath.Join(dir, "private.pem"), filepath.Join(dir, "public.pem"))
	require.NoError(t, err)
	kid, err := authjwt.Thumbprint(&key.PublicKey)
	require.NoError(t, err)
	issuer := authjwt.NewIssuer(key, kid, "orderhub-auth-service", 300*time.Second, 30*24*time.Hour)
	user := &domain.User{ID: uuid.New(), Email: "user@example.com", Name: "User", Roles: []string{domain.RoleCustomer}}
	token, _, err := issuer.IssueAccessToken(user)
	require.NoError(t, err)

	otherDir := t.TempDir()
	otherKey, err := authjwt.LoadOrGenerateKeyPair(filepath.Join(otherDir, "private.pem"), filepath.Join(otherDir, "public.pem"))
	require.NoError(t, err)

	verifier := authjwt.NewVerifier(&otherKey.PublicKey)
	_, err = verifier.VerifySubject(token)

	assert.Error(t, err)
}

func jwkToRSAPublicKey(t *testing.T, k authjwt.JWK) *rsa.PublicKey {
	t.Helper()
	nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
	require.NoError(t, err)
	eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
	require.NoError(t, err)

	n := new(big.Int).SetBytes(nBytes)
	e := new(big.Int).SetBytes(eBytes)

	return &rsa.PublicKey{N: n, E: int(e.Int64())}
}
