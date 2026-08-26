package jwt

import (
	"crypto/rsa"
	"encoding/base64"
	"math/big"
)

// JWK is the standard JSON Web Key shape for an RSA public key (RFC 7517).
type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type JWKSet struct {
	Keys []JWK `json:"keys"`
}

// BuildJWKSet encodes the RSA public key as a single-entry JWK Set, matching what
// api-gateway's Spring Security jwk-set-uri resolver expects.
func BuildJWKSet(pub *rsa.PublicKey, kid string) JWKSet {
	return JWKSet{
		Keys: []JWK{
			{
				Kty: "RSA",
				Use: "sig",
				Kid: kid,
				Alg: "RS256",
				N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
				E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
			},
		},
	}
}
