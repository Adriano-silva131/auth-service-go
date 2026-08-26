package jwt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
)

const rsaKeyBits = 2048

// LoadOrGenerateKeyPair loads an RSA key pair from the given PEM paths, or generates
// and persists a new one if either file is missing. This keeps local dev and a fresh
// `kubectl apply` zero-config (no operator has to pre-generate and inject a key) at the
// cost of every stored session becoming invalid if the key file is ever lost — an
// acceptable trade-off for a portfolio/local-dev project, not a production KMS setup.
func LoadOrGenerateKeyPair(privPath, pubPath string) (*rsa.PrivateKey, error) {
	if fileExists(privPath) && fileExists(pubPath) {
		return loadPrivateKey(privPath)
	}

	key, err := rsa.GenerateKey(rand.Reader, rsaKeyBits)
	if err != nil {
		return nil, fmt.Errorf("generating RSA key pair: %w", err)
	}

	if err := savePrivateKey(privPath, key); err != nil {
		return nil, err
	}
	if err := savePublicKey(pubPath, &key.PublicKey); err != nil {
		return nil, err
	}

	return key, nil
}

// Thumbprint returns a stable "kid" for the given public key, deterministic so it
// naturally changes if the key file is ever swapped, with no config knob needed.
func Thumbprint(pub *rsa.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("marshalling public key: %w", err)
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])[:16], nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func loadPrivateKey(path string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading private key file: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %s", path)
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing private key: %w", err)
	}
	return key, nil
}

func savePrivateKey(path string, key *rsa.PrivateKey) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("creating key directory: %w", err)
	}
	block := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}
	return os.WriteFile(path, pem.EncodeToMemory(block), 0o600)
}

func savePublicKey(path string, pub *rsa.PublicKey) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("creating key directory: %w", err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return fmt.Errorf("marshalling public key: %w", err)
	}
	block := &pem.Block{Type: "PUBLIC KEY", Bytes: der}
	return os.WriteFile(path, pem.EncodeToMemory(block), 0o644)
}
