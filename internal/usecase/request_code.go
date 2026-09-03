package usecase

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"time"

	"github.com/google/uuid"

	"github.com/adriano-linux/auth-service-go/internal/domain"
)

const (
	verificationCodeLength = 6
	verificationCodeTTL    = 10 * time.Minute
)

type RequestCodeInput struct {
	Email string
}

type RequestCode struct {
	codes  VerificationCodeRepository
	sender CodeSender
}

func NewRequestCode(codes VerificationCodeRepository, sender CodeSender) *RequestCode {
	return &RequestCode{codes: codes, sender: sender}
}

func (uc *RequestCode) Handle(ctx context.Context, in RequestCodeInput) error {
	email := normalizeEmail(in.Email)

	code, err := generateVerificationCode()
	if err != nil {
		return fmt.Errorf("generating verification code: %w", err)
	}

	now := time.Now().UTC()
	record := &domain.VerificationCode{
		ID:        uuid.New(),
		Email:     email,
		CodeHash:  hashVerificationCode(code),
		ExpiresAt: now.Add(verificationCodeTTL),
		CreatedAt: now,
	}
	if err := uc.codes.Insert(ctx, record); err != nil {
		return fmt.Errorf("persisting verification code: %w", err)
	}

	if err := uc.sender.SendVerificationCode(ctx, email, code); err != nil {
		return fmt.Errorf("sending verification code: %w", err)
	}

	return nil
}

func generateVerificationCode() (string, error) {
	const digits = "0123456789"
	b := make([]byte, verificationCodeLength)
	for i := range b {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(digits))))
		if err != nil {
			return "", err
		}
		b[i] = digits[n.Int64()]
	}
	return string(b), nil
}

func hashVerificationCode(code string) string {
	sum := sha256.Sum256([]byte(code))
	return hex.EncodeToString(sum[:])
}
