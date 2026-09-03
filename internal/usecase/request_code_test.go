package usecase_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/adriano-linux/auth-service-go/internal/domain"
	"github.com/adriano-linux/auth-service-go/internal/usecase"
)

type fakeVerificationCodeRepo struct {
	byID []*domain.VerificationCode
}

func newFakeVerificationCodeRepo() *fakeVerificationCodeRepo {
	return &fakeVerificationCodeRepo{}
}

func (f *fakeVerificationCodeRepo) Insert(ctx context.Context, c *domain.VerificationCode) error {
	f.byID = append(f.byID, c)
	return nil
}

func (f *fakeVerificationCodeRepo) FindLatestByEmail(ctx context.Context, email string) (*domain.VerificationCode, error) {
	var latest *domain.VerificationCode
	for _, c := range f.byID {
		if c.Email != email {
			continue
		}
		if latest == nil || c.CreatedAt.After(latest.CreatedAt) {
			latest = c
		}
	}
	if latest == nil {
		return nil, domain.ErrCodeNotFound
	}
	return latest, nil
}

func (f *fakeVerificationCodeRepo) IncrementAttempts(ctx context.Context, id uuid.UUID) error {
	for _, c := range f.byID {
		if c.ID == id {
			c.Attempts++
		}
	}
	return nil
}

func (f *fakeVerificationCodeRepo) MarkConsumed(ctx context.Context, id uuid.UUID) error {
	now := time.Now().UTC()
	for _, c := range f.byID {
		if c.ID == id {
			c.ConsumedAt = &now
		}
	}
	return nil
}

type fakeCodeSender struct {
	sentTo   string
	sentCode string
}

func (f *fakeCodeSender) SendVerificationCode(ctx context.Context, email, code string) error {
	f.sentTo = email
	f.sentCode = code
	return nil
}

func TestRequestCode_PersistsAndSendsA6DigitCode(t *testing.T) {
	codes := newFakeVerificationCodeRepo()
	sender := &fakeCodeSender{}
	uc := usecase.NewRequestCode(codes, sender)

	err := uc.Handle(context.Background(), usecase.RequestCodeInput{Email: "New.User@Example.com"})

	require.NoError(t, err)
	assert.Equal(t, "new.user@example.com", sender.sentTo, "email should be normalized")
	assert.Len(t, sender.sentCode, 6)
	assert.Len(t, codes.byID, 1)
	assert.Equal(t, "new.user@example.com", codes.byID[0].Email)
	assert.NotEmpty(t, codes.byID[0].CodeHash)
	assert.NotEqual(t, sender.sentCode, codes.byID[0].CodeHash, "the stored value must be a hash, not the plaintext code")
	assert.WithinDuration(t, time.Now().UTC().Add(10*time.Minute), codes.byID[0].ExpiresAt, time.Minute)
}

func TestRequestCode_EachCallIssuesANewCode(t *testing.T) {
	codes := newFakeVerificationCodeRepo()
	sender := &fakeCodeSender{}
	uc := usecase.NewRequestCode(codes, sender)

	require.NoError(t, uc.Handle(context.Background(), usecase.RequestCodeInput{Email: "user@example.com"}))
	require.NoError(t, uc.Handle(context.Background(), usecase.RequestCodeInput{Email: "user@example.com"}))

	assert.Len(t, codes.byID, 2, "requesting again should not overwrite the previous code")
}
