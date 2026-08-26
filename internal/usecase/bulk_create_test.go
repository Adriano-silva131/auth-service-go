package usecase_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/adriano-linux/auth-service-go/internal/usecase"
)

func TestCreateUsersBulk_ReportsDuplicatesWithoutFailingBatch(t *testing.T) {
	repo := newFakeUserRepo()
	register := usecase.NewRegister(repo, fakeHasher{})
	uc := usecase.NewCreateUsersBulk(register)

	items := []usecase.BulkCreateItem{
		{Email: "a@example.com", Password: "supersecret", Name: "A"},
		{Email: "b@example.com", Password: "supersecret", Name: "B"},
	}
	result := uc.Handle(context.Background(), items)
	assert.Len(t, result.Created, 2)
	assert.Empty(t, result.Skipped)

	// Re-run the same batch — everything should be reported as skipped, not fail.
	result = uc.Handle(context.Background(), items)
	assert.Empty(t, result.Created)
	assert.Len(t, result.Skipped, 2)
}
