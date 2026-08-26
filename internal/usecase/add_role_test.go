package usecase_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/adriano-linux/auth-service-go/internal/domain"
	"github.com/adriano-linux/auth-service-go/internal/usecase"
)

func TestAddRole_GrantsSellerRole(t *testing.T) {
	repo := newFakeUserRepo()
	uc := usecase.NewRegister(repo, fakeHasher{})
	ctx := context.Background()

	registered, err := uc.Handle(ctx, usecase.RegisterInput{Email: "seller@example.com", Password: "supersecret", Name: "Seller"})
	require.NoError(t, err)

	addRole := usecase.NewAddRole(repo)
	updated, err := addRole.Handle(ctx, usecase.AddRoleInput{UserID: registered.ID, Role: domain.RoleSeller})

	require.NoError(t, err)
	assert.ElementsMatch(t, []string{domain.RoleCustomer, domain.RoleSeller}, updated.Roles)
}

func TestAddRole_IsIdempotent(t *testing.T) {
	repo := newFakeUserRepo()
	registerUC := usecase.NewRegister(repo, fakeHasher{})
	ctx := context.Background()

	registered, err := registerUC.Handle(ctx, usecase.RegisterInput{Email: "seller2@example.com", Password: "supersecret", Name: "Seller"})
	require.NoError(t, err)

	addRole := usecase.NewAddRole(repo)
	_, err = addRole.Handle(ctx, usecase.AddRoleInput{UserID: registered.ID, Role: domain.RoleSeller})
	require.NoError(t, err)

	updated, err := addRole.Handle(ctx, usecase.AddRoleInput{UserID: registered.ID, Role: domain.RoleSeller})
	require.NoError(t, err)
	assert.Equal(t, []string{domain.RoleCustomer, domain.RoleSeller}, updated.Roles)
}

func TestAddRole_RejectsUnknownRole(t *testing.T) {
	repo := newFakeUserRepo()
	registerUC := usecase.NewRegister(repo, fakeHasher{})
	ctx := context.Background()

	registered, err := registerUC.Handle(ctx, usecase.RegisterInput{Email: "customer@example.com", Password: "supersecret", Name: "Customer"})
	require.NoError(t, err)

	addRole := usecase.NewAddRole(repo)
	_, err = addRole.Handle(ctx, usecase.AddRoleInput{UserID: registered.ID, Role: "ADMIN"})

	assert.ErrorIs(t, err, domain.ErrInvalidRole)
}
