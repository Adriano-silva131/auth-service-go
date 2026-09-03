package domain

import "errors"

var (
	ErrUserNotFound          = errors.New("user not found")
	ErrEmailAlreadyExists    = errors.New("email already registered")
	ErrInvalidCredentials    = errors.New("invalid credentials")
	ErrRefreshTokenInvalid   = errors.New("refresh token is invalid, expired, or revoked")
	ErrInvalidRole           = errors.New("invalid role")
	ErrCodeNotFound          = errors.New("verification code not found")
	ErrCodeInvalid           = errors.New("verification code is invalid, expired, or already used")
	ErrTooManyAttempts       = errors.New("too many attempts, request a new code")
	ErrOAuthStateInvalid     = errors.New("oauth state is invalid or expired")
	ErrOAuthEmailNotVerified = errors.New("google account email is not verified")
)
