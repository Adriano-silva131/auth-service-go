package mail

import (
	"context"
	"log/slog"
)

type ConsoleSender struct{}

func NewConsoleSender() *ConsoleSender { return &ConsoleSender{} }

func (s *ConsoleSender) SendVerificationCode(ctx context.Context, to, code string) error {
	slog.InfoContext(ctx, "verification code (SMTP_HOST not set — logging instead of emailing)",
		"email", to, "code", code)
	return nil
}
