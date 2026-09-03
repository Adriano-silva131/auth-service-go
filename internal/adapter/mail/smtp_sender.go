package mail

import (
	"context"
	"fmt"
	"net/smtp"
)

type SMTPSender struct {
	host     string
	port     string
	username string
	password string
	from     string
}

func NewSMTPSender(host, port, username, password, from string) *SMTPSender {
	return &SMTPSender{host: host, port: port, username: username, password: password, from: from}
}

func (s *SMTPSender) SendVerificationCode(ctx context.Context, to, code string) error {
	subject := "Seu código de acesso OrderHub"
	body := fmt.Sprintf(
		"Seu código de verificação é: %s\r\n\r\nEle expira em 10 minutos. Se você não pediu esse código, ignore este e-mail.",
		code,
	)
	msg := []byte(fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\n\r\n%s\r\n", s.from, to, subject, body))

	auth := smtp.PlainAuth("", s.username, s.password, s.host)
	addr := s.host + ":" + s.port

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	return smtp.SendMail(addr, auth, s.from, []string{to}, msg)
}
