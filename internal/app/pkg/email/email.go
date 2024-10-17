package email

import (
	"go-tech/config"

	"gopkg.in/gomail.v2"
)

type IEmailService interface {
	Send(req EmailRequest) (err error)
}

type emailService struct {
	cfg    *config.ConfigObject
	dialer gomail.Dialer
}

func NewEmailService(cfg *config.ConfigObject) IEmailService {
	dialer := gomail.NewDialer(
		cfg.MailSmtpHost, cfg.MailSmtpPort, cfg.MailAuth, cfg.MailAuthPassword,
	)
	return &emailService{
		cfg:    cfg,
		dialer: *dialer,
	}
}

func (e *emailService) Send(req EmailRequest) (err error) {
	mailer := gomail.NewMessage()

	mailer.SetAddressHeader("From", e.cfg.MailSenderName, e.cfg.MailAlias)
	mailer.SetHeader("From", e.cfg.MailSenderName)
	mailer.SetHeader("To", req.EmailTo...)
	mailer.SetHeader("Subject", req.Subject)
	mailer.SetBody("text/html", req.Message)
	if req.Attachment != "" {
		mailer.Attach(req.Attachment)
	}

	err = e.dialer.DialAndSend(mailer)

	return
}
