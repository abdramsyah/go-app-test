package middleware

import (
	"go-tech/internal/app/commons"
	"go-tech/internal/app/service"

	"go.uber.org/zap"
)

type CustomMiddleware struct {
	Service *service.Services
	Logger  *zap.Logger
}

func NewCustomMiddleware(opt commons.Options, svc *service.Services) *CustomMiddleware {
	return &CustomMiddleware{
		Service: svc,
		Logger:  opt.Logger,
	}
}
