package service

import (
	"go-tech/internal/app/commons"
	"go-tech/internal/app/pkg/email"
	"go-tech/internal/app/pkg/minio"
	"go-tech/internal/app/repository"
	"go-tech/pkg/cache"
)

// Option anything any service object needed
type Option struct {
	commons.Options
	*repository.Repository
	Cache        cache.ICache
	EMailService email.IEmailService
	MinioService minio.IMinioService
}

// Services all service object injected here
type Services struct {
	Health     IHealthService
	Auth       IAuthService
	AuditTrail IAuditTrailService
	User       IUserService
	Task       ITaskService
}
