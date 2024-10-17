package repository

import (
	"go-tech/internal/app/commons"
)

// Option anything any repo object needed
type Option struct {
	commons.Options
}

// Repository all repo object injected here
type Repository struct {
	Admin         IAdminRepository
	User          IUserRepository
	AuditTrail    IAuditTrailRepository
	Student       IStudentRepository
	ResetPassword IResetPasswordRepository
	Role          IRoleRepository
	Task          ITaskRepository
}
