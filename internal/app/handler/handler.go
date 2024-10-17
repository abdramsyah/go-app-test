package handler

import (
	"go-tech/internal/app/commons"
	"go-tech/internal/app/service"
)

// HandlerOption option for handler, including all service
type HandlerOption struct {
	commons.Options
	*service.Services
}

type Handlers struct {
	Health HealthHandler
	Auth   AuthHandler
	User   UserHandler
	Task   TaskHandler
}
