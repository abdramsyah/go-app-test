package service

import (
	"go-tech/internal/app/dto"

	"github.com/labstack/echo/v4"
)

type IHealthService interface {
	CheckHealth(ctx echo.Context) (resp dto.HealthResponse)
}

type healthService struct {
	opt Option
}

func NewHealthService(opt Option) IHealthService {
	return &healthService{
		opt: opt,
	}
}

func (s *healthService) CheckHealth(ctx echo.Context) (resp dto.HealthResponse) {
	resp = dto.HealthResponse{Message: "OK"}
	return
}
