package handler

import (
	"go-tech/internal/app/constant"
	"go-tech/internal/app/dto"
	"net/http"

	"github.com/labstack/echo/v4"
)

type HealthHandler struct {
	HandlerOption
}

func (h HealthHandler) Check(ctx echo.Context) (resp dto.HttpResponse) {
	healthResp := h.Services.Health.CheckHealth(ctx)
	resp = dto.HttpResponse{
		Status:     constant.RespSuccessStatus,
		Code:       "-",
		Message:    healthResp.Message,
		HttpStatus: http.StatusOK,
	}
	return
}
