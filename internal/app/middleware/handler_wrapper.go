package middleware

import (
	"fmt"
	"go-tech/internal/app/dto"
	"time"

	"github.com/labstack/echo/v4"
)

type HandlerJson func(ctx echo.Context) (resp dto.HttpResponse)

func HandlerWrapperJson(next HandlerJson) func(ctx echo.Context) error {
	return func(ctx echo.Context) error {
		start := time.Now()
		resp := next(ctx)
		resp.ProcessTime = fmt.Sprintf("%dms", time.Since(start).Milliseconds())
		return ctx.JSON(resp.HttpStatus, resp)
	}
}
