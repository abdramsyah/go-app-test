package util

import (
	"github.com/labstack/echo/v4"
	"github.com/twinj/uuid"
)

func GetRequestID(ctx echo.Context) string {
	requestID := ctx.Response().Header().Get(echo.HeaderXRequestID)
	if requestID == "" {
		return uuid.NewV4().String()
	}
	return requestID
}
