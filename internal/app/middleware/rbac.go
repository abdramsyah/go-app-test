package middleware

import (
	"go-tech/internal/app/dto"
	"go-tech/internal/app/util"
	"net/http"

	"github.com/labstack/echo/v4"
)

func (m *CustomMiddleware) RBACMiddleware(object string, action string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			isPermitted, err := m.Service.Auth.PermissionCheck(c, object, action)
			if err != nil {
				data := dto.FailedHttpResponse(util.ErrUnknownError("Gagal melakukan pengecekan akses"), nil)
				return c.JSON(data.HttpStatus, data)
			}
			if !isPermitted {
				data := dto.FailedHttpResponse(util.ErrUserDontHavePermission(), nil)
				return c.JSON(data.HttpStatus, data)
			}
			return next(c)
		}
	}
}

// Sample request [][]interface{}{{"13", "37"}, {"13", "39"}}
func (m *CustomMiddleware) RBACBatchMiddleware(request [][]interface{}) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			isPermitted, err := m.Service.Auth.BatchPermissionCheck(c, request)
			if err != nil {
				data := dto.FailedHttpResponse(util.ErrUnknownError("Gagal melakukan pengecekan akses"), nil)
				return c.JSON(http.StatusInternalServerError, data)
			}
			if !isPermitted {
				data := dto.FailedHttpResponse(util.ErrUserDontHavePermission(), nil)
				return c.JSON(data.HttpStatus, data)
			}
			return next(c)
		}
	}
}
