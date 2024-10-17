package middleware

import (
	"go-tech/internal/app/dto"
	"go-tech/internal/app/util"

	"github.com/labstack/echo/v4"
)

func (m *CustomMiddleware) JWTMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		result, err := m.Service.Auth.ValidateToken(c, c.Request())
		if err != nil {
			resp := dto.FailedHttpResponse(err, nil)
			return c.JSON(resp.HttpStatus, resp)
		}

		actx := util.NewEmptyAppContext(c)
		actx.SetUserID(result.UserID)
		actx.SetAccessUUID(result.AccessUUID)
		actx.SetRoleType(result.RoleType)
		return next(actx)
	}
}
