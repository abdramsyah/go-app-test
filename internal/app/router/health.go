package router

import (
	"go-tech/internal/app/handler"
	"go-tech/internal/app/middleware"

	"github.com/labstack/echo/v4"
)

type health struct {
	server     *echo.Echo
	handlers   handler.Handlers
	middleware *middleware.CustomMiddleware
}

func newHealth(server *echo.Echo, handlers handler.Handlers, middleware *middleware.CustomMiddleware) *health {
	return &health{
		server:     server,
		handlers:   handlers,
		middleware: middleware,
	}
}

func (h *health) initialize() {
	g := h.server.Group("/health")
	g.GET("/check", middleware.HandlerWrapperJson(h.handlers.Health.Check))
}
