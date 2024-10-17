package router

import (
	"go-tech/internal/app/handler"
	"go-tech/internal/app/middleware"

	"github.com/labstack/echo/v4"
)

type user struct {
	server     *echo.Echo
	handlers   handler.Handlers
	middleware *middleware.CustomMiddleware
}

func newUser(server *echo.Echo, handlers handler.Handlers, middleware *middleware.CustomMiddleware) *user {
	return &user{
		server:     server,
		handlers:   handlers,
		middleware: middleware,
	}
}

func (h *user) initialize() {
	g := h.server.Group("/api/v1/users")
	g.Use(h.middleware.JWTMiddleware)
	g.Use(h.middleware.AuditTrailMiddleware)
	g.GET("", middleware.HandlerWrapperJson(h.handlers.User.RetrievedList)).Name = "Get List User"
	g.GET("/:ID", middleware.HandlerWrapperJson(h.handlers.User.FindByID)).Name = "Get Detail User"
	g.POST("", middleware.HandlerWrapperJson(h.handlers.User.Create)).Name = "Create User"
	g.PUT("/:ID", middleware.HandlerWrapperJson(h.handlers.User.Update)).Name = "Update User"
	g.DELETE("/:ID", middleware.HandlerWrapperJson(h.handlers.User.Delete)).Name = "Delete User"
}
