package router

import (
	"go-tech/internal/app/handler"
	"go-tech/internal/app/middleware"

	"github.com/labstack/echo/v4"
)

type auth struct {
	server     *echo.Echo
	handlers   handler.Handlers
	middleware *middleware.CustomMiddleware
}

func newAuth(server *echo.Echo, handlers handler.Handlers, middleware *middleware.CustomMiddleware) *auth {
	return &auth{
		server:     server,
		handlers:   handlers,
		middleware: middleware,
	}
}

func (h *auth) initialize() {
	g := h.server.Group("/api/v1/auth")
	g.POST("/register", middleware.HandlerWrapperJson(h.handlers.Auth.Register))
	g.POST("/login", middleware.HandlerWrapperJson(h.handlers.Auth.Login))
	g.POST("/refresh", middleware.HandlerWrapperJson(h.handlers.Auth.RefreshToken))
	g.POST("/forgot-password", middleware.HandlerWrapperJson(h.handlers.Auth.ForgotPassword))
	g.GET("/reset-password", middleware.HandlerWrapperJson(h.handlers.Auth.VerifyResetToken))
	g.POST("/reset-password", middleware.HandlerWrapperJson(h.handlers.Auth.ResetPassword))
	g.Use(h.middleware.JWTMiddleware)
	g.Use(h.middleware.AuditTrailMiddleware)
	g.GET("/logout", middleware.HandlerWrapperJson(h.handlers.Auth.Logout)).Name = "Logout"
}
