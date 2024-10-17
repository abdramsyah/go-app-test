package router

import (
	"go-tech/internal/app/handler"
	"go-tech/internal/app/middleware"

	"github.com/labstack/echo/v4"
)

type task struct {
	server     *echo.Echo
	handlers   handler.Handlers
	middleware *middleware.CustomMiddleware
}

func newTask(server *echo.Echo, handlers handler.Handlers, middleware *middleware.CustomMiddleware) *task {
	return &task{
		server:     server,
		handlers:   handlers,
		middleware: middleware,
	}
}

func (h *task) initialize() {
	g := h.server.Group("/api/v1/task")
	g.Use(h.middleware.JWTMiddleware)
	g.Use(h.middleware.AuditTrailMiddleware)
	g.GET("", middleware.HandlerWrapperJson(h.handlers.Task.RetrievedList)).Name = "Get List Task"
	g.GET("/:ID", middleware.HandlerWrapperJson(h.handlers.Task.FindByID)).Name = "Get Detail Task"
	g.POST("", middleware.HandlerWrapperJson(h.handlers.Task.Create)).Name = "Create Task"
	g.PUT("/:ID", middleware.HandlerWrapperJson(h.handlers.Task.Update)).Name = "Update Task"
	g.DELETE("/:ID", middleware.HandlerWrapperJson(h.handlers.Task.Delete)).Name = "Delete Task"
}
