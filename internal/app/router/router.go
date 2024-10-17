package router

import (
	"go-tech/internal/app/handler"
	"go-tech/internal/app/middleware"

	"github.com/labstack/echo/v4"
)

type Router struct {
	health *health
	auth   *auth
	user   *user
	task   *task
}

func NewRouter(server *echo.Echo, handlers handler.Handlers, cmiddleware *middleware.CustomMiddleware) (router *Router) {
	health := newHealth(server, handlers, cmiddleware)
	auth := newAuth(server, handlers, cmiddleware)
	user := newUser(server, handlers, cmiddleware)
	task := newTask(server, handlers, cmiddleware)
	return &Router{
		health: health,
		auth:   auth,
		user:   user,
		task:   task,
	}
}

func (r *Router) Initialize() {
	r.health.initialize()
	r.auth.initialize()
	r.user.initialize()
	r.task.initialize()
}
