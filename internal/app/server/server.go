package server

import (
	"context"
	"fmt"
	"go-tech/internal/app/commons"
	"go-tech/internal/app/handler"
	cmiddleware "go-tech/internal/app/middleware"
	"go-tech/internal/app/router"
	"go-tech/internal/app/service"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/spf13/cast"
	"github.com/ucarion/urlpath"
	"go.uber.org/zap"
)

// IServer interface for server
type IServer interface {
	StartApp()
}

type server struct {
	opt      commons.Options
	services *service.Services
}

type requestBodyException struct {
	URL    string
	Method string
}

// NewServer create object server
func NewServer(opt commons.Options, services *service.Services) IServer {
	return &server{
		opt:      opt,
		services: services,
	}
}

func initHandler(opt commons.Options, services *service.Services) (handlers handler.Handlers) {
	hOpt := handler.HandlerOption{
		Options:  opt,
		Services: services,
	}

	healthHandler := handler.HealthHandler{
		HandlerOption: hOpt,
	}

	authHandler := handler.AuthHandler{
		HandlerOption: hOpt,
	}

	userHandler := handler.UserHandler{
		HandlerOption: hOpt,
	}

	taskHandler := handler.TaskHandler{
		HandlerOption: hOpt,
	}

	handlers = handler.Handlers{
		Health: healthHandler,
		Auth:   authHandler,
		User:   userHandler,
		Task:   taskHandler,
	}
	return
}

func (s *server) StartApp() {
	e := echo.New()
	// Middleware
	e.Use(middleware.Recover())
	if cast.ToBool(s.opt.Config.DumpRequest) {
		e.Use(middleware.BodyDump(func(c echo.Context, reqBody, resBody []byte) {
			urlString := c.Request().URL.String()
			var bodyString string
			var contain bool
			var requestBodyExceptions []requestBodyException
			// URL exception to print request body
			requestBodyExceptions = append(requestBodyExceptions, requestBodyException{
				URL:    "/auth/login",
				Method: "POST",
			})

			for _, e := range requestBodyExceptions {
				var path = urlpath.New(e.URL)
				_, ok := path.Match(urlString)
				if ok && (c.Request().Method == e.Method) {
					contain = true
					break
				}
			}
			// Dump request body except urlExceptions
			if !contain {
				bodyString = string(reqBody)
			}
			s.opt.Logger.Info("Intercept request",
				zap.String("method", c.Request().Method),
				zap.String("uri", urlString),
				zap.String("ip", c.Request().RemoteAddr),
				zap.String("body", bodyString),
			)
		}))
	}

	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins: strings.Split(s.opt.Config.AllowOrigins, ","),
		AllowHeaders: []string{
			echo.HeaderOrigin,
			echo.HeaderContentType,
			echo.HeaderAccept,
			echo.HeaderAccessControlAllowOrigin,
			echo.HeaderAuthorization,
			"CoreAccessToken",
			"CoreAuthID"},
		MaxAge:       600,
		AllowMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"},
	}))

	// Initialize Casbin Policy
	if s.opt.Rbac != nil {
		s.opt.Rbac.StartAutoLoadPolicy(cast.ToDuration(s.opt.Config.CasbinPolicyReloadDuration))
		defer s.opt.Rbac.StopAutoLoadPolicy()
	}

	idleConnectionClosed := make(chan struct{})
	go func() {
		sigint := make(chan os.Signal, 1)
		signal.Notify(sigint, os.Interrupt)
		<-sigint

		s.opt.Logger.Info("[API] Server is shutting down")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		// We received an interrupt signal, shut down.
		if err := e.Shutdown(ctx); err != nil {
			s.opt.Logger.Error("[API] Fail to shutting down",
				zap.Error(err),
			)
		}
		close(idleConnectionClosed)
	}()

	srvAddr := fmt.Sprintf("%s:%d", s.opt.Config.AppHost, s.opt.Config.AppPort)

	handlers := initHandler(s.opt, s.services)
	customMiddleware := cmiddleware.NewCustomMiddleware(s.opt, s.services)
	routers := router.NewRouter(e, handlers, customMiddleware)
	routers.Initialize()

	s.opt.Logger.Info(fmt.Sprintf("[API] HTTP serve at %s", srvAddr))
	if err := e.Start(srvAddr); err != nil {
		s.opt.Logger.Error("[API] Fail to start listen and server",
			zap.Error(err),
		)
	}

	<-idleConnectionClosed
	s.opt.Logger.Info("[API] Bye")
}
