package cmd

import (
	"fmt"
	"go-tech/config"
	"go-tech/internal/app/appcontext"
	"go-tech/internal/app/commons"
	"go-tech/internal/app/pkg/email"
	"go-tech/internal/app/repository"
	"go-tech/internal/app/server"
	"go-tech/internal/app/service"
	"go-tech/pkg/cache"
	"os"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var levelMapper = map[string]zapcore.Level{
	"debug":  zapcore.DebugLevel,
	"info":   zapcore.InfoLevel,
	"warn":   zapcore.WarnLevel,
	"error":  zapcore.ErrorLevel,
	"dpanic": zapcore.DPanicLevel,
	"panic":  zapcore.PanicLevel,
	"fatal":  zapcore.FatalLevel,
}

func initLogger(cfg config.ConfigObject) *zap.Logger {
	var level zapcore.Level
	if lvl, ok := levelMapper[cfg.AppLogLevel]; ok {
		level = lvl
	} else {
		level = zapcore.InfoLevel
	}

	loggerCfg := zap.Config{
		Encoding:         "json",
		Level:            zap.NewAtomicLevelAt(level),
		OutputPaths:      []string{"stderr"},
		ErrorOutputPaths: []string{"stderr"},
		EncoderConfig: zapcore.EncoderConfig{
			MessageKey: "message",

			LevelKey:    "level",
			EncodeLevel: zapcore.CapitalLevelEncoder,

			TimeKey:    "time",
			EncodeTime: zapcore.RFC3339NanoTimeEncoder,

			CallerKey:    "caller",
			EncodeCaller: zapcore.ShortCallerEncoder,
		},
	}
	logger, _ := loggerCfg.Build()
	return logger
}

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "api",
	Short: "A brief description of your application",
	Long:  `A longer description that spans multiple lines and likely contains examples and usage of using your application.`,
	Run: func(cmd *cobra.Command, args []string) {
		start()
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize()
}

func initRepository(repoOption repository.Option) *repository.Repository {
	admin := repository.NewAdminRepository(repoOption)
	auditTrail := repository.NewAuditTrailRepository(repoOption)
	user := repository.NewUserRepository(repoOption)
	student := repository.NewStudentRepository(repoOption)
	resetPassword := repository.NewResetPasswordRepository(repoOption)
	role := repository.NewRoleRepository(repoOption)
	task := repository.NewTaskRepository(repoOption)
	repositories := repository.Repository{
		Admin:         admin,
		AuditTrail:    auditTrail,
		User:          user,
		Student:       student,
		ResetPassword: resetPassword,
		Role:          role,
		Task:          task,
	}
	return &repositories
}

func initService(serviceOption service.Option) *service.Services {
	health := service.NewHealthService(serviceOption)
	auth := service.NewAuthService(serviceOption)
	auditTrail := service.NewAuditTrailService(serviceOption)
	user := service.NewUserService(serviceOption)
	task := service.NewTaskService(serviceOption)
	services := service.Services{
		Health:     health,
		Auth:       auth,
		AuditTrail: auditTrail,
		User:       user,
		Task:       task,
	}
	return &services
}

func start() {
	cfg := config.Config()
	logger := initLogger(cfg)

	app := appcontext.NewAppContext(cfg)

	opt := commons.InitCommonOptions(
		commons.WithConfig(cfg),
		commons.WithLogger(logger),
		commons.WithDB(app),
		commons.WithCache(app),
		commons.WithRBAC(app),
		// commons.WithMinio(app),
		commons.WithMongoDB(app),
	)

	if len(opt.Errors) > 0 {
		logger.Fatal("Init common options error",
			zap.Any("context", opt.Errors),
		)
		return
	}

	repos := initRepository(repository.Option{
		Options: *opt,
	})

	cachePkg := cache.NewCache(opt.CachePool)
	emailSvcPkg := email.NewEmailService(&opt.Config)
	// minioSvcPkg := minio.NewMinioService(opt.Minio)

	services := initService(service.Option{
		Options:      *opt,
		Repository:   repos,
		Cache:        cachePkg,
		EMailService: emailSvcPkg,
		// MinioService: minioSvcPkg,
	})

	srv := server.NewServer(*opt, services)

	// run app
	srv.StartApp()
}
