package commons

import (
	"go-tech/config"
	"go-tech/internal/app/appcontext"

	"github.com/casbin/casbin/v2"
	"github.com/gomodule/redigo/redis"
	"github.com/minio/minio-go/v7"
	"go.mongodb.org/mongo-driver/mongo"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// Options common option for all object that needed
type Options struct {
	Config    config.ConfigObject
	DB        *gorm.DB
	MongoDB   *mongo.Database
	Logger    *zap.Logger
	CachePool *redis.Pool
	Rbac      *casbin.SyncedEnforcer
	Minio     *minio.Client
	Errors    []error
}

func InitCommonOptions(options ...func(*Options)) *Options {
	opt := &Options{}
	for _, o := range options {
		o(opt)
		if opt.Errors != nil {
			return opt
		}
	}
	return opt
}

func WithConfig(cfg config.ConfigObject) func(*Options) {
	return func(opt *Options) {
		opt.Config = cfg
	}
}

func WithDB(appCtx *appcontext.AppContext) func(*Options) {
	return func(opt *Options) {
		db, err := appCtx.GetDBInstance()
		if err != nil {
			opt.Errors = append(opt.Errors, err)
			return
		}
		opt.DB = db
	}
}

func WithLogger(logger *zap.Logger) func(*Options) {
	return func(opt *Options) {
		opt.Logger = logger
	}
}

func WithCache(appCtx *appcontext.AppContext) func(*Options) {
	return func(opt *Options) {
		cache := appCtx.GetCachePool()
		opt.CachePool = cache
	}
}

// Must call after WithDB to prevent nil pointer exception
func WithRBAC(appCtx *appcontext.AppContext) func(*Options) {
	return func(opt *Options) {
		rbac, err := appCtx.GetRbacOption(opt.DB)
		if err != nil {
			opt.Errors = append(opt.Errors, err)
			return
		}
		opt.Rbac = rbac
	}
}

func WithMinio(appCtx *appcontext.AppContext) func(*Options) {
	return func(opt *Options) {
		minioClient, err := appCtx.GetMinioInstance()
		if err != nil {
			opt.Errors = append(opt.Errors, err)
			return
		}
		opt.Minio = minioClient
	}
}

func WithMongoDB(appCtx *appcontext.AppContext) func(*Options) {
	return func(opt *Options) {
		db, err := appCtx.GetMongoDBInstance()
		if err != nil {
			opt.Errors = append(opt.Errors, err)
			return
		}
		opt.MongoDB = db
	}
}
