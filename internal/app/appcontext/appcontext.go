package appcontext

import (
	"go-tech/config"
	"go-tech/internal/app/driver"

	"github.com/casbin/casbin/v2"
	gormadapter "github.com/casbin/gorm-adapter/v3"
	"github.com/gomodule/redigo/redis"
	"github.com/minio/minio-go/v7"
	"github.com/spf13/cast"
	"go.mongodb.org/mongo-driver/mongo"
	"gorm.io/gorm"
)

// AppContext the app context struct
type AppContext struct {
	config config.ConfigObject
}

// NewAppContext initiate appcontext object
func NewAppContext(config config.ConfigObject) *AppContext {
	return &AppContext{
		config: config,
	}
}

func (a *AppContext) GetDBInstance() (db *gorm.DB, err error) {
	dbOption := a.getPostgreOption()
	db, err = driver.NewPostgreDatabase(dbOption)

	return
}

func (a *AppContext) getPostgreOption() driver.DBPostgreOption {
	return driver.DBPostgreOption{
		Host:        a.config.DBHost,
		Port:        a.config.DBPort,
		Username:    a.config.DBUsername,
		Password:    a.config.DBPassword,
		DBName:      a.config.DBName,
		MaxPoolSize: a.config.DBMaxPoolSize,
		BatchSize:   a.config.DBBatchSize,
	}
}

// GetCachePool get cache pool connection
func (a *AppContext) GetCachePool() *redis.Pool {
	return driver.NewCache(a.getCacheOption())
}

func (a *AppContext) getCacheOption() driver.CacheOption {
	return driver.CacheOption{
		Host:               a.config.RedisHost,
		Port:               a.config.RedisPort,
		Namespace:          a.config.RedisNamespace,
		Password:           a.config.RedisPassword,
		DialConnectTimeout: cast.ToDuration(a.config.RedisDialConnectTimeout),
		ReadTimeout:        cast.ToDuration(a.config.RedisReadTimeout),
		WriteTimeout:       cast.ToDuration(a.config.RedisWriteTimeout),
		IdleTimeout:        cast.ToDuration(a.config.RedisIdleTimeout),
		MaxConnLifetime:    cast.ToDuration(a.config.RedisConnLifetimeMax),
		MaxIdle:            a.config.RedisConnIdleMax,
		MaxActive:          a.config.RedisConnActiveMax,
		Wait:               a.config.RedisIsWait,
	}
}

func (a *AppContext) GetRbacOption(db *gorm.DB) (enforcer *casbin.SyncedEnforcer, err error) {
	adapter, err := gormadapter.NewAdapterByDB(db)
	if err != nil {
		return
	}
	enforcer, err = casbin.NewSyncedEnforcer(a.config.CasbinModelPath, adapter)

	return
}

// GetMinioInstance gets the MinIO client instance
func (a *AppContext) GetMinioInstance() (*minio.Client, error) {
	minioOption := a.getMinioOption()
	minioClient, err := driver.NewMinioClient(minioOption)
	if err != nil {
		return nil, err
	}
	return minioClient, nil
}

// getMinioOption prepares the MinIO client options
func (a *AppContext) getMinioOption() driver.MinioOption {
	return driver.MinioOption{
		Endpoint:        a.config.MinioEndpoint,
		AccessKeyID:     a.config.MinioAccessKeyID,
		SecretAccessKey: a.config.MinioSecretAccessKey,
		UseSSL:          a.config.MinioUseSSL,
	}
}

func (a *AppContext) GetMongoDBInstance() (db *mongo.Database, err error) {
	dbOption := a.getMongoDBOption()
	db, err = driver.NewMongoDBDatabase(dbOption)

	return
}

func (a *AppContext) getMongoDBOption() driver.DBMongoDBOption {
	return driver.DBMongoDBOption{
		Host:        a.config.MongoDBHost,
		Port:        a.config.MongoDBPort,
		Username:    a.config.MongoDBUsername,
		Password:    a.config.MongoDBPassword,
		DBName:      a.config.MongoDBName,
		MaxPoolSize: a.config.DBMaxPoolSize,
		BatchSize:   a.config.DBBatchSize,
	}
}
