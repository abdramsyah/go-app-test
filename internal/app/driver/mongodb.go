package driver

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cast"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// DBMongoDBOption options for mongoDB connection
type DBMongoDBOption struct {
	Host        string
	Port        int
	Username    string
	Password    string
	DBName      string
	MaxPoolSize int
	BatchSize   int
}

func NewMongoDBDatabase(option DBMongoDBOption) (db *mongo.Database, err error) {
	uri := fmt.Sprintf("mongodb://%s:%d", option.Host, option.Port)

	clientOptions := options.Client().ApplyURI(uri).SetMaxPoolSize(cast.ToUint64(option.MaxPoolSize))
	if option.Username != "" && option.Password != "" {
		credential := options.Credential{
			Username: option.Username,
			Password: option.Password,
		}
		clientOptions.SetAuth(credential)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client, err := mongo.Connect(ctx, clientOptions)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to MongoDB: %v", err)
	}

	err = client.Ping(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to ping MongoDB: %v", err)
	}

	fmt.Println("Successfully connected to MongoDB!")

	return client.Database(option.DBName), nil
}
