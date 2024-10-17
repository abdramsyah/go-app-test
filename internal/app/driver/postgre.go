package driver

import (
	"fmt"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// DBPostgreOption options for postgre connection
type DBPostgreOption struct {
	Host        string
	Port        int
	Username    string
	Password    string
	DBName      string
	MaxPoolSize int
	BatchSize   int
}

func NewPostgreDatabase(option DBPostgreOption) (db *gorm.DB, err error) {
	dsn := fmt.Sprintf("host=%s port=%d user=%s dbname=%s password=%s sslmode=disable", option.Host, option.Port, option.Username, option.DBName, option.Password)
	db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{
		CreateBatchSize: option.BatchSize,
	})

	return
}
