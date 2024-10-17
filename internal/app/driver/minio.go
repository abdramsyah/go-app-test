package driver

import (
	"fmt"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// MinioOption holds the configuration for MinIO client
type MinioOption struct {
	Endpoint        string
	AccessKeyID     string
	SecretAccessKey string
	UseSSL          bool
}

// NewMinioClient creates a new MinIO client instance
func NewMinioClient(opt MinioOption) (*minio.Client, error) {
	minioClient, err := minio.New(opt.Endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(opt.AccessKeyID, opt.SecretAccessKey, ""),
		Secure: opt.UseSSL,
	})
	if err != nil {
		return nil, fmt.Errorf("ERROR connect minio | %v", err)
	}
	return minioClient, nil
}
