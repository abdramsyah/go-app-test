package minio

import (
	"bytes"
	"context"
	"fmt"
	"io"

	"github.com/minio/minio-go/v7"
)

type IMinioService interface {
	Upload(bucket string, object string, data []byte, contentType string) (err error)
	Download(bucket string, object string) (data []byte, err error)
}

type minioService struct {
	minioClient *minio.Client
}

// NewMinioService creates a new instance of MinioService
func NewMinioService(minioClient *minio.Client) IMinioService {
	return &minioService{
		minioClient: minioClient,
	}
}

// Upload uploads a file to the specified bucket and object name in Minio
func (s *minioService) Upload(bucket string, object string, data []byte, contentType string) (err error) {
	if contentType == "" {
		contentType = "application/octet-stream" // Default content type if not provided
	}

	_, err = s.minioClient.PutObject(
		context.Background(),
		bucket,
		object,
		bytes.NewReader(data),
		int64(len(data)),
		minio.PutObjectOptions{ContentType: contentType},
	)

	if err != nil {
		return fmt.Errorf("failed to upload object %s to bucket %s: %w", object, bucket, err)
	}

	return nil
}

// Download mengunduh file dari bucket dan nama objek yang ditentukan di Minio
func (s *minioService) Download(bucket string, object string) (data []byte, err error) {
	// Unduh objek dari Minio
	obj, err := s.minioClient.GetObject(context.Background(), bucket, object, minio.GetObjectOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to download object %s from bucket %s: %w", object, bucket, err)
	}
	defer obj.Close()

	// Baca data dari objek
	data, err = io.ReadAll(obj)
	if err != nil {
		return nil, fmt.Errorf("failed to read object data: %w", err)
	}

	return data, nil
}
