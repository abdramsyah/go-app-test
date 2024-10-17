package dto

import (
	"time"

	validation "github.com/go-ozzo/ozzo-validation/v4"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type TaskFilter struct {
	Search *string `query:"search"`
}

type CreateTaskRequest struct {
	Title       string `json:"title" validate:"required"`                              // Judul task yang harus diisi
	Description string `json:"description" validate:"required"`                        // Deskripsi task yang harus diisi
	Status      string `json:"status" validate:"required,oneof=todo in-progress done"` // Status task, dibatasi pada nilai tertentu
}

// Response DTO untuk menampilkan Task
type TaskResponse struct {
	ID          primitive.ObjectID `json:"id"`          // ObjectID MongoDB, diubah ke string jika dikembalikan ke pengguna
	Title       string             `json:"title"`       // Judul task
	Description string             `json:"description"` // Deskripsi task
	Status      string             `json:"status"`      // Status task
	CreatedAt   time.Time          `json:"created_at"`  // Timestamp pembuatan task
	UpdatedAt   time.Time          `json:"updated_at"`  // Timestamp update task
}

func (r CreateTaskRequest) Validate() error {
	validation.ErrorTag = "tag"
	return validation.ValidateStruct(&r,
		validation.Field(&r.Title,
			validation.Required, validation.Length(1, 100)),
		validation.Field(&r.Description,
			validation.Required, validation.Length(3, 50)),
		validation.Field(&r.Status,
			validation.Required, validation.Length(3, 15)),
	)
}

type UpdateTaskRequest struct {
	Title       string `json:"title" validate:"required"`                              // Judul task yang harus diisi
	Description string `json:"description" validate:"required"`                        // Deskripsi task yang harus diisi
	Status      string `json:"status" validate:"required,oneof=todo in-progress done"` // Status task, dibatasi pada nilai tertentu
}

func (r UpdateTaskRequest) Validate() error {
	validation.ErrorTag = "tag"
	return validation.ValidateStruct(&r,
		validation.Field(&r.Title,
			validation.Required, validation.Length(1, 100)),
		validation.Field(&r.Description,
			validation.Required, validation.Length(3, 50)),
		validation.Field(&r.Status,
			validation.Required, validation.Length(3, 15)),
	)
}
