package model

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// Task struct sebagai representasi dokumen Task di MongoDB
type Task struct {
	ID          primitive.ObjectID `bson:"_id,omitempty"` // ObjectID MongoDB, diisi otomatis jika kosong
	Title       string             `bson:"title"`         // Judul task
	Description string             `bson:"description"`   // Deskripsi task
	Status      string             `bson:"status"`        // Status task (e.g., "todo", "in-progress", "done")
	CreatedBy   uint               `bson:"created_by"`
	UpdatedBy   uint               `bson:"updated_by"`
	CreatedAt   time.Time          `bson:"created_at"` // Timestamp pembuatan task
	UpdatedAt   time.Time          `bson:"updated_at"` // Timestamp update task
}
