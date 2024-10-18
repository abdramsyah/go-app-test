package model

import (
	"time"

	"gorm.io/gorm"
)

type Student struct {
	gorm.Model
	UserID      uint `gorm:"index;foreignKey:UserID;references:ID"`
	NISN        string
	BirthPlace  string
	BirthDate   time.Time
	ExamGroup   string
	ParentName  string
	ParentPhone string
	SchoolID    uint `gorm:"index;foreignKey:SchoolID;references:ID"`
	ClassID     uint `gorm:"index;foreignKey:ClassID;references:ID"`
	CreatedBy   uint
	UpdatedBy   uint
	DeletedBy   uint
}

// TableName sets the table name for the Student struct.
func (Student) TableName() string {
	return "students"
}
