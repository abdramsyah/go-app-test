package model

import (
	"database/sql"

	"gorm.io/gorm"
)

type Admin struct {
	gorm.Model
	FullName     string
	Email        string
	PasswordHash string
	RoleID       uint
	Status       string
	CreatedBy    uint64
	UpdatedBy    uint64
	DeletedBy    sql.NullInt64
	AdminCreate  *Admin `gorm:"foreignKey:CreatedBy"`
	AdminUpdate  *Admin `gorm:"foreignKey:UpdatedBy"`
	AdminDelete  *Admin `gorm:"foreignKey:DeletedBy"`
	Role         *Role
}

// TableName sets the insert table name for this struct type
func (a *Admin) TableName() string {
	return "admins"
}
