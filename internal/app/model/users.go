package model

import (
	"database/sql"

	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Email        string `gorm:"size:100;not null;unique"`
	Name         string `gorm:"size:100;not null"`
	Username     string `gorm:"size:100;not null"`
	PasswordHash string `gorm:"size:100;not null"`
	PhoneNumber  string `gorm:"size:20;not null"`
	RoleID       uint
	Role         *Role
	CreatedBy    uint
	UpdatedBy    uint
	DeletedBy    sql.NullInt64
}

func (c *User) TableName() string {
	return "users"
}
