package model

import (
	"time"

	"gorm.io/gorm"
)

type ResetPassword struct {
	gorm.Model
	Email        string     `gorm:"type:varchar(255);not null;index"`
	Token        string     `gorm:"type:text;not null;index"`
	Status       string     `gorm:"type:enum('unused','used');default:'unused';not null"`
	IsClicked    bool       `gorm:"not null"`
	ExpiresAt    time.Time  `gorm:"not null"`
	UsedAt       *time.Time `gorm:"default:null"`
	RequestedIP  string     `gorm:"type:varchar(45)"`
	AttemptCount int        `gorm:"default:0"`
}

func (ResetPassword) TableName() string {
	return "reset_passwords"
}
