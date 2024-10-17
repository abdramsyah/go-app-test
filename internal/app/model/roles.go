package model

import (
	"database/sql"
	"go-tech/internal/app/util"

	"gorm.io/gorm"
)

type Role struct {
	gorm.Model
	Name      string
	RoleType  string
	CreatedBy uint
	UpdatedBy uint
	DeletedBy sql.NullInt64
}

func (m *Role) TableName() string {
	return "educatix.roles"
}

func (m *Role) BeforeDelete(tx *gorm.DB) (err error) {
	result := tx.Where("role_id = ?", m.ID).Find(&User{})
	if result.RowsAffected > 0 {
		err = util.ErrDataRelatedToOtherData()
	}
	return
}

func (m *Role) AfterDelete(tx *gorm.DB) (err error) {
	err = tx.Model(m).Unscoped().Where("id = ?", m.ID).Update("deleted_by", m.DeletedBy.Int64).Error
	return
}
