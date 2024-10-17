package repository

import (
	"go-tech/internal/app/model"

	"gorm.io/gorm"
)

type IStudentRepository interface {
	Create(user *model.Student, tx *gorm.DB) (err error)
}

type studentRepository struct {
	opt Option
}

func NewStudentRepository(opt Option) IStudentRepository {
	return &studentRepository{
		opt: opt,
	}
}

func (r *studentRepository) Create(student *model.Student, tx *gorm.DB) (err error) {
	if tx != nil {
		err = tx.Create(student).Error
	} else {
		err = r.opt.DB.Create(student).Error
	}
	return
}
