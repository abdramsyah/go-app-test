package repository

import (
	"go-tech/internal/app/commons"
	"go-tech/internal/app/model"
	"go-tech/internal/app/util"

	"gorm.io/gorm"
)

type IAdminRepository interface {
	Count() (count int64, err error)
	Find(pConfig commons.PaginationConfig) (units []model.Admin, err error)
	FindByEmail(email string) (admin model.Admin, err error)
	FindById(userID uint64) (admin model.Admin, err error)
	Update(admin model.Admin, conditions *model.Admin, tx *gorm.DB) (err error)
	Create(admin *model.Admin, tx *gorm.DB) (err error)
}

type adminRepository struct {
	opt Option
}

func NewAdminRepository(opt Option) IAdminRepository {
	return &adminRepository{
		opt: opt,
	}
}

func (r *adminRepository) Count() (count int64, err error) {
	err = r.opt.DB.Model(&model.Admin{}).Count(&count).Error
	return
}

func (r *adminRepository) Find(pConfig commons.PaginationConfig) (admins []model.Admin, err error) {
	err = r.opt.DB.Scopes(util.Paginate(pConfig)).Preload("Role").Preload("Unit").Preload("JobTitle").Preload("AdminCreate").Preload("AdminUpdate").Order("id DESC").Find(&admins).Error
	return
}

func (r *adminRepository) FindByEmail(email string) (admin model.Admin, err error) {
	err = r.opt.DB.Preload("Role").First(&admin, "email = ?", email).Error
	return
}

func (r *adminRepository) FindById(userID uint64) (admin model.Admin, err error) {
	err = r.opt.DB.Preload("Role").Preload("AdminCreate").Preload("AdminUpdate").First(&admin, userID).Error
	return
}

func (r *adminRepository) Update(admin model.Admin, conditions *model.Admin, tx *gorm.DB) (err error) {
	if tx != nil {
		err = tx.Where(conditions).Updates(admin).Error
	} else {
		err = r.opt.DB.Where(conditions).Updates(admin).Error
	}
	return
}

func (r *adminRepository) Create(admin *model.Admin, tx *gorm.DB) (err error) {
	if tx != nil {
		err = tx.Create(admin).Error
	} else {
		err = r.opt.DB.Create(admin).Error
	}
	return
}
