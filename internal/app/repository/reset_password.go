package repository

import (
	"go-tech/internal/app/model"

	"github.com/labstack/echo/v4"
	"gorm.io/gorm"
)

type IResetPasswordRepository interface {
	FindByEmail(ctx echo.Context, email string) (resetPassword model.ResetPassword, err error)
	FindByEmailAndToken(ctx echo.Context, email string, token string) (resetPassword model.ResetPassword, err error)
	StoreResetPassword(resetPassword *model.ResetPassword, tx *gorm.DB) (ID uint, err error)
	Update(resetPassword model.ResetPassword, conditions *model.ResetPassword, tx *gorm.DB) (err error)
}

type resetPasswordRepository struct {
	opt Option
}

func NewResetPasswordRepository(opt Option) IResetPasswordRepository {
	return &resetPasswordRepository{
		opt: opt,
	}
}

func (r *resetPasswordRepository) FindByEmail(ctx echo.Context, email string) (resetPassword model.ResetPassword, err error) {
	err = r.opt.DB.
		First(&resetPassword, "email = ?", email).Error
	return
}

func (r *resetPasswordRepository) FindByEmailAndToken(ctx echo.Context, email string, token string) (resetPassword model.ResetPassword, err error) {
	err = r.opt.DB.
		First(&resetPassword, "email = ? and token = ?", email, token).Error
	return
}

func (r *resetPasswordRepository) Update(resetPassword model.ResetPassword, conditions *model.ResetPassword, tx *gorm.DB) (err error) {
	if tx != nil {
		err = tx.Where(conditions).Updates(resetPassword).Error
	} else {
		err = r.opt.DB.Where(conditions).Updates(resetPassword).Error
	}
	return
}

func (r *resetPasswordRepository) StoreResetPassword(resetPassword *model.ResetPassword, tx *gorm.DB) (ID uint, err error) {
	if tx != nil {
		err = tx.Create(resetPassword).Error
	} else {
		err = r.opt.DB.Create(resetPassword).Error
	}
	ID = resetPassword.ID
	return
}

// func (r *resetPasswordRepository) Update(ctx echo.Context, ID uint, resetPassword model.ResetPassword) (err error) {
// 	err = r.opt.DB.
// 		First(&resetPassword, "email = ?", resetPassword.Email).Error
// 	return
// }
