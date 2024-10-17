package repository

import (
	"database/sql"
	"go-tech/internal/app/commons"
	"go-tech/internal/app/dto"
	"go-tech/internal/app/model"
	"go-tech/internal/app/util"

	"github.com/labstack/echo/v4"
	"gorm.io/gorm"
)

type IUserRepository interface {
	Count(ctx echo.Context, filter *dto.UserFilter) (count int64, err error)
	Find(ctx echo.Context, pConfig commons.PaginationConfig, filter *dto.UserFilter) (users []model.User, err error)
	FindByUsername(ctx echo.Context, username string) (user model.User, err error)
	FindByEmail(ctx echo.Context, email string) (user model.User, err error)
	FindByID(ctx echo.Context, userID uint) (user model.User, err error)
	UpdateWithMap(ctx echo.Context, userID uint, user map[string]interface{}) (err error)
	Update(user model.User, conditions *model.User, tx *gorm.DB) (err error)
	Create(user *model.User, tx *gorm.DB) (ID uint, err error)
	CreateUser(ctx echo.Context, user *model.User, tx *gorm.DB) (ID uint, err error)
	StoreResetPassword(user *model.ResetPassword, tx *gorm.DB) (ID uint, err error)
	Delete(ctx echo.Context, ID uint, userID uint) (err error)
}

type userRepository struct {
	opt Option
}

func NewUserRepository(opt Option) IUserRepository {
	return &userRepository{
		opt: opt,
	}
}

func (r *userRepository) generateCondition(db *gorm.DB, filter *dto.UserFilter) *gorm.DB {
	if filter.Search != nil {
		db = db.Where("(LOWER(code) like LOWER(?) or LOWER(name) like LOWER(?) OR level::text like LOWER(?))", *filter.Search+"%", *filter.Search+"%", *filter.Search+"%")
	}

	return db
}

func (r *userRepository) Count(ctx echo.Context, filter *dto.UserFilter) (count int64, err error) {
	db := r.opt.DB
	db = r.generateCondition(db, filter)
	err = db.Model(&model.User{}).
		// Preload("Role").
		Count(&count).Error
	return
}

func (r *userRepository) Find(ctx echo.Context, pConfig commons.PaginationConfig, filter *dto.UserFilter) (users []model.User, err error) {
	db := r.opt.DB
	db = r.generateCondition(db, filter)
	err = db.Scopes(util.Paginate(pConfig)).
		Preload("Role").
		Order("id DESC").
		Find(&users).Error
	return
}

func (r *userRepository) FindByUsername(ctx echo.Context, username string) (user model.User, err error) {
	err = r.opt.DB.
		// Joins("Role").
		First(&user, "username = ?", username).Error
	return
}

func (r *userRepository) FindByEmail(ctx echo.Context, email string) (user model.User, err error) {
	err = r.opt.DB.
		Joins("Role").
		First(&user, "email = ?", email).Error
	return
}

func (r *userRepository) FindByID(ctx echo.Context, userID uint) (user model.User, err error) {
	err = r.opt.DB.
		Joins("Role").
		First(&user, userID).Error
	return
}

func (r *userRepository) UpdateWithMap(ctx echo.Context, userID uint, user map[string]interface{}) (err error) {
	err = r.opt.DB.Model(&model.User{}).Where("id = ?", userID).Updates(user).Error
	return
}

func (r *userRepository) Update(user model.User, conditions *model.User, tx *gorm.DB) (err error) {
	if tx != nil {
		err = tx.Where(conditions).Updates(user).Error
	} else {
		err = r.opt.DB.Where(conditions).Updates(user).Error
	}
	return
}

func (r *userRepository) Create(user *model.User, tx *gorm.DB) (ID uint, err error) {
	if tx != nil {
		err = tx.Create(user).Error
	} else {
		err = r.opt.DB.Create(user).Error
	}
	ID = user.ID
	return
}

func (r *userRepository) CreateUser(ctx echo.Context, user *model.User, tx *gorm.DB) (ID uint, err error) {
	executor := r.opt.DB
	if tx != nil {
		executor = tx
	}
	err = executor.Create(user).Error
	ID = user.ID
	return
}

func (r *userRepository) StoreResetPassword(resetPassword *model.ResetPassword, tx *gorm.DB) (ID uint, err error) {
	if tx != nil {
		err = tx.Create(resetPassword).Error
	} else {
		err = r.opt.DB.Create(resetPassword).Error
	}
	ID = resetPassword.ID
	return
}

func (r *userRepository) Delete(ctx echo.Context, ID uint, userID uint) (err error) {
	user := &model.User{}
	user.ID = ID
	user.DeletedBy = sql.NullInt64{
		Valid: true,
		Int64: int64(userID),
	}
	err = r.opt.DB.Delete(user, ID).Error
	return

}
