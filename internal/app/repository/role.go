package repository

import (
	"go-tech/internal/app/model"

	"github.com/labstack/echo/v4"
)

type IRoleRepository interface {
	FindRoleByID(ctx echo.Context, ID uint) (role *model.Role, err error)
}

type roleRepository struct {
	opt Option
}

func NewRoleRepository(opt Option) IRoleRepository {
	return &roleRepository{
		opt: opt,
	}
}

func (r *roleRepository) FindRoleByID(ctx echo.Context, ID uint) (role *model.Role, err error) {
	role = &model.Role{}
	err = r.opt.DB.
		First(role, ID).Error
	return
}
