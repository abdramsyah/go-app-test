package handler

import (
	"go-tech/internal/app/commons"
	"go-tech/internal/app/constant"
	"go-tech/internal/app/dto"
	"go-tech/internal/app/util"
	"net/http"
	"strconv"

	"github.com/labstack/echo/v4"
	"github.com/spf13/cast"
	"go.uber.org/zap"
)

type UserHandler struct {
	HandlerOption
}

// func (h UserHandler) GetPermission(c echo.Context) (resp dto.HttpResponse) {
// 	actx, err := util.NewAppContext(c)
// 	if err != nil {
// 		return
// 	}
// 	userID := actx.GetUserID()
// 	res, err := h.Services.User.GetPermissions(actx, userID)
// 	if err != nil {
// 		resp = dto.FailedHttpResponse(err, nil)
// 		return
// 	}

// 	resp = dto.SuccessHttpResponse(http.StatusOK, "", "Berhasil mendapatkan akses pengguna", res)
// 	return
// }

func (h UserHandler) RetrievedList(c echo.Context) (resp dto.HttpResponse) {
	pConfig := util.GeneratePaginateConfig(c)
	filter := new(dto.UserFilter)

	if err := c.Bind(filter); err != nil {
		resp = dto.FailedHttpResponse(err, nil)
		return
	}

	users, count, err := h.Services.User.Find(c, pConfig, filter)
	if err != nil {
		resp = dto.FailedHttpResponse(err, nil)
		return
	}

	respData := []dto.ListUserResponse{}
	res := commons.PaginateResponse{
		List:  respData,
		Count: count,
	}
	if count == 0 {
		resp = dto.SuccessHttpResponse(http.StatusOK, "", "Berhasil mendapatkan semua users", res)
		return
	}

	for _, data := range users {
		user := dto.ListUserResponse{
			ID:   data.ID,
			Name: data.Name,
			Role: dto.RoleEmbed{
				ID:       data.Role.ID,
				Name:     data.Role.Name,
				RoleType: data.Role.RoleType,
			},
			CreatedAt: data.CreatedAt.Format(constant.FeDatetimeFormat),
			UpdatedAt: data.UpdatedAt.Format(constant.FeDatetimeFormat),
		}
		respData = append(respData, user)
	}

	res.List = respData
	resp = dto.SuccessHttpResponse(http.StatusOK, "", "Berhasil mendapatkan users", res)
	return
}

func (h UserHandler) FindByID(c echo.Context) (resp dto.HttpResponse) {
	paramID := c.Param("ID")
	ID, err := strconv.Atoi(paramID)
	if err != nil {
		resp = dto.FailedHttpResponse(util.ErrRequestValidation("ID user tidak valid"), nil)
		return
	}

	user, err := h.Services.User.FindByID(c, cast.ToUint(ID))
	if err != nil {
		resp = dto.FailedHttpResponse(err, nil)
		return
	}

	result := dto.UserProfileResponse{
		ID:          user.ID,
		Email:       user.Email,
		Name:        user.Name,
		Username:    user.Username,
		PhoneNumber: user.PhoneNumber,
		Role: dto.RoleEmbed{
			ID:       user.Role.ID,
			Name:     user.Role.Name,
			RoleType: user.Role.RoleType,
		},
		PathImage: user.PathImage,
	}

	resp = dto.SuccessHttpResponse(http.StatusOK, "", "Berhasil mendapatkan detail User", result)
	return
}

func (h UserHandler) Create(c echo.Context) (resp dto.HttpResponse) {

	var err error
	req := new(dto.CreateUserRequest)
	if err = c.Bind(req); err != nil {
		h.HandlerOption.Options.Logger.Error("Error bind request",
			zap.Error(err),
		)
		resp = dto.FailedHttpResponse(util.ErrBindRequest(), nil)
		return
	}

	err = req.Validate()
	if err != nil {
		resp = dto.FailedHttpResponse(util.ErrRequestValidation(err.Error()), nil)
		return
	}

	err = h.Services.User.Create(c, req)
	if err != nil {
		resp = dto.FailedHttpResponse(err, nil)
		return
	}

	resp = dto.SuccessHttpResponse(http.StatusCreated, "", "Berhasil membuat pengguna", nil)
	return
}

func (h UserHandler) Update(c echo.Context) (resp dto.HttpResponse) {
	actx, err := util.NewAppContext(c)
	if err != nil {
		return
	}
	req := new(dto.UpdateUserRequest)
	if err = actx.Bind(req); err != nil {
		h.HandlerOption.Options.Logger.Error("Error bind request",
			zap.Error(err),
		)
		resp = dto.FailedHttpResponse(util.ErrBindRequest(), nil)
		return
	}

	err = req.Validate()
	if err != nil {
		resp = dto.FailedHttpResponse(util.ErrRequestValidation(err.Error()), nil)
		return
	}

	ID := c.Param("ID")
	if ID == "" {
		resp = dto.FailedHttpResponse(util.ErrRequestValidation("ID User tidak valid"), nil)
		return
	}

	err = h.Services.User.Update(c, cast.ToUint(ID), req)
	if err != nil {
		resp = dto.FailedHttpResponse(err, nil)
		return
	}

	resp = dto.SuccessHttpResponse(http.StatusCreated, "", "Berhasil memperbaharui User", nil)
	return
}

func (h UserHandler) Delete(c echo.Context) (resp dto.HttpResponse) {
	paramID := c.Param("ID")
	ID, err := strconv.Atoi(paramID)
	if err != nil {
		resp = dto.FailedHttpResponse(util.ErrRequestValidation("ID user tidak valid"), nil)
		return
	}

	err = h.Services.User.Delete(c, cast.ToUint(ID))
	if err != nil {
		resp = dto.FailedHttpResponse(err, nil)
		return
	}

	resp = dto.SuccessHttpResponse(http.StatusOK, "", "Berhasil menghapus User", nil)
	return
}
