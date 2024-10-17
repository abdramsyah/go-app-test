package handler

import (
	"go-tech/internal/app/constant"
	"go-tech/internal/app/dto"
	"go-tech/internal/app/util"
	"net/http"

	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
)

type AuthHandler struct {
	HandlerOption
}

func (h AuthHandler) Register(c echo.Context) (resp dto.HttpResponse) {
	var err error
	req := new(dto.RegisterStudentRequest)
	if err = c.Bind(req); err != nil {
		h.HandlerOption.Options.Logger.Error("Error bind request",
			zap.Error(err),
		)
		resp = dto.FailedHttpResponse(err, nil)
		return
	}

	err = req.Validate()
	if err != nil {
		resp = dto.FailedHttpResponse(err, nil)
		return
	}

	err = h.Services.Auth.Register(c, req)
	if err != nil {
		resp = dto.FailedHttpResponse(err, nil)
		return
	}

	resp = dto.SuccessHttpResponse(http.StatusOK, "", "Register success", nil)
	return
}

func (h AuthHandler) Login(c echo.Context) (resp dto.HttpResponse) {
	var err error
	req := new(dto.LoginRequest)
	if err = c.Bind(req); err != nil {
		h.HandlerOption.Options.Logger.Error("Error bind request",
			zap.Error(err),
		)
		resp = dto.FailedHttpResponse(util.ErrBindRequest(), nil)
		return
	}

	err = req.Validate()
	if err != nil {
		resp = dto.FailedHttpResponse(err, nil)
		return
	}

	token, err := h.Services.Auth.Login(c, req)
	if err != nil {
		resp = dto.FailedHttpResponse(err, nil)
		return
	}

	resp = dto.SuccessHttpResponse(http.StatusOK, "", "Login success", token)
	return
}

func (h AuthHandler) Logout(c echo.Context) (resp dto.HttpResponse) {
	var err error
	actx, err := util.NewAppContext(c)
	if err != nil {
		resp = dto.FailedHttpResponse(err, nil)
		return
	}

	userID := actx.GetUserID()
	accessUUID := actx.GetAccessUUID()
	err = h.Services.Auth.Logout(c, userID, accessUUID)
	if err != nil {
		resp = dto.FailedHttpResponse(err, nil)
		return
	}

	resp = dto.SuccessHttpResponse(http.StatusOK, "", "Logout success", nil)
	return
}

func (h AuthHandler) RefreshToken(c echo.Context) (resp dto.HttpResponse) {
	var err error
	req := new(dto.RefreshTokenRequest)
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

	token, err := h.Services.Auth.RefreshToken(c, req.RefreshToken)
	if err != nil {
		resp = dto.FailedHttpResponse(err, nil)
		return
	}

	resp = dto.SuccessHttpResponse(http.StatusOK, "", "Refresh token success", token)
	return
}

func (h AuthHandler) ForgotPassword(c echo.Context) (resp dto.HttpResponse) {
	var err error
	req := new(dto.ForgotPasswordRequest)
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

	err = h.Services.Auth.ForgotPassword(c, req)
	if err != nil {
		resp = dto.FailedHttpResponse(err, nil)
		return
	}

	resp = dto.SuccessHttpResponse(http.StatusOK, "", constant.SuccessRequestResetPassword, "")
	return
}

func (h AuthHandler) VerifyResetToken(c echo.Context) (resp dto.HttpResponse) {
	var err error

	token := c.QueryParam("token")
	if token == "" {
		resp = dto.FailedHttpResponse(util.ErrRequestValidation("Token is required"), nil)
		return
	}

	req := &dto.VerifyResetPasswordRequest{Token: token}
	err = req.Validate()
	if err != nil {
		resp = dto.FailedHttpResponse(util.ErrRequestValidation(err.Error()), nil)
		return
	}

	err = h.Services.Auth.VerifyResetToken(c, req)
	if err != nil {
		resp = dto.FailedHttpResponse(err, nil)
		return
	}

	resp = dto.SuccessHttpResponse(http.StatusOK, "", constant.VerifyResetPassword, "")
	return
}

func (h AuthHandler) ResetPassword(c echo.Context) (resp dto.HttpResponse) {
	var err error

	req := new(dto.ChangePasswordRequest)
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

	err = h.Services.Auth.ResetPassword(c, req)
	if err != nil {
		resp = dto.FailedHttpResponse(err, nil)
		return
	}

	resp = dto.SuccessHttpResponse(http.StatusOK, "", constant.SuccessResetPassword, "")
	return
}
