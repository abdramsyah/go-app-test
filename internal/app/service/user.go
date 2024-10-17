package service

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"go-tech/internal/app/commons"
	"go-tech/internal/app/constant"
	"go-tech/internal/app/dto"
	"go-tech/internal/app/model"
	"go-tech/internal/app/util"
	"log"
	"strings"
	"sync"

	"github.com/labstack/echo/v4"
	"github.com/minio/minio-go/v7"
	"github.com/spf13/cast"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

type IUserService interface {
	Find(ctx echo.Context, pConfig commons.PaginationConfig, filter *dto.UserFilter) (users []model.User, count int64, err error)
	FindByID(ctx echo.Context, ID uint) (data model.User, err error)
	Profile(ctx echo.Context, userID uint) (user model.User, err error)
	ChangePassword(ctx echo.Context, userID uint, oldPassword string, newPassword string) (err error)
	Create(ctx echo.Context, req *dto.CreateUserRequest) (err error)
	Update(ctx echo.Context, userID uint, req *dto.UpdateUserRequest) (err error)
	FindUserByID(ctx echo.Context, ID uint) (user model.User, err error)
	Delete(ctx echo.Context, ID uint) (err error)
}

type userService struct {
	opt Option
}

func NewUserService(opt Option) IUserService {
	return &userService{
		opt: opt,
	}
}

func (s *userService) Find(ctx echo.Context, pConfig commons.PaginationConfig, filter *dto.UserFilter) (users []model.User, count int64, err error) {
	var waitGroup sync.WaitGroup
	c := make(chan error)

	waitGroup.Add(2)

	go func() {
		waitGroup.Wait()
		close(c)
	}()

	go func() {
		defer waitGroup.Done()

		count, err = s.opt.Repository.User.Count(ctx, filter)
		if err != nil {
			s.opt.Logger.With(zap.String("RequestID", util.GetRequestID(ctx))).Error("Get user count",
				zap.Error(err),
			)
			err = util.ErrFailedGetDataCount()
			c <- err
		}
	}()

	go func() {
		defer waitGroup.Done()

		users, err = s.opt.Repository.User.Find(ctx, pConfig, filter)
		if err != nil {
			s.opt.Logger.With(zap.String("RequestID", util.GetRequestID(ctx))).Error("Get users",
				zap.Error(err),
			)
			err = util.ErrFailedFetchData()
			c <- err
		}
	}()

	for errChan := range c {
		if errChan != nil {
			err = errChan
			return
		}
	}

	return
}

func (s *userService) FindByID(ctx echo.Context, ID uint) (data model.User, err error) {
	data, err = s.opt.Repository.User.FindByID(ctx, ID)
	if err != nil {
		s.opt.Logger.With(zap.String("RequestID", util.GetRequestID(ctx))).Error("Get group by id",
			zap.Error(err),
			zap.Uint("group id", ID),
		)
		if errors.Is(err, gorm.ErrRecordNotFound) {
			err = util.ErrDataNotFound()
		} else {
			err = util.ErrUnknownError("Gagal menemukan group melalui ID")
		}
	}
	return
}

func (s *userService) Profile(ctx echo.Context, userID uint) (user model.User, err error) {
	user, err = s.opt.Repository.User.FindByID(ctx, userID)
	if err != nil {
		s.opt.Logger.With(zap.String("RequestID", util.GetRequestID(ctx))).Error("Failed to get profile", zap.Error(err),
			zap.Uint("User ID", userID))
		if errors.Is(err, gorm.ErrRecordNotFound) {
			err = util.ErrDataNotFound()
			return
		}
		err = util.ErrInternalServerError()
		return
	}
	return
}

func (s *userService) ChangePassword(ctx echo.Context, userID uint, oldPassword string, newPassword string) (err error) {
	user, err := s.Profile(ctx, userID)
	if err != nil {
		return
	}

	check := util.CheckPasswordHash(oldPassword, user.PasswordHash)
	if !check {
		err = util.ErrRequestValidation("Password lama tidak valid")
		return
	}

	isNewPasswordValid := util.PasswordValidator2(newPassword, constant.UserMinPasswordLength)
	if !isNewPasswordValid {
		err = util.ErrRequestValidation("Format password baru tidak sesuai")
		return
	}

	hashPassword, err := util.HashPassword(newPassword)
	if err != nil {
		s.opt.Logger.With(zap.String("RequestID", util.GetRequestID(ctx))).Error("Failed to hash password",
			zap.Error(err),
			zap.Uint("User ID", userID))
		err = util.ErrUnknownError("Ubah password gagal, silahkan coba lagi")
		return
	}

	dataUpdate := map[string]interface{}{
		"password_hash": hashPassword,
	}
	err = s.opt.Repository.User.UpdateWithMap(ctx, userID, dataUpdate)
	if err != nil {
		s.opt.Logger.With(zap.String("RequestID", util.GetRequestID(ctx))).Error("Failed to update user", zap.Error(err), zap.Uint("User ID", userID))
		err = util.ErrInternalServerError()
		return
	}
	return
}

func (s *userService) FindUserByID(ctx echo.Context, ID uint) (user model.User, err error) {
	user, err = s.opt.Repository.User.FindByID(ctx, ID)
	if err != nil {
		s.opt.Logger.With(zap.String("RequestID", util.GetRequestID(ctx))).Error("Error users by ID",
			zap.Uint("User ID", ID),
			zap.Error(err),
		)
		err = util.ErrUnknownError("Gagal menemukan pengguna melalui ID")
	}
	return
}

func (s *userService) Create(ctx echo.Context, req *dto.CreateUserRequest) (err error) {
	actx, err := util.NewAppContext(ctx)
	if err != nil {
		return
	}
	_, err = s.opt.Repository.User.FindByEmail(actx, req.Email)
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		s.opt.Logger.With(zap.String("RequestID", util.GetRequestID(actx))).Warn("Error get user",
			zap.String("Email", req.Email),
			zap.Error(err))
		err = util.ErrInternalServerError()
		return
	}
	if err == nil {
		err = util.ErrRequestValidation("Email sudah digunakan oleh pengguna lain")
		return
	}

	_, err = s.opt.Repository.User.FindByUsername(actx, req.Username)
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		s.opt.Logger.With(zap.String("RequestID", util.GetRequestID(actx))).Warn("Error get user",
			zap.String("Username", req.Username),
			zap.Error(err))
		err = util.ErrInternalServerError()
		return
	}
	if err == nil {
		err = util.ErrRequestValidation("Username sudah digunakan oleh pengguna lain")
		return
	}

	_, err = s.opt.Repository.Role.FindRoleByID(actx, cast.ToUint(req.RoleID))
	if err != nil {
		s.opt.Logger.With(zap.String("RequestID", util.GetRequestID(actx))).Error("Error create user",
			zap.Error(err),
		)
		if errors.Is(err, gorm.ErrRecordNotFound) {
			err = util.ErrRequestValidation("Role tidak ditemukan")
		} else {
			err = util.ErrInternalServerError()
		}
		return
	}

	if req.Password != req.ConfirmPassword {
		err = util.ErrRequestValidation("Password user tidak boleh beda")
		return
	}

	userID := actx.GetUserID()
	user := &model.User{
		Email:        req.Email,
		CreatedBy:    userID,
		UpdatedBy:    userID,
		Name:         req.Name,
		Username:     req.Username,
		PhoneNumber:  req.PhoneNumber,
		PasswordHash: req.Password,
		RoleID:       req.RoleID,
	}

	tx := s.opt.DB.Begin()

	if req.ProfileImage != "" {
		path, err := s.uploadimage(actx.Request().Context(), "master-data", "admin/", req.ProfileImage)
		if err != nil {
			return err
		}
		user.PathImage = path
	}
	err = s.createUser(actx, user, tx)
	if err != nil {
		s.opt.Logger.With(zap.String("RequestID", util.GetRequestID(actx))).Error("Error create user",
			zap.Error(err),
		)
		err = util.ErrInternalServerError()
		return
	}
	tx.Commit()
	return
}

func (s *userService) uploadimage(ctx context.Context, bucketName, path, base64Image string) (string, error) {
	fileName := util.RandomString(20)
	if strings.Contains(base64Image, "data:image/png") {
		fileName += ".png"
	} else if strings.Contains(base64Image, "data:image/jpeg") {
		fileName += ".jpeg"
	}

	// Decode string base64
	base64Image = strings.TrimPrefix(base64Image, "data:image/png;base64,")
	base64Image = strings.TrimPrefix(base64Image, "data:image/jpeg;base64,")

	imgData, err := base64.StdEncoding.DecodeString(base64Image)
	if err != nil {
		s.opt.Logger.Error("Failed decoding base64 string", zap.Error(err))
		return "", err
	}

	// Tentukan tipe MIME file berdasarkan ekstensi
	var contentType string
	if strings.HasSuffix(fileName, ".png") {
		contentType = "image/png"
	} else if strings.HasSuffix(fileName, ".jpg") || strings.HasSuffix(fileName, ".jpeg") {
		contentType = "image/jpeg"
	} else {
		s.opt.Logger.Error("unsupported file format")
		return "", fmt.Errorf("unsupported file format")
	}

	// Set bucket name dan object name
	objectName := path + fileName

	// Upload file ke MinIO
	uploadInfo, err := s.opt.Minio.PutObject(ctx, bucketName, objectName, strings.NewReader(string(imgData)), int64(len(imgData)), minio.PutObjectOptions{
		ContentType: contentType,
	})

	if err != nil {
		s.opt.Logger.Error("error uploading file to Minio", zap.Error(err))
		return "", err
	}

	log.Printf("Successfully uploaded %s with size %d. Location: %s\n", uploadInfo.Key, uploadInfo.Size, uploadInfo.Location)
	return objectName, nil
}

func (s *userService) createUser(actx echo.Context, user *model.User, tx *gorm.DB) (err error) {
	password := user.PasswordHash
	passwordHash, err := util.HashPassword(password)
	if err != nil {
		s.opt.Logger.With(zap.String("RequestID", util.GetRequestID(actx))).Error("Error create password",
			zap.Error(err),
		)
		err = util.ErrUnknownError("Gagal untuk melakukan encrypt password")
		return
	}

	user.PasswordHash = passwordHash
	_, err = s.opt.Repository.User.CreateUser(actx, user, tx)
	if err != nil {
		s.opt.Logger.With(zap.String("RequestID", util.GetRequestID(actx))).Error("Error create user",
			zap.Error(err),
		)
		err = util.ErrUnknownError("Gagal untuk menambahkan pengguna")
		return
	}

	_, err = s.opt.Options.Rbac.AddRoleForUser(util.FormatRbacSubject(user.ID), util.FormatRbacRole(user.RoleID))
	if err != nil {
		s.opt.Logger.With(zap.String("RequestID", util.GetRequestID(actx))).Error("Failed to set role",
			zap.Error(err),
		)
		err = util.ErrUnknownError("Gagal untuk set role")
		tx.Rollback()
		return
	}

	return
}

func (s *userService) Update(ctx echo.Context, userID uint, req *dto.UpdateUserRequest) (err error) {
	actx, err := util.NewAppContext(ctx)
	if err != nil {
		return
	}

	id := actx.GetUserID()
	user := &model.User{
		Email:        req.Email,
		UpdatedBy:    id,
		Name:         req.Name,
		Username:     req.Username,
		PhoneNumber:  req.PhoneNumber,
		PasswordHash: req.Password,
		PathImage:    req.ProfileImage,
		RoleID:       cast.ToUint(req.RoleID),
	}

	if user.Email != "" {
		_, err = s.opt.Repository.User.FindByEmail(actx, req.Email)
		if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			s.opt.Logger.With(zap.String("RequestID", util.GetRequestID(actx))).Warn("Error update user",
				zap.String("Email", req.Email),
				zap.Error(err))
			err = util.ErrInternalServerError()
			return
		}
		if err == nil {
			err = util.ErrRequestValidation("Email sudah digunakan oleh pengguna lain")
			return
		}
	}

	if user.Username != "" {
		_, err = s.opt.Repository.User.FindByUsername(actx, req.Username)
		if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			s.opt.Logger.With(zap.String("RequestID", util.GetRequestID(actx))).Warn("Error update user",
				zap.String("Username", req.Username),
				zap.Error(err))
			err = util.ErrInternalServerError()
			return
		}
		if err == nil {
			err = util.ErrRequestValidation("Username sudah digunakan oleh pengguna lain")
			return
		}
	}

	_, err = s.opt.Repository.Role.FindRoleByID(actx, cast.ToUint(req.RoleID))
	if err != nil {
		s.opt.Logger.With(zap.String("RequestID", util.GetRequestID(actx))).Error("Error update user",
			zap.Error(err),
		)
		if errors.Is(err, gorm.ErrRecordNotFound) {
			err = util.ErrRequestValidation("Role tidak ditemukan")
		} else {
			err = util.ErrInternalServerError()
		}
		return
	}

	if req.Password != req.ConfirmPassword {
		err = util.ErrRequestValidation("Password user tidak boleh beda")
		return
	}

	tx := s.opt.DB.Begin()

	if req.ProfileImage != "" {
		path, err := s.uploadimage(actx.Request().Context(), "master-data", "admin/", req.ProfileImage)
		if err != nil {
			return err
		}
		user.PathImage = path
	}

	password := user.PasswordHash
	passwordHash, err := util.HashPassword(password)
	if err != nil {
		s.opt.Logger.With(zap.String("RequestID", util.GetRequestID(actx))).Error("Error create password",
			zap.Error(err),
		)
		err = util.ErrUnknownError("Gagal untuk melakukan encrypt password")
		return
	}

	dataUpdate := map[string]interface{}{
		"name":         user.Name,
		"username":     user.Username,
		"email":        user.Email,
		"phone_number": user.PhoneNumber,
		"updated_by":   user.UpdatedBy,
		"path_image":   user.PathImage,
		"role_id":      user.RoleID,
	}
	if user.PasswordHash != "0" {
		dataUpdate["password_hash"] = passwordHash
	} else {
		dataUpdate["password_hash"] = nil
	}
	err = s.opt.Repository.User.UpdateWithMap(actx, userID, dataUpdate)
	if err != nil {
		s.opt.Logger.With(zap.String("RequestID", util.GetRequestID(actx))).Error("Error create user",
			zap.Error(err),
		)
		err = util.ErrUnknownError("Gagal untuk menambahkan pengguna")
		return
	}
	tx.Commit()
	return
}

func (s *userService) Delete(ctx echo.Context, ID uint) (err error) {
	actx, err := util.NewAppContext(ctx)
	if err != nil {
		return
	}

	userID := actx.GetUserID()
	_, err = s.opt.Repository.User.FindByID(actx, ID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			err = util.ErrDataNotFound()
		} else {
			err = util.ErrInternalServerError()
		}
		return
	}

	err = s.opt.Repository.User.Delete(actx, ID, userID)
	if err != nil {
		s.opt.Logger.With(zap.String("RequestID", util.GetRequestID(actx))).Error("Error delete user ",
			zap.Error(err),
			zap.Uint("user id", ID),
		)
		if errors.Is(err, util.ErrDataRelatedToOtherData()) {
			err = util.ErrRequestValidation(err.Error())
		} else {
			err = util.ErrUnknownError("Gagal menghapus user")
		}
	}
	return
}
