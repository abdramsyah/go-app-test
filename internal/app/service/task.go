package service

import (
	"errors"
	"fmt"
	"go-tech/internal/app/commons"
	"go-tech/internal/app/dto"
	"go-tech/internal/app/model"
	"go-tech/internal/app/util"
	"sync"

	"github.com/labstack/echo/v4"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

type ITaskService interface {
	Find(ctx echo.Context, pConfig commons.PaginationConfig, filter *dto.TaskFilter) (users []model.Task, count int64, err error)
	// FindByID(ctx echo.Context, ID uint) (data model.Task, err error)
	// Profile(ctx echo.Context, userID uint) (user model.Task, err error)
	// ChangePassword(ctx echo.Context, userID uint, oldPassword string, newPassword string) (err error)
	Create(ctx echo.Context, req *dto.CreateTaskRequest) (err error)
	Update(ctx echo.Context, ID primitive.ObjectID, req *dto.UpdateTaskRequest) (err error)
	FindByID(ctx echo.Context, ID primitive.ObjectID) (user model.Task, err error)
	Delete(ctx echo.Context, ID primitive.ObjectID) (err error)
}

type taskService struct {
	opt Option
}

func NewTaskService(opt Option) ITaskService {
	return &taskService{
		opt: opt,
	}
}

func (s *taskService) Find(ctx echo.Context, pConfig commons.PaginationConfig, filter *dto.TaskFilter) (taks []model.Task, count int64, err error) {
	var waitGroup sync.WaitGroup
	c := make(chan error)

	waitGroup.Add(2)

	go func() {
		waitGroup.Wait()
		close(c)
	}()

	go func() {
		defer waitGroup.Done()

		count, err = s.opt.Repository.Task.Count(ctx, filter)
		if err != nil {
			s.opt.Logger.With(zap.String("RequestID", util.GetRequestID(ctx))).Error("Get task count",
				zap.Error(err),
			)
			err = util.ErrFailedGetDataCount()
			c <- err
		}
	}()

	go func() {
		defer waitGroup.Done()

		taks, err = s.opt.Repository.Task.Find(ctx, pConfig, filter)
		if err != nil {
			s.opt.Logger.With(zap.String("RequestID", util.GetRequestID(ctx))).Error("Get tasks",
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

func (s *taskService) FindByID(ctx echo.Context, ID primitive.ObjectID) (data model.Task, err error) {
	data, err = s.opt.Repository.Task.FindByID(ctx, ID)
	if err != nil {
		s.opt.Logger.With(zap.String("RequestID", util.GetRequestID(ctx))).Error("Get task by id",
			zap.Error(err),
			zap.String("group id", ID.Hex()),
		)
		if errors.Is(err, gorm.ErrRecordNotFound) {
			err = util.ErrDataNotFound()
		} else {
			err = util.ErrUnknownError("Gagal menemukan task melalui ID")
		}
	}
	return
}

// func (s *taskService) Profile(ctx echo.Context, userID uint) (user model.Task, err error) {
// 	user, err = s.opt.Repository.Task.FindByID(ctx, userID)
// 	if err != nil {
// 		s.opt.Logger.With(zap.String("RequestID", util.GetRequestID(ctx))).Error("Failed to get profile", zap.Error(err),
// 			zap.Uint("User ID", userID))
// 		if errors.Is(err, gorm.ErrRecordNotFound) {
// 			err = util.ErrDataNotFound()
// 			return
// 		}
// 		err = util.ErrInternalServerError()
// 		return
// 	}
// 	return
// }

// func (s *taskService) ChangePassword(ctx echo.Context, userID uint, oldPassword string, newPassword string) (err error) {
// 	user, err := s.Profile(ctx, userID)
// 	if err != nil {
// 		return
// 	}

// 	check := util.CheckPasswordHash(oldPassword, user.PasswordHash)
// 	if !check {
// 		err = util.ErrRequestValidation("Password lama tidak valid")
// 		return
// 	}

// 	isNewPasswordValid := util.PasswordValidator2(newPassword, constant.UserMinPasswordLength)
// 	if !isNewPasswordValid {
// 		err = util.ErrRequestValidation("Format password baru tidak sesuai")
// 		return
// 	}

// 	hashPassword, err := util.HashPassword(newPassword)
// 	if err != nil {
// 		s.opt.Logger.With(zap.String("RequestID", util.GetRequestID(ctx))).Error("Failed to hash password",
// 			zap.Error(err),
// 			zap.Uint("User ID", userID))
// 		err = util.ErrUnknownError("Ubah password gagal, silahkan coba lagi")
// 		return
// 	}

// 	dataUpdate := map[string]interface{}{
// 		"password_hash": hashPassword,
// 	}
// 	err = s.opt.Repository.Task.UpdateWithMap(ctx, userID, dataUpdate)
// 	if err != nil {
// 		s.opt.Logger.With(zap.String("RequestID", util.GetRequestID(ctx))).Error("Failed to update user", zap.Error(err), zap.Uint("User ID", userID))
// 		err = util.ErrInternalServerError()
// 		return
// 	}
// 	return
// }

// func (s *taskService) FindUserByID(ctx echo.Context, ID uint) (user model.Task, err error) {
// 	user, err = s.opt.Repository.Task.FindByID(ctx, ID)
// 	if err != nil {
// 		s.opt.Logger.With(zap.String("RequestID", util.GetRequestID(ctx))).Error("Error users by ID",
// 			zap.Uint("User ID", ID),
// 			zap.Error(err),
// 		)
// 		err = util.ErrUnknownError("Gagal menemukan pengguna melalui ID")
// 	}
// 	return
// }

func (s *taskService) Create(ctx echo.Context, req *dto.CreateTaskRequest) (err error) {
	// actx, err := util.NewAppContext(ctx)
	// if err != nil {
	// 	return
	// }

	// userID := actx.GetUserID()
	group := &model.Task{
		Title:       req.Title,
		Description: req.Description,
		Status:      req.Status,
		CreatedBy:   1,
		UpdatedBy:   1,
	}

	err = s.opt.Repository.Task.Create(ctx, group)
	if err != nil {
		s.opt.Logger.With(zap.String("RequestID", util.GetRequestID(ctx))).Error("Error create Task",
			zap.Error(err),
		)
		err = util.ErrUnknownError("Gagal untuk menambahkan Task")
		return
	}
	return
}

// func (s *taskService) uploadimage(ctx context.Context, bucketName, path, base64Image string) (string, error) {
// 	fileName := util.RandomString(20)
// 	if strings.Contains(base64Image, "data:image/png") {
// 		fileName += ".png"
// 	} else if strings.Contains(base64Image, "data:image/jpeg") {
// 		fileName += ".jpeg"
// 	}

// 	// Decode string base64
// 	base64Image = strings.TrimPrefix(base64Image, "data:image/png;base64,")
// 	base64Image = strings.TrimPrefix(base64Image, "data:image/jpeg;base64,")

// 	imgData, err := base64.StdEncoding.DecodeString(base64Image)
// 	if err != nil {
// 		s.opt.Logger.Error("Failed decoding base64 string", zap.Error(err))
// 		return "", err
// 	}

// 	// Tentukan tipe MIME file berdasarkan ekstensi
// 	var contentType string
// 	if strings.HasSuffix(fileName, ".png") {
// 		contentType = "image/png"
// 	} else if strings.HasSuffix(fileName, ".jpg") || strings.HasSuffix(fileName, ".jpeg") {
// 		contentType = "image/jpeg"
// 	} else {
// 		s.opt.Logger.Error("unsupported file format")
// 		return "", fmt.Errorf("unsupported file format")
// 	}

// 	// Set bucket name dan object name
// 	objectName := path + fileName

// 	// Upload file ke MinIO
// 	uploadInfo, err := s.opt.Minio.PutObject(ctx, bucketName, objectName, strings.NewReader(string(imgData)), int64(len(imgData)), minio.PutObjectOptions{
// 		ContentType: contentType,
// 	})

// 	if err != nil {
// 		s.opt.Logger.Error("error uploading file to Minio", zap.Error(err))
// 		return "", err
// 	}

// 	log.Printf("Successfully uploaded %s with size %d. Location: %s\n", uploadInfo.Key, uploadInfo.Size, uploadInfo.Location)
// 	return objectName, nil
// }

// func (s *taskService) createUser(actx echo.Context, user *model.Task, tx *gorm.DB) (err error) {
// 	password := user.PasswordHash
// 	passwordHash, err := util.HashPassword(password)
// 	if err != nil {
// 		s.opt.Logger.With(zap.String("RequestID", util.GetRequestID(actx))).Error("Error create password",
// 			zap.Error(err),
// 		)
// 		err = util.ErrUnknownError("Gagal untuk melakukan encrypt password")
// 		return
// 	}

// 	user.PasswordHash = passwordHash
// 	_, err = s.opt.Repository.Task.CreateUser(actx, user, tx)
// 	if err != nil {
// 		s.opt.Logger.With(zap.String("RequestID", util.GetRequestID(actx))).Error("Error create user",
// 			zap.Error(err),
// 		)
// 		err = util.ErrUnknownError("Gagal untuk menambahkan pengguna")
// 		return
// 	}

// 	_, err = s.opt.Options.Rbac.AddRoleForUser(util.FormatRbacSubject(user.ID), util.FormatRbacRole(user.RoleID))
// 	if err != nil {
// 		s.opt.Logger.With(zap.String("RequestID", util.GetRequestID(actx))).Error("Failed to set role",
// 			zap.Error(err),
// 		)
// 		err = util.ErrUnknownError("Gagal untuk set role")
// 		tx.Rollback()
// 		return
// 	}

// 	return
// }

func (s *taskService) Update(ctx echo.Context, ID primitive.ObjectID, req *dto.UpdateTaskRequest) (err error) {
	_, err = s.opt.Repository.Task.FindByID(ctx, ID)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			err = util.ErrDataNotFound()
		} else {
			err = util.ErrInternalServerError()
		}
		return
	}
	fmt.Println("TEST LOLOs FOUND")
	actx, err := util.NewAppContext(ctx)
	if err != nil {
		return
	}

	userID := actx.GetUserID()
	task := &model.Task{
		Title:       req.Title,
		Description: req.Description,
		Status:      req.Status,
		CreatedBy:   userID,
		UpdatedBy:   userID,
	}
	fmt.Println("TEST LOLOs DEFINE 2")

	err = s.opt.Repository.Task.Update(ctx, task, ID)
	if err != nil {
		s.opt.Logger.With(zap.String("RequestID", util.GetRequestID(actx))).Error("Error create Task",
			zap.Error(err),
		)
		err = util.ErrUnknownError("Gagal untuk menambahkan Task")
		return
	}
	return
}

func (s *taskService) Delete(ctx echo.Context, ID primitive.ObjectID) (err error) {
	actx, err := util.NewAppContext(ctx)
	if err != nil {
		return
	}

	userID := actx.GetUserID()
	_, err = s.opt.Repository.Task.FindByID(actx, ID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			err = util.ErrDataNotFound()
		} else {
			err = util.ErrInternalServerError()
		}
		return
	}

	err = s.opt.Repository.Task.Delete(actx, ID, userID)
	if err != nil {
		s.opt.Logger.With(zap.String("RequestID", util.GetRequestID(actx))).Error("Error delete user ",
			zap.Error(err),
			zap.String("task id", ID.Hex()),
		)
		if errors.Is(err, util.ErrDataRelatedToOtherData()) {
			err = util.ErrRequestValidation(err.Error())
		} else {
			err = util.ErrUnknownError("Gagal menghapus user")
		}
	}
	return
}
