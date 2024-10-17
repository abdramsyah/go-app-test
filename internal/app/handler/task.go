package handler

import (
	"go-tech/internal/app/commons"
	"go-tech/internal/app/dto"
	"go-tech/internal/app/util"
	"net/http"

	"github.com/labstack/echo/v4"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.uber.org/zap"
)

type TaskHandler struct {
	HandlerOption
}

// func (h TaskHandler) GetPermission(c echo.Context) (resp dto.HttpResponse) {
// 	actx, err := util.NewAppContext(c)
// 	if err != nil {
// 		return
// 	}
// 	userID := actx.GetUserID()
// 	res, err := h.Services.Task.GetPermissions(actx, userID)
// 	if err != nil {
// 		resp = dto.FailedHttpResponse(err, nil)
// 		return
// 	}

// 	resp = dto.SuccessHttpResponse(http.StatusOK, "", "Berhasil mendapatkan akses pengguna", res)
// 	return
// }

func (h TaskHandler) RetrievedList(c echo.Context) (resp dto.HttpResponse) {
	pConfig := util.GeneratePaginateConfig(c)
	filter := new(dto.TaskFilter)

	if err := c.Bind(filter); err != nil {
		resp = dto.FailedHttpResponse(err, nil)
		return
	}

	task, count, err := h.Services.Task.Find(c, pConfig, filter)
	if err != nil {
		resp = dto.FailedHttpResponse(err, nil)
		return
	}

	respData := []dto.TaskResponse{}
	res := commons.PaginateResponse{
		List:  respData,
		Count: count,
	}
	if count == 0 {
		resp = dto.SuccessHttpResponse(http.StatusOK, "", "Berhasil mendapatkan semua task", res)
		return
	}

	for _, data := range task {
		user := dto.TaskResponse{
			ID:          data.ID,
			Title:       data.Title,
			Description: data.Description,
			Status:      data.Status,
			CreatedAt:   data.CreatedAt,
			UpdatedAt:   data.UpdatedAt,
		}
		respData = append(respData, user)
	}

	res.List = respData
	resp = dto.SuccessHttpResponse(http.StatusOK, "", "Berhasil mendapatkan users", res)
	return
}

func (h TaskHandler) FindByID(c echo.Context) (resp dto.HttpResponse) {
	ID := c.Param("ID")
	if ID == "" {
		resp = dto.FailedHttpResponse(util.ErrRequestValidation("ID Task tidak valid"), nil)
		return
	}

	objectID, err := primitive.ObjectIDFromHex(ID)
	if err != nil {
		resp = dto.FailedHttpResponse(util.ErrRequestValidation("ID Task tidak valid"), nil)
		return
	}

	data, err := h.Services.Task.FindByID(c, objectID)
	if err != nil {
		resp = dto.FailedHttpResponse(err, nil)
		return
	}

	result := dto.TaskResponse{
		ID:          data.ID,
		Title:       data.Title,
		Description: data.Description,
		Status:      data.Status,
		CreatedAt:   data.CreatedAt,
		UpdatedAt:   data.UpdatedAt,
	}

	resp = dto.SuccessHttpResponse(http.StatusOK, "", "Berhasil mendapatkan detail Task", result)
	return
}

func (h TaskHandler) Create(c echo.Context) (resp dto.HttpResponse) {
	var err error
	req := new(dto.CreateTaskRequest)
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

	err = h.Services.Task.Create(c, req)
	if err != nil {
		resp = dto.FailedHttpResponse(err, nil)
		return
	}

	resp = dto.SuccessHttpResponse(http.StatusCreated, "", "Berhasil membuat task", nil)
	return
}

func (h TaskHandler) Update(c echo.Context) (resp dto.HttpResponse) {
	actx, err := util.NewAppContext(c)
	if err != nil {
		return
	}
	req := new(dto.UpdateTaskRequest)
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
		resp = dto.FailedHttpResponse(util.ErrRequestValidation("ID Task tidak valid"), nil)
		return
	}

	objectID, err := primitive.ObjectIDFromHex(ID)
	if err != nil {
		resp = dto.FailedHttpResponse(util.ErrRequestValidation("ID Task tidak valid"), nil)
		return
	}

	err = h.Services.Task.Update(c, objectID, req)
	if err != nil {
		resp = dto.FailedHttpResponse(err, nil)
		return
	}

	resp = dto.SuccessHttpResponse(http.StatusCreated, "", "Berhasil memperbaharui Task", nil)
	return
}

func (h TaskHandler) Delete(c echo.Context) (resp dto.HttpResponse) {
	ID := c.Param("ID")
	if ID == "" {
		resp = dto.FailedHttpResponse(util.ErrRequestValidation("ID Task tidak valid"), nil)
		return
	}

	objectID, err := primitive.ObjectIDFromHex(ID)
	if err != nil {
		resp = dto.FailedHttpResponse(util.ErrRequestValidation("ID Task tidak valid"), nil)
		return
	}

	err = h.Services.Task.Delete(c, objectID)
	if err != nil {
		resp = dto.FailedHttpResponse(err, nil)
		return
	}

	resp = dto.SuccessHttpResponse(http.StatusOK, "", "Berhasil menghapus Task", nil)
	return
}
