package dto

import (
	"go-tech/internal/app/constant"
	"go-tech/internal/app/util"
)

type (
	HttpResponse struct {
		ProcessTime string      `json:"process_time"`
		Status      string      `json:"status"`
		Code        string      `json:"code"`
		Message     string      `json:"message"`
		Data        interface{} `json:"data,omitempty"`
		ErrorData   *ErrorData  `json:"error_data,omitempty"`
		HttpStatus  int         `json:"-"`
	}

	ErrorData struct {
		Title         string `json:"title"`
		Description   string `json:"description"`
		Icon          string `json:"icon"`
		PrimaryText   string `json:"primary_text"`
		SecondaryText string `json:"secondary_text"`
		PrimaryLink   string `json:"primary_link"`
		SecondaryLink string `json:"secondary_link"`
		DismissedLink string `json:"dismissed_link"`
	}
)

func SuccessHttpResponse(httpStatus int, code, message string, data interface{}) HttpResponse {
	return HttpResponse{
		Status:     constant.RespSuccessStatus,
		Code:       code,
		Message:    message,
		Data:       data,
		HttpStatus: httpStatus,
	}
}

func FailedHttpResponse(err error, data interface{}) HttpResponse {
	var (
		ed = util.ExtractError(err)
	)
	return HttpResponse{
		Status:     constant.RespFailedStatus,
		Code:       ed.Code,
		Message:    ed.Message,
		Data:       data,
		HttpStatus: ed.HttpCode,
		ErrorData: &ErrorData{
			Title:         ed.Title,
			Description:   ed.Message,
			Icon:          ed.ErrorData.Icon,
			PrimaryText:   ed.ErrorData.PrimaryText,
			SecondaryText: ed.ErrorData.SecondaryText,
			PrimaryLink:   ed.ErrorData.PrimaryLink,
			SecondaryLink: ed.ErrorData.SecondaryLink,
			DismissedLink: ed.ErrorData.DismissedLink,
		},
	}
}
