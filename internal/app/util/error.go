package util

import (
	"fmt"
	"go-tech/internal/app/constant"
	"net/http"

	"github.com/joomcode/errorx"
)

var (
	ErrLoginDefault = func() error {
		return ErrorCreationWithTitle("Gagal Masuk!", "Username atau kata sandi salah", "01", http.StatusBadRequest, errorData{
			PrimaryText: "OK",
			Icon:        constant.ErrIconURL,
		})
	}
	ErrLogoutDefault = func() error {
		return ErrorCreationWithTitle("Gagal", "Gagal keluar, silahkan coba lagi nanti", "02", http.StatusInternalServerError, errorData{
			PrimaryText: "OK",
			Icon:        constant.ErrIconURL,
		})
	}
	ErrInternalServerError = func() error {
		return ErrorCreationWithTitle("Gagal", "Kegagalan sistem, silahkan coba lagi nanti", "03", http.StatusInternalServerError, errorData{
			PrimaryText: "OK",
			Icon:        constant.ErrIconURL,
		})
	}
	ErrBindRequest = func() error {
		return ErrorCreationWithTitle("Gagal", "Gagal menautkan permintaan", "04", http.StatusBadRequest, errorData{
			PrimaryText: "OK",
			Icon:        constant.ErrIconURL,
		})
	}
	ErrRequestValidation = func(message string) error {
		return ErrorCreationWithTitle("Gagal", message, "05", http.StatusBadRequest, errorData{
			PrimaryText: "OK",
			Icon:        constant.ErrIconURL,
		})
	}
	ErrDataNotFound = func() error {
		return ErrorCreationWithTitle("Gagal", "Data tidak ditemukan", "06", http.StatusNotFound, errorData{
			PrimaryText: "OK",
			Icon:        constant.ErrIconURL,
		})
	}
	ErrAccountDoesntExist = func() error {
		return ErrorCreationWithTitle("Fail", "Account doesn't exist.", "06", http.StatusNotFound, errorData{
			PrimaryText: "OK",
			Icon:        constant.ErrIconURL,
		})
	}
	ErrUnauthorized = func() error {
		return ErrorCreationWithTitle("Gagal", "Tidak dikenal: akses ditolak karena credential tidak valid", "07", http.StatusUnauthorized, errorData{
			PrimaryText: "OK",
			Icon:        constant.ErrIconURL,
		})
	}
	ErrFailedToCreateResetPassword = func() error {
		return ErrorCreationWithTitle("Fail", "Failed to create reset password.", "08", http.StatusInternalServerError, errorData{
			PrimaryText: "OK",
			Icon:        constant.ErrIconURL,
		})
	}
	ErrTokenExpired = func() error {
		return ErrorCreationWithTitle("Expired", "Reset password token has expired.", "09", http.StatusUnauthorized, errorData{
			PrimaryText: "Token expired",
			Icon:        constant.ErrIconURL,
		})
	}
	ErrFailedFetchData = func() error {
		return ErrorCreationWithTitle("Gagal", "Gagal menarik data", "11", http.StatusInternalServerError, errorData{
			PrimaryText: "OK",
			Icon:        constant.ErrIconURL,
		})
	}
	ErrFailedGetDataCount = func() error {
		return ErrorCreationWithTitle("Gagal", "Gagal mendapatkan perhitungan data", "12", http.StatusInternalServerError, errorData{
			PrimaryText: "OK",
			Icon:        constant.ErrIconURL,
		})
	}

	ErrUserDontHavePermission = func() error {
		return ErrorCreationWithTitle("Gagal", "Akun anda tidak memiliki akses ke resource ini", "19", http.StatusForbidden, errorData{
			PrimaryText: "OK",
			Icon:        constant.ErrIconURL,
		})
	}
	ErrDataRelatedToOtherData = func() error {
		return ErrorCreationWithTitle("Gagal", "Data tidak dapat dihapus karena terkait dengan data lainnya", "20", http.StatusUnprocessableEntity, errorData{
			PrimaryText: "OK",
			Icon:        constant.ErrIconURL,
		})
	}

	//Kesalahan tidak diketahui
	ErrUnknownError = func(message string) error {
		return ErrorCreationWithTitle("Gagal", fmt.Sprintf("Kesalahan tidak diketahui : %s", message), "99", http.StatusInternalServerError, errorData{
			PrimaryText: "OK",
			Icon:        constant.ErrIconURL,
		})
	}
)

type ErrorDescription struct {
	Code        string
	HttpCode    int
	Title       string
	Message     string
	FullMessage string
	Source      string
	ErrorData   errorData
}

type errorData struct {
	Icon          string
	PrimaryText   string
	SecondaryText string
	PrimaryLink   string
	SecondaryLink string
	DismissedLink string
}

var (
	ErrNamespace        = errorx.NewNamespace("go-tech")
	ErrBase             = errorx.NewType(ErrNamespace, "base")
	ErrCodeProperty     = errorx.RegisterProperty("code")
	ErrHttpCodeProperty = errorx.RegisterProperty("httpcode")
	ErrSourceProperty   = errorx.RegisterProperty("source")
	ErrTitle            = errorx.RegisterProperty("title")
	ErrMessage          = errorx.RegisterProperty("message")
	ErrData             = errorx.RegisterProperty("error_data")
)

func ErrorCreation(message string, errCodeProperty string, errHttpCodeProperty int, errData errorData) error {
	return ErrBase.New(message).
		WithProperty(ErrCodeProperty, errCodeProperty).
		WithProperty(ErrHttpCodeProperty, errHttpCodeProperty).
		WithProperty(ErrData, errData)
}

func ErrorCreationWithTitle(title, message, errCodeProperty string, errHttpCodeProperty int, errData errorData) error {
	return ErrBase.New(message).
		WithProperty(ErrTitle, title).
		WithProperty(ErrCodeProperty, errCodeProperty).
		WithProperty(ErrHttpCodeProperty, errHttpCodeProperty).
		WithProperty(ErrData, errData)
}

func ExtractError(err error) ErrorDescription {
	var (
		e, ok = err.(*errorx.Error)
	)

	if ok {
		if ErrNamespace.IsNamespaceOf(e.Type()) {
			code, source, httpcode := "0", "internal", 0
			c, ok := errorx.ExtractProperty(e, ErrCodeProperty)

			if ok {
				code = c.(string)
			} else {
				code = "99"
			}

			hc, ok := errorx.ExtractProperty(e, ErrHttpCodeProperty)

			if ok {
				httpcode = hc.(int)
			} else {
				httpcode = http.StatusInternalServerError
			}

			s, ok := errorx.ExtractProperty(e, ErrSourceProperty)

			if ok {
				source = s.(string)
			}

			var title string
			if s, ok := errorx.ExtractProperty(e, ErrTitle); ok && s != nil {
				title = s.(string)
			}

			var errData errorData
			if s, ok := errorx.ExtractProperty(e, ErrData); ok && s != nil {
				errData = s.(errorData)
			}

			return ErrorDescription{
				Code:        code,
				HttpCode:    httpcode,
				Title:       title,
				Message:     e.Message(),
				FullMessage: e.Error(),
				Source:      source,
				ErrorData:   errData,
			}
		}
	}

	return ErrorDescription{
		Code:        "99",
		HttpCode:    http.StatusInternalServerError,
		Message:     "internal server error",
		FullMessage: err.Error(),
		Source:      "internal",
		ErrorData: errorData{
			PrimaryText: "OK",
			Icon:        constant.ErrIconURL,
		},
	}
}
