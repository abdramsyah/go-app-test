package util

import (
	"go-tech/internal/app/commons"
	"strconv"

	"github.com/labstack/echo/v4"
	"gorm.io/gorm"
)

func convertPaginateQueryParam(pageParam string, pageSizeParam string) (page int, pageSize int) {
	page, err := strconv.Atoi(pageParam)
	if page == 0 || err != nil {
		page = 1
	}

	pageSize, err = strconv.Atoi(pageSizeParam)
	switch {
	case pageSize > 100:
		pageSize = 100
	case pageSize <= 0:
		pageSize = 10
	case err != nil:
		pageSize = 10
	}

	return
}

func GeneratePaginateConfig(c echo.Context) (pConfig commons.PaginationConfig) {
	page, pageSize := convertPaginateQueryParam(c.QueryParam("page"), c.QueryParam("page_size"))
	pConfig = paginateConfig(page, pageSize)

	return
}

func GeneratePaginateConfigWithoutConversion(page int, pageSize int) (pConfig commons.PaginationConfig) {
	pConfig = paginateConfig(page, pageSize)

	return
}

func GenerateMobilePaginateConfig(c echo.Context) (pConfig commons.PaginationConfig) {
	page, pageSize := convertPaginateQueryParam(c.QueryParam("pageNumber"), c.QueryParam("pageSize"))
	pConfig = paginateConfig(page, pageSize)

	return
}

func paginateConfig(page int, pageSize int) (pConfig commons.PaginationConfig) {
	offset := (page - 1) * pageSize
	pConfig.Offset = offset
	pConfig.PageSize = pageSize

	return
}

func Paginate(pConfig commons.PaginationConfig) func(db *gorm.DB) *gorm.DB {
	return func(db *gorm.DB) *gorm.DB {
		return db.Offset(pConfig.Offset).Limit(pConfig.PageSize)
	}
}
