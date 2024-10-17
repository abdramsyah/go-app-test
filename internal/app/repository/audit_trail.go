package repository

import (
	"go-tech/internal/app/commons"
	"go-tech/internal/app/constant"
	"go-tech/internal/app/dto"
	"go-tech/internal/app/model"
	"go-tech/internal/app/util"

	"github.com/labstack/echo/v4"
	"gorm.io/gorm"
)

type IAuditTrailRepository interface {
	Create(ctx echo.Context, data *model.AuditTrails) (err error)
	Count(ctx echo.Context, filter *dto.AuditTrailFilter) (count int64, err error)
	Find(ctx echo.Context, pConfig commons.PaginationConfig, filter *dto.AuditTrailFilter) (list []model.AuditTrails, err error)
}

type auditTrailRepository struct {
	opt Option
}

func NewAuditTrailRepository(opt Option) IAuditTrailRepository {
	return &auditTrailRepository{
		opt: opt,
	}
}

func (r *auditTrailRepository) Create(ctx echo.Context, data *model.AuditTrails) (err error) {
	err = r.opt.DB.Create(data).Error
	return
}

func (r *auditTrailRepository) generateCondition(db *gorm.DB, filter *dto.AuditTrailFilter) *gorm.DB {
	if filter.UserEmail != nil {
		db = db.Where("LOWER(admin_email) like LOWER(?)", *filter.UserEmail+"%")
	}
	if filter.Action != nil {
		db = db.Where("action = ?", *filter.Action)
	}
	if filter.StartDate != nil {
		start := *filter.StartDate
		db = db.Where("created_at >= ?", start.Format(constant.DbDateFormat)+" 00:00:00")
	}
	if filter.EndDate != nil {
		end := *filter.EndDate
		db = db.Where("created_at <= ?", end.Format(constant.DbDateFormat)+" 23:59:59")
	}

	return db
}

func (r *auditTrailRepository) Count(ctx echo.Context, filter *dto.AuditTrailFilter) (count int64, err error) {
	db := r.opt.DB
	db = r.generateCondition(db, filter)
	err = db.Model(&model.AuditTrails{}).Count(&count).Error
	return
}

func (r *auditTrailRepository) Find(ctx echo.Context, pConfig commons.PaginationConfig, filter *dto.AuditTrailFilter) (list []model.AuditTrails, err error) {
	db := r.opt.DB
	db = r.generateCondition(db, filter)
	err = db.Scopes(util.Paginate(pConfig)).Order("id DESC").Find(&list).Error
	return
}
