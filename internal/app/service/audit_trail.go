package service

import (
	"errors"
	"go-tech/internal/app/commons"
	"go-tech/internal/app/constant"
	"go-tech/internal/app/dto"
	"go-tech/internal/app/model"
	"go-tech/internal/app/util"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/guregu/null"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
)

type IAuditTrailService interface {
	Create(ctx echo.Context, req *dto.AuditTrailRequest) (err error)
	FindRoutes(ctx echo.Context) (routes []dto.BORoutesResponse)
	Find(ctx echo.Context, pConfig commons.PaginationConfig, filter *dto.AuditTrailFilter) (list []model.AuditTrails, count int64, httpStatus int, err error)
}

type auditTrailService struct {
	opt Option
}

func NewAuditTrailService(opt Option) IAuditTrailService {
	return &auditTrailService{
		opt: opt,
	}
}

func (s *auditTrailService) Create(ctx echo.Context, req *dto.AuditTrailRequest) (err error) {
	user, err := s.opt.Repository.User.FindByID(ctx, req.UserID)
	if err != nil {
		s.opt.Logger.With(zap.String("RequestID", util.GetRequestID(ctx))).Error("Error get user by ID",
			zap.Error(err),
		)
		return
	}

	data := model.AuditTrails{
		UserID:    req.UserID,
		UserEmail: user.Email,
		UserName:  user.Name,
		// UserRole:  user.Role.Name,
		Action:    req.RouteName,
		URL:       req.URL,
		CreatedAt: time.Now(),
		RequestID: null.NewString(util.GetRequestID(ctx), true),
	}

	err = s.opt.Repository.AuditTrail.Create(ctx, &data)
	if err != nil {
		s.opt.Logger.With(zap.String("RequestID", util.GetRequestID(ctx))).Error("Error save audit trail",
			zap.Error(err),
		)
	}
	return
}

func (s *auditTrailService) FindRoutes(ctx echo.Context) (routes []dto.BORoutesResponse) {
	allRoutes := ctx.Echo().Routes()
	for _, r := range allRoutes {
		if strings.Contains(r.Name, "github.com/") || strings.Contains(r.Path, "/mobile/") || strings.Contains(r.Path, "go-tech/") {
			continue
		}
		routes = append(routes, dto.BORoutesResponse{
			Name:   r.Name,
			Path:   r.Path,
			Method: r.Method,
		})
	}
	return
}

func (s *auditTrailService) Find(ctx echo.Context, pConfig commons.PaginationConfig, filter *dto.AuditTrailFilter) (list []model.AuditTrails, count int64, httpStatus int, err error) {
	var waitGroup sync.WaitGroup
	c := make(chan error)

	waitGroup.Add(2)

	go func() {
		waitGroup.Wait()
		close(c)
	}()

	go func() {
		defer waitGroup.Done()

		count, err = s.opt.Repository.AuditTrail.Count(ctx, filter)
		if err != nil {
			s.opt.Logger.With(zap.String("RequestID", util.GetRequestID(ctx))).Error("Get Audit Trail Count",
				zap.Error(err),
			)
			err = errors.New(constant.ErrFailedGetDataCount)
			c <- err
		}
	}()

	go func() {
		defer waitGroup.Done()

		list, err = s.opt.Repository.AuditTrail.Find(ctx, pConfig, filter)
		if err != nil {
			s.opt.Logger.With(zap.String("RequestID", util.GetRequestID(ctx))).Error("Get Audit Trail",
				zap.Error(err),
			)
			err = errors.New(constant.ErrFailedFetchData)
			c <- err
		}
	}()

	for errChan := range c {
		if errChan != nil {
			err = errChan
			httpStatus = http.StatusInternalServerError
			return
		}
	}

	return
}
