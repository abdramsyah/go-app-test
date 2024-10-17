package util

import (
	"github.com/labstack/echo/v4"
	"github.com/twinj/uuid"
)

type AppContext struct {
	echo.Context
	userID     *uint
	accessUUID *string
	roleType   *string
}

func (c *AppContext) GetRequestID() string {
	requestID := c.Response().Header().Get(echo.HeaderXRequestID)
	if requestID == "" {
		return uuid.NewV4().String()
	}
	return requestID
}

func (c *AppContext) SetUserID(userID uint) {
	c.userID = &userID
}

func (c *AppContext) SetAccessUUID(accessUUID string) {
	c.accessUUID = &accessUUID
}

func (c *AppContext) SetRoleType(roleType string) {
	c.roleType = &roleType
}

func (c *AppContext) GetUserID() uint {
	return *c.userID
}

func (c *AppContext) GetAccessUUID() string {
	return *c.accessUUID
}

func (c *AppContext) GetRoleType() string {
	return *c.roleType
}

func NewEmptyAppContext(parent echo.Context) *AppContext {
	return &AppContext{parent, nil, nil, nil}
}

func NewAppContext(parent echo.Context) (*AppContext, error) {
	pctx, ok := parent.(*AppContext)
	if !ok {
		return nil, ErrUnauthorized()
	}
	if pctx.userID == nil || pctx.accessUUID == nil {
		return nil, ErrUnauthorized()
	}
	return pctx, nil
}
