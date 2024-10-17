package dto

import "time"

type AuditTrailRequest struct {
	RouteName string
	UserID    uint
	URL       string
}

type AuditTrailFilter struct {
	UserEmail *string
	Action    *string
	StartDate *time.Time
	EndDate   *time.Time
}

type BORoutesResponse struct {
	Method string `json:"method"`
	Path   string `json:"path"`
	Name   string `json:"name"`
}

type AuditTrailResponse struct {
	ID        int64  `json:"id"`
	UserID    int64  `json:"user_id"`
	UserEmail string `json:"user_email"`
	UserName  string `json:"user_name"`
	UserRole  string `json:"user_role"`
	Action    string `json:"action"`
	URL       string `json:"url"`
	CreatedAt string `json:"created_at"`
	RequestID string `json:"request_id"`
}
