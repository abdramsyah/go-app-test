package dto

import (
	"time"

	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/go-ozzo/ozzo-validation/v4/is"
)

type UserProfileResponse struct {
	ID          uint       `json:"id"`
	Email       string     `json:"email"`
	Name        string     `json:"name"`
	Username    string     `json:"username"`
	PhoneNumber string     `json:"phone_number"`
	Role        RoleEmbed  `json:"role"`
	PathImage   string     `json:"path_image"`
	CreatedBy   uint       `json:"created_by"`
	UpdatedBy   uint       `json:"updated_by"`
	DeletedBy   *uint      `json:"deleted_by,omitempty"`
	CreatedAt   string     `json:"created_at"`
	UpdatedAt   string     `json:"updated_at"`
	DeletedAt   *time.Time `json:"deleted_at,omitempty"`
}

type ListUserResponse struct {
	ID        uint       `json:"id"`
	Email     string     `json:"email"`
	Name      string     `json:"name"`
	Role      RoleEmbed  `json:"role"`
	PathImage string     `json:"path_image"`
	CreatedBy uint       `json:"created_by"`
	UpdatedBy uint       `json:"updated_by"`
	DeletedBy *uint      `json:"deleted_by,omitempty"`
	CreatedAt string     `json:"created_at"`
	UpdatedAt string     `json:"updated_at"`
	DeletedAt *time.Time `json:"deleted_at,omitempty"`
}

type UserFilter struct {
	Search *string `query:"search"`
}

type CreateUserRequest struct {
	Email           string `json:"email"`
	Name            string `json:"name"`
	Username        string `json:"username"`
	PhoneNumber     string `json:"phone_number"`
	RoleID          uint   `json:"role_id"`
	Password        string `json:"password"`
	ConfirmPassword string `json:"confirm_password"`
	ProfileImage    string `json:"image,omitempty"`
}

func (r CreateUserRequest) Validate() error {
	validation.ErrorTag = "tag"
	return validation.ValidateStruct(&r,
		validation.Field(&r.Email,
			validation.Required, validation.Length(5, 100), is.Email),
		validation.Field(&r.Name,
			validation.Required, validation.Length(1, 100)),
		validation.Field(&r.Username,
			validation.Required, validation.Length(3, 50)),
		validation.Field(&r.PhoneNumber,
			validation.Required, validation.Length(10, 15)),
		validation.Field(&r.Password,
			validation.Required, validation.Length(8, 50)),
		validation.Field(&r.ConfirmPassword,
			validation.Required, validation.Length(8, 50)),
	)
}

type UpdateUserRequest struct {
	Email           string `json:"email"`
	Name            string `json:"name"`
	Username        string `json:"username"`
	PhoneNumber     string `json:"phone_number"`
	RoleID          int    `json:"role_id"`
	Password        string `json:"password"`
	ConfirmPassword string `json:"confirm_password"`
	ProfileImage    string `json:"image,omitempty"`
}

func (r UpdateUserRequest) Validate() error {
	validation.ErrorTag = "tag"
	return validation.ValidateStruct(&r,
		validation.Field(&r.Email,
			validation.Required, validation.Length(5, 100), is.Email),
		validation.Field(&r.Name,
			validation.Required, validation.Length(1, 100)),
		validation.Field(&r.Username,
			validation.Required, validation.Length(3, 50)),
		validation.Field(&r.PhoneNumber,
			validation.Required, validation.Length(10, 15)),
	)
}
