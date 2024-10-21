package dto

import (
	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/go-ozzo/ozzo-validation/v4/is"
)

type RegisterRequest struct {
	Name        string `json:"name" tag:"Name"`
	Email       string `json:"email" tag:"email"`
	PhoneNumber string `json:"phone_number" tag:"phone_number"`
	Password    string `json:"password" tag:"password"`
	RoleID      uint   `json:"role_id" tag:"role_id"`
}

// Validate adalah metode untuk memvalidasi RegisterRequest
func (r RegisterRequest) Validate() error {
	validation.ErrorTag = "tag"
	return validation.ValidateStruct(&r,
		validation.Field(&r.Name,
			validation.Required.Error("Full name is required"),
			validation.Length(1, 100).Error("Full name must be between 1 and 100 characters")),
		validation.Field(&r.Email,
			validation.Required.Error("Email is required")),
		validation.Field(&r.PhoneNumber, validation.Required, validation.Length(0, 15), is.Digit),
		validation.Field(&r.Password, validation.Required, validation.Length(0, 100)),
		validation.Field(&r.RoleID,
			validation.Required),
	)
}

type RegisterStudentRequest struct {
	Name        string `json:"name" tag:"Name"`
	Email       string `json:"email" tag:"email"`
	RoleID      uint   `json:"role_id" tag:"role_id"`
	PhoneNumber string `json:"phone_number" tag:"phone_number"`
	Password    string `json:"password" tag:"password"`
}

func (r RegisterStudentRequest) Validate() error {
	validation.ErrorTag = "tag"
	return validation.ValidateStruct(&r,
		validation.Field(&r.Name,
			validation.Required.Error("Full name is required"),
			validation.Length(1, 100).Error("Full name must be between 1 and 100 characters")),
		validation.Field(&r.Email,
			validation.Required.Error("Email is required"),
			is.Email.Error("Invalid email format")),
		validation.Field(&r.PhoneNumber,
			validation.Required.Error("Phone number is required"),
			validation.Length(0, 15).Error("Phone number must be between 0 and 15 characters"),
			is.Digit.Error("Phone number must contain only digits")),
		validation.Field(&r.Password,
			validation.Required.Error("Password is required"),
			validation.Length(0, 100).Error("Password must be between 0 and 100 characters")),
		validation.Field(&r.RoleID,
			validation.Required.Error("Role ID is required")),
	)
}

type RegisterResponse struct {
	ID      string `json:"id"`
	Message string `json:"message"`
}

type LoginRequest struct {
	Email    string `json:"email" tag:"Email"`
	Password string `json:"password" tag:"Password"`
}

func (r LoginRequest) Validate() error {
	validation.ErrorTag = "tag"
	return validation.ValidateStruct(&r,
		validation.Field(&r.Email,
			validation.Required,
			is.Email),
		validation.Field(&r.Password,
			validation.Required),
	)
}

type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token" tag:"Refresh Token"`
}

func (r RefreshTokenRequest) Validate() error {
	validation.ErrorTag = "tag"
	return validation.ValidateStruct(&r,
		validation.Field(&r.RefreshToken,
			validation.Required),
	)
}

type ForgotPasswordRequest struct {
	Email string `json:"email" tag:"Email"`
}

func (r ForgotPasswordRequest) Validate() error {
	validation.ErrorTag = "tag"
	return validation.ValidateStruct(&r,
		validation.Field(&r.Email,
			validation.Required.Error("Please enter your email address."),
			is.Email.Error("Please enter the correct email format."),
		),
	)
}

type VerifyResetPasswordRequest struct {
	Token string `json:"token" tag:"Token"`
}

func (r VerifyResetPasswordRequest) Validate() error {
	validation.ErrorTag = "tag"
	return validation.ValidateStruct(&r,
		validation.Field(&r.Token,
			validation.Required.Error("Please enter your reset password token."),
		),
	)
}

type ChangePasswordRequest struct {
	Token    string `json:"token" tag:"Token"`
	Password string `json:"password" tag:"Password"`
}

func (r ChangePasswordRequest) Validate() error {
	validation.ErrorTag = "tag"
	return validation.ValidateStruct(&r,
		validation.Field(&r.Token,
			validation.Required.Error("Please enter your reset password token."),
		),
		validation.Field(&r.Password,
			validation.Required.Error("Please enter your new password."),
		),
	)
}

type JwtToken struct {
	AccessToken         string `json:"accessToken"`
	AccessTokenExpires  int64  `json:"accessTokenExpires"`
	RefreshToken        string `json:"refreshToken"`
	RefreshTokenExpires int64  `json:"refreshTokenExpires"`
}

type TokenValidationResult struct {
	UserID     uint
	AccessUUID string
	RoleType   string
}
