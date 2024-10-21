package service

import (
	"encoding/json"
	"errors"
	"fmt"
	"go-tech/internal/app/commons"
	"go-tech/internal/app/constant"
	"go-tech/internal/app/dto"
	"go-tech/internal/app/model"
	"go-tech/internal/app/pkg/email"
	"go-tech/internal/app/util"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/guregu/null"
	"github.com/labstack/echo/v4"
	"github.com/spf13/cast"
	"github.com/twinj/uuid"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

type IAuthService interface {
	Register(ctx echo.Context, req *dto.RegisterRequest) (err error)
	Login(ctx echo.Context, req *dto.LoginRequest) (jwtToken dto.JwtToken, err error)
	Logout(ctx echo.Context, userID uint, accessUUID string) (err error)
	RefreshToken(ctx echo.Context, refreshToken string) (jwtToken dto.JwtToken, err error)
	ForgotPassword(ctx echo.Context, req *dto.ForgotPasswordRequest) (err error)
	ValidateToken(ctx echo.Context, r *http.Request) (result dto.TokenValidationResult, err error)
	VerifyResetToken(ctx echo.Context, req *dto.VerifyResetPasswordRequest) (err error)
	ResetPassword(ctx echo.Context, req *dto.ChangePasswordRequest) (err error)
	PermissionCheck(ctx echo.Context, object string, action string) (isPermitted bool, err error)
	BatchPermissionCheck(ctx echo.Context, request [][]interface{}) (isPermitted bool, err error)
}

type authService struct {
	opt Option
}

func NewAuthService(opt Option) IAuthService {
	return &authService{
		opt: opt,
	}
}

func (s *authService) createJwtToken(userID uint, roleType string) (td *commons.TokenDetails, err error) {
	td = &commons.TokenDetails{}
	accessExpired := cast.ToDuration(s.opt.Config.JwtAccessTtl)
	refreshExpired := cast.ToDuration(s.opt.Config.JwtRefreshTtl)
	td.AtExpires = time.Now().Add(accessExpired).Unix()
	td.AccessUuid = uuid.NewV4().String()

	td.RtExpires = time.Now().Add(refreshExpired).Unix()
	td.RefreshUuid = td.AccessUuid + "++" + strconv.Itoa(int(userID))

	accessSecret := s.opt.Config.JwtAccessSecret
	atClaims := jwt.MapClaims{}
	atClaims["authorized"] = true
	atClaims["access_uuid"] = td.AccessUuid
	atClaims["user_id"] = userID
	atClaims["role_type"] = roleType
	atClaims["exp"] = td.AtExpires
	at := jwt.NewWithClaims(jwt.SigningMethodHS256, atClaims)
	td.AccessToken, err = at.SignedString([]byte(accessSecret))
	if err != nil {
		return
	}
	err = s.storeToRedis(constant.TokenAccessType, td.AccessUuid, userID, accessExpired)
	if err != nil {
		return
	}

	refreshSecret := s.opt.Config.JwtRefreshSecret
	rtClaims := jwt.MapClaims{}
	rtClaims["refresh_uuid"] = td.RefreshUuid
	rtClaims["user_id"] = userID
	rtClaims["role_type"] = roleType
	rtClaims["exp"] = td.RtExpires
	rt := jwt.NewWithClaims(jwt.SigningMethodHS256, rtClaims)
	td.RefreshToken, err = rt.SignedString([]byte(refreshSecret))
	if err != nil {
		return
	}

	err = s.storeToRedis(constant.TokenRefreshType, td.RefreshUuid, userID, refreshExpired)

	return
}

func (s *authService) createJwtTokenForResetPassword(userID uint, Email string) (td *commons.TokenDetails, err error) {
	td = &commons.TokenDetails{}
	accessExpired := cast.ToDuration(s.opt.Config.JwtAccessTtl)
	refreshExpired := cast.ToDuration(s.opt.Config.JwtRefreshTtl)
	td.AtExpires = time.Now().Add(accessExpired).Unix()
	td.AccessUuid = uuid.NewV4().String()

	td.RtExpires = time.Now().Add(refreshExpired).Unix()
	td.RefreshUuid = td.AccessUuid + "++" + strconv.Itoa(int(userID))

	accessSecret := s.opt.Config.JwtAccessSecret
	atClaims := jwt.MapClaims{}
	atClaims["authorized"] = true
	atClaims["access_uuid"] = td.AccessUuid
	atClaims["user_id"] = userID
	atClaims["email"] = Email
	atClaims["exp"] = td.AtExpires
	at := jwt.NewWithClaims(jwt.SigningMethodHS256, atClaims)
	td.AccessToken, err = at.SignedString([]byte(accessSecret))
	if err != nil {
		return
	}
	// err = s.storeToRedis(constant.TokenAccessType, td.AccessUuid, userID, accessExpired)
	// if err != nil {
	// 	return
	// }

	return
}

func (s *authService) storeToRedis(tokenType string, uuid string, userID uint, duration time.Duration) (err error) {
	val := commons.AuthCacheValue{
		UserID: userID,
	}
	b, err := json.Marshal(val)
	if err != nil {
		s.opt.Logger.Error("failed to marshal data", zap.Error(err))
		return
	}
	err = s.opt.Cache.WriteCache(fmt.Sprintf("%s:%s", util.CacheKeyFormatter("jwt"), uuid), b, duration)
	if err != nil {
		s.opt.Logger.Error("failed to marshal data", zap.Error(err))
		return
	}
	valUUID := commons.AuthUUIDCacheValue{
		UUID: uuid,
	}
	b, err = json.Marshal(valUUID)
	if err != nil {
		s.opt.Logger.Error("failed to marshal data", zap.Error(err))
		return
	}
	err = s.opt.Cache.WriteCache(fmt.Sprintf("%s:%s:%d", util.CacheKeyFormatter("uuid"), tokenType, userID), b, duration)
	if err != nil {
		s.opt.Logger.Error("failed to marshal data", zap.Error(err))
		return
	}
	return
}

func (s *authService) Register(ctx echo.Context, req *dto.RegisterRequest) (err error) {
	_, err = s.opt.Repository.User.FindByEmail(ctx, req.Email)
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		s.opt.Logger.With(zap.String("RequestID", "register")).Warn("Error get user",
			zap.String("Email", req.Email),
			zap.Error(err))
		err = util.ErrInternalServerError()
		return
	}
	if err == nil {
		err = util.ErrRequestValidation("Email sudah digunakan oleh pengguna lain")
		return
	}

	user := &model.User{
		Email:        req.Email,
		Name:         req.Name,
		PhoneNumber:  req.PhoneNumber,
		PasswordHash: req.Password,
		RoleID:       req.RoleID,
	}

	tx := s.opt.DB.Begin()
	err = s.createUser(user, tx)
	if err != nil {
		s.opt.Logger.With(zap.String("RequestID", "register")).Error("Error create user user",
			zap.Error(err),
		)
		err = util.ErrInternalServerError()
		return
	}

	tx.Commit()
	return
}

func (s *authService) createUser(user *model.User, tx *gorm.DB) (err error) {
	password := user.PasswordHash
	passwordHash, err := util.HashPassword(password)
	if err != nil {
		s.opt.Logger.With(zap.String("RequestID", "register")).Error("Error create password",
			zap.Error(err),
		)
		err = util.ErrUnknownError("Gagal untuk melakukan encrypt password")
		return
	}

	user.PasswordHash = passwordHash
	_, err = s.opt.Repository.User.Create(user, tx)
	if err != nil {
		s.opt.Logger.With(zap.String("RequestID", "register")).Error("Error create user",
			zap.Error(err),
		)
		err = util.ErrUnknownError("Gagal untuk menambahkan pengguna")
		return
	}
	return
}

func (s *authService) Login(ctx echo.Context, req *dto.LoginRequest) (jwtToken dto.JwtToken, err error) {
	user, err := s.opt.Repository.User.FindByEmail(ctx, req.Email)
	if err != nil {
		s.opt.Logger.Warn(util.ErrLoginDefault().Error(),
			zap.String("Email", req.Email),
			zap.Error(err))
		err = util.ErrLoginDefault()
		return
	}

	check := util.CheckPasswordHash(req.Password, user.PasswordHash)
	if !check {
		err = util.ErrLoginDefault()
		return
	}

	//auto logout old session
	err = s.autoLogout(user.ID)
	if err != nil {
		return
	}

	// tokenDetail, err := s.createJwtToken(user.ID, user.Role.RoleType)
	tokenDetail, err := s.createJwtToken(user.ID, "test_role")
	if err != nil {
		s.opt.Logger.Error("Failed to generate access token",
			zap.String("Email", req.Email),
			zap.Error(err))
		err = util.ErrUnknownError("Gagal generate access token 1")
		return
	}

	auditTrail := model.AuditTrails{
		UserID:    user.ID,
		UserEmail: user.Email,
		UserName:  user.Username,
		UserRole:  "test_role",
		Action:    "Login",
		URL:       "[POST] /login",
		CreatedAt: time.Now(),
		RequestID: null.NewString(util.GetRequestID(ctx), true),
	}

	err = s.opt.Repository.AuditTrail.Create(ctx, &auditTrail)
	if err != nil {
		s.opt.Logger.With(zap.String("RequestID", util.GetRequestID(ctx))).Error("Failed to save audit trail",
			zap.String("Email", req.Email),
			zap.Error(err))
		err = util.ErrUnknownError("Gagal generate access token 1")
		return
	}

	jwtToken = dto.JwtToken{
		AccessToken:         tokenDetail.AccessToken,
		AccessTokenExpires:  tokenDetail.AtExpires,
		RefreshToken:        tokenDetail.RefreshToken,
		RefreshTokenExpires: tokenDetail.RtExpires,
	}

	return
}

func (s *authService) Logout(ctx echo.Context, userID uint, accessUUID string) (err error) {
	refreshUuid := fmt.Sprintf("%s++%d", accessUUID, userID)
	// delete access token
	err = s.opt.Cache.DeleteCache(fmt.Sprintf("%s:%s", util.CacheKeyFormatter("jwt"), accessUUID))
	if err != nil {
		s.opt.Logger.Warn(util.ErrLogoutDefault().Error(),
			zap.Uint("User ID", userID),
			zap.Error(err))
		err = util.ErrLogoutDefault()
		return
	}
	// delete refresh token
	err = s.opt.Cache.DeleteCache(fmt.Sprintf("%s:%s", util.CacheKeyFormatter("jwt"), refreshUuid))
	if err != nil {
		s.opt.Logger.Warn(util.ErrLogoutDefault().Error(),
			zap.Uint("User ID", userID),
			zap.Error(err))
		err = util.ErrLogoutDefault()
		return
	}

	return
}

func (s *authService) verifyToken(tokenString string, tokenType string) (tokenStruct *jwt.Token, err error) {
	var secret string
	switch tokenType {
	case constant.TokenAccessType:
		secret = s.opt.Config.JwtAccessSecret
	case constant.TokenRefreshType:
		secret = s.opt.Config.JwtRefreshSecret
	default:
		err = errors.New("Unknown token type")
		return
	}

	tokenStruct, err = jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Invalid signing method : %v", token.Header["alg"])
		}
		return []byte(secret), nil
	})
	return
}

func (s *authService) RefreshToken(ctx echo.Context, refreshToken string) (jwtToken dto.JwtToken, err error) {
	tokenStruct, err := s.verifyToken(refreshToken, constant.TokenRefreshType)
	if err != nil {
		s.opt.Logger.Error("Error Verify Token",
			zap.Error(err),
		)
		err = util.ErrUnknownError("Refresh token tidak valid")
		return
	}

	claims, ok := tokenStruct.Claims.(jwt.MapClaims)
	if !ok || !tokenStruct.Valid {
		err = util.ErrUnknownError("Refresh token tidak valid")
		return
	}

	util.CustomLog.Info("[LOG]: claims : ", claims)

	refreshUuid, ok := claims["refresh_uuid"].(string) //convert the interface to string
	if !ok {
		err = util.ErrUnknownError("Klaim refresh token tidak valid")
		return
	}

	roleType, ok := claims["role_type"].(string) //convert the interface to string
	if !ok {
		err = util.ErrUnknownError("Tipe user tidak valid")
		return
	}

	userID, errConv := strconv.ParseUint(fmt.Sprintf("%.f", claims["user_id"]), 10, 64)
	if err != nil {
		s.opt.Logger.Error("ID pengguna tidak valid",
			zap.Error(errConv),
		)
		err = util.ErrUnknownError("Refresh token tidak valid")
		return
	}

	cacheKey := fmt.Sprintf("%s:%s", util.CacheKeyFormatter("jwt"), refreshUuid)
	isRefreshTokenExist := s.opt.Cache.CheckCacheExists(cacheKey)
	if !isRefreshTokenExist {
		err = util.ErrUnknownError("Anda telah keluar, silahkan login kembali")
		return
	}

	err = s.opt.Cache.DeleteCache(cacheKey)
	if err != nil {
		s.opt.Logger.Error("Failed to delete refresh token",
			zap.Error(err),
		)
		err = util.ErrUnknownError("Gagal menghapus refresh token")
		return
	}

	tokenDetail, errCrt := s.createJwtToken(uint(userID), roleType)
	if errCrt != nil {
		s.opt.Logger.Error("Failed to generate refresh token",
			zap.Error(errCrt))
		err = util.ErrUnknownError("Gagal generate refresh token")
		return
	}

	jwtToken = dto.JwtToken{
		AccessToken:         tokenDetail.AccessToken,
		AccessTokenExpires:  tokenDetail.AtExpires,
		RefreshToken:        tokenDetail.RefreshToken,
		RefreshTokenExpires: tokenDetail.RtExpires,
	}
	return
}

func (s *authService) ForgotPassword(ctx echo.Context, req *dto.ForgotPasswordRequest) (err error) {
	user, err := s.opt.Repository.User.FindByEmail(ctx, req.Email)
	if err != nil {
		s.opt.Logger.Warn(util.ErrAccountDoesntExist().Error(),
			zap.String("Email", req.Email),
			zap.Error(err))
		err = util.ErrAccountDoesntExist()
		return
	}

	tokenDetail, err := s.createJwtTokenForResetPassword(uint(user.ID), user.Email)
	if err != nil {
		s.opt.Logger.Error("Failed to generate token forget password",
			zap.Error(err))
		err = util.ErrUnknownError("Gagal generate token forget password")
		return
	}

	tx := s.opt.DB.Begin()

	resetPassword := &model.ResetPassword{
		Email:     req.Email,
		Token:     tokenDetail.AccessToken,
		Status:    "unused",
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}
	_, err = s.opt.Repository.ResetPassword.StoreResetPassword(resetPassword, tx)
	if err != nil {
		s.opt.Logger.Warn(util.ErrFailedToCreateResetPassword().Error(),
			zap.String("Email", req.Email),
			zap.Error(err))
		err = util.ErrFailedToCreateResetPassword()
		return
	}
	tx.Commit()

	var (
		replacer        []string
		placeholderName = map[string]interface{}{
			"fullname":            user.Name,
			"username":            user.Username,
			"forgot_password_url": fmt.Sprintf("%s?token=%s", s.opt.Config.ForgotPasswordURL, tokenDetail.AccessToken),
		}
	)

	for k, p := range placeholderName {
		replacer = append(replacer, fmt.Sprintf("[%s]", k))
		replacer = append(replacer, cast.ToString(p))
	}
	r := strings.NewReplacer(replacer...)
	emailMessage := constant.EmailForgotPassword
	emailMessage = r.Replace(emailMessage)
	err = s.opt.EMailService.Send(email.EmailRequest{
		EmailTo: []string{user.Email},
		Subject: "Forgot Password",
		Message: emailMessage,
	})

	if err != nil {
		s.opt.Logger.With(zap.String("RequestID", util.GetRequestID(ctx))).Error("Failed to send user link forgot password",
			zap.Error(err),
		)
		err = util.ErrUnknownError("Gagal mengirimkan link reset password pengguna")
		return
	}

	return
}

func (s *authService) ValidateToken(ctx echo.Context, r *http.Request) (result dto.TokenValidationResult, err error) {
	tokenString, err := util.ExtractBearerToken(r.Header)
	if err != nil {
		s.opt.Logger.Error("Error Extract Token",
			zap.Error(err),
		)
		err = util.ErrUnauthorized()
		return
	}
	tokenStruct, err := s.verifyToken(tokenString, constant.TokenAccessType)
	if err != nil {
		s.opt.Logger.Error("Error Verify Token",
			zap.Error(err),
		)
		err = util.ErrUnauthorized()
		return
	}
	claims, ok := tokenStruct.Claims.(jwt.MapClaims)
	if !ok || !tokenStruct.Valid {
		s.opt.Logger.Error("Token claims is not valid")
		err = util.ErrUnauthorized()
		return
	}

	accessUuid, ok := claims["access_uuid"].(string)
	if !ok {
		s.opt.Logger.Error("Access UUID is not valid")
		err = util.ErrUnauthorized()
		return
	}
	roleType, ok := claims["role_type"].(string)
	if !ok {
		s.opt.Logger.Error("User type is not valid")
		err = util.ErrUnauthorized()
		return
	}
	userID, err := strconv.ParseUint(fmt.Sprintf("%.f", claims["user_id"]), 10, 64)
	if err != nil {
		s.opt.Logger.Error("Error Parse User ID From Token",
			zap.Error(err),
		)
		err = util.ErrUnauthorized()
		return
	}
	cacheKey := fmt.Sprintf("%s:%s", util.CacheKeyFormatter("jwt"), accessUuid)
	authCache, err := s.opt.Cache.ReadCache(cacheKey)
	if err != nil {
		s.opt.Logger.Error("Error Get User ID From Cache",
			zap.Error(err),
		)
		err = util.ErrUnauthorized()
		return
	}
	authCacheValue := new(commons.AuthCacheValue)
	err = json.Unmarshal(authCache, authCacheValue)
	if userID != uint64(authCacheValue.UserID) {
		s.opt.Logger.Error("User ID from token different with User ID from cache")
		err = util.ErrUnauthorized()
		return
	}

	result.UserID = uint(userID)
	result.AccessUUID = accessUuid
	result.RoleType = roleType
	return
}

func (s *authService) VerifyResetToken(ctx echo.Context, req *dto.VerifyResetPasswordRequest) (err error) {
	tokenStruct, err := s.verifyToken(req.Token, constant.TokenAccessType)
	if err != nil {
		s.opt.Logger.Error("Error Verify Token",
			zap.Error(err),
		)
		err = util.ErrUnauthorized()
		return
	}

	claims, ok := tokenStruct.Claims.(jwt.MapClaims)
	if !ok || !tokenStruct.Valid {
		s.opt.Logger.Error("Token claims is not valid")
		err = util.ErrUnauthorized()
		return
	}

	email, ok := claims["email"].(string)
	if !ok {
		s.opt.Logger.Error("User email is not valid")
		err = util.ErrUnauthorized()
		return
	}

	resetPassword, err := s.opt.Repository.ResetPassword.FindByEmailAndToken(ctx, email, req.Token)
	if err != nil {
		s.opt.Logger.Warn(util.ErrDataNotFound().Error(),
			zap.String("Email", email),
			zap.Error(err))
		err = util.ErrDataNotFound()
		return
	}

	if time.Now().After(resetPassword.ExpiresAt) {
		s.opt.Logger.Warn(util.ErrTokenExpired().Error(),
			zap.String("Email", email),
			zap.Error(err))
		err = util.ErrTokenExpired()
		return
	}

	return
}

func (s *authService) ResetPassword(ctx echo.Context, req *dto.ChangePasswordRequest) (err error) {
	tokenStruct, err := s.verifyToken(req.Token, constant.TokenAccessType)
	if err != nil {
		s.opt.Logger.Error("Error Verify Token",
			zap.Error(err),
		)
		err = util.ErrUnauthorized()
		return
	}

	claims, ok := tokenStruct.Claims.(jwt.MapClaims)
	if !ok || !tokenStruct.Valid {
		s.opt.Logger.Error("Token claims is not valid")
		err = util.ErrUnauthorized()
		return
	}

	email, ok := claims["email"].(string)
	if !ok {
		s.opt.Logger.Error("User email is not valid")
		err = util.ErrUnauthorized()
		return
	}

	resetPassword, err := s.opt.Repository.ResetPassword.FindByEmailAndToken(ctx, email, req.Token)
	if err != nil {
		s.opt.Logger.Warn(util.ErrDataNotFound().Error(),
			zap.String("Email", email),
			zap.Error(err))
		err = util.ErrDataNotFound()
		return
	}

	user := model.User{
		Email: email,
	}

	condition := &model.User{
		Email: email,
	}

	password := req.Password
	passwordHash, err := util.HashPassword(password)
	if err != nil {
		s.opt.Logger.With(zap.String("RequestID", "encrypt new password")).Error("Error encrypt new password",
			zap.Error(err),
		)
		err = util.ErrUnknownError("Gagal untuk melakukan encrypt password baru")
		return
	}
	tx := s.opt.DB.Begin()
	user.PasswordHash = passwordHash
	err = s.opt.Repository.User.Update(user, condition, tx)
	if err != nil {
		s.opt.Logger.With(zap.String("RequestID", "change password")).Error("Error change password user",
			zap.Error(err),
		)
		err = util.ErrUnknownError("Gagal untuk mengubah password pengguna")
		return
	}
	resetPassword.Status = "used"
	resetPassword.IsClicked = true
	resetPassword.AttemptCount = resetPassword.AttemptCount + 1

	rpCondition := &model.ResetPassword{
		Email: resetPassword.Email,
		Token: resetPassword.Token,
	}

	err = s.opt.Repository.ResetPassword.Update(resetPassword, rpCondition, tx)
	if err != nil {
		s.opt.Logger.Warn(util.ErrDataNotFound().Error(),
			zap.String("Email", email),
			zap.Error(err))
		err = util.ErrDataNotFound()
		return
	}
	tx.Commit()
	return
}

func (s *authService) PermissionCheck(ctx echo.Context, object string, action string) (isPermitted bool, err error) {
	actx, err := util.NewAppContext(ctx)
	if err != nil {
		return
	}
	userID := actx.GetUserID()
	subject := util.FormatRbacSubject(userID)
	isPermitted, err = s.opt.Options.Rbac.Enforce(subject, object, action)
	if err != nil {
		s.opt.Logger.With(zap.String("RequestID", util.GetRequestID(actx))).Error("Error Checking Policy",
			zap.Error(err),
		)
	}
	return
}

func (s *authService) BatchPermissionCheck(ctx echo.Context, request [][]interface{}) (isPermitted bool, err error) {
	actx, err := util.NewAppContext(ctx)
	if err != nil {
		return
	}
	userID := actx.GetUserID()
	subject := util.FormatRbacSubject(userID)
	permissions := [][]interface{}{}
	for _, req := range request {
		permissions = append(permissions, util.PrependArray(req, subject))
	}

	results, err := s.opt.Options.Rbac.BatchEnforce(permissions)
	if err != nil {
		s.opt.Logger.With(zap.String("RequestID", util.GetRequestID(actx))).Error("Error Checking Policy",
			zap.Error(err),
		)
		return
	}
	for _, r := range results {
		if r {
			isPermitted = true
			return
		}
	}
	err = errors.New("User don't has permission")
	return
}

func (s *authService) autoLogout(userID uint) (err error) {
	uuidAccessKey := fmt.Sprintf("%s:%s:%d", util.CacheKeyFormatter("uuid"), constant.TokenAccessType, userID)
	uuidAccessCache, err := s.opt.Cache.ReadCache(uuidAccessKey)
	if err != nil {
		s.opt.Logger.Error("error get uuid access token from cache",
			zap.Uint("user id", userID),
			zap.Error(err),
		)
		if !strings.Contains(err.Error(), "Cache key didn't exists") {
			err = util.ErrUnknownError("Gagal auto logout pengguna")
			return
		}
		//if err is cache key didn't exists, ignore error
		err = nil
	} else {
		uuidAccessCacheValue := new(commons.AuthUUIDCacheValue)
		err = json.Unmarshal(uuidAccessCache, uuidAccessCacheValue)
		if err != nil {
			s.opt.Logger.Error("error unmarshal uuid access token from cache",
				zap.Uint("user id", userID),
				zap.Error(err),
			)
			err = util.ErrUnknownError("Gagal auto logout pengguna")
			return
		}
		// delete access token
		err = s.opt.Cache.DeleteCache(fmt.Sprintf("%s:%s", util.CacheKeyFormatter("jwt"), uuidAccessCacheValue.UUID))
		if err != nil {
			s.opt.Logger.Error(util.ErrLogoutDefault().Error(),
				zap.Uint("user id", userID),
				zap.Error(err))
			err = util.ErrUnknownError("Gagal auto logout pengguna")
			return
		}
	}

	uuidRefreshKey := fmt.Sprintf("%s:%s:%d", util.CacheKeyFormatter("uuid"), constant.TokenRefreshType, userID)
	uuidRefreshCache, err := s.opt.Cache.ReadCache(uuidRefreshKey)
	if err != nil {
		s.opt.Logger.Error("error get uuid refresh token from cache",
			zap.Error(err),
		)
		if !strings.Contains(err.Error(), "Cache key didn't exists") {
			fmt.Sprintln(" MASUK SINI NIH ")
			err = util.ErrUnknownError("Gagal auto logout pengguna")
			return
		}
		//if err is cache key didn't exists, ignore error
		err = nil
	} else {
		uuidRefreshCacheValue := new(commons.AuthUUIDCacheValue)
		err = json.Unmarshal(uuidRefreshCache, uuidRefreshCacheValue)
		if err != nil {
			s.opt.Logger.Error("error unmarshal uuid refresh token from cache",
				zap.Uint("user id", userID),
				zap.Error(err),
			)
			err = util.ErrUnknownError("Gagal auto logout pengguna")
			return
		}

		// delete refresh token
		err = s.opt.Cache.DeleteCache(fmt.Sprintf("%s:%s", util.CacheKeyFormatter("jwt"), uuidRefreshCacheValue.UUID))
		if err != nil {
			s.opt.Logger.Error(util.ErrLogoutDefault().Error(),
				zap.Uint("user id", userID),
				zap.Error(err))
			err = util.ErrUnknownError("Gagal auto logout pengguna")
			return
		}
	}
	return
}
