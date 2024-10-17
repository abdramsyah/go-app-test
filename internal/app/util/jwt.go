package util

import (
	"errors"
	"net/http"
	"strings"
)

func ExtractBearerToken(header http.Header) (tokenString string, err error) {
	authHeader := header.Get("Authorization")
	if authHeader == "" {
		err = errors.New("Failed get Authorization header")
		return
	}
	strArr := strings.Split(authHeader, " ")
	if len(strArr) != 2 {
		err = errors.New("Failed Authorization header not valid")
		return
	}
	authType := strArr[0]
	authValue := strArr[1]
	if authType != "Bearer" {
		err = errors.New("Failed Authorization missing bearer token")
		return
	}
	tokenString = authValue
	return
}
