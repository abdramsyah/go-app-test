package util

import (
	"fmt"
	"math/rand"
	"strings"
	"time"
	"unicode"
)

const charset = "abcdefghijklmnopqrstuvwxyz" +
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

var seededRand *rand.Rand = rand.New(
	rand.NewSource(time.Now().UnixNano()))

var (
	LowerCaseRune   = []rune("abcdefghijklmnopqrstuvwxyz")
	UpperCaseRune   = []rune("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	NumericRune     = []rune("1234567890")
	SpecialCharRune = []rune("@$!%*#?&")
)

func StringWithCharset(length int, charset string) string {
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[seededRand.Intn(len(charset))]
	}
	return string(b)
}

func RandomString(length int) string {
	return StringWithCharset(length, charset)
}

func LowerAndTrimSpace(input string) string {
	return strings.TrimSpace(strings.ToLower(input))
}

func CacheKeyFormatter(key string) string {
	return fmt.Sprintf("go-tech-be-%s", key)
}

func GenerateRandomPassword(length int) (password string) {
	rand.NewSource(time.Now().UnixNano())
	allChars := append(LowerCaseRune, UpperCaseRune...)
	allChars = append(allChars, NumericRune...)
	allChars = append(allChars, SpecialCharRune...)

	b := make([]rune, length)
	// select 1 upper, 1 lower, 1 number and 1 special
	b[0] = LowerCaseRune[rand.Intn(len(LowerCaseRune))]
	b[1] = UpperCaseRune[rand.Intn(len(UpperCaseRune))]
	b[2] = NumericRune[rand.Intn(len(NumericRune))]
	b[3] = SpecialCharRune[rand.Intn(len(SpecialCharRune))]
	for i := 4; i < length; i++ {
		// randomly select 1 character from given charset
		b[i] = allChars[rand.Intn(len(allChars))]
	}

	//shuffle character
	rand.Shuffle(len(b), func(i, j int) {
		b[i], b[j] = b[j], b[i]
	})
	return string(b)
}

/*
Password rule:
1. Minimum n characters
2. At least one uppercase letter
3. At least one lowercase letter
4. At least one number
5. At least one special character (special char allowed can be refer to SpecialCharRune)
*/
func PasswordValidator(password string, minLen int) (isValid bool) {
	var hasNumber, hasUpper, hasLower, hasSpecial, hasMinLen bool
	if len(password) >= minLen {
		hasMinLen = true
	}
	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsNumber(char):
			hasNumber = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSpecial = true
		}
	}
	return hasMinLen && hasUpper && hasLower && hasNumber && hasSpecial
}

/*
Password rule:
1. Minimum n characters
2. At least one letter
3. At least one number
*/
func PasswordValidator2(password string, minLen int) (isValid bool) {
	var hasNumber, hasLetter, hasMinLen bool
	if len(password) >= minLen {
		hasMinLen = true
	}
	for _, char := range password {
		switch {
		case unicode.IsLetter(char):
			hasLetter = true
		case unicode.IsNumber(char):
			hasNumber = true
		}
	}
	return hasMinLen && hasLetter && hasNumber
}
