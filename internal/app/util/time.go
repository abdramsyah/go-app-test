package util

import (
	"errors"
	"fmt"
	"go-tech/internal/app/constant"
	"regexp"
	"time"

	"github.com/guregu/null"
)

func IsValidMonth(month string) bool {
	r, _ := regexp.Compile("^0[1-9]|1[0-2]$")
	return r.MatchString(month)
}

func IsValidYear(year string) bool {
	r, _ := regexp.Compile("^[12][0-9]{3}$")
	return r.MatchString(year)
}

// This function will convert timestamp to local timezone (WIB) without change the time value
// Example: change 2021-03-04 12:30:46.839596 +0000 UTC to 2021-03-04 12:30:46.839596 +0700 WIB
func ConvertUTCToLocalTimestamp(input time.Time) (output time.Time, err error) {
	inputString := input.Format(constant.FeDatetimeFormat)
	output, err = time.Parse(constant.FeDatetimeFormat+" MST", inputString+" WIB")
	return
}

func ConvertTimestampDBToFE(timestamp null.Time) string {
	if timestamp.Valid {
		return timestamp.Time.Format(constant.FeDatetimeFormat)
	}
	return ""
}

func GetBeginTimeAndEndTimeFromMonthAndYear(month string, year string) (beginTime time.Time, endTime time.Time, err error) {
	if month == "" {
		err = errors.New("Month can't be empty")
		return
	} else {
		if !IsValidMonth(month) {
			err = errors.New("Invalid month format")
			return
		}
	}

	if year == "" {
		err = errors.New("Year can't be empty")
		return
	} else {
		if !IsValidYear(year) {
			err = errors.New("Invalid year format")
			return
		}
	}

	beginTime, err = time.Parse(constant.FeDatetimeFormat, fmt.Sprintf("01-%s-%s %s", month, year, "00:00:00"))
	if err != nil {
		return
	}
	endDate := beginTime.AddDate(0, 1, -1).Day()
	endTime, err = time.Parse(constant.FeDatetimeFormat, fmt.Sprintf("%d-%s-%s %s", endDate, month, year, "23:59:59"))

	return
}
