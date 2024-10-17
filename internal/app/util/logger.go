package util

import (
	"fmt"
	"log"
)

const (
	LCERROR   = "\033[31m%s\033[0m" // red
	LCWARN    = "\033[33m%s\033[0m" // yellow
	LCINFO    = "\033[36m%s\033[0m" // cyan
	LCSUCCESS = "\033[32m%s\033[0m" // green
)

type Logger struct{}

func (l Logger) Error(message string, v ...interface{}) {
	log.Printf(LCERROR, fmt.Sprintf(message, v...))
}

func (l Logger) Warn(message string, v ...interface{}) {
	log.Printf(LCWARN, fmt.Sprintf(message, v...))
}

func (l Logger) Info(message string, v ...interface{}) {
	log.Printf(LCINFO, fmt.Sprintf(message, v...))
}

func (l Logger) Success(message string, v ...interface{}) {
	log.Printf(LCSUCCESS, fmt.Sprintf(message, v...))
}

// Instantiate the logger
var CustomLog = Logger{}
