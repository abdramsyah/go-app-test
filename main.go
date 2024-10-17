package main

import (
	"go-tech/cmd"
	"log"
	"time"
)

func setTimezone(tz string) error {
	loc, err := time.LoadLocation(tz)
	if err != nil {
		return err
	}
	time.Local = loc
	return nil
}

func main() {
	if err := setTimezone("Asia/Jakarta"); err != nil {
		log.Panicf("Set timezone error: %s", err)
	}

	cmd.Execute()
}
