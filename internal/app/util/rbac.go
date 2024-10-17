package util

import "fmt"

func FormatRbacSubject(adminID uint) string {
	return fmt.Sprintf("user%d", adminID)
}

func FormatRbacRole(roleID uint) string {
	return fmt.Sprintf("role%d", roleID)
}
