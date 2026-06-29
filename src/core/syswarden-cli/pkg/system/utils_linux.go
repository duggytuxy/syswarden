//go:build linux

package system

import "os"

// IsAlpine detects if the current OS is Alpine Linux based on the existence of /etc/alpine-release
func IsAlpine() bool {
	_, err := os.Stat("/etc/alpine-release")
	return err == nil
}
