//go:build freebsd

package system

// IsAlpine returns false on FreeBSD since Alpine is a Linux distribution.
func IsAlpine() bool {
	return false
}
