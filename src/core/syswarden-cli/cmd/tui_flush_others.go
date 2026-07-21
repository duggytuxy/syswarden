//go:build !linux

package cmd

//nolint:unused // Used in tui.go, but linter struggles with OS-specific files
func flushStdin() {
	// Not required or not supported
}
