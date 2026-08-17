//go:build !freebsd

package cmd

import (
	"reflect"
	"testing"
)

func TestCoreServiceRestartCommandUsesOpenRCOnAlpine_SW_PKG_002(t *testing.T) {
	command := coreServiceRestartCommand(true)
	want := []string{"rc-service", "syswarden-core", "restart"}
	if !reflect.DeepEqual(command.Args, want) {
		t.Fatalf("Alpine restart command = %q, want %q", command.Args, want)
	}
}

func TestCoreServiceRestartCommandUsesSystemdOutsideAlpine_SW_PKG_003(t *testing.T) {
	command := coreServiceRestartCommand(false)
	want := []string{"systemctl", "restart", "syswarden-core.service"}
	if !reflect.DeepEqual(command.Args, want) {
		t.Fatalf("non-Alpine restart command = %q, want %q", command.Args, want)
	}
}
