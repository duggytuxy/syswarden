//go:build freebsd

package cmd

import (
	"fmt"
	"os/exec"
	"strings"
)

func restartCoreService() error {
	if output, err := exec.Command("service", "syswarden", "restart").CombinedOutput(); err != nil {
		return fmt.Errorf("restart syswarden: %s: %w", strings.TrimSpace(string(output)), err)
	}
	if output, err := exec.Command("service", "syswarden", "onestatus").CombinedOutput(); err != nil {
		return fmt.Errorf("verify syswarden after restart: %s: %w", strings.TrimSpace(string(output)), err)
	}
	return nil
}
