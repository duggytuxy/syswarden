package system

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syswarden-cli/config"
)

// PreflightSelectedModuleDependencies checks explicit optional features before
// install/reload changes firewall state. It never installs or removes packages,
// changes repositories, or starts dependency services.
func PreflightSelectedModuleDependencies() error {
	return preflightSelectedModuleDependencies(config.GlobalConfig, exec.LookPath, func(path string) error { return validateOfflineQualificationDependency(path, os.Geteuid()) })
}

func preflightSelectedModuleDependencies(c *config.Config, look func(string) (string, error), validate func(string) error) error {
	if c == nil || look == nil || validate == nil {
		return errors.New("module dependency selection unavailable")
	}
	var required []struct{ module, binary string }
	if c.LogBridgeEnabled || c.SiemEnabled {
		required = append(required, struct{ module, binary string }{"log forwarding", "rsyslogd"})
	}
	if c.EnableWG {
		required = append(required, struct{ module, binary string }{"WireGuard", "wg"}, struct{ module, binary string }{"WireGuard", "wg-quick"})
	}
	for _, item := range required {
		path, err := look(item.binary)
		if err != nil {
			return fmt.Errorf("selected %s requires the administrator-installed %s executable: %w", item.module, item.binary, err)
		}
		if err := validate(path); err != nil {
			return fmt.Errorf("selected %s prerequisite %s is untrusted: %w", item.module, item.binary, err)
		}
	}
	return nil
}
