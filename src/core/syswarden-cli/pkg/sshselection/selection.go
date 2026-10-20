// Package sshselection defines the explicit TOML choice for SSH hardening.
// A selection is never migration approval or proof of policy ownership.
package sshselection

import (
	"fmt"
	"os"
	"strings"

	"github.com/pelletier/go-toml/v2"
)

const (
	ModulePath = "modules/05-ssh.toml"
	Path       = "/etc/syswarden/config/" + ModulePath
	MaxBytes   = 32 << 10
)

// Config is deliberately separate from historical core OS/CIS settings.
// Empty means undeclared, not consent inferred from another setting.
type Config struct {
	Hardening string `mapstructure:"hardening"`
}

func (selection Config) Validate() error {
	switch selection.Hardening {
	case "", "disabled", "forwarding", "cis":
		return nil
	default:
		return fmt.Errorf("ssh.hardening must be disabled, forwarding or cis")
	}
}

// Authorize requires agreement with the independently reviewed role/profile.
// It does not replace the caller's exact plan digest and ownership checks.
func (selection Config) Authorize(owner, profile string) error {
	if err := selection.Validate(); err != nil {
		return err
	}
	if owner == "external" && profile == "observe" &&
		(selection.Hardening == "" || selection.Hardening == "disabled") {
		return nil
	}
	if owner == "syswarden" && (profile == "forwarding" || profile == "cis") &&
		selection.Hardening == profile {
		return nil
	}
	return fmt.Errorf("SSH publication requires an explicit matching ssh.hardening selection in %s; historical OS/CIS settings do not authorize SSH changes", ModulePath)
}

// ValidateDocument rejects misplaced, aliased or weakly typed declarations
// before a general configuration loader can merge or coerce their values.
// The dedicated module contains only this choice, avoiding unrelated secrets
// in the SSH transaction journal.
func ValidateDocument(relative string, document map[string]any) error {
	for key := range document {
		top, _, _ := strings.Cut(key, ".")
		if strings.EqualFold(top, "ssh") && key != "ssh" {
			return fmt.Errorf("%s contains a noncanonical SSH table", relative)
		}
		if relative == ModulePath && key != "ssh" {
			return fmt.Errorf("%s permits only the ssh table", ModulePath)
		}
	}
	value, present := document["ssh"]
	if !present {
		return nil
	}
	if relative != ModulePath {
		return fmt.Errorf("ssh may be declared only in %s", ModulePath)
	}
	table, ok := value.(map[string]any)
	if !ok {
		return fmt.Errorf("ssh must be a TOML table")
	}
	for key := range table {
		if key != "hardening" {
			return fmt.Errorf("ssh contains an unsupported key")
		}
	}
	value, present = table["hardening"]
	if !present {
		return nil
	}
	text, ok := value.(string)
	if !ok || text == "" {
		return fmt.Errorf("ssh.hardening must be a nonempty string")
	}
	return (Config{Hardening: text}).Validate()
}

// ParseModule accepts only bytes from the dedicated module. The caller must
// independently attest its path, metadata, absence and stability.
func ParseModule(content []byte) (Config, error) {
	if len(content) > MaxBytes {
		return Config{}, fmt.Errorf("SSH selection module exceeds its size limit")
	}
	var document map[string]any
	if err := toml.Unmarshal(content, &document); err != nil {
		// Do not reflect raw TOML, which may contain pasted credentials.
		return Config{}, fmt.Errorf("SSH selection module is not valid TOML")
	}
	if err := ValidateDocument(ModulePath, document); err != nil {
		return Config{}, err
	}
	if table, ok := document["ssh"].(map[string]any); ok {
		if value, present := table["hardening"]; present {
			text, ok := value.(string)
			if !ok {
				return Config{}, fmt.Errorf("SSH selection is not a string")
			}
			return Config{Hardening: text}, nil
		}
	}
	return Config{}, nil
}

// RejectEnvironment prevents Viper overrides from disagreeing with the
// protected on-disk choice. Neither an environment value nor a legacy boolean
// can grant SSH publication consent.
func RejectEnvironment() error {
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		name = strings.ToUpper(strings.ReplaceAll(name, "-", "_"))
		if name == "SYSWARDEN_SSH" || name == "SYSWARDEN_SSH_HARDENING" ||
			strings.HasPrefix(name, "SYSWARDEN_SSH_HARDENING_") {
			return fmt.Errorf("SSH environment overrides are forbidden; use %s", ModulePath)
		}
	}
	return nil
}
