package config

import "fmt"

// The new profile has two explicit publication markers and a fixed base file
// inventory. This is completeness evidence, never authority to activate it.
// Historical and standard-v1 layouts retain their existing missing-file rules.
type unconfiguredProfileInventory struct {
	files    map[string]bool
	profiles map[string]string
}

func (inventory *unconfiguredProfileInventory) record(relative string, document map[string]any) {
	if inventory.files == nil {
		inventory.files = make(map[string]bool)
	}
	inventory.files[relative] = true
	inventory.recordProfile(relative, document)
}

// A proposed new user module contributes its declaration, but cannot count as
// an already published file when checking the existing installation inventory.
func (inventory *unconfiguredProfileInventory) recordProfile(relative string, document map[string]any) {
	if inventory.profiles == nil {
		inventory.profiles = make(map[string]string)
	}
	if core, ok := document["core"].(map[string]any); ok {
		if profile, ok := core["install_profile"].(string); ok {
			inventory.profiles[relative] = profile
		}
	}
}

func (inventory *unconfiguredProfileInventory) validate() error {
	selected := false
	for _, profile := range inventory.profiles {
		selected = selected || profile == UnconfiguredInstallProfile
	}
	if !selected {
		return nil
	}
	for relative, profile := range inventory.profiles {
		if profile != UnconfiguredInstallProfile {
			return fmt.Errorf("%s conflicts with the unconfigured-v1 publication profile; profile shadowing cannot bypass completeness", relative)
		}
	}
	for _, relative := range []string{"config.toml", "modules/00-core.toml", "modules/10-network.toml", "modules/20-security.toml", "modules/30-waap.toml", "modules/40-integrations.toml", "modules/99-user.toml"} {
		if !inventory.files[relative] {
			return fmt.Errorf("incomplete unconfigured-v1 publication: %s is missing; complete exact fresh staging or restore retained administrator configuration", relative)
		}
	}
	for _, relative := range []string{"config.toml", "modules/00-core.toml"} {
		if inventory.profiles[relative] != UnconfiguredInstallProfile {
			return fmt.Errorf("incomplete unconfigured-v1 publication: %s lacks its explicit profile marker", relative)
		}
	}
	return nil
}
