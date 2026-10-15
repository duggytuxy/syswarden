//go:build linux

package firewall

import (
	"fmt"
	"sort"
	"strings"
)

// resolveFirewalldPortZone selects a zone only from explicit protected interface
// bindings, or from the unique interface-bound zone when no scope was configured.
// Other zones are preserved regardless of their names or default annotation.
func resolveFirewalldPortZone(path string, selectedInterfaces []string) (string, error) {
	output, err := runLinuxFirewallCommand(path, "--get-active-zones")
	if err != nil {
		return "", fmt.Errorf("list active firewalld zones: %w: %s", err, strings.TrimSpace(string(output)))
	}
	interfaceZones := make(map[string]struct{})
	interfaceBindings := make(map[string]string)
	currentZone := ""
	for lineNumber, line := range strings.Split(string(output), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
			if currentZone == "" {
				return "", fmt.Errorf("active firewalld zone detail at line %d has no zone header", lineNumber+1)
			}
			fields := strings.Fields(trimmed)
			if len(fields) > 1 && fields[0] == "interfaces:" {
				interfaceZones[currentZone] = struct{}{}
				for _, name := range fields[1:] {
					canonical, err := canonicalInterfaceName(name)
					if err != nil {
						return "", fmt.Errorf("invalid active firewalld interface: %w", err)
					}
					if previous, exists := interfaceBindings[canonical]; exists {
						return "", fmt.Errorf("active firewalld interface %q has duplicate bindings in %q and %q", canonical, previous, currentZone)
					}
					interfaceBindings[canonical] = currentZone
				}
			}
			continue
		}
		fields := strings.Fields(line)
		// firewalld 2.4 annotates the default zone in --get-active-zones.
		// This is display metadata, not authority to select a zone: an
		// interface binding and an unambiguous zone are still required.
		if len(fields) == 2 && fields[1] == "(default)" {
			fields = fields[:1]
		}
		if len(fields) != 1 {
			return "", fmt.Errorf("active firewalld zone line %d is malformed", lineNumber+1)
		}
		if err := validateFirewalldZone(fields[0]); err != nil {
			return "", fmt.Errorf("active firewalld zone line %d: %w", lineNumber+1, err)
		}
		currentZone = fields[0]
	}
	if len(selectedInterfaces) > 0 {
		selectedZones := make(map[string]struct{})
		for _, name := range selectedInterfaces {
			canonical, err := canonicalInterfaceName(name)
			if err != nil {
				return "", fmt.Errorf("invalid protected firewalld interface: %w", err)
			}
			zone, exists := interfaceBindings[canonical]
			if !exists {
				return "", fmt.Errorf("protected interface %q has no active firewalld zone binding; preserve NetworkManager and firewalld assignments", canonical)
			}
			selectedZones[zone] = struct{}{}
		}
		if len(selectedZones) != 1 {
			return "", fmt.Errorf("protected interfaces span multiple firewalld zones; automatic compatibility port expansion is refused")
		}
		for zone := range selectedZones {
			return zone, nil
		}
	}
	if len(interfaceZones) == 0 {
		return "", fmt.Errorf("firewalld has no active interface-bound zone for the required compatibility port")
	}
	if len(interfaceZones) > 1 {
		names := make([]string, 0, len(interfaceZones))
		for zone := range interfaceZones {
			names = append(names, zone)
		}
		sort.Strings(names)
		return "", fmt.Errorf("firewalld has multiple active interface-bound zones for the required compatibility port: %s; configure network.interfaces (legacy SYSWARDEN_INTERFACES) to select the protected interfaces in one existing zone; do not remove interface bindings", strings.Join(names, ", "))
	}
	for zone := range interfaceZones {
		return zone, nil
	}
	return "", fmt.Errorf("firewalld active zone resolution failed")
}
