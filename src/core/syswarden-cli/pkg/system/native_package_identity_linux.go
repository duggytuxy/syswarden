//go:build linux

package system

import (
	"fmt"
	"slices"
	"strings"
)

const (
	compatibilityNativePackageName = "syswarden"
	baseNativePackageName          = "syswarden-base"
)

var nativeProductPackageNames = [...]string{compatibilityNativePackageName, baseNativePackageName}

func validNativeProductPackageName(name string) bool {
	return name == compatibilityNativePackageName || name == baseNativePackageName
}

type nativeProductRegistration struct {
	name, manager, state, recovery string
}

func nativeProductRegistrationArguments(manager, name string) ([]string, error) {
	if !validNativeProductPackageName(name) {
		return nil, fmt.Errorf("unknown native product package")
	}
	switch manager {
	case "dpkg-query":
		return []string{"--show", "--showformat=${Package}\\t${db:Status-Status}\\n", name}, nil
	case "rpm":
		return []string{"--query", "--queryformat", "%{NAME}\\n", name}, nil
	case "apk":
		return []string{"info", "--quiet", "-e", name}, nil
	default:
		return nil, fmt.Errorf("unsupported native product package manager")
	}
}

func allowedNativeProductRegistrationQuery(path string, arguments []string) bool {
	manager := ""
	switch path {
	case "/usr/bin/dpkg-query":
		manager = "dpkg-query"
	case "/usr/bin/rpm":
		manager = "rpm"
	case "/sbin/apk", "/usr/sbin/apk":
		manager = "apk"
	default:
		return false
	}
	for _, name := range nativeProductPackageNames {
		expected, err := nativeProductRegistrationArguments(manager, name)
		if err == nil && slices.Equal(arguments, expected) {
			return true
		}
	}
	return false
}

func nativeProductPackageAbsentOutput(manager, name string) string {
	switch manager {
	case "dpkg-query":
		return "dpkg-query: no packages found matching " + name + "\n"
	case "rpm":
		return "package " + name + " is not installed\n"
	case "apk":
		return ""
	default:
		return "invalid package manager"
	}
}

// Every query names one of the two full-payload variants. A foreign owner,
// unknown native state or ambiguous absence never establishes deletion authority.
func queryNativeProductRegistrations(executor firewallManagerExecutor, executable, manager string, rpmTransaction bool) ([]nativeProductRegistration, error) {
	var registrations []nativeProductRegistration
	for _, name := range nativeProductPackageNames {
		arguments, err := nativeProductRegistrationArguments(manager, name)
		if err != nil {
			return nil, err
		}
		registration := nativeProductRegistration{name: name, manager: manager, state: "installed"}
		switch manager {
		case "dpkg-query":
			registration.recovery = "use 'sudo apt-get purge " + name + "' or 'sudo apt-get remove " + name + "' through verified native package removal"
		case "rpm":
			registration.recovery = "use 'sudo dnf remove " + name + "' through the native package manager"
		case "apk":
			registration.recovery = "use 'sudo apk del " + name + "' through the native package manager"
		}
		output, err := executor.output(executable, arguments...)
		if err != nil {
			code, known := firewallRemovalExitCode(err)
			if known && code == 1 && string(output) == nativeProductPackageAbsentOutput(manager, name) {
				continue
			}
			return nil, fmt.Errorf("cannot establish %s package registration through %s: %w", name, manager, err)
		}
		switch manager {
		case "dpkg-query":
			fields := strings.Split(strings.TrimSuffix(string(output), "\n"), "\t")
			if len(fields) != 2 || fields[0] != name || strings.Count(string(output), "\n") != 1 || !strings.HasSuffix(string(output), "\n") {
				return nil, fmt.Errorf("ambiguous dpkg SysWarden package registration")
			}
			registration.state = fields[1]
			switch registration.state {
			case "not-installed":
				continue
			case "config-files", "half-installed", "unpacked", "half-configured", "triggers-awaited", "triggers-pending", "installed":
			default:
				return nil, fmt.Errorf("unknown dpkg SysWarden package state")
			}
		case "rpm":
			if string(output) != name+"\n" && !(rpmTransaction && string(output) == name+"\n"+name+"\n") {
				return nil, fmt.Errorf("ambiguous RPM SysWarden package registration")
			}
		case "apk":
			if len(output) != 0 {
				return nil, fmt.Errorf("ambiguous APK SysWarden package registration")
			}
		}
		registrations = append(registrations, registration)
	}
	return registrations, nil
}

func inspectNativeProductRegistrations(executor firewallManagerExecutor, exists func(string) (bool, error)) ([]nativeProductRegistration, error) {
	if exists == nil {
		return nil, fmt.Errorf("native package database inspection is unavailable")
	}
	managers := []struct {
		name      string
		databases []string
	}{
		{"dpkg-query", []string{"/var/lib/dpkg/status"}},
		{"rpm", []string{"/usr/lib/sysimage/rpm", "/var/lib/rpm"}},
		{"apk", []string{"/lib/apk/db/installed"}},
	}
	var registrations []nativeProductRegistration
	for _, manager := range managers {
		path, present, err := resolveOptionalFirewallRemovalExecutable(executor, manager.name)
		if err != nil {
			return nil, err
		}
		if !present {
			for _, database := range manager.databases {
				found, err := exists(database)
				if err != nil {
					return nil, fmt.Errorf("inspect native package database: %w", err)
				}
				if found {
					return nil, fmt.Errorf("cannot rule out native package ownership: %s database exists but its query tool is unavailable", manager.name)
				}
			}
			continue
		}
		claims, err := queryNativeProductRegistrations(executor, path, manager.name, false)
		if err != nil {
			return nil, err
		}
		registrations = append(registrations, claims...)
	}
	return registrations, nil
}
