//go:build linux

package sshpolicy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const sshSystemdCommon = "Id,Names,LoadState,ActiveState,SubState,UnitFileState,NeedDaemonReload,Job,InvocationID,FragmentPath,DropInPaths,ControlPID"
const sshSystemdService = sshSystemdCommon + ",MainPID,ExecMainStartTimestampMonotonic,TriggeredBy"
const sshSystemdSocket = sshSystemdCommon + ",Triggers,Accept"
const maxSSHSystemdOutput = 64 << 10

// SystemdSummary describes a stable manager observation only. Neither manager
// state nor a reported PID proves which configuration a daemon loaded, a live
// listening socket, or a new authenticated administrator connection.
type SystemdSummary struct {
	Schema            int    `json:"schema"`
	Manager           string `json:"manager"`
	ManagerSHA256     string `json:"manager_sha256"`
	UnitsSHA256       string `json:"units_sha256"`
	Mode              string `json:"mode"`
	Service           string `json:"service,omitempty"`
	Socket            string `json:"socket,omitempty"`
	ServiceActive     bool   `json:"service_active"`
	SocketActive      bool   `json:"socket_active"`
	SocketInstanced   bool   `json:"socket_instanced"`
	ManagerObserved   bool   `json:"manager_observed"`
	ProcessVerified   bool   `json:"process_verified"`
	ListenersVerified bool   `json:"listeners_verified"`
	RuntimeActivated  bool   `json:"runtime_activated"`
	AccessVerified    bool   `json:"access_verified"`
}

type sshSystemdUnit map[string]string
type sshSystemdRun func(context.Context, string) ([]byte, error)

func sshSystemdProperties(unit string) (string, error) {
	switch unit {
	case "ssh.service", "sshd.service":
		return sshSystemdService, nil
	case "ssh.socket", "sshd.socket":
		return sshSystemdSocket, nil
	default:
		return "", fmt.Errorf("SSH manager observation requires a fixed supported unit")
	}
}

func sshSystemdNames(value, suffix string) ([]string, error) {
	names := strings.Fields(value)
	if strings.Join(names, " ") != value || len(names) > 2 {
		return nil, ErrInventoryUnsafe
	}
	sort.Strings(names)
	for i, name := range names {
		if (name != "ssh."+suffix && name != "sshd."+suffix) || (i > 0 && names[i-1] == name) {
			return nil, fmt.Errorf("SSH manager reported an unsupported or duplicate unit relationship")
		}
	}
	return names, nil
}

func sshSystemdUint(value string, bits int) (uint64, error) {
	n, err := strconv.ParseUint(value, 10, bits)
	if err != nil || strconv.FormatUint(n, 10) != value {
		return 0, ErrInventoryUnsafe
	}
	return n, nil
}

func parseSSHSystemdUnit(requested string, wire []byte) (sshSystemdUnit, error) {
	properties, err := sshSystemdProperties(requested)
	if err != nil {
		return nil, err
	}
	if len(wire) == 0 || len(wire) > maxSSHSystemdOutput || wire[len(wire)-1] != '\n' || !utf8.Valid(wire) {
		return nil, ErrInventoryBounds
	}
	for _, ch := range string(wire) {
		if (ch < 32 && ch != '\n') || ch == 127 {
			return nil, ErrInventoryUnsafe
		}
	}
	allowed := make(map[string]bool)
	for _, key := range strings.Split(properties, ",") {
		allowed[key] = true
	}
	u := make(sshSystemdUnit)
	for _, line := range strings.Split(strings.TrimSuffix(string(wire), "\n"), "\n") {
		key, value, found := strings.Cut(line, "=")
		if !found || !allowed[key] {
			return nil, fmt.Errorf("SSH manager output has an unexpected property")
		}
		if _, duplicate := u[key]; duplicate {
			return nil, fmt.Errorf("SSH manager output has a duplicate property")
		}
		u[key] = value
	}
	if len(u) != len(allowed) || u["ControlPID"] != "0" || u["Job"] != "" || u["NeedDaemonReload"] != "no" {
		return nil, fmt.Errorf("SSH manager observation is incomplete, changing or needs a daemon reload")
	}
	suffix := strings.Split(requested, ".")[1]
	names, err := sshSystemdNames(u["Names"], suffix)
	if err != nil || !containsSSHUnit(names, requested) || !containsSSHUnit(names, u["Id"]) {
		return nil, errors.Join(ErrInventoryUnsafe, err)
	}
	u["Names"] = strings.Join(names, " ")
	invocation := u["InvocationID"]
	if invocation != "" && (len(invocation) != 32 || strings.Trim(invocation, "0123456789abcdef") != "" || strings.Trim(invocation, "0") == "") {
		return nil, fmt.Errorf("SSH manager invocation identity is invalid")
	}
	active := u["ActiveState"] == "active"
	if (!active && (u["ActiveState"] != "inactive" || u["SubState"] != "dead")) || (active && invocation == "") {
		return nil, fmt.Errorf("SSH manager unit is not in a supported stable state")
	}
	if suffix == "service" {
		pid, pidErr := sshSystemdUint(u["MainPID"], 32)
		started, startErr := sshSystemdUint(u["ExecMainStartTimestampMonotonic"], 64)
		if pidErr != nil || startErr != nil || (active && (pid <= 1 || started == 0 || u["SubState"] != "running")) || (!active && pid != 0) {
			return nil, fmt.Errorf("SSH manager service process observation is inconsistent")
		}
		links, err := sshSystemdNames(u["TriggeredBy"], "socket")
		if err != nil {
			return nil, err
		}
		u["TriggeredBy"] = strings.Join(links, " ")
	} else {
		if (u["Accept"] != "no" && u["Accept"] != "yes") || (active && (u["Accept"] != "no" || (u["SubState"] != "listening" && u["SubState"] != "running"))) {
			return nil, fmt.Errorf("SSH socket requires a stable non-instanced activation mode")
		}
		links, err := sshSystemdNames(u["Triggers"], "service")
		if err != nil || len(links) > 1 {
			return nil, errors.Join(ErrInventoryUnsafe, err)
		}
		if u["Accept"] == "yes" && len(links) != 0 {
			return nil, fmt.Errorf("inactive instanced SSH socket has an unexpected target")
		}
		u["Triggers"] = strings.Join(links, " ")
	}
	switch u["LoadState"] {
	case "loaded":
		if !safePath(u["FragmentPath"]) || u["UnitFileState"] == "" {
			return nil, fmt.Errorf("SSH manager loaded unit has no configuration identity")
		}
	case "not-found":
		if u["Id"] != requested || len(names) != 1 || active || invocation != "" || u["FragmentPath"] != "" || u["DropInPaths"] != "" || u["UnitFileState"] != "" ||
			u["TriggeredBy"] != "" || u["Triggers"] != "" || (suffix == "service" && u["ExecMainStartTimestampMonotonic"] != "0") || (suffix == "socket" && u["Accept"] != "no") {
			return nil, fmt.Errorf("SSH manager absence contradicts other unit observations")
		}
	default:
		return nil, fmt.Errorf("SSH manager unit is masked, invalid or unsupported")
	}
	return u, nil
}

func containsSSHUnit(names []string, name string) bool {
	for _, candidate := range names {
		if candidate == name {
			return true
		}
	}
	return false
}

func classifySSHSystemd(units map[string]sshSystemdUnit, digest string) (SystemdSummary, error) {
	if len(units) != 4 || !lowerDigest.MatchString(digest) {
		return SystemdSummary{}, ErrInventoryUnsafe
	}
	var service, socket sshSystemdUnit
	for _, name := range []string{"ssh.service", "sshd.service", "ssh.socket", "sshd.socket"} {
		u := units[name]
		if u["LoadState"] == "not-found" {
			continue
		}
		if u["LoadState"] != "loaded" {
			return SystemdSummary{}, ErrInventoryUnsafe
		}
		for _, alias := range strings.Fields(u["Names"]) {
			if units[alias]["LoadState"] != "loaded" || units[alias]["Id"] != u["Id"] {
				return SystemdSummary{}, fmt.Errorf("SSH manager alias is not independently resolvable")
			}
		}
		slot := &service
		if strings.HasSuffix(name, ".socket") {
			slot = &socket
		}
		if *slot != nil && !reflect.DeepEqual(*slot, u) {
			return SystemdSummary{}, fmt.Errorf("SSH manager has distinct or inconsistent unit aliases")
		}
		*slot = u
	}
	// Relationships must resolve to the same observed canonical unit. A name
	// resembling ssh is not permission to select another service or instance.
	resolve := func(name, id string) bool {
		return name != "" && units[name] != nil && units[name]["LoadState"] == "loaded" && units[name]["Id"] == id
	}
	instanced := socket != nil && socket["Accept"] == "yes"
	if socket != nil && !instanced && (service == nil || !resolve(socket["Triggers"], service["Id"])) {
		return SystemdSummary{}, fmt.Errorf("SSH socket target is not the independently observed service")
	}
	for _, name := range strings.Fields(service["TriggeredBy"]) {
		if socket == nil || instanced || !resolve(name, socket["Id"]) {
			return SystemdSummary{}, fmt.Errorf("SSH service has an unresolved socket relationship")
		}
	}
	if socket != nil && !instanced && service["TriggeredBy"] == "" {
		return SystemdSummary{}, fmt.Errorf("SSH socket relationship is not reciprocal")
	}
	data, err := json.Marshal(units)
	if err != nil {
		return SystemdSummary{}, err
	}
	result := SystemdSummary{Schema: 1, Manager: "systemd", ManagerSHA256: digest,
		UnitsSHA256: digestBytes(data), Mode: "absent", ManagerObserved: true}
	if service != nil {
		result.Service, result.Mode = service["Id"], "inactive"
		result.ServiceActive = service["ActiveState"] == "active"
	}
	if socket != nil {
		result.Socket = socket["Id"]
		result.SocketActive = socket["ActiveState"] == "active"
		result.SocketInstanced = instanced
		if result.Mode == "absent" {
			result.Mode = "inactive"
		}
	}
	if result.SocketActive {
		result.Mode = "socket"
	} else if result.ServiceActive {
		result.Mode = "service"
	}
	return result, nil
}

func observeSSHSystemd(ctx context.Context, digest string, run sshSystemdRun, recheck func() error) (SystemdSummary, error) {
	if ctx == nil || run == nil || recheck == nil || !lowerDigest.MatchString(digest) {
		return SystemdSummary{}, ErrInventoryUnsafe
	}
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	var previous map[string]sshSystemdUnit
	for pass := 0; pass < 2; pass++ {
		units := make(map[string]sshSystemdUnit, 4)
		for _, name := range []string{"ssh.service", "sshd.service", "ssh.socket", "sshd.socket"} {
			if err := errors.Join(ctx.Err(), recheck()); err != nil {
				return SystemdSummary{}, err
			}
			wire, runErr := run(ctx, name)
			if err := errors.Join(ctx.Err(), recheck(), runErr); err != nil {
				return SystemdSummary{}, fmt.Errorf("SSH manager query failed or changed: %w", err)
			}
			u, err := parseSSHSystemdUnit(name, wire)
			if err != nil {
				return SystemdSummary{}, err
			}
			units[name] = u
		}
		if _, err := classifySSHSystemd(units, digest); err != nil {
			return SystemdSummary{}, err
		}
		if previous != nil && !reflect.DeepEqual(previous, units) {
			return SystemdSummary{}, ErrInventoryChanged
		}
		previous = units
	}
	if err := errors.Join(ctx.Err(), recheck()); err != nil {
		return SystemdSummary{}, err
	}
	return classifySSHSystemd(previous, digest)
}
