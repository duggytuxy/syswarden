//go:build linux

package sshpolicy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"unicode/utf8"
)

// This is a deliberately bounded subset of systemd environment-file syntax.
// No shell, variable expansion, continuation or escape interpretation occurs.
// Unsupported syntax is refused, never treated as an empty option value.
func parseSSHStartupEnvironmentFile(data []byte) (map[string]string, error) {
	if len(data) > maxSSHSystemdOutput || !utf8.Valid(data) {
		return nil, ErrInventoryBounds
	}
	for _, c := range string(data) {
		if c == 0 || c == '\ufeff' || c >= 0xfdd0 && c <= 0xfdef || c&0xffff == 0xfffe || c&0xffff == 0xffff || c < 32 && c != '\n' && c != '\r' && c != '\t' {
			return nil, ErrInventoryUnsafe
		}
	}
	result := make(map[string]string)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.Trim(line, " \t\r")
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		key, value = strings.Trim(key, " \t\r"), strings.Trim(value, " \t\r")
		if !ok || !validSSHEnvironmentName(key) || strings.ContainsAny(value, "\\\r") {
			return nil, ErrInventoryUnsafe
		}
		if strings.HasPrefix(value, "\"") || strings.HasPrefix(value, "'") {
			quote := value[:1]
			if len(value) < 2 || !strings.HasSuffix(value, quote) || strings.Contains(value[1:len(value)-1], quote) {
				return nil, ErrInventoryUnsafe
			}
			value = value[1 : len(value)-1]
		} else if strings.ContainsAny(value, "\"'") {
			return nil, ErrInventoryUnsafe
		}
		result[key] = value
		if len(result) > 128 {
			return nil, ErrInventoryBounds
		}
	}
	return result, nil
}

func validSSHEnvironmentName(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for i, c := range value {
		if !(c == '_' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || i > 0 && c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}

type sshEnvironmentFile struct {
	path     string
	optional bool
}
type sshStartupEnvironment struct {
	assignments []string
	files       []sshEnvironmentFile
}

type sshEnvironmentResult struct {
	values map[string]string
	digest string
}

type sshEnvironmentCapture func(context.Context, string) (sshEnvironmentResult, error)

func decodeSSHStartupEnvironment(environment, files, pam []byte) (result sshStartupEnvironment, err error) {
	defer func() {
		if err != nil {
			result = sshStartupEnvironment{}
		}
	}()
	data, err := decodeSSHBusValue(environment, "as")
	if err != nil {
		return result, err
	}
	var entries []json.RawMessage
	if json.Unmarshal(data, &entries) != nil || entries == nil || len(entries) > 128 {
		return result, ErrInventoryUnsafe
	}
	result.assignments = make([]string, 0, len(entries))
	for _, entry := range entries {
		var assignment string
		if bytes.Equal(bytes.TrimSpace(entry), []byte("null")) || json.Unmarshal(entry, &assignment) != nil {
			return result, ErrInventoryUnsafe
		}
		key, value, ok := strings.Cut(assignment, "=")
		if !ok || !validSSHEnvironmentName(key) || strings.ContainsRune(value, 0) || len(value) > 4096 {
			return result, ErrInventoryUnsafe
		}
		result.assignments = append(result.assignments, assignment)
	}
	data, err = decodeSSHBusValue(files, "a(sb)")
	if err != nil {
		return result, err
	}
	var rows [][]json.RawMessage
	if json.Unmarshal(data, &rows) != nil || rows == nil || len(rows) > 2 {
		return result, ErrInventoryUnsafe
	}
	seen := make(map[string]bool)
	result.files = make([]sshEnvironmentFile, 0, len(rows))
	for _, row := range rows {
		var file sshEnvironmentFile
		if len(row) != 2 || bytes.Equal(bytes.TrimSpace(row[0]), []byte("null")) || bytes.Equal(bytes.TrimSpace(row[1]), []byte("null")) || json.Unmarshal(row[0], &file.path) != nil || json.Unmarshal(row[1], &file.optional) != nil {
			return result, ErrInventoryUnsafe
		}
		if file.path != "/etc/default/ssh" && file.path != "/etc/sysconfig/sshd" || seen[file.path] {
			return result, ErrInventoryUnsafe
		}
		seen[file.path] = true
		result.files = append(result.files, file)
	}
	data, err = decodeSSHBusValue(pam, "s")
	if err != nil {
		return result, err
	}
	var name string
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) || json.Unmarshal(data, &name) != nil || name != "" {
		return result, ErrInventoryUnsafe
	}
	return result, nil
}

func readSSHStartupEnvironment(root *os.File, uid int, environment sshStartupEnvironment) (map[string]string, inventorySnapshot, error) {
	if root == nil {
		return nil, inventorySnapshot{}, ErrInventoryUnsafe
	}
	reader := inventoryReader{root: root, uid: uid, state: inventorySnapshot{files: make(map[string][]byte), nodes: make(map[string]inventoryStamp), links: make(map[string]string)}}
	values := make(map[string]string)
	for _, entry := range environment.assignments {
		key, value, ok := strings.Cut(entry, "=")
		if !ok || !validSSHEnvironmentName(key) {
			return nil, inventorySnapshot{}, ErrInventoryUnsafe
		}
		values[key] = value
	}
	for _, file := range environment.files {
		if file.path != "/etc/default/ssh" && file.path != "/etc/sysconfig/sshd" {
			return nil, inventorySnapshot{}, ErrInventoryUnsafe
		}
		data, exists, err := reader.readFile(file.path)
		if err != nil || !exists && !file.optional {
			return nil, inventorySnapshot{}, errors.Join(ErrInventoryUnsafe, err)
		}
		if !exists {
			continue
		}
		assignments, err := parseSSHStartupEnvironmentFile(data)
		if err != nil {
			return nil, inventorySnapshot{}, err
		}
		for key, value := range assignments {
			values[key] = value
		}
	}
	return values, reader.state, nil
}

func captureSSHStartupEnvironment(ctx context.Context, unit string, root *os.File, uid int, query sshStartupQuery, guard func() error) (sshEnvironmentResult, error) {
	if ctx == nil || root == nil || query == nil || guard == nil || unit != "ssh.service" && unit != "sshd.service" {
		return sshEnvironmentResult{}, ErrInventoryUnsafe
	}
	read := func() (sshStartupEnvironment, []byte, error) {
		var wires [][]byte
		for _, property := range []string{"environment", "environment-files", "pam-name"} {
			if err := errors.Join(ctx.Err(), guard()); err != nil {
				return sshStartupEnvironment{}, nil, err
			}
			wire, err := query(ctx, unit+"/"+property)
			if err = errors.Join(err, ctx.Err(), guard()); err != nil {
				return sshStartupEnvironment{}, nil, err
			}
			wires = append(wires, wire)
		}
		decoded, err := decodeSSHStartupEnvironment(wires[0], wires[1], wires[2])
		wire, marshalErr := json.Marshal(wires)
		return decoded, wire, errors.Join(err, marshalErr)
	}
	before, wire, err := read()
	if err != nil {
		return sshEnvironmentResult{}, err
	}
	values, inventory, err := readSSHStartupEnvironment(root, uid, before)
	if err != nil {
		return sshEnvironmentResult{}, err
	}
	after, nextWire, err := read()
	if err != nil || !bytes.Equal(wire, nextWire) || !reflect.DeepEqual(before, after) {
		return sshEnvironmentResult{}, errors.Join(ErrInventoryChanged, err)
	}
	nextValues, nextInventory, err := readSSHStartupEnvironment(root, uid, after)
	if err = errors.Join(err, ctx.Err(), guard()); err != nil || !reflect.DeepEqual(inventory, nextInventory) || !reflect.DeepEqual(values, nextValues) {
		return sshEnvironmentResult{}, errors.Join(ErrInventoryChanged, err)
	}
	h := sha256.New()
	hashPart(h, []byte("SYSWARDEN-SSH-STARTUP-ENVIRONMENT-V1"))
	hashPart(h, wire)
	hashSSHInventory(h, inventory)
	return sshEnvironmentResult{values, fmt.Sprintf("%x", h.Sum(nil))}, nil
}

// Only explicitly assigned, exactly empty standalone option variables can
// disappear. Undefined is not empty evidence: manager/global inputs could set
// it. Braced variables produce one argument and are never erased here.
func resolveSSHStartupEnvironment(command sshStartupCommand, environment sshEnvironmentResult) (sshStartupCommand, error) {
	if environment.values == nil || !lowerDigest.MatchString(environment.digest) {
		return sshStartupCommand{}, ErrInventoryUnsafe
	}
	resolved := command
	resolved.args = nil
	seen := make(map[string]bool)
	for i, arg := range command.args {
		if strings.Contains(arg, "$") {
			if i == 0 || arg != "$OPTIONS" && arg != "$SSHD_OPTS" || seen[arg] {
				return sshStartupCommand{}, ErrInventoryUnsafe
			}
			value, explicit := environment.values[arg[1:]]
			if !explicit || value != "" {
				return sshStartupCommand{}, fmt.Errorf("SSH startup options are not explicitly empty; separate qualification is required")
			}
			seen[arg] = true
		} else {
			resolved.args = append(resolved.args, arg)
		}
	}
	return resolved, nil
}
