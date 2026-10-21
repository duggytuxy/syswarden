//go:build linux

package sshpolicy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
)

// StartupSummary describes the manager's qualified command for the observed
// invocation. It is not evidence of configuration consumption or activation.
// Raw arguments, timestamps and process identifiers remain private.
type StartupSummary struct {
	EnvironmentSHA256     string `json:"environment_sha256,omitempty"`
	Schema                int    `json:"schema"`
	CommandSHA256         string `json:"command_sha256"`
	DeclarationVerified   bool   `json:"declaration_verified"`
	ExplicitConfiguration bool   `json:"explicit_configuration"`
}

type sshStartupCommand struct {
	path                                       string
	args, flags                                []string
	started, monotonic, stopped, stopMonotonic uint64
	pid                                        uint32
	code, status                               int32
}

type sshStartupQuery func(context.Context, string) ([]byte, error)

// Decode the typed D-Bus value, never systemctl's flattened argv display or a
// process title. Keep each argument separate and refuse missing/extra fields,
// duplicate keys, unknown signatures, nulls and trailing documents.
func decodeSSHBusValue(wire []byte, expectedType string) (json.RawMessage, error) {
	if len(wire) == 0 || len(wire) > maxSSHSystemdOutput || !utf8.Valid(wire) {
		return nil, ErrInventoryBounds
	}
	d := json.NewDecoder(bytes.NewReader(wire))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return nil, ErrInventoryUnsafe
	}
	fields := make(map[string]json.RawMessage)
	for d.More() {
		token, err = d.Token()
		key, ok := token.(string)
		if err != nil || !ok || (key != "type" && key != "data") || fields[key] != nil {
			return nil, ErrInventoryUnsafe
		}
		var value json.RawMessage
		if err = d.Decode(&value); err != nil {
			return nil, ErrInventoryUnsafe
		}
		fields[key] = value
	}
	if token, err = d.Token(); err != nil || token != json.Delim('}') {
		return nil, ErrInventoryUnsafe
	}
	if _, err = d.Token(); err != io.EOF || len(fields) != 2 {
		return nil, ErrInventoryUnsafe
	}
	var signature string
	if json.Unmarshal(fields["type"], &signature) != nil || signature != expectedType {
		return nil, ErrInventoryUnsafe
	}
	return fields["data"], nil
}

func decodeSSHStartup(wire []byte) (sshStartupCommand, error) {
	var result sshStartupCommand
	data, err := decodeSSHBusValue(wire, "a(sasasttttuii)")
	if err != nil {
		return result, err
	}
	var commands [][]json.RawMessage
	if json.Unmarshal(data, &commands) != nil || len(commands) != 1 || len(commands[0]) != 10 {
		return result, ErrInventoryUnsafe
	}
	row := commands[0]
	targets := []any{&result.path, &result.args, &result.flags, &result.started, &result.monotonic, &result.stopped, &result.stopMonotonic, &result.pid, &result.code, &result.status}
	for i, target := range targets {
		if bytes.Equal(bytes.TrimSpace(row[i]), []byte("null")) || json.Unmarshal(row[i], target) != nil {
			return sshStartupCommand{}, ErrInventoryUnsafe
		}
	}
	if result.path == "" || len(result.args) == 0 || len(result.args) > 16 || result.args == nil || result.flags == nil {
		return sshStartupCommand{}, ErrInventoryUnsafe
	}
	for _, value := range append(append([]string{result.path}, result.args...), result.flags...) {
		if len(value) == 0 || len(value) > 4096 {
			return sshStartupCommand{}, ErrInventoryBounds
		}
		for _, c := range value {
			if c < 32 || c == 127 {
				return sshStartupCommand{}, ErrInventoryUnsafe
			}
		}
	}
	return result, nil
}

func verifySSHStartup(command sshStartupCommand, snapshot sshSystemdSnapshot, executable string) (StartupSummary, error) {
	empty := StartupSummary{}
	if !snapshot.summary.ManagerObserved || !snapshot.summary.ServiceActive || snapshot.summary.SocketActive || snapshot.summary.SocketInstanced || snapshot.summary.Mode != "service" {
		return empty, fmt.Errorf("SSH startup binding requires a running non-socket service")
	}
	unit := snapshot.units[snapshot.summary.Service]
	pid, err := sshSystemdUint(unit["MainPID"], 32)
	start, startErr := sshSystemdUint(unit["ExecMainStartTimestampMonotonic"], 64)
	if errors.Join(err, startErr) != nil || pid <= 1 || start == 0 || uint64(command.pid) != pid || command.monotonic != start || command.started == 0 || command.stopped != 0 || command.stopMonotonic != 0 || command.code != 0 || command.status != 0 {
		return empty, fmt.Errorf("SSH startup command does not identify the current manager invocation")
	}
	if (executable != "/usr/bin/sshd" && executable != "/usr/sbin/sshd") || command.path != executable || len(command.args) < 2 || len(command.args) > 6 || command.args[0] != executable || len(command.flags) != 0 {
		return empty, fmt.Errorf("SSH startup command has an unsupported executable or execution flags")
	}
	seen := make(map[string]bool)
	explicit := false
	for i := 1; i < len(command.args); i++ {
		arg := command.args[i]
		if seen[arg] {
			return empty, ErrInventoryUnsafe
		}
		seen[arg] = true
		switch arg {
		case "-D", "-e":
		case "-f":
			i++
			if i >= len(command.args) || command.args[i] != MainPath {
				return empty, fmt.Errorf("SSH startup selects a different configuration")
			}
			explicit = true
		default:
			return empty, fmt.Errorf("SSH startup options require separate qualification; no expansion or override is inferred")
		}
	}
	if !seen["-D"] {
		return empty, ErrInventoryUnsafe
	}
	wire, err := json.Marshal([]any{command.path, command.args, command.flags, command.started, command.monotonic, command.pid})
	if err != nil {
		return empty, err
	}
	return StartupSummary{Schema: 1, CommandSHA256: digestBytes(wire), DeclarationVerified: true, ExplicitConfiguration: explicit}, nil
}

func observeSSHStartup(ctx context.Context, snapshot sshSystemdSnapshot, executable string, query sshStartupQuery, guard func() error) (StartupSummary, error) {
	return observeSSHStartupEnvironment(ctx, snapshot, executable, query, guard, nil)
}

func observeSSHStartupEnvironment(ctx context.Context, snapshot sshSystemdSnapshot, executable string, query sshStartupQuery, guard func() error, capture sshEnvironmentCapture) (StartupSummary, error) {
	if ctx == nil || query == nil || guard == nil {
		return StartupSummary{}, ErrInventoryUnsafe
	}
	if err := errors.Join(ctx.Err(), guard()); err != nil {
		return StartupSummary{}, err
	}
	unit := snapshot.summary.Service
	if unit != "ssh.service" && unit != "sshd.service" {
		return StartupSummary{}, ErrInventoryUnsafe
	}
	wire, queryErr := query(ctx, unit)
	if err := errors.Join(queryErr, ctx.Err(), guard()); err != nil {
		return StartupSummary{}, err
	}
	command, err := decodeSSHStartup(wire)
	if err != nil {
		return StartupSummary{}, fmt.Errorf("SSH startup property is invalid: %w", err)
	}
	original := command
	var environment sshEnvironmentResult
	needsEnvironment := false
	for _, arg := range command.args {
		needsEnvironment = needsEnvironment || strings.Contains(arg, "$")
	}
	if needsEnvironment {
		if capture == nil {
			return StartupSummary{}, ErrInventoryUnsafe
		}
		environment, err = capture(ctx, unit)
		if err = errors.Join(err, ctx.Err(), guard()); err != nil {
			return StartupSummary{}, err
		}
		command, err = resolveSSHStartupEnvironment(command, environment)
		if err != nil {
			return StartupSummary{}, err
		}
	}
	summary, err := verifySSHStartup(command, snapshot, executable)
	if err != nil {
		return StartupSummary{}, err
	}
	if needsEnvironment {
		// Bind the original declaration as well as its protected explicit inputs.
		wire, err := json.Marshal([]any{original.path, original.args, original.flags, original.started, original.monotonic, original.pid, environment.digest})
		if err != nil {
			return StartupSummary{}, err
		}
		summary.CommandSHA256 = digestBytes(wire)
		summary.EnvironmentSHA256 = environment.digest
	}
	return summary, nil
}
