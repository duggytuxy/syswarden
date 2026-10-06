//go:build linux

package firewall

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"sort"
	"strings"
)

// Clearing these data properties invalidates CommandAction's substitution
// cache. No action method, arbitrary value, global stop, reload or unban is
// permitted. The installed class and configured/live values must be attested
// independently before a coordinator publishes a retirement intent.
func legacyFail2banHookProperty(key string) bool {
	base, condition, conditional := strings.Cut(key, "?")
	if conditional && condition != "family=inet4" && condition != "family=inet6" {
		return false
	}
	switch base {
	case "actionstart", "actionban", "actionreban", "actionunban", "actioncheck", "actionrepair", "actionflush", "actionstop", "actionreload", "actionprolong":
		return true
	}
	return false
}

func encodeLegacyFail2banRetirementCommand(command []string) ([]byte, error) {
	invalid := func() ([]byte, error) {
		return nil, fmt.Errorf("unsupported targeted Fail2ban retirement command")
	}
	if len(command) < 2 || !validLegacyFail2banJailName(command[1]) || command[1][0] == '-' {
		return invalid()
	}
	switch {
	case len(command) == 2 && command[0] == "stop":
	case len(command) == 4 && command[0] == "set" && command[2] == "idle" && command[3] == "on":
	case len(command) == 6 && command[0] == "set" && command[2] == "action" && validLegacyFail2banRuntimeName(command[3]) &&
		legacyFail2banHookProperty(command[4]) && command[5] == "":
	default:
		return invalid()
	}
	var result bytes.Buffer
	_, _ = result.Write([]byte{0x80, 2, ']', '('})
	for _, value := range command {
		lengthValue := len(value)
		if lengthValue < 0 || lengthValue > 128 {
			return invalid()
		}
		_ = result.WriteByte('X')
		var size [4]byte
		binary.LittleEndian.PutUint32(size[:], uint32(lengthValue))
		_, _ = result.Write(size[:])
		_, _ = result.WriteString(value)
	}
	_, _ = result.WriteString("e." + legacyFail2banEnd)
	return result.Bytes(), nil
}

type legacyFail2banRetirementSocket struct {
	client legacyFail2banReadOnlySocket
	// The coordinator must re-read the already durable exact intent and bind
	// this transition, service invocation, source plan, barrier and kernel
	// safety before every send. A nil authorization cannot mutate anything.
	authorize func(context.Context, []string) error
}

func (socket legacyFail2banRetirementSocket) command(ctx context.Context, command []string) error {
	request, err := encodeLegacyFail2banRetirementCommand(command)
	if err != nil {
		return err
	}
	if socket.authorize == nil || socket.client.guard == nil {
		return fmt.Errorf("targeted Fail2ban retirement requires a durable transition and live guard")
	}
	client := socket.client
	client.guard = func() error {
		if err := socket.client.guard(); err != nil {
			return err
		}
		return socket.authorize(ctx, append([]string(nil), command...))
	}
	response, err := exchangeLegacyFail2banSocket(ctx, client, request)
	if err != nil {
		return fmt.Errorf("targeted Fail2ban transition is unconfirmed; preserve its journal: %w", err)
	}
	valid := command[0] == "stop" && response.kind == 'N'
	if command[0] == "set" {
		valid = command[2] == "idle" && response.kind == 0x88 || command[2] == "action" && response.kind == 's' && response.text == ""
	}
	if !valid {
		return fmt.Errorf("targeted Fail2ban transition returned an unexpected acknowledgment; preserve its journal")
	}
	return nil
}

// This constructs an inert transition list only. It cannot establish jail
// ownership from names or execute the result. The caller must derive targets
// from complete owned templates bound to the durable file plan, then publish
// and verify a runtime intent before using the guarded command adapter.
func planLegacyFail2banQuiescence(live legacyFail2banRuntimeSnapshot, targets map[string]bool) ([][]string, error) {
	if len(targets) == 0 || len(targets) > 128 {
		return nil, fmt.Errorf("Fail2ban quiescence requires bounded attested targets")
	}
	var names []string
	for name, selected := range targets {
		if !selected || !validLegacyFail2banJailName(name) || name[0] == '-' {
			return nil, fmt.Errorf("Fail2ban quiescence target is invalid")
		}
		if _, active := live.jails[name]; active {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	var commands [][]string
	for _, name := range names {
		commands = append(commands, []string{"set", name, "idle", "on"})
	}
	for _, name := range names {
		jail := live.jails[name]
		if len(jail.actions) > 32 {
			return nil, fmt.Errorf("Fail2ban quiescence action count exceeds its limit")
		}
		var actions []string
		for action := range jail.actions {
			actions = append(actions, action)
		}
		sort.Strings(actions)
		for _, action := range actions {
			if !validLegacyFail2banRuntimeName(action) {
				return nil, fmt.Errorf("Fail2ban quiescence action is unsupported")
			}
			properties := jail.actions[action]
			if len(properties) > 128 {
				return nil, fmt.Errorf("Fail2ban quiescence property count exceeds its limit")
			}
			for _, required := range []string{"actionstart", "actionban", "actionreban", "actionunban", "actioncheck", "actionrepair", "actionflush", "actionstop", "actionreload"} {
				if properties[required].kind != 's' {
					return nil, fmt.Errorf("Fail2ban quiescence lacks complete CommandAction hook evidence")
				}
			}
			var hooks []string
			for key, value := range properties {
				if !legacyFail2banHookProperty(key) {
					if base, _, conditional := strings.Cut(key, "?"); conditional && legacyFail2banHookProperty(base) {
						return nil, fmt.Errorf("Fail2ban quiescence has an unsupported conditional hook")
					}
					continue
				}
				if value.kind != 's' {
					return nil, fmt.Errorf("Fail2ban quiescence hook is not a string property")
				}
				hooks = append(hooks, key)
			}
			sort.Strings(hooks)
			for _, key := range hooks {
				commands = append(commands, []string{"set", name, "action", action, key, ""})
				if len(commands)+len(names) > 4096 {
					return nil, fmt.Errorf("Fail2ban quiescence exceeds its transition limit")
				}
			}
		}
	}
	// Stop only after every targeted hook has been cleared and independently
	// re-read. The coordinator must enforce that phase boundary. An idle reply
	// alone never proves that an already running hook has completed.
	for _, name := range names {
		commands = append(commands, []string{"stop", name})
	}
	if len(commands) > 4096 {
		return nil, fmt.Errorf("Fail2ban quiescence exceeds its transition limit")
	}
	return commands, nil
}
