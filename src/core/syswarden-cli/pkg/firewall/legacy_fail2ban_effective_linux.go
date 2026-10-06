//go:build linux

package firewall

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"strings"
)

const (
	maximumLegacyFail2banDumpBytes = 8 << 20
	maximumLegacyFail2banDumpLines = 65536
)

// verifyLegacyFail2banEffectiveRetirement compares successful, trusted
// fail2ban-client -d output before and after a staged configuration edit.
// Callers must validate both configurations with fail2ban-client -t first.
// This is an exact command-stream comparison, not a Python parser or an
// evaluator. It permits only removal of the attested jails' commands. Every
// unrelated command, including global defaults and expanded action settings,
// must remain byte-for-byte identical and in its original order.
//
// The comparison neither establishes live runtime state nor authorizes a
// mutation. A caller must also attest files, includes, the trusted producer,
// live actions and continued protection at the mutation boundary.
func verifyLegacyFail2banEffectiveRetirement(before, after []byte, templates []legacyFail2banTemplateMatch) error {
	if len(templates) == 0 || len(templates) > 256 {
		return fmt.Errorf("historical Fail2ban retirement requires bounded, attested jail templates")
	}
	jails := make(map[string]bool, len(templates))
	for _, template := range templates {
		if template.kind != "jail" || template.sha256 == ([sha256.Size]byte{}) ||
			template.path != "/etc/fail2ban/jail.d/"+template.jail+".conf" ||
			template.templateSource == "" || template.templateRevision == "" ||
			!validLegacyFail2banJailName(template.jail) || jails[template.jail] {
			return fmt.Errorf("historical Fail2ban retirement has an invalid or duplicate jail template")
		}
		jails[template.jail] = true
	}
	preserved, err := retainedLegacyFail2banCommands(before, jails, true)
	if err != nil {
		return err
	}
	remaining, err := retainedLegacyFail2banCommands(after, jails, false)
	if err != nil {
		return err
	}
	if !bytes.Equal(preserved, remaining) {
		return fmt.Errorf("historical Fail2ban retirement changes unrelated effective configuration; preserve shared dependencies for reviewed recovery")
	}
	return nil
}

func validLegacyFail2banJailName(name string) bool {
	if len(name) == 0 || len(name) > 128 {
		return false
	}
	for _, value := range name {
		if value < 'a' || value > 'z' {
			if value < 'A' || value > 'Z' {
				if value < '0' || value > '9' {
					if value != '-' && value != '_' {
						return false
					}
				}
			}
		}
	}
	return true
}

func retainedLegacyFail2banCommands(content []byte, jails map[string]bool, expectPresent bool) ([]byte, error) {
	return retainedLegacyFail2banCommandsWithPresence(content, jails, expectPresent, expectPresent)
}

// The enabled view may omit a disabled target. The all-jails view must contain
// every target. In either view a partially represented target is an error.
func retainedLegacyFail2banCommandsWithPresence(content []byte, jails map[string]bool, allowTarget, requireTarget bool) ([]byte, error) {
	if len(content) == 0 || len(content) > maximumLegacyFail2banDumpBytes || content[len(content)-1] != '\n' ||
		bytes.Count(content, []byte{'\n'}) > maximumLegacyFail2banDumpLines {
		return nil, fmt.Errorf("Fail2ban configuration dump is empty, incomplete or exceeds its limit")
	}
	for _, value := range content {
		if value < 0x20 && value != '\n' || value == 0x7f {
			return nil, fmt.Errorf("Fail2ban configuration dump contains unsupported control bytes")
		}
	}
	added, started := make(map[string]bool), make(map[string]bool)
	var retained bytes.Buffer
	for _, line := range strings.Split(string(content[:len(content)-1]), "\n") {
		command := ""
		for _, verb := range []string{"add", "set", "multi-set", "start"} {
			if strings.HasPrefix(line, "['"+verb+"', ") && strings.HasSuffix(line, "]") {
				command = verb
				break
			}
		}
		if command == "" {
			// In particular, never ignore config-error records, diagnostic
			// text, pretty-print continuations or unknown command kinds.
			return nil, fmt.Errorf("Fail2ban configuration dump has an unsupported command record")
		}
		removed := false
		for jail := range jails {
			prefix := "['" + command + "', '" + jail + "'"
			if line != prefix+"]" && !strings.HasPrefix(line, prefix+", ") {
				continue
			}
			if !allowTarget {
				return nil, fmt.Errorf("historical Fail2ban jail remains in the staged effective configuration")
			}
			switch command {
			case "add":
				if added[jail] || started[jail] || !strings.HasPrefix(line, prefix+", '") {
					return nil, fmt.Errorf("historical Fail2ban jail has an ambiguous creation record")
				}
				added[jail] = true
			case "start":
				if !added[jail] || started[jail] || line != prefix+"]" {
					return nil, fmt.Errorf("historical Fail2ban jail has an ambiguous start record")
				}
				started[jail] = true
			default:
				if !added[jail] || started[jail] || !strings.HasPrefix(line, prefix+", ") {
					return nil, fmt.Errorf("historical Fail2ban jail has an out-of-order setting")
				}
			}
			removed = true
			break
		}
		if !removed {
			retained.WriteString(line)
			retained.WriteByte('\n')
		}
	}
	if allowTarget {
		for jail := range jails {
			if (requireTarget || added[jail] || started[jail]) && (!added[jail] || !started[jail]) {
				return nil, fmt.Errorf("historical Fail2ban jail is not fully represented in the configuration dump")
			}
		}
	}
	return retained.Bytes(), nil
}
