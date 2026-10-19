package sshpolicy

import (
	"crypto/sha256"
	"fmt"
	"strings"
)

var legacyCISBlock = []string{
	"# --- SYSWARDEN CIS SSH HARDENING ---",
	"X11Forwarding no", "MaxAuthTries 4", "ClientAliveInterval 300", "ClientAliveCountMax 3",
	"# ------------------------------------",
}

// migrateMain is a pure transformation of explicitly selected source lines.
// Names, values and marker comments alone never establish attribution. The
// protected administrator declaration supplies it for an exact source hash.
// Publication still requires a separately reviewed plan and durable recovery.
func migrateMain(content []byte, declaration *legacyIntent) ([]byte, error) {
	if declaration == nil {
		return append([]byte(nil), content...), nil
	}
	if fmt.Sprintf("%x", sha256.Sum256(content)) != declaration.MainSHA256 {
		return nil, fmt.Errorf("legacy SSH main-file digest changed; review attribution again")
	}
	lines := strings.Split(string(content), "\n")
	actions := make(map[int]string, len(declaration.Edits))
	for _, edit := range declaration.Edits {
		if edit.Line < 1 || edit.Line > len(lines) || actions[edit.Line] != "" {
			return nil, fmt.Errorf("legacy SSH edit has an invalid source line")
		}
		actions[edit.Line] = edit.Action
	}
	for _, edit := range declaration.Edits {
		line := lines[edit.Line-1]
		if edit.Action == "restore" {
			if _, err := restoreLegacyOverride(line); err != nil {
				return nil, err
			}
			continue
		}
		if edit.Action != "remove" {
			return nil, fmt.Errorf("unsupported legacy SSH edit action")
		}
		if line == legacyCISBlock[0] || line == legacyCISBlock[len(legacyCISBlock)-1] {
			start := edit.Line - 1
			if line == legacyCISBlock[len(legacyCISBlock)-1] {
				start -= len(legacyCISBlock) - 1
			}
			if start < 0 || start+len(legacyCISBlock) > len(lines) {
				return nil, fmt.Errorf("legacy SSH block is incomplete")
			}
			for offset, expected := range legacyCISBlock {
				if lines[start+offset] != expected || actions[start+offset+1] != "remove" {
					return nil, fmt.Errorf("legacy SSH block requires all exact lines to be reviewed together")
				}
			}
			continue
		}
		if !legacyPolicyLine(line) {
			return nil, fmt.Errorf("refusing removal of an unrecognized SSH line")
		}
	}
	result := make([]string, 0, len(lines))
	for index, line := range lines {
		switch actions[index+1] {
		case "remove":
			continue
		case "restore":
			var err error
			line, err = restoreLegacyOverride(line)
			if err != nil {
				return nil, err
			}
		}
		result = append(result, line)
	}
	return []byte(strings.Join(result, "\n")), nil
}

func legacyPolicyLine(line string) bool {
	switch line {
	case "AllowTcpForwarding no", "X11Forwarding no", "MaxAuthTries 4", "ClientAliveInterval 300", "ClientAliveCountMax 3":
		return true
	default:
		return false
	}
}

func restoreLegacyOverride(line string) (string, error) {
	const prefix = "# SYSWARDEN OVERRIDE: "
	if !strings.HasPrefix(line, prefix) {
		return "", fmt.Errorf("legacy SSH restore requires an exact historical override prefix")
	}
	restored := strings.TrimPrefix(line, prefix)
	key, rest := splitDirective(restored)
	switch key {
	case "allowtcpforwarding", "x11forwarding", "maxauthtries", "clientaliveinterval", "clientalivecountmax":
	default:
		return "", fmt.Errorf("legacy SSH override does not contain a supported directive")
	}
	arguments, err := arguments(rest)
	if err != nil || len(arguments) != 1 || !printableASCII(restored) {
		return "", fmt.Errorf("legacy SSH override has unsupported directive syntax")
	}
	return restored, nil
}
