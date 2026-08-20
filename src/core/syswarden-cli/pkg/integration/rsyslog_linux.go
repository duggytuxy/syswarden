//go:build linux

package integration

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

func quoteRsyslogString(value string) (string, error) {
	if value == "" || len(value) > 4096 || !utf8.ValidString(value) || strings.IndexFunc(value, unicode.IsControl) >= 0 {
		return "", fmt.Errorf("rsyslog string is empty, oversized, or contains invalid characters")
	}
	var encoded strings.Builder
	encoded.Grow(len(value) + 2)
	encoded.WriteByte('"')
	for _, character := range value {
		switch character {
		case '\\', '"':
			encoded.WriteByte('\\')
		}
		encoded.WriteRune(character)
	}
	encoded.WriteByte('"')
	return encoded.String(), nil
}

func validatedRsyslogLogPatterns(raw string) ([]string, error) {
	if raw == "" {
		return nil, nil
	}
	patterns := strings.Fields(raw)
	if len(patterns) == 0 || strings.Join(patterns, " ") != raw {
		return nil, fmt.Errorf("rsyslog log patterns must use canonical single-space separation")
	}
	activeSet := make(map[string]struct{})
	seenPatterns := make(map[string]struct{}, len(patterns))
	for _, pattern := range patterns {
		if _, duplicate := seenPatterns[pattern]; duplicate {
			return nil, fmt.Errorf("rsyslog log pattern %q is duplicated", pattern)
		}
		seenPatterns[pattern] = struct{}{}
		if !filepath.IsAbs(pattern) || filepath.Clean(pattern) != pattern || strings.IndexFunc(pattern, unicode.IsControl) >= 0 {
			return nil, fmt.Errorf("rsyslog log pattern %q is not an absolute canonical path", pattern)
		}
		if _, err := filepath.Match(pattern, pattern); err != nil {
			return nil, fmt.Errorf("rsyslog log pattern %q is invalid: %w", pattern, err)
		}
		matches, err := filepath.Glob(pattern)
		if err != nil {
			return nil, fmt.Errorf("expand rsyslog log pattern %q: %w", pattern, err)
		}
		if len(matches) == 0 {
			continue
		}
		for _, match := range matches {
			if err := verifyRsyslogLogFile(match); err != nil {
				return nil, err
			}
			// Emit the verified exact match rather than its glob. Rsyslog must not
			// reinterpret the pattern after this process has checked its type.
			activeSet[match] = struct{}{}
		}
	}
	active := make([]string, 0, len(activeSet))
	for match := range activeSet {
		active = append(active, match)
	}
	sort.Strings(active)
	return active, nil
}

func verifyRsyslogLogFile(path string) error {
	before, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect rsyslog log match %q: %w", path, err)
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return fmt.Errorf("rsyslog log match %q is not a real regular file", path)
	}
	file, err := os.Open(path) // #nosec G304 -- path is an exact match of a validated absolute log pattern
	if err != nil {
		return fmt.Errorf("open rsyslog log match %q: %w", path, err)
	}
	opened, statErr := file.Stat()
	closeErr := file.Close()
	if statErr != nil {
		return fmt.Errorf("inspect opened rsyslog log match %q: %w", path, statErr)
	}
	after, lstatErr := os.Lstat(path)
	if lstatErr != nil || !os.SameFile(before, opened) || !os.SameFile(opened, after) || opened.Mode() != after.Mode() {
		return fmt.Errorf("rsyslog log match %q changed while verifying its type", path)
	}
	if closeErr != nil {
		return fmt.Errorf("close rsyslog log match %q: %w", path, closeErr)
	}
	return nil
}

func rsyslogTarget(ip, port string) (string, error) {
	address, err := netip.ParseAddr(ip)
	if err != nil || address.Zone() != "" || address.Is4In6() {
		return "", fmt.Errorf("invalid rsyslog target IP %q", ip)
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return "", fmt.Errorf("invalid rsyslog target port %q", port)
	}
	return net.JoinHostPort(address.String(), strconv.Itoa(portNumber)), nil
}
