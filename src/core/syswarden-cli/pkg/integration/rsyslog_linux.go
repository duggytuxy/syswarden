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

	"golang.org/x/sys/unix"
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
	return verifyRsyslogLogFileForOwner(path, int64(os.Geteuid()))
}

func verifyRsyslogLogFileForOwner(path string, expectedUID int64) error {
	var before unix.Stat_t
	if err := unix.Lstat(path, &before); err != nil {
		return fmt.Errorf("inspect rsyslog log match %q: %w", path, err)
	}
	if err := validateRsyslogLogSecurity(before, expectedUID); err != nil {
		return fmt.Errorf("rsyslog log match %q is unsafe: %w", path, err)
	}
	// Refuse a final-component link or blocking special-file replacement between
	// the initial inspection and open. Check ownership and mode on the held file.
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open rsyslog log match %q: %w", path, err)
	}
	var opened, after unix.Stat_t
	statErr := unix.Fstat(fd, &opened)
	lstatErr := unix.Lstat(path, &after)
	closeErr := unix.Close(fd)
	if statErr != nil {
		return fmt.Errorf("inspect opened rsyslog log match %q: %w", path, statErr)
	}
	if lstatErr != nil || before.Dev != opened.Dev || before.Ino != opened.Ino ||
		opened.Dev != after.Dev || opened.Ino != after.Ino || opened.Mode != after.Mode ||
		opened.Uid != after.Uid || opened.Gid != after.Gid {
		return fmt.Errorf("rsyslog log match %q changed while verifying its identity", path)
	}
	if err := validateRsyslogLogSecurity(opened, expectedUID); err != nil {
		return fmt.Errorf("opened rsyslog log match %q is unsafe: %w", path, err)
	}
	if err := validateRsyslogLogSecurity(after, expectedUID); err != nil {
		return fmt.Errorf("rsyslog log match %q became unsafe: %w", path, err)
	}
	if closeErr != nil {
		return fmt.Errorf("close rsyslog log match %q: %w", path, closeErr)
	}
	return nil
}

func validateRsyslogLogSecurity(identity unix.Stat_t, expectedUID int64) error {
	if identity.Mode&unix.S_IFMT != unix.S_IFREG {
		return fmt.Errorf("not a real regular file")
	}
	if int64(identity.Uid) != expectedUID {
		return fmt.Errorf("owner UID %d does not match expected UID %d", identity.Uid, expectedUID)
	}
	if identity.Mode&0022 != 0 {
		return fmt.Errorf("group or other write bits are set")
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
