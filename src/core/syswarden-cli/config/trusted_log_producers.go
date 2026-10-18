package config

import (
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// ParseTrustedLogProducers parses explicit administrator grants for exact
// collector-visible log paths and producer UIDs. It never discovers or adopts
// trust from the log's current owner, a service name or a container image.
// Keep this contract identical in the independently built CLI and core modules.
func ParseTrustedLogProducers(raw string) (map[string]uint32, error) {
	grants := make(map[string]uint32)
	if raw == "" {
		return grants, nil
	}
	if len(raw) > 16384 || !utf8.ValidString(raw) || strings.IndexFunc(raw, unicode.IsControl) >= 0 {
		return nil, fmt.Errorf("trusted log producers exceed the limit or contain invalid characters")
	}
	entries := strings.Fields(raw)
	if len(entries) > 32 || strings.Join(entries, " ") != raw {
		return nil, fmt.Errorf("trusted log producers require at most 32 single-space-separated path=UID grants")
	}
	for _, entry := range entries {
		path, encoded, found := strings.Cut(entry, "=")
		if !found || len(path) > 4096 || !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" || strings.ContainsAny(path, "*?[]\\") {
			return nil, fmt.Errorf("trusted log producer requires an exact absolute canonical path")
		}
		uid, err := strconv.ParseUint(encoded, 10, 32)
		if err != nil || uid == 0 || uid == 65534 || uid == 4294967295 || strconv.FormatUint(uid, 10) != encoded {
			return nil, fmt.Errorf("trusted log producer UID must be canonical, non-root and explicitly mapped")
		}
		if _, exists := grants[path]; exists {
			return nil, fmt.Errorf("trusted log producer path is duplicated")
		}
		grants[path] = uint32(uid)
	}
	return grants, nil
}

// DirectBridgeLogPatterns transfers the historical bridge inputs to the secure
// core follower when explicit producer trust is configured. Exact grants also
// enroll their files. Return a fresh slice so callers cannot mutate the policy.
func DirectBridgeLogPatterns(producers map[string]uint32) []string {
	if len(producers) == 0 {
		return nil
	}
	patterns := []string{"/var/log/nginx/*.log", "/var/log/apache2/*.log", "/var/log/httpd/*.log", "/var/log/auth.log", "/var/log/secure", "/var/log/syslog", "/var/log/messages"}
	paths := make([]string, 0, len(producers))
	for path := range producers {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	seen := make(map[string]bool, len(patterns))
	for _, path := range patterns {
		seen[path] = true
	}
	for _, path := range paths {
		if !seen[path] {
			patterns = append(patterns, path)
		}
	}
	return patterns
}
