package system

import (
	"fmt"
	"sort"
	"strings"
)

func parseSSHDirective(line string) (string, string, bool) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return "", "", false
	}
	keywordEnd := strings.IndexAny(trimmed, " \t=")
	if keywordEnd < 0 {
		return trimmed, "", true
	}
	keyword := trimmed[:keywordEnd]
	remainder := strings.TrimSpace(trimmed[keywordEnd:])
	if strings.HasPrefix(remainder, "=") {
		remainder = strings.TrimSpace(remainder[1:])
	}
	return keyword, remainder, keyword != ""
}

var approvedSSHDirectives = map[string]map[string]struct{}{
	"AllowTcpForwarding":  {"no": {}},
	"X11Forwarding":       {"no": {}},
	"MaxAuthTries":        {"4": {}},
	"ClientAliveInterval": {"300": {}},
	"ClientAliveCountMax": {"3": {}},
}

func normalizeSSHDirectives(content string, directives map[string]string) (string, error) {
	keys := make([]string, 0, len(directives))
	for key, value := range directives {
		approvedValues, approved := approvedSSHDirectives[key]
		if !approved {
			return "", fmt.Errorf("SSH directive is not approved: %s", key)
		}
		if _, approved := approvedValues[value]; !approved {
			return "", fmt.Errorf("SSH directive value is not approved: %s", key)
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	wanted := make(map[string]string, len(keys))
	for _, key := range keys {
		wanted[strings.ToLower(key)] = key
	}

	lines := strings.Split(content, "\n")
	normalized := make([]string, 0, len(lines)+len(keys))
	insertAt := -1
	for _, line := range lines {
		keyword, value, active := parseSSHDirective(line)
		if active {
			if (strings.EqualFold(keyword, "Match") || strings.EqualFold(keyword, "Include")) && insertAt < 0 {
				insertAt = len(normalized)
			}
			if canonical, managed := wanted[strings.ToLower(keyword)]; managed {
				valueFields := strings.Fields(value)
				if len(valueFields) == 1 && strings.EqualFold(valueFields[0], directives[canonical]) {
					continue
				}
				normalized = append(normalized, "# SYSWARDEN OVERRIDE: "+line)
				continue
			}
		}
		normalized = append(normalized, line)
	}
	for len(normalized) > 0 && normalized[len(normalized)-1] == "" {
		normalized = normalized[:len(normalized)-1]
	}
	if insertAt < 0 || insertAt > len(normalized) {
		insertAt = len(normalized)
	}
	replacements := make([]string, 0, len(keys))
	for _, key := range keys {
		replacements = append(replacements, key+" "+directives[key])
	}
	withDirectives := make([]string, 0, len(normalized)+len(replacements)+1)
	withDirectives = append(withDirectives, normalized[:insertAt]...)
	withDirectives = append(withDirectives, replacements...)
	withDirectives = append(withDirectives, normalized[insertAt:]...)
	withDirectives = append(withDirectives, "")
	return strings.Join(withDirectives, "\n"), nil
}

func normalizeSSHForwarding(content string) string {
	normalized, err := normalizeSSHDirectives(
		content,
		map[string]string{"AllowTcpForwarding": "no"},
	)
	if err != nil {
		panic(err)
	}
	return normalized
}
