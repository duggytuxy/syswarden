package firewall

import (
	"fmt"
	"strconv"
	"strings"
	"unicode"
)

// canonicalHoneyPorts validates the legacy flat representation and returns the
// kernel syntax shared by nftables and PF. The order configured by the operator
// is preserved, but every value must already use its canonical decimal form.
func canonicalHoneyPorts(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", fmt.Errorf("honeyport list is empty")
	}

	for _, r := range trimmed {
		if !unicode.IsDigit(r) && r != ',' && !unicode.IsSpace(r) {
			return "", fmt.Errorf("honeyport list contains an invalid character %q", r)
		}
	}

	if strings.Contains(trimmed, ",") {
		for _, group := range strings.Split(trimmed, ",") {
			if strings.TrimSpace(group) == "" {
				return "", fmt.Errorf("honeyport list contains an empty item")
			}
		}
	}

	items := strings.FieldsFunc(trimmed, func(r rune) bool {
		return r == ',' || unicode.IsSpace(r)
	})
	if len(items) == 0 {
		return "", fmt.Errorf("honeyport list is empty")
	}

	seen := make(map[int]string, len(items))
	canonical := make([]string, 0, len(items))
	for _, item := range items {
		port, err := strconv.Atoi(item)
		if err != nil || port < 1 || port > 65535 {
			return "", fmt.Errorf("invalid honeyport %q: expected an integer between 1 and 65535", item)
		}
		value := strconv.Itoa(port)
		if item != value {
			return "", fmt.Errorf("honeyport %q is not in canonical decimal form", item)
		}
		if previous, exists := seen[port]; exists {
			return "", fmt.Errorf("duplicate honeyport %q (already declared as %q)", item, previous)
		}
		seen[port] = item
		canonical = append(canonical, value)
	}

	return strings.Join(canonical, ", "), nil
}
