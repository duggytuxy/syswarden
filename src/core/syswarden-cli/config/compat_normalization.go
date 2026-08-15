package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// normalizeHistoricalModularHA repairs only the complete v4.02.8 default HA
// state. That release shipped enabled=true with no token and no peers. Partial
// states, environment overrides, and operator-owned 99-user overrides are not
// rewritten and remain fail-closed validation errors.
func normalizeHistoricalModularHA(candidate *ModularConfig, sources []modularConfigSource) error {
	if candidate == nil || !candidate.Integrations.HA.Enabled ||
		candidate.Integrations.HA.Token != "" || len(candidate.Integrations.HA.PeerIPs) != 0 ||
		candidate.Integrations.BunkerWeb.Enabled {
		return nil
	}
	for _, key := range []string{
		"SYSWARDEN_INTEGRATIONS_HA_ENABLED",
		"SYSWARDEN_INTEGRATIONS_HA_TOKEN",
		"SYSWARDEN_INTEGRATIONS_HA_PEER_IPS",
		"SYSWARDEN_INTEGRATIONS_BUNKERWEB_ENABLED",
	} {
		if _, configured := os.LookupEnv(key); configured {
			return fmt.Errorf("historical HA compatibility normalization refuses to persist over environment override %s", key)
		}
	}

	normalized := *candidate
	normalized.Integrations.HA.Enabled = false
	normalized.Integrations.BunkerWeb.Enabled = false
	if err := validateConfig(&normalized); err != nil {
		return fmt.Errorf("historical HA compatibility candidate is otherwise invalid: %w", err)
	}

	var target *modularConfigSource
	var rewritten []byte
	for index := len(sources) - 1; index >= 0; index-- {
		content, found, oldValue, err := rewriteTOMLBoolAssignment(
			sources[index].content,
			"integrations.ha",
			"enabled",
			false,
		)
		if err != nil {
			return err
		}
		if !found {
			continue
		}
		if !oldValue {
			return fmt.Errorf("effective historical HA state is not backed by a persistent enabled=true assignment")
		}
		if sources[index].relative == "modules/99-user.toml" {
			return fmt.Errorf("historical HA normalization refuses to rewrite operator-owned 99-user.toml")
		}
		target = &sources[index]
		rewritten = content
		break
	}
	if target == nil {
		return fmt.Errorf("effective historical HA state cannot be normalized without rewriting an environment override")
	}

	hasBunkerAssignment := false
	hasBunkerSection := false
	for _, source := range sources {
		if tomlHasAssignment(source.content, "integrations.bunkerweb", "enabled") {
			hasBunkerAssignment = true
		}
		if tomlHasSection(source.content, "integrations.bunkerweb") {
			hasBunkerSection = true
		}
	}
	if !hasBunkerAssignment {
		if hasBunkerSection {
			return fmt.Errorf("historical HA normalization found an incomplete BunkerWeb section")
		}
		if len(rewritten) > 0 && rewritten[len(rewritten)-1] != '\n' {
			rewritten = append(rewritten, '\n')
		}
		rewritten = append(rewritten, []byte("\n[integrations.bunkerweb]\nenabled = false\n")...)
	}

	if err := replaceSecureFileAtomicallyIfUnchanged(filepath.Dir(target.path), filepath.Base(target.path), rewritten, target.identity); err != nil {
		return fmt.Errorf("persist historical HA compatibility normalization: %w", err)
	}
	*candidate = normalized
	return nil
}

func rewriteTOMLBoolAssignment(content []byte, section, key string, replacement bool) ([]byte, bool, bool, error) {
	text := string(content)
	offset := 0
	currentSection := ""
	for _, line := range strings.SplitAfter(text, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			currentSection = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(trimmed, "["), "]"))
			offset += len(line)
			continue
		}
		if currentSection != section || trimmed == "" || strings.HasPrefix(trimmed, "#") {
			offset += len(line)
			continue
		}
		equals := strings.IndexByte(line, '=')
		if equals < 0 || strings.TrimSpace(line[:equals]) != key {
			offset += len(line)
			continue
		}
		valueStart := equals + 1
		for valueStart < len(line) && (line[valueStart] == ' ' || line[valueStart] == '\t') {
			valueStart++
		}
		valueEnd := valueStart
		for valueEnd < len(line) && line[valueEnd] != ' ' && line[valueEnd] != '\t' &&
			line[valueEnd] != '#' && line[valueEnd] != '\r' && line[valueEnd] != '\n' {
			valueEnd++
		}
		raw := line[valueStart:valueEnd]
		if raw != "true" && raw != "false" {
			return nil, false, false, fmt.Errorf("%s.%s is not a TOML boolean assignment", section, key)
		}
		value := raw == "true"
		replacementText := "false"
		if replacement {
			replacementText = "true"
		}
		start := offset + valueStart
		end := offset + valueEnd
		rewritten := make([]byte, 0, len(content)+len(replacementText)-(end-start))
		rewritten = append(rewritten, content[:start]...)
		rewritten = append(rewritten, replacementText...)
		rewritten = append(rewritten, content[end:]...)
		return rewritten, true, value, nil
	}
	return nil, false, false, nil
}

func tomlHasAssignment(content []byte, section, key string) bool {
	_, found, _, err := rewriteTOMLBoolAssignment(content, section, key, false)
	return found && err == nil
}

func tomlHasSection(content []byte, section string) bool {
	needle := "[" + section + "]"
	for _, line := range strings.Split(string(content), "\n") {
		if strings.TrimSpace(line) == needle {
			return true
		}
	}
	return false
}

type legacyAssignment struct {
	start int
	end   int
	quote byte
	value bool
	found bool
}

func persistHistoricalLegacyHA(content []byte) ([]byte, error) {
	ha, err := findLegacyBoolAssignment(content, "SYSWARDEN_HA_ENABLED")
	if err != nil {
		return nil, err
	}
	if !ha.found || !ha.value {
		return nil, fmt.Errorf("historical HA state is not backed by a persistent enabled assignment")
	}
	replacement := []byte("n")
	if ha.quote != 0 {
		replacement = []byte{ha.quote, 'n', ha.quote}
	}
	rewritten := make([]byte, 0, len(content)+len(replacement)-(ha.end-ha.start))
	rewritten = append(rewritten, content[:ha.start]...)
	rewritten = append(rewritten, replacement...)
	rewritten = append(rewritten, content[ha.end:]...)

	bunker, err := findLegacyBoolAssignment(rewritten, "SYSWARDEN_BUNKERWEB_ENABLED")
	if err != nil {
		return nil, err
	}
	if bunker.found {
		if bunker.value {
			return nil, fmt.Errorf("historical HA normalization refuses an enabled BunkerWeb assignment")
		}
		return rewritten, nil
	}
	if len(rewritten) > 0 && rewritten[len(rewritten)-1] != '\n' {
		rewritten = append(rewritten, '\n')
	}
	return append(rewritten, []byte("SYSWARDEN_BUNKERWEB_ENABLED=\"n\"\n")...), nil
}

func findLegacyBoolAssignment(content []byte, key string) (legacyAssignment, error) {
	var result legacyAssignment
	offset := 0
	for _, line := range strings.SplitAfter(string(content), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			offset += len(line)
			continue
		}
		equals := strings.IndexByte(line, '=')
		if equals < 0 || strings.TrimSpace(line[:equals]) != key {
			offset += len(line)
			continue
		}
		valueStart := equals + 1
		for valueStart < len(line) && (line[valueStart] == ' ' || line[valueStart] == '\t') {
			valueStart++
		}
		if valueStart >= len(line) {
			return legacyAssignment{}, fmt.Errorf("legacy key %s has an empty assignment", key)
		}
		valueEnd := valueStart
		quote := byte(0)
		if line[valueStart] == '\'' || line[valueStart] == '"' {
			quote = line[valueStart]
			valueEnd++
			escaped := false
			for valueEnd < len(line) {
				character := line[valueEnd]
				if quote == '"' && character == '\\' && !escaped {
					escaped = true
					valueEnd++
					continue
				}
				if character == quote && !escaped {
					valueEnd++
					break
				}
				escaped = false
				valueEnd++
			}
			if valueEnd > len(line) || valueEnd == 0 || line[valueEnd-1] != quote {
				return legacyAssignment{}, fmt.Errorf("legacy key %s has an unterminated quoted value", key)
			}
		} else {
			for valueEnd < len(line) && line[valueEnd] != ' ' && line[valueEnd] != '\t' &&
				line[valueEnd] != '#' && line[valueEnd] != '\r' && line[valueEnd] != '\n' {
				valueEnd++
			}
		}
		parsed, err := parseLegacyValue(line[valueStart:])
		if err != nil {
			return legacyAssignment{}, fmt.Errorf("parse legacy key %s: %w", key, err)
		}
		value, err := parseLegacyBoolValue(key, parsed)
		if err != nil {
			return legacyAssignment{}, err
		}
		result = legacyAssignment{
			start: offset + valueStart,
			end:   offset + valueEnd,
			quote: quote,
			value: value,
			found: true,
		}
		offset += len(line)
	}
	return result, nil
}
