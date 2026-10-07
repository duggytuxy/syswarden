//go:build linux

package firewall

import (
	"context"
	"fmt"
	"net/netip"
	"os/exec"
	"reflect"
	"strings"
)

var legacyIPTablesOwnedPreflightCheck = preflightOwnedLegacyIPTables

// This read-only exception preserves the existing manifest-bound cleanup
// route. It neither adopts unowned rules nor performs a wrapper mutation.
// An opaque administrator comment is not a product marker. Duplicate matching
// rules remain ambiguous because a manifest entry does not identify a handle.
func preflightOwnedLegacyIPTables(ctx context.Context) error {
	previous, exists, migration, err := readLinuxWrapperState(linuxWrapperStateFile)
	if err != nil {
		return err
	}
	observer, err := newLegacyIPTablesObserver()
	if err != nil {
		return err
	}
	current, _, _, err := observer.observe(ctx)
	if err != nil {
		return err
	}
	if err := preflightOwnedLegacyIPTablesObservation(current, previous); err != nil {
		return err
	}
	for _, rule := range current.rules {
		if rule.chain == "INPUT" && strings.Contains(rule.line, "SYSWARDEN_CORE") {
			if err := requireLegacyIPTablesCleanupBackend(observer.identity); err != nil {
				return err
			}
			break
		}
	}
	repeated, repeatedExists, repeatedMigration, err := readLinuxWrapperState(linuxWrapperStateFile)
	if err != nil || exists != repeatedExists || migration != repeatedMigration || !sameLinuxWrapperRules(previous, repeated) {
		return fmt.Errorf("compatibility ownership changed during historical removal preflight")
	}
	return nil
}

func legacyIPTablesOwnedRuleProfile(rule linuxWrapperRule) (string, []any, error) {
	if rule.backend != "iptables" || rule.pending {
		return "", nil, fmt.Errorf("compatibility entry does not prove committed IPv4 ownership")
	}
	base := "-A INPUT"
	switch rule.kind {
	case "port":
		line := base + " -p tcp -m tcp --dport " + rule.value + " -m comment --comment SYSWARDEN_CORE -j ACCEPT"
		expressions, err := legacyIPTablesGeneratedExpression(line)
		return line, expressions, err
	case "source":
		value := rule.value
		if address, err := netip.ParseAddr(value); err == nil && address.Is4() {
			value += "/32"
		}
		prefix, err := netip.ParsePrefix(value)
		if err != nil || !prefix.Addr().Is4() || prefix != prefix.Masked() {
			return "", nil, fmt.Errorf("compatibility source is not a canonical IPv4 input")
		}
		if prefix.Bits() != 0 {
			base += " -s " + value
		}
	default:
		return "", nil, fmt.Errorf("unsupported compatibility ownership kind")
	}
	expressions, err := legacyIPTablesGeneratedExpression(base + " -j ACCEPT")
	if err != nil {
		return "", nil, err
	}
	comment := map[string]any{"xt": map[string]any{"type": "match", "name": "comment"}}
	index := len(expressions) - 2
	result := append([]any{}, expressions[:index]...)
	result = append(result, comment)
	result = append(result, expressions[index:]...)
	return base + " -m comment --comment SYSWARDEN_CORE -j ACCEPT", result, nil
}

func preflightOwnedLegacyIPTablesObservation(current legacyIPTablesObservation, owned map[string]linuxWrapperRule) error {
	seen := make(map[string]bool)
	profiles := legacyIPTablesOwnedProfiles(owned)
	for _, observed := range current.rules {
		entry, valid := observed.entry.(map[string]any)
		value, body := entry["rule"].(map[string]any)
		if !valid || !body {
			return fmt.Errorf("invalid compatibility rule observation")
		}
		if observed.chain != "INPUT" {
			continue
		}
		if value["comment"] != "SYSWARDEN_CORE" && !strings.Contains(observed.line, "SYSWARDEN_CORE") {
			continue
		}
		profile, exists := profiles[observed.line]
		if !exists || profile.key == "" || seen[profile.key] {
			return legacyIPTablesRemovalRefusal()
		}
		if !legacyFail2banNFTFields(value, "family table chain handle expr", "") ||
			value["family"] != "ip" || value["table"] != "filter" || value["chain"] != "INPUT" || !reflect.DeepEqual(value["expr"], profile.expressions) {
			return fmt.Errorf("compatibility ownership does not identify one exact unmodified rule")
		}
		seen[profile.key] = true
	}
	return nil
}

// Pin the writer as well as its observer. A manifest does not distinguish
// iptables alternatives, so a different active backend cannot consume it.
func requireLegacyIPTablesCleanupBackend(expected nftExecutableIdentity) error {
	path, err := exec.LookPath("iptables")
	if err != nil {
		return err
	}
	path, err = resolveLinuxWrapperExecutable(path)
	if err != nil {
		return err
	}
	writer, observed, err := pinNFTExecutable(path)
	if err != nil {
		return err
	}
	closeErr := writer.Close()
	if closeErr != nil || observed != expected {
		return fmt.Errorf("owned compatibility rules have no matching active cleanup backend")
	}
	return nil
}

type legacyIPTablesOwnedProfile struct {
	key         string
	expressions []any
}

func legacyIPTablesOwnedProfiles(owned map[string]linuxWrapperRule) map[string]legacyIPTablesOwnedProfile {
	profiles := make(map[string]legacyIPTablesOwnedProfile)
	for key, rule := range owned {
		line, expressions, err := legacyIPTablesOwnedRuleProfile(rule)
		if err != nil {
			continue
		}
		if _, duplicate := profiles[line]; duplicate {
			profiles[line] = legacyIPTablesOwnedProfile{}
		} else {
			profiles[line] = legacyIPTablesOwnedProfile{key, expressions}
		}
	}
	return profiles
}
