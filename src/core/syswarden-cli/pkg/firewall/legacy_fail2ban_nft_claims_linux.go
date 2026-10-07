//go:build linux

package firewall

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/netip"
	"reflect"
	"sort"
	"strings"
)

// These are complete CommandAction data profiles produced by the Debian
// 1.1.0-8 reader from the exact default nftables-allports action or the exact
// historical SysWarden action. Only the jail name and properties unused by
// these kernel expressions are normalized. Every hook and address-family
// substitution remains part of the fingerprint. No hook is evaluated here.
const (
	legacyFail2banUpstreamNFTActionProfile = "b1bd6d435dcfaad124ab19267d51f7928869ec2416ad4ee05924fb05a94b6096"
	legacyFail2banHistoricalNFTProfile     = "9667dd031ef3e5b3e31611dd5a3e6ce0baa76d029c8dc9edb478e688d2552f0f"
)

func verifyLegacyFail2banNFTActionProfile(jail, profile string, properties map[string]legacyFail2banValue) error {
	if !validLegacyFail2banJailName(jail) || jail[0] == '-' || len(properties) > 128 ||
		properties["name"].kind != 's' || properties["name"].text != jail ||
		properties["actname"].kind != 's' || properties["actname"].text != profile ||
		properties["timeout"].kind != 'i' || properties["timeout"].number <= 0 || properties["timeout"].number > 86400 ||
		properties["banEpoch"].kind != 'i' || properties["banEpoch"].number != 0 {
		return fmt.Errorf("Fail2ban nftables action lacks an exact supported data profile")
	}
	expected := legacyFail2banHistoricalNFTProfile
	if profile == "nftables-allports" {
		expected = legacyFail2banUpstreamNFTActionProfile
	} else if profile != "syswarden-nft" {
		return fmt.Errorf("unsupported historical Fail2ban firewall action")
	}
	var names []string
	for name := range properties {
		names = append(names, name)
	}
	sort.Strings(names)
	var records [][]any
	for _, name := range names {
		value := properties[name]
		if name == "timeout" || name == "banEpoch" {
			continue
		}
		if name == "port" || profile == "syswarden-nft" && (name == "protocol" || name == "chain") {
			// The complete recognized hooks contain no such placeholder.
			// Optional generic jail parameters cannot affect these profiles.
			if value.kind != 's' || len(value.text) > 256 {
				return fmt.Errorf("unsupported unused Fail2ban action parameter")
			}
			continue
		}
		if profile == "nftables-allports" && name == "chain" && value.kind == 's' && value.text == "<known/chain>" {
			// Debian's complete jail defaults retain this alias as public data
			// after resolving every action hook to the literal f2b-chain.
			// Only this exact alias is equivalent; all resolved hooks and all
			// other properties still participate in the complete fingerprint.
			value.text = "f2b-chain"
		}
		var primitive any
		switch value.kind {
		case 's':
			primitive = strings.ReplaceAll(value.text, jail, "<jail>")
		case 'r':
			primitive = value.text
		case 'i':
			primitive = value.number
		default:
			return fmt.Errorf("unsupported Fail2ban nftables action value")
		}
		records = append(records, []any{name, string(value.kind), primitive})
	}
	encoded, err := json.Marshal(records)
	if err != nil || fmt.Sprintf("%x", sha256.Sum256(encoded)) != expected {
		return fmt.Errorf("Fail2ban nftables action differs from its complete supported profile")
	}
	return nil
}

func legacyFail2banOwnedJails(host nftPersistenceFilesystem, plan legacyFail2banRetirementPlan) (map[string]legacyFail2banTemplateMatch, legacyFail2banInventory, error) {
	var empty legacyFail2banInventory
	_, digest, err := encodeLegacyFail2banPlan(plan.binding, host.expectedUID, host.expectedGID)
	if err != nil || digest != plan.sha256 {
		return nil, empty, fmt.Errorf("Fail2ban ownership file plan differs from its reviewed digest")
	}
	state, err := inspectLegacyFail2banPlanState(host, plan.binding)
	if err != nil || len(state.retired) != 0 {
		return nil, empty, fmt.Errorf("fresh Fail2ban ownership claims require intact original configuration")
	}
	selected := make(map[string]bool)
	for _, path := range plan.binding.Targets {
		selected[path] = true
	}
	jails := make(map[string]legacyFail2banTemplateMatch)
	for _, source := range state.baseline.sources {
		if !selected[source.path] {
			continue
		}
		match, exact := matchLegacyFail2banTemplate(source.path, source.snapshot.content)
		if !exact {
			return nil, empty, fmt.Errorf("Fail2ban retirement target lost complete source provenance")
		}
		if match.kind == "jail" {
			if _, exists := jails[match.jail]; exists {
				return nil, empty, fmt.Errorf("Fail2ban ownership has duplicate jail provenance")
			}
			jails[match.jail] = match
		}
	}
	if len(jails) == 0 {
		return nil, empty, fmt.Errorf("Fail2ban file plan contains no owned jail")
	}
	return jails, state.baseline, nil
}

func verifyLegacyFail2banNFTActionSources(inventory legacyFail2banInventory, profile string) error {
	wanted := map[string]string{
		"/etc/fail2ban/action.d/syswarden-nft.conf": "a5386f5d303ee719d7ab5e15f3243226f8301aaceae2a6ba816e5ca926b1171b",
	}
	if profile == "nftables-allports" {
		// Exact packaged defaults. Local overlays still contribute to the
		// independently compared configured/live action profile above.
		wanted = map[string]string{
			"/etc/fail2ban/action.d/nftables.conf":          "9f22efdb0c6835202781559d261e87375d8a56e400847bf8664fd23c91b1d51a",
			"/etc/fail2ban/action.d/nftables-allports.conf": "68558b09a2c7a9d013d770ae0d09e9323c08c3fcf260718f49611ec357662ee7",
		}
	} else if profile != "syswarden-nft" {
		return fmt.Errorf("unsupported Fail2ban nftables source profile")
	}
	for _, source := range inventory.sources {
		expected, found := wanted[source.path]
		if !found {
			continue
		}
		if source.sha256 != sha256.Sum256(source.snapshot.content) || fmt.Sprintf("%x", source.sha256) != expected {
			return fmt.Errorf("Fail2ban action source differs from its complete supported template")
		}
		delete(wanted, source.path)
	}
	if len(wanted) != 0 {
		return fmt.Errorf("Fail2ban action source provenance is incomplete")
	}
	return nil
}

// Bind fresh kernel claims before any hook is neutralized. This function joins
// complete file provenance, an immutable parser view and the separately
// authenticated runtime snapshot. It does not itself attest the producer of
// that snapshot; the production entry point below performs that inspection.
func bindLegacyFail2banNFTClaims(host nftPersistenceFilesystem, plan legacyFail2banRetirementPlan, parserSHA [sha256.Size]byte, actionsSource []byte, live legacyFail2banRuntimeSnapshot) ([]legacyFail2banNFTClaim, error) {
	if parserSHA != plan.binding.ParserSHA256 {
		return nil, fmt.Errorf("Fail2ban kernel claims require the file plan's exact parser")
	}
	jails, inventory, err := legacyFail2banOwnedJails(host, plan)
	if err != nil {
		return nil, err
	}
	expected, err := decodeLegacyFail2banConfiguredActions(actionsSource)
	if err != nil {
		return nil, err
	}
	if err := verifyLegacyFail2banConfiguredRuntime(expected, live); err != nil {
		return nil, err
	}
	var names []string
	for name := range jails {
		names = append(names, name)
	}
	sort.Strings(names)
	var claims []legacyFail2banNFTClaim
	for _, name := range names {
		profile := jails[name].banaction
		actions, configured := expected[name]
		if !configured || len(actions) != 1 {
			return nil, fmt.Errorf("historical Fail2ban jail requires separate recovery for absent or additional actions")
		}
		properties, found := actions[profile]
		if !found {
			return nil, fmt.Errorf("historical Fail2ban jail uses a different effective action")
		}
		if err := verifyLegacyFail2banNFTActionSources(inventory, profile); err != nil {
			return nil, err
		}
		if err := verifyLegacyFail2banNFTActionProfile(name, profile, properties); err != nil {
			return nil, err
		}
		families := []string{"ip"}
		if profile == "nftables-allports" {
			families = append(families, "ip6")
		}
		bans := map[string][]string{"ip": {}, "ip6": {}}
		seen := make(map[string]bool)
		for _, record := range live.jails[name].bans {
			text, timing, found := strings.Cut(record, "\t")
			address, err := netip.ParseAddr(strings.TrimSpace(text))
			if !found || timing == "" || err != nil || address.Zone() != "" || address.Is4In6() || seen[address.String()] {
				return nil, fmt.Errorf("Fail2ban kernel claims require exact individual ban addresses")
			}
			seen[address.String()] = true
			family := "ip6"
			if address.Is4() {
				family = "ip"
			} else if profile != "nftables-allports" {
				return nil, fmt.Errorf("historical Fail2ban action has unsupported IPv6 ban evidence")
			}
			bans[family] = append(bans[family], address.String())
		}
		for _, family := range families {
			sort.Strings(bans[family])
			claims = append(claims, legacyFail2banNFTClaim{name, profile, family, plan.sha256, fmt.Sprintf("%x", sha256.Sum256(actionsSource)), bans[family]})
		}
	}
	return claims, nil
}

func inspectLegacyFail2banNFTClaims(ctx context.Context, host nftPersistenceFilesystem, plan legacyFail2banRetirementPlan, inspection *legacyFail2banServiceInspection) ([]legacyFail2banNFTClaim, error) {
	if inspection == nil {
		return nil, fmt.Errorf("Fail2ban kernel claims require an inspected service")
	}
	probe := legacyFail2banConfigurationProbeUsingParser(host, inspection.parser)
	view, err := probe(cloneLegacyFail2banInventory(inspection.inventory), nil)
	if err != nil || sha256.Sum256(view.enabled) != plan.binding.Views[0] || sha256.Sum256(view.allJails) != plan.binding.Views[1] ||
		!bytes.Equal(view.actionsEnabled, inspection.actionsSource) || view.parserSHA256 != plan.binding.ParserSHA256 {
		return nil, fmt.Errorf("Fail2ban kernel claims differ from the file plan's independently resolved actions")
	}
	live, err := inspection.runtime(ctx)
	if err != nil {
		return nil, err
	}
	expected, err := decodeLegacyFail2banConfiguredActions(inspection.actionsSource)
	if err != nil || !reflect.DeepEqual(expected, inspection.actions) {
		return nil, fmt.Errorf("Fail2ban kernel claim action evidence changed")
	}
	claims, err := bindLegacyFail2banNFTClaims(host, plan, inspection.parser.digest, inspection.actionsSource, live)
	if err != nil {
		return nil, err
	}
	if err := inspection.verify(ctx); err != nil {
		return nil, err
	}
	return claims, nil
}
