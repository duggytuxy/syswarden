//go:build linux

package network

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"syswarden-cli/pkg/wireguardstate"
	"testing"
)

type fakeLegacyWireGuardNFTState struct {
	tablePresent      bool
	tableHandle       uint64
	forwardRules      map[string][]LegacyWireGuardForwardRuleEvidence
	batches           []string
	batchErr          error
	replaceAfterApply bool
}

func (state *fakeLegacyWireGuardNFTState) Run(_ context.Context, args ...string) ([]byte, error) {
	switch strings.Join(args, " ") {
	case "-a -j list tables":
		if !state.tablePresent {
			return []byte(`{"nftables":[{"metainfo":{"json_schema_version":1}}]}`), nil
		}
		return []byte(fmt.Sprintf(
			`{"nftables":[{"metainfo":{"json_schema_version":1}},{"table":{"family":"inet","name":"syswarden_wg","handle":%d}}]}`,
			state.tableHandle,
		)), nil
	case "-a -j list table inet syswarden_wg":
		if !state.tablePresent {
			return nil, errors.New("table absent")
		}
		return []byte(fmt.Sprintf(`{"nftables":[
{"metainfo":{"json_schema_version":1}},
{"table":{"family":"inet","name":"syswarden_wg","handle":%d}},
{"chain":{"family":"inet","table":"syswarden_wg","name":"prerouting","type":"nat","hook":"prerouting","prio":-100,"policy":"accept","handle":8}},
{"chain":{"family":"inet","table":"syswarden_wg","name":"postrouting","type":"nat","hook":"postrouting","prio":100,"policy":"accept","handle":9}},
{"rule":{"family":"inet","table":"syswarden_wg","chain":"postrouting","expr":[{"match":{"op":"==","left":{"meta":{"key":"oifname"}},"right":"ens3"}},{"masquerade":null}],"handle":11}}
]}`, state.tableHandle)), nil
	case "-a -j list chain inet filter forward":
		parts := []string{
			`{"metainfo":{"json_schema_version":1}}`,
			`{"table":{"family":"inet","name":"filter","handle":1}}`,
			`{"chain":{"family":"inet","table":"filter","name":"forward","type":"filter","hook":"forward","prio":0,"policy":"drop","handle":2}}`,
			`{"rule":{"family":"inet","table":"filter","chain":"forward","expr":[{"match":{"op":"==","left":{"meta":{"key":"l4proto"}},"right":"tcp"}},{"accept":null}],"handle":90}}`,
		}
		for _, interfaceName := range []string{"wg0", "wg-syswarden"} {
			for _, rule := range state.forwardRules[interfaceName] {
				parts = append(parts, fmt.Sprintf(
					`{"rule":{"family":"inet","table":"filter","chain":"forward","expr":[{"match":{"op":"==","left":{"meta":{"key":"%s"}},"right":"%s"}},{"accept":null}],"handle":%d}}`,
					rule.Direction, interfaceName, rule.Handle,
				))
			}
		}
		return []byte(`{"nftables":[` + strings.Join(parts, ",") + `]}`), nil
	default:
		return nil, fmt.Errorf("unexpected nft request %q", strings.Join(args, " "))
	}
}

func (state *fakeLegacyWireGuardNFTState) apply(_ context.Context, script string) ([]byte, error) {
	state.batches = append(state.batches, script)
	if state.batchErr != nil {
		return []byte("synthetic nft rejection"), state.batchErr
	}
	for interfaceName, rules := range state.forwardRules {
		remaining := make([]LegacyWireGuardForwardRuleEvidence, 0, len(rules))
		for _, rule := range rules {
			line := fmt.Sprintf("delete rule inet filter forward handle %d\n", rule.Handle)
			if !strings.Contains(script, line) {
				remaining = append(remaining, rule)
			}
		}
		state.forwardRules[interfaceName] = remaining
	}
	if strings.Contains(script, fmt.Sprintf("delete table inet handle %d\n", state.tableHandle)) {
		state.tablePresent = false
	}
	if state.replaceAfterApply {
		state.tablePresent = true
		state.tableHandle = 99
	}
	return nil, nil
}

func historicalWireGuardTestConfiguration(interfaceName string) []byte {
	key := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	var postUp string
	switch interfaceName {
	case "wg0":
		// Exact nftables PostUp bytes from f768a763^.
		postUp = `nft 'add table inet syswarden_wg'; nft 'add chain inet syswarden_wg prerouting { type nat hook prerouting priority dstnat; }'; nft 'add chain inet syswarden_wg postrouting { type nat hook postrouting priority srcnat; }'; nft 'add rule inet syswarden_wg postrouting oifname "ens3" masquerade'; nft 'add chain inet filter forward { type filter hook forward priority 0; }' 2>/dev/null || true; nft 'insert rule inet filter forward iifname "wg0" accept'; nft 'insert rule inet filter forward oifname "wg0" accept'`
	case "wg-syswarden":
		// Exact nftables PostUp bytes from v4.02.8 after 295275ba added
		// the bounded shared-table creation attempt.
		postUp = `nft 'add table inet syswarden_wg'; nft 'add chain inet syswarden_wg prerouting { type nat hook prerouting priority dstnat; }'; nft 'add chain inet syswarden_wg postrouting { type nat hook postrouting priority srcnat; }'; nft 'add rule inet syswarden_wg postrouting oifname "ens3" masquerade'; nft 'add table inet filter' 2>/dev/null || true; nft 'add chain inet filter forward { type filter hook forward priority 0; }' 2>/dev/null || true; nft 'insert rule inet filter forward iifname "wg-syswarden" accept'; nft 'insert rule inet filter forward oifname "wg-syswarden" accept'`
	default:
		panic("unsupported historical WireGuard test interface")
	}
	return []byte(fmt.Sprintf(`[Interface]
Address = 10.66.66.1/24
ListenPort = 51820
PrivateKey = %s
PostUp = %s
PostDown = %s

[Peer]
PublicKey = %s
PresharedKey = %s
AllowedIPs = 10.66.66.2/32
`, key, postUp,
		legacyWireGuardPostDown(interfaceName), key, key))
}

func writeHistoricalWireGuardTestConfiguration(t *testing.T, root, interfaceName string) {
	t.Helper()
	directory := filepath.Join(root, "etc", "wireguard")
	if err := os.MkdirAll(directory, 0755); err != nil { // #nosec G301 -- fixture models the protected system WireGuard directory beneath t.TempDir
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(root, "etc"), 0755); err != nil { // #nosec G302 -- fixture must reproduce the attested system configuration parent mode
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0755); err != nil { // #nosec G302 -- fixture must reproduce the attested system WireGuard directory mode
		t.Fatal(err)
	}
	path := filepath.Join(directory, interfaceName+".conf")
	if err := os.WriteFile(path, historicalWireGuardTestConfiguration(interfaceName), 0600); err != nil { // #nosec G703 -- path is confined to the private fixture root and interfaceName is a fixed historical generation
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
}

func writeHistoricalOpenRCService(t *testing.T, root, interfaceName string) {
	t.Helper()
	directory := filepath.Join(root, "etc", "init.d")
	if err := os.MkdirAll(directory, 0755); err != nil { // #nosec G301 -- fixture models the protected system OpenRC directory beneath t.TempDir
		t.Fatal(err)
	}
	path := filepath.Join(directory, "wg-quick."+interfaceName)
	if err := os.WriteFile(path, []byte("#!/sbin/openrc-run\n"), 0755); err != nil { // #nosec G306 G703 -- executable mode is required and the fixed service name is confined to the private fixture root
		t.Fatal(err)
	}
}

func legacyWireGuardFixtureIdentity(t *testing.T, root string) (uint32, uint32) {
	t.Helper()
	info, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}
	identity, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("private legacy WireGuard fixture root has no Linux stat identity")
	}
	return identity.Uid, identity.Gid
}

func fakeLegacyWireGuardServiceOutput(active, enabled, present bool) wireGuardServiceOutputRunner {
	return func(name string, args ...string) ([]byte, error) {
		command := strings.Join(append([]string{name}, args...), " ")
		switch {
		case strings.HasPrefix(command, "systemctl show ") && strings.Contains(command, "--property=LoadState --value"):
			return []byte("loaded\n"), nil
		case strings.HasPrefix(command, "systemctl show ") && strings.Contains(command, "--property=ActiveState --value"):
			if active {
				return []byte("active\n"), nil
			}
			return []byte("inactive\n"), nil
		case strings.HasPrefix(command, "systemctl show ") && strings.Contains(command, "--property=UnitFileState --value"):
			if enabled {
				return []byte("enabled\n"), nil
			}
			return []byte("disabled\n"), nil
		case command == "wg show interfaces":
			if present {
				return []byte("wg0\n"), nil
			}
			return []byte("\n"), nil
		default:
			return nil, fmt.Errorf("unexpected service inspection %q", command)
		}
	}
}

func newLegacyWireGuardTestHost(
	t *testing.T,
	interfaceName string,
	rules []LegacyWireGuardForwardRuleEvidence,
) (legacyWireGuardRecoveryHost, *fakeLegacyWireGuardNFTState) {
	t.Helper()
	root := t.TempDir()
	uid, gid := legacyWireGuardFixtureIdentity(t, root)
	writeHistoricalWireGuardTestConfiguration(t, root, interfaceName)
	state := &fakeLegacyWireGuardNFTState{
		tablePresent: true,
		tableHandle:  7,
		forwardRules: map[string][]LegacyWireGuardForwardRuleEvidence{
			"wg0":          {},
			"wg-syswarden": {},
		},
	}
	state.forwardRules[interfaceName] = append([]LegacyWireGuardForwardRuleEvidence{}, rules...)
	host := legacyWireGuardRecoveryHost{
		filesystemRoot: root,
		expectedUID:    uid,
		expectedGID:    gid,
		effectiveUID:   func() int { return 0 },
		managerState:   func() (string, error) { return "ACTIVE", nil },
		isAlpine:       func() bool { return false },
		commandOutput:  fakeLegacyWireGuardServiceOutput(false, false, false),
		nftRunner:      state,
		nftBatch:       state.apply,
		guard:          func() (func() error, error) { return func() error { return nil }, nil },
	}
	return host, state
}

func TestLegacyWireGuardRecoveryAcceptsBoundedPartialWG0Cleanup_SW2_WGRECOVERY_001(t *testing.T) {
	for _, rules := range [][]LegacyWireGuardForwardRuleEvidence{
		{},
		{{Direction: "iifname", Handle: 17}},
		{{Direction: "iifname", Handle: 17}, {Direction: "oifname", Handle: 18}},
	} {
		host, _ := newLegacyWireGuardTestHost(t, "wg0", rules)
		plan, err := host.inspect()
		if err != nil {
			t.Fatalf("inspect %d remaining rules: %v", len(rules), err)
		}
		if !plan.SafeToApply || plan.Generation != legacyWireGuardGenerationWG0 ||
			plan.HistoricalInterface != "wg0" || plan.ForwardRules == nil ||
			!reflect.DeepEqual(plan.ForwardRules, rules) {
			t.Fatalf("unexpected partial-cleanup plan: %#v", plan)
		}
	}
}

func TestLegacyWireGuardRecoveryDryRunIsDeterministicAndRedacted_SW2_WGRECOVERY_002(t *testing.T) {
	host, state := newLegacyWireGuardTestHost(t, "wg-syswarden", []LegacyWireGuardForwardRuleEvidence{
		{Direction: "iifname", Handle: 17},
		{Direction: "oifname", Handle: 18},
	})
	first, err := host.inspect()
	if err != nil {
		t.Fatal(err)
	}
	second, err := host.inspect()
	if err != nil {
		t.Fatal(err)
	}
	firstDigest, err := LegacyWireGuardRecoveryPlanSHA256(first)
	if err != nil {
		t.Fatal(err)
	}
	secondDigest, err := LegacyWireGuardRecoveryPlanSHA256(second)
	if err != nil {
		t.Fatal(err)
	}
	if firstDigest != secondDigest || !reflect.DeepEqual(first, second) {
		t.Fatalf("dry-run plan is not deterministic: %s != %s", firstDigest, secondDigest)
	}
	wire, err := RenderLegacyWireGuardRecoveryPlan(first)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"PrivateKey", "PresharedKey", "AAAAAAAAAAAAAAAA"} {
		if strings.Contains(string(wire), secret) {
			t.Fatalf("rendered plan leaks %q: %s", secret, wire)
		}
	}
	if len(state.batches) != 0 {
		t.Fatalf("dry run mutated nftables: %v", state.batches)
	}
}

func TestLegacyWireGuardRecoveryAppliesOnlyExactDigestAndHandles_SW2_WGRECOVERY_003(t *testing.T) {
	host, state := newLegacyWireGuardTestHost(t, "wg0", []LegacyWireGuardForwardRuleEvidence{
		{Direction: "oifname", Handle: 18},
	})
	plan, err := host.inspect()
	if err != nil {
		t.Fatal(err)
	}
	digest, err := LegacyWireGuardRecoveryPlanSHA256(plan)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := host.apply(strings.Repeat("0", 64)); err == nil || !strings.Contains(err.Error(), "digest mismatch") {
		t.Fatalf("wrong digest was not refused: %v", err)
	}
	if len(state.batches) != 0 {
		t.Fatalf("wrong digest reached mutation: %v", state.batches)
	}
	result, err := host.apply(digest)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(result, plan) || state.tablePresent || len(state.batches) != 1 {
		t.Fatalf("unexpected recovery result=%#v state=%#v", result, state)
	}
	want := "delete rule inet filter forward handle 18\ndelete table inet handle 7\n"
	if state.batches[0] != want {
		t.Fatalf("atomic handle batch = %q, want %q", state.batches[0], want)
	}
}

func TestLegacyWireGuardRecoveryRejectsConflictingGenerationAndUnsafeConfig_SW2_WGRECOVERY_004(t *testing.T) {
	host, _ := newLegacyWireGuardTestHost(t, "wg0", nil)
	writeHistoricalWireGuardTestConfiguration(t, host.filesystemRoot, "wg-syswarden")
	if _, err := host.inspect(); err == nil || !strings.Contains(err.Error(), "multiple historical") {
		t.Fatalf("ambiguous historical configurations were not refused: %v", err)
	}

	host, state := newLegacyWireGuardTestHost(t, "wg0", nil)
	state.forwardRules["wg-syswarden"] = []LegacyWireGuardForwardRuleEvidence{{Direction: "iifname", Handle: 44}}
	if _, err := host.inspect(); err == nil || !strings.Contains(err.Error(), "conflicting historical interface") {
		t.Fatalf("conflicting generation rule was not refused: %v", err)
	}

	host, _ = newLegacyWireGuardTestHost(t, "wg0", nil)
	path := filepath.Join(host.filesystemRoot, "etc", "wireguard", "wg0.conf")
	if err := os.Chmod(path, 0644); err != nil { // #nosec G302 -- adversarial fixture deliberately proves a group-readable private key is rejected
		t.Fatal(err)
	}
	if _, err := host.inspect(); err == nil || !strings.Contains(err.Error(), "owner-only") {
		t.Fatalf("unsafe historical configuration was not refused: %v", err)
	}

	host, _ = newLegacyWireGuardTestHost(t, "wg0", nil)
	path = filepath.Join(host.filesystemRoot, "etc", "wireguard", "wg0.conf")
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/passwd", path); err != nil {
		t.Fatal(err)
	}
	if _, err := host.inspect(); err == nil || !strings.Contains(err.Error(), "owner-only") {
		t.Fatalf("symlinked historical configuration was not refused: %v", err)
	}
}

func TestLegacyWireGuardRecoveryReattestsStateUnderGuard_SW2_WGRECOVERY_005(t *testing.T) {
	host, state := newLegacyWireGuardTestHost(t, "wg0", nil)
	plan, err := host.inspect()
	if err != nil {
		t.Fatal(err)
	}
	digest, err := LegacyWireGuardRecoveryPlanSHA256(plan)
	if err != nil {
		t.Fatal(err)
	}
	host.guard = func() (func() error, error) {
		state.tableHandle = 99
		return func() error { return nil }, nil
	}
	if _, err := host.apply(digest); err == nil || !strings.Contains(err.Error(), "changed before guarded attestation") {
		t.Fatalf("guarded state drift was not refused: %v", err)
	}
	if len(state.batches) != 0 {
		t.Fatalf("drift reached mutation: %v", state.batches)
	}
}

func TestLegacyWireGuardRecoveryRequiresInactiveDisabledService_SW2_WGRECOVERY_006(t *testing.T) {
	host, _ := newLegacyWireGuardTestHost(t, "wg0", nil)
	host.commandOutput = fakeLegacyWireGuardServiceOutput(true, true, true)
	plan, err := host.inspect()
	if err != nil {
		t.Fatal(err)
	}
	if plan.SafeToApply || len(plan.Blockers) != 3 {
		t.Fatalf("active historical runtime was not blocked: %#v", plan)
	}
}

func TestLegacyWireGuardRecoveryCanonicalPlanAllowsNoSharedRules_SW2_WGRECOVERY_007(t *testing.T) {
	host, _ := newLegacyWireGuardTestHost(t, "wg0", nil)
	plan, err := host.inspect()
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.ForwardRules) != 0 || plan.ForwardRules == nil {
		t.Fatalf("empty remaining-rule evidence is not canonical: %#v", plan.ForwardRules)
	}
	if _, err := LegacyWireGuardRecoveryPlanSHA256(plan); err != nil {
		t.Fatal(err)
	}
	plan.ForwardRules = nil
	if _, err := LegacyWireGuardRecoveryPlanSHA256(plan); err == nil {
		t.Fatal("nil forward-rule evidence was accepted")
	}
}

func TestLegacyWireGuardRecoveryRejectsMalformedHistoricalTable_SW2_WGRECOVERY_008(t *testing.T) {
	host, state := newLegacyWireGuardTestHost(t, "wg0", nil)
	ctx := context.Background()
	valid, err := state.Run(ctx, "-a", "-j", "list", "table", "inet", "syswarden_wg")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		wire []byte
	}{
		{
			name: "tokenized table",
			wire: bytes.Replace(valid,
				[]byte(`"name":"syswarden_wg","handle":7`),
				[]byte(`"name":"syswarden_wg","comment":"syswarden-wg-v1:`+strings.Repeat("a", 64)+`","handle":7`), 1),
		},
		{
			name: "extra chain",
			wire: bytes.Replace(valid, []byte(`]}`), []byte(
				`,{"chain":{"family":"inet","table":"syswarden_wg","name":"forward","type":"filter","hook":"forward","prio":0,"policy":"accept","handle":12}}]}`,
			), 1),
		},
		{
			name: "extra rule",
			wire: bytes.Replace(valid, []byte(`]}`), []byte(
				`,{"rule":{"family":"inet","table":"syswarden_wg","chain":"postrouting","expr":[{"match":{"op":"==","left":{"meta":{"key":"oifname"}},"right":"ens3"}},{"masquerade":null}],"handle":13}}]}`,
			), 1),
		},
		{
			name: "wrong chain policy",
			wire: bytes.Replace(valid, []byte(`"policy":"accept","handle":8`), []byte(`"policy":"drop","handle":8`), 1),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := validateLegacyWireGuardNFTTable(test.wire, 7); err == nil {
				t.Fatal("malformed historical table was accepted")
			}
		})
	}
	if _, err := validateLegacyWireGuardNFTTable(valid, 99); err == nil || !strings.Contains(err.Error(), "not stable") {
		t.Fatalf("inventory/detail handle drift was not refused: %v", err)
	}
	_ = host
}

func TestLegacyWireGuardRecoveryRejectsDuplicateForwardDirection_SW2_WGRECOVERY_009(t *testing.T) {
	host, state := newLegacyWireGuardTestHost(t, "wg0", nil)
	state.forwardRules["wg0"] = []LegacyWireGuardForwardRuleEvidence{
		{Direction: "iifname", Handle: 17},
		{Direction: "iifname", Handle: 18},
	}
	if _, err := host.inspect(); err == nil || !strings.Contains(err.Error(), "direction iifname") {
		t.Fatalf("duplicate forward direction was not refused: %v", err)
	}
}

func TestLegacyWireGuardRecoveryReportsAtomicFailureAndReplacement_SW2_WGRECOVERY_010(t *testing.T) {
	host, state := newLegacyWireGuardTestHost(t, "wg0", nil)
	plan, err := host.inspect()
	if err != nil {
		t.Fatal(err)
	}
	digest, err := LegacyWireGuardRecoveryPlanSHA256(plan)
	if err != nil {
		t.Fatal(err)
	}
	state.batchErr = errors.New("batch rejected")
	if _, err := host.apply(digest); err == nil || !strings.Contains(err.Error(), "synthetic nft rejection") {
		t.Fatalf("nft batch failure was not reported: %v", err)
	}
	if !state.tablePresent {
		t.Fatal("failed atomic batch changed the fake table")
	}

	host, state = newLegacyWireGuardTestHost(t, "wg0", nil)
	plan, err = host.inspect()
	if err != nil {
		t.Fatal(err)
	}
	digest, err = LegacyWireGuardRecoveryPlanSHA256(plan)
	if err != nil {
		t.Fatal(err)
	}
	state.replaceAfterApply = true
	if _, err := host.apply(digest); err == nil || !strings.Contains(err.Error(), "replacement") {
		t.Fatalf("post-apply replacement was not reported: %v", err)
	}
}

func TestLegacyWireGuardRecoveryRejectsConfigurationDriftUnderGuard_SW2_WGRECOVERY_011(t *testing.T) {
	host, state := newLegacyWireGuardTestHost(t, "wg0", nil)
	plan, err := host.inspect()
	if err != nil {
		t.Fatal(err)
	}
	digest, err := LegacyWireGuardRecoveryPlanSHA256(plan)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(host.filesystemRoot, "etc", "wireguard", "wg0.conf")
	host.guard = func() (func() error, error) {
		content, readErr := os.ReadFile(path) // #nosec G304 -- path is the fixed historical configuration beneath the private fixture root
		if readErr != nil {
			return nil, readErr
		}
		content = bytes.ReplaceAll(
			content,
			[]byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="),
			[]byte("AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="),
		)
		if writeErr := os.WriteFile(path, content, 0600); writeErr != nil { // #nosec G703 -- path is the fixed historical configuration beneath the private fixture root
			return nil, writeErr
		}
		return func() error { return nil }, nil
	}
	if _, err := host.apply(digest); err == nil || !strings.Contains(err.Error(), "changed before guarded attestation") {
		t.Fatalf("guarded configuration drift was not refused: %v", err)
	}
	if len(state.batches) != 0 {
		t.Fatalf("configuration drift reached mutation: %v", state.batches)
	}
}

func TestLegacyWireGuardRecoveryAcceptsEarlyWGSysWardenBytes_SW2_WGRECOVERY_012(t *testing.T) {
	host, _ := newLegacyWireGuardTestHost(t, "wg-syswarden", nil)
	path := filepath.Join(host.filesystemRoot, "etc", "wireguard", "wg-syswarden.conf")
	content, err := os.ReadFile(path) // #nosec G304 -- path is the fixed historical configuration beneath the private fixture root
	if err != nil {
		t.Fatal(err)
	}
	content = bytes.Replace(content, []byte(` nft 'add table inet filter' 2>/dev/null || true;`), nil, 1)
	if err := os.WriteFile(path, content, 0600); err != nil { // #nosec G703 -- path is the fixed historical configuration beneath the private fixture root
		t.Fatal(err)
	}
	plan, err := host.inspect()
	if err != nil {
		t.Fatal(err)
	}
	if plan.Generation != legacyWireGuardGenerationWGSysWarden ||
		plan.Configuration.Source != "exact-historical-config" {
		t.Fatalf("early wg-syswarden bytes were not classified exactly: %#v", plan)
	}
}

func TestLegacyWireGuardRecoveryRejectsAmbiguousServiceCommandResults_SW2_WGRECOVERY_013(t *testing.T) {
	host, _ := newLegacyWireGuardTestHost(t, "wg0", nil)
	host.commandOutput = func(name string, args ...string) ([]byte, error) {
		command := strings.Join(append([]string{name}, args...), " ")
		if strings.Contains(command, "--property=LoadState") {
			return []byte("loaded\n"), errors.New("untrusted systemctl exit")
		}
		return fakeLegacyWireGuardServiceOutput(false, false, false)(name, args...)
	}
	if _, err := host.inspect(); err == nil || !strings.Contains(err.Error(), "untrusted systemctl exit") {
		t.Fatalf("systemctl output with an error was accepted: %v", err)
	}

	host, _ = newLegacyWireGuardTestHost(t, "wg0", nil)
	host.isAlpine = func() bool { return true }
	writeHistoricalOpenRCService(t, host.filesystemRoot, "wg0")
	host.commandOutput = func(name string, args ...string) ([]byte, error) {
		switch name {
		case "rc-update":
			return []byte("sshd | default\n"), nil
		case "rc-service":
			return []byte("* status: stopped\n"), errors.New("arbitrary OpenRC failure")
		default:
			return nil, fmt.Errorf("unexpected command")
		}
	}
	if _, _, _, err := host.inspectHistoricalService("wg0"); err == nil || !strings.Contains(err.Error(), "arbitrary OpenRC failure") {
		t.Fatalf("OpenRC stopped text with an arbitrary error was accepted: %v", err)
	}

	exitThree := exec.Command("sh", "-c", "exit 3").Run()
	host.commandOutput = func(name string, args ...string) ([]byte, error) {
		switch name {
		case "rc-service":
			return []byte("* status: stopped\n"), exitThree
		case "rc-update":
			return []byte("sshd | default\n"), nil
		case "wg":
			return []byte("\n"), nil
		default:
			return nil, fmt.Errorf("unexpected command")
		}
	}
	manager, service, present, err := host.inspectHistoricalService("wg0")
	if err != nil || manager != "openrc" || service.ActiveState != "inactive" ||
		service.EnabledState != "disabled" || present {
		t.Fatalf("exact OpenRC stopped exit was not accepted: manager=%s service=%#v present=%t err=%v", manager, service, present, err)
	}

	host, _ = newLegacyWireGuardTestHost(t, "wg0", nil)
	host.commandOutput = func(name string, args ...string) ([]byte, error) {
		command := strings.Join(append([]string{name}, args...), " ")
		if strings.Contains(command, "--property=LoadState") {
			return []byte("not-found\n"), nil
		}
		if command == "wg show interfaces" {
			return []byte("\n"), nil
		}
		return nil, fmt.Errorf("unexpected command %q", command)
	}
	plan, err := host.inspect()
	if err != nil || !plan.SafeToApply || plan.Service.LoadState != "not-found" ||
		plan.Service.ActiveState != "not-found" || plan.Service.EnabledState != "not-found" {
		t.Fatalf("absent systemd unit was not classified distinctly: plan=%#v err=%v", plan, err)
	}
}

func TestLegacyWireGuardRecoveryAcceptsAbsentOpenRCServiceAfterPartialCleanup_SW2_WGRECOVERY_015(t *testing.T) {
	for _, rules := range [][]LegacyWireGuardForwardRuleEvidence{
		{},
		{{Direction: "iifname", Handle: 17}},
		{{Direction: "iifname", Handle: 17}, {Direction: "oifname", Handle: 18}},
	} {
		host, _ := newLegacyWireGuardTestHost(t, "wg0", rules)
		host.isAlpine = func() bool { return true }
		host.commandOutput = func(name string, args ...string) ([]byte, error) {
			switch name {
			case "rc-update":
				return []byte("sshd | default\n"), nil
			case "wg":
				return []byte("\n"), nil
			case "rc-service":
				return nil, fmt.Errorf("rc-service must not inspect an absent init script")
			default:
				return nil, fmt.Errorf("unexpected command %s %v", name, args)
			}
		}

		plan, err := host.inspect()
		if err != nil {
			t.Fatalf("inspect %d-rule Alpine cleanup: %v", len(rules), err)
		}
		if !plan.SafeToApply || plan.ServiceManager != "openrc" ||
			plan.Service.LoadState != "not-found" || plan.Service.ActiveState != "not-found" ||
			plan.Service.EnabledState != "not-found" || plan.InterfacePresent {
			t.Fatalf("unexpected absent OpenRC plan: %#v", plan)
		}
		if _, err := LegacyWireGuardRecoveryPlanSHA256(plan); err != nil {
			t.Fatalf("canonicalize absent OpenRC plan: %v", err)
		}
	}
}

func TestLegacyWireGuardRecoveryRejectsIncoherentAbsentOpenRCState_SW2_WGRECOVERY_016(t *testing.T) {
	host, _ := newLegacyWireGuardTestHost(t, "wg0", nil)
	host.isAlpine = func() bool { return true }
	host.commandOutput = func(name string, args ...string) ([]byte, error) {
		switch name {
		case "rc-update":
			return []byte("wg-quick.wg0 | default\n"), nil
		default:
			return nil, fmt.Errorf("unexpected command %s %v", name, args)
		}
	}
	if _, err := host.inspect(); err == nil || !strings.Contains(err.Error(), "absent historical OpenRC service still has runlevel enablement") {
		t.Fatalf("absent OpenRC service with a runlevel was accepted: %v", err)
	}

	host, _ = newLegacyWireGuardTestHost(t, "wg0", nil)
	host.isAlpine = func() bool { return true }
	host.commandOutput = func(name string, args ...string) ([]byte, error) {
		switch name {
		case "rc-update":
			return []byte("sshd | default\n"), nil
		case "wg":
			return []byte("wg0\n"), nil
		default:
			return nil, fmt.Errorf("unexpected command %s %v", name, args)
		}
	}
	plan, err := host.inspect()
	if err != nil {
		t.Fatal(err)
	}
	if plan.SafeToApply || plan.Service.LoadState != "not-found" ||
		!reflect.DeepEqual(plan.Blockers, []string{"historical interface is present"}) {
		t.Fatalf("present interface was not retained as an Alpine blocker: %#v", plan)
	}

	host, _ = newLegacyWireGuardTestHost(t, "wg0", nil)
	host.isAlpine = func() bool { return true }
	writeHistoricalOpenRCService(t, host.filesystemRoot, "wg0")
	host.commandOutput = func(name string, args ...string) ([]byte, error) {
		switch name {
		case "rc-update":
			return []byte("wg-quick.wg0 | default\n"), nil
		case "rc-service":
			return []byte("* status: started\n"), nil
		case "wg":
			return []byte("\n"), nil
		default:
			return nil, fmt.Errorf("unexpected command %s %v", name, args)
		}
	}
	plan, err = host.inspect()
	if err != nil {
		t.Fatal(err)
	}
	if plan.SafeToApply || !reflect.DeepEqual(plan.Blockers, []string{
		"historical service is not inactive",
		"historical service is not disabled",
	}) {
		t.Fatalf("active enabled OpenRC service was not retained as a blocker: %#v", plan)
	}
}

func TestLegacyWireGuardRecoveryAcceptsVerifiedModernManifestEvidence_SW2_WGRECOVERY_014(t *testing.T) {
	root := t.TempDir()
	for _, directory := range []string{"etc", "etc/wireguard", "etc/wireguard/clients", "etc/sysctl.d"} {
		if err := os.Mkdir(filepath.Join(root, directory), 0755); err != nil { // #nosec G301 -- fixture reproduces the protected system directory modes required by manifest attestation
			t.Fatal(err)
		}
	}
	input := validWireGuardRenderInput()
	input.ActiveIf = "ens3"
	server, client, err := renderWireGuardConfigurations(input)
	if err != nil {
		t.Fatal(err)
	}
	uid, gid := legacyWireGuardFixtureIdentity(t, root)
	publication, err := wireguardstate.StageOwnedArtifacts(root, map[string][]byte{
		wireguardstate.ServerConfigurationPath:     []byte(server),
		wireguardstate.ClientConfigurationPath:     []byte(client),
		wireguardstate.ForwardingConfigurationPath: []byte("net.ipv4.ip_forward = 1\n"),
	}, uid, gid)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = publication.Rollback() })
	if err := publication.Publish(); err != nil {
		t.Fatal(err)
	}
	manifest, err := wireguardstate.CaptureManifest(root, uid, gid)
	if err != nil {
		t.Fatal(err)
	}
	stagedManifest, err := publication.StageManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := stagedManifest.Publish(); err != nil {
		t.Fatal(err)
	}
	if err := publication.Commit(); err != nil {
		t.Fatal(err)
	}
	state := &fakeLegacyWireGuardNFTState{
		tablePresent: true, tableHandle: 7,
		forwardRules: map[string][]LegacyWireGuardForwardRuleEvidence{
			"wg0": {}, "wg-syswarden": {},
		},
	}
	host := legacyWireGuardRecoveryHost{
		filesystemRoot: root, expectedUID: uid, expectedGID: gid,
		effectiveUID:  func() int { return 0 },
		managerState:  func() (string, error) { return "ACTIVE", nil },
		isAlpine:      func() bool { return false },
		commandOutput: fakeLegacyWireGuardServiceOutput(false, false, false),
		nftRunner:     state, nftBatch: state.apply,
		guard: func() (func() error, error) { return func() error { return nil }, nil },
	}
	plan, err := host.inspect()
	if err != nil {
		t.Fatal(err)
	}
	if plan.Configuration.Source != "verified-current-manifest" ||
		plan.Ownership.State != "verified-manifest" {
		t.Fatalf("modern manifest evidence was not bound: %#v", plan)
	}
}
