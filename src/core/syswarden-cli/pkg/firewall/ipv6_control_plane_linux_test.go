//go:build linux

package firewall

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"
	"time"
)

func ipv6ControlPlaneFixtureSource(t *testing.T, original string) string {
	t.Helper()
	for _, family := range []string{"netdev", "inet"} {
		_, baseChain, _ := ipv6ControlPlaneTarget(family)
		anchor := "\tchain " + baseChain + " {\n"
		start := strings.Index(original, anchor)
		if start < 0 {
			t.Fatal("fixture base chain missing")
		}
		end := start + len(anchor) + strings.IndexByte(original[start+len(anchor):], '\n') + 1
		original = original[:end] + ipv6ControlPlaneDispatch + original[end:]
		original = original[:start] + ipv6ControlPlaneSource(family) + original[start:]
	}
	return original
}

func TestIPv6ControlPlaneSourceOwnership(t *testing.T) {
	for _, fixture := range fixtureNFTCurrentFiles(t) {
		source := ipv6ControlPlaneFixtureSource(t, fixture.Source)
		generation := fixtureNFTPolicyGeneration(t, fixture)
		generation.IPv6ControlPlane = ipv6ControlPlaneVersion
		receipt, err := prepareNFTPolicyOwnership([]byte(source), generation, recoveryFixtureTransactionID)
		if err != nil {
			t.Fatal(err)
		}
		input, err := currentNFTInputsFromOwnership([]byte(source), receipt)
		if err != nil {
			t.Fatal(err)
		}
		if input.IPv6ControlPlane != ipv6ControlPlaneVersion {
			t.Fatal("generation binding lost")
		}
		if _, err := inspectNFTCurrentPersistentFile([]byte(source), fixture.inputs()); err == nil {
			t.Fatal("new source adopted without its generation")
		}
		for _, changed := range []string{
			strings.Replace(source, "hoplimit 255", "hoplimit 254", 1),
			strings.Replace(source, "udp dport 546", "udp dport 547", 1),
			strings.Replace(source, ipv6ControlPlaneDispatch, "", 1),
			strings.Replace(source, ipv6ControlPlaneDispatch, ipv6ControlPlaneDispatch+ipv6ControlPlaneDispatch, 1),
			strings.Replace(source, ipv6ControlPlaneDispatch, "\t\taccept\n"+ipv6ControlPlaneDispatch, 1),
			strings.Replace(source, "icmpv6 code 0", "icmpv6 code 1", 1),
		} {
			if _, err := inspectNFTCurrentPersistentFile([]byte(changed), input); err == nil {
				t.Fatal("modified extension adopted")
			}
		}
		input.IPv6ControlPlane = "future-unreviewed-generation"
		if _, err := inspectNFTCurrentPersistentFile([]byte(source), input); err == nil {
			t.Fatal("unknown generation adopted")
		}
	}
}

func TestIPv6ControlPlanePostcheckRejectsDrift(t *testing.T) {
	plan := operatorPolicyPostcheckPlan(t)
	plan.generation = &nftPolicyGeneration{IPv6ControlPlane: ipv6ControlPlaneVersion}
	wire := nftVerificationJSON(plan, 0)
	for _, family := range []string{"inet", "netdev"} {
		document, err := decodeNFTJSON(wire)
		if err != nil {
			t.Fatal(err)
		}
		if err := verifyIPv6ControlPlane(document, family); err != nil {
			t.Fatal(err)
		}
		for _, change := range []func(*nftJSONRule){
			func(r *nftJSONRule) { r.Expressions = []json.RawMessage{json.RawMessage(`{"accept":null}`)} },
			func(r *nftJSONRule) { r.Comment = "customized" },
			func(r *nftJSONRule) { r.Chain = "other" },
			func(r *nftJSONRule) { r.Expressions = append(r.Expressions, json.RawMessage(`{"drop":null}`)) },
		} {
			for ordinal := range ipv6ControlPlaneExpressions(family) {
				changed, err := decodeNFTJSON(wire)
				if err != nil {
					t.Fatal(err)
				}
				index := 0
				for _, entry := range changed.NFTables {
					if r := entry.Rule; r != nil && r.Family == family && r.Chain == ipv6ControlPlaneChain {
						if index == ordinal {
							change(r)
						}
						index++
					}
				}
				if err := verifyIPv6ControlPlane(changed, family); err == nil {
					t.Fatal("modified rule passed postcheck")
				}
			}
		}
	}
}

func TestIPv6ControlPlaneHistoricalCodeZeroRendering(t *testing.T) {
	plan := operatorPolicyPostcheckPlan(t)
	plan.generation = &nftPolicyGeneration{IPv6ControlPlane: ipv6ControlPlaneVersion}
	wire := nftVerificationJSON(plan, 0)
	for _, family := range []string{"inet", "netdev"} {
		for _, test := range []struct {
			name       string
			expression string
			accepted   bool
		}{
			{"code-zero-symbol", `{"match":{"op":"==","left":{"payload":{"protocol":"icmpv6","field":"code"}},"right":"no-route"}}`, true},
			{"different-code", `{"match":{"op":"==","left":{"payload":{"protocol":"icmpv6","field":"code"}},"right":"admin-prohibited"}}`, false},
			{"different-protocol", `{"match":{"op":"==","left":{"payload":{"protocol":"icmp","field":"code"}},"right":"no-route"}}`, false},
			{"different-field", `{"match":{"op":"==","left":{"payload":{"protocol":"icmpv6","field":"type"}},"right":"no-route"}}`, false},
			{"different-operator", `{"match":{"op":"!=","left":{"payload":{"protocol":"icmpv6","field":"code"}},"right":"no-route"}}`, false},
			{"extra-field", `{"match":{"op":"==","left":{"payload":{"protocol":"icmpv6","field":"code"}},"right":"no-route","extra":0}}`, false},
		} {
			t.Run(family+"/"+test.name, func(t *testing.T) {
				document, err := decodeNFTJSON(wire)
				if err != nil {
					t.Fatal(err)
				}
				changed := 0
				for _, entry := range document.NFTables {
					rule := entry.Rule
					if rule == nil || rule.Family != family || rule.Chain != ipv6ControlPlaneChain {
						continue
					}
					for index, expression := range rule.Expressions {
						canonical, err := canonicalNFTJSONExpression(expression)
						if err != nil {
							t.Fatal(err)
						}
						if bytes.Equal(canonical, []byte(ipv6CodeZeroJSON)) {
							rule.Expressions[index] = json.RawMessage(test.expression)
							changed++
						}
					}
				}
				if changed != 5 {
					t.Fatalf("replaced %d code-zero checks, expected 5", changed)
				}
				before, _ := json.Marshal(document)
				err = verifyIPv6ControlPlane(document, family)
				if (err == nil) != test.accepted {
					t.Fatalf("accepted=%t, expected %t: %v", err == nil, test.accepted, err)
				}
				after, _ := json.Marshal(document)
				if !bytes.Equal(before, after) {
					t.Fatal("verification rewrote the original observation")
				}
			})
		}
	}
}

func TestIPv6ControlPlaneKernel(t *testing.T) {
	const helper = "SYSWARDEN_IPV6_KERNEL_HELPER"
	if os.Getenv(helper) == "1" {
		current, err := os.Readlink("/proc/self/ns/net")
		if err != nil || current == os.Getenv("SYSWARDEN_IPV6_PARENT_NETNS") || os.Getenv("SYSWARDEN_IPV6_PARENT_NETNS") == "" || os.Geteuid() != 0 {
			t.Fatal("refusing kernel test outside its isolated user and network namespaces")
		}
		runIPv6ControlPlaneKernel(t)
		return
	}
	for _, tool := range []string{"nft", "ip", "unshare"} {
		if _, err := exec.LookPath(tool); err != nil {
			if os.Getenv("SYSWARDEN_REQUIRE_IPV6_KERNEL") == "1" {
				t.Fatalf("required kernel tool unavailable: %s", tool)
			}
			t.Skipf("kernel tool unavailable: %s", tool)
		}
	}
	parent, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	probe := exec.CommandContext(ctx, "unshare", "--user", "--map-root-user", "--net", "--", "nft", "list", "tables")
	if output, err := probe.CombinedOutput(); err != nil {
		if os.Getenv("SYSWARDEN_REQUIRE_IPV6_KERNEL") == "1" {
			t.Fatalf("kernel namespace required: %v: %s", err, output)
		}
		t.Skipf("kernel namespace unavailable: %s", output)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(ctx, "unshare", "--user", "--map-root-user", "--net", "--", executable, "-test.run=^TestIPv6ControlPlaneKernel$", "-test.v") // #nosec G204 -- the resolved current test executable runs only the fixed helper in new namespaces
	command.Env = append(os.Environ(), helper+"=1", "SYSWARDEN_IPV6_PARENT_NETNS="+parent)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("isolated kernel regression: %v\n%s", err, output)
	}
	t.Log(string(output))
}

func runIPv6ControlPlaneKernel(t *testing.T) {
	t.Helper()
	nft := func(source string, args ...string) []byte {
		t.Helper()
		command := exec.Command("nft", args...) // #nosec G204 -- fixed test commands inside an attested isolated network namespace
		command.Stdin = strings.NewReader(source)
		out, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("nft %v: %v: %s", args, err, out)
		}
		return out
	}
	interfaces := make(map[string]bool)
	for index, fixture := range fixtureNFTCurrentFiles(t) {
		for _, name := range fixture.Interfaces {
			if !interfaces[name] {
				out, err := exec.Command("ip", "link", "add", name, "type", "dummy").CombinedOutput() // #nosec G204 -- interface names come from fixed test fixtures
				if err != nil {
					t.Fatalf("isolated interface: %v: %s", err, out)
				}
				interfaces[name] = true
			}
		}
		// Establish the existing ownership result with this exact nft userland.
		// nftables 1.0.9 omits ingress device identities from JSON; incomplete
		// observations must keep failing closed, including after this patch.
		nft("flush ruleset\n"+fixture.Source, "-f", "-")
		baselineInet := nft("", "-j", "list", "table", "inet", "syswarden")
		baselineIngress := nft("", "-j", "list", "table", "netdev", "syswarden_hw_drop")
		var baselineARP []byte
		if fixture.ARP {
			baselineARP = nft("", "-j", "list", "table", "arp", "syswarden_arp")
		}
		_, baselineErr := inspectNFTCurrentPersistenceRuntime([]byte(fixture.Source), baselineInet, baselineIngress, baselineARP, fixture.inputs())
		if baselineErr != nil && (!ipv6KernelLegacyIncompleteIngress(t, baselineIngress) || baselineErr.Error() != "ingress kernel topology includes changed or unrecognized objects, rules or ordering") {
			t.Fatalf("case %d unexpected baseline ownership failure: %v", index, baselineErr)
		}
		source := ipv6ControlPlaneFixtureSource(t, fixture.Source)
		nft("flush ruleset\n"+source, "-f", "-")
		observations := make(map[string][]byte)
		for _, family := range []string{"inet", "netdev"} {
			table, _, _ := ipv6ControlPlaneTarget(family)
			live := nft("", "-j", "list", "table", family, table)
			observations[family] = live
			document, err := decodeNFTJSON(live)
			if err != nil {
				t.Fatal(err)
			}
			if err := verifyIPv6ControlPlane(document, family); err != nil {
				t.Fatal(err)
			}
		}
		var arp []byte
		if fixture.ARP {
			arp = nft("", "-j", "list", "table", "arp", "syswarden_arp")
		}
		input := fixture.inputs()
		input.IPv6ControlPlane = ipv6ControlPlaneVersion
		for family, baseline := range map[string][]byte{"inet": baselineInet, "netdev": baselineIngress} {
			normalized, err := normalizeIPv6ControlPlaneRuntime(observations[family], family, ipv6ControlPlaneVersion)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(ipv6KernelTopologyWithoutHandles(t, normalized), ipv6KernelTopologyWithoutHandles(t, baseline)) {
				t.Fatalf("case %d %s: extension changed the existing topology", index, family)
			}
		}
		_, retirementErr := inspectNFTCurrentPersistenceRuntime([]byte(source), observations["inet"], observations["netdev"], arp, input)
		if baselineErr == nil && retirementErr != nil || baselineErr != nil && (retirementErr == nil || retirementErr.Error() != baselineErr.Error()) {
			t.Fatalf("case %d retirement behavior changed: baseline=%v, candidate=%v", index, baselineErr, retirementErr)
		}
		runIPv6ControlPlaneReloads(t, fixture, source)
		// A modified live extension must fail exact retirement, even if its
		// private persistent bytes and ownership inputs are still intact.
		nft("", "add", "rule", "inet", "syswarden", ipv6ControlPlaneChain, "accept")
		changed := nft("", "-j", "list", "table", "inet", "syswarden")
		if bytes.Equal(changed, observations["inet"]) {
			t.Fatal("kernel mutation did not happen")
		}
		if _, err := inspectNFTCurrentPersistenceRuntime([]byte(source), changed, observations["netdev"], arp, input); err == nil {
			t.Fatal("modified live extension adopted")
		}
		if baselineErr != nil {
			t.Logf("case %d: IPv6 kernel postcheck and unchanged topology passed; retirement correctly refuses nftables 1.0.9's incomplete ingress observation", index)
		} else {
			t.Logf("case %d: kernel compilation, exact IPv6 postcheck, retirement and mutation refusal passed", index)
		}
	}
	runIPv6ControlPlanePackets(t, nft)
	fmt.Println("IPv6 control-plane kernel ownership regression passed")
}

type ipv6KernelCommandRunner struct{}

func (ipv6KernelCommandRunner) Run(ctx context.Context, input []byte, args ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, "nft", args...) // #nosec G204 -- fixed nft test executable inside the attested isolated user and network namespaces
	command.Stdin = bytes.NewReader(input)
	return command.CombinedOutput()
}

// Reapply the complete generated policy through the real transaction engine.
// Compiling its first installation alone cannot detect a reload-time rejection.
func runIPv6ControlPlaneReloads(t *testing.T, fixture nftCurrentFileFixture, source string) {
	t.Helper()
	operator, err := compileOperatorPolicy(nil)
	if err != nil {
		t.Fatal(err)
	}
	var populations []nftSetPopulation
	for _, population := range fixture.Populations {
		kind := nftAddressPopulation
		if strings.Contains(population.Name, "_ports") {
			kind = nftAddressPortPopulation
		}
		populations = append(populations, nftSetPopulation{population.Name, population.Entries, kind, strings.Contains(population.Name, "_ssh_bypass")})
	}
	plan := buildNftVerificationPlan(populations, fixture.ARP, operator.verificationPlan())
	plan.generation = fixtureNFTPolicyGeneration(t, fixture)
	plan.generation.IPv6ControlPlane = ipv6ControlPlaneVersion
	base, _, _ := strings.Cut(source, "add element ")
	directory := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	for cycle := 0; cycle < 2; cycle++ {
		if _, err := applyNftablesTransactionLocked(ctx, ipv6KernelCommandRunner{}, directory, base, populations, plan, fmt.Sprintf("%016x", cycle+1), nil); err != nil {
			t.Fatalf("generated IPv6 policy reload %d: %v", cycle, err)
		}
	}
}

// Compare every observed field and expression except kernel-assigned handles.
// New rules receive new handles, but the extension must preserve the base model.
func ipv6KernelTopologyWithoutHandles(t *testing.T, wire []byte) map[string]any {
	t.Helper()
	document, err := decodeLegacyFail2banNFTJSON(wire)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range document["nftables"].([]any) {
		for _, value := range entry.(map[string]any) {
			delete(value.(map[string]any), "handle")
		}
	}
	return document
}

func ipv6KernelLegacyIncompleteIngress(t *testing.T, wire []byte) bool {
	t.Helper()
	document := ipv6KernelTopologyWithoutHandles(t, wire)
	oldVersion, missingDevice := false, false
	for _, entry := range document["nftables"].([]any) {
		wrapper := entry.(map[string]any)
		if meta, ok := wrapper["metainfo"].(map[string]any); ok {
			oldVersion = meta["version"] == "1.0.9"
		}
		if chain, ok := wrapper["chain"].(map[string]any); ok && chain["name"] == "ingress_frontline" {
			_, present := chain["dev"]
			missingDevice = !present
		}
	}
	return oldVersion && missingDevice
}
