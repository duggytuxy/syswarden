//go:build linux

package firewall

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"
	"time"
)

func scopedForwardFixture(t *testing.T, source string, interfaces []string) string {
	t.Helper()
	var old strings.Builder
	appendStrictAllowForwardRules(&old, true)
	if strings.Count(source, old.String()) != 1 {
		t.Fatal("strict forward fixture is incomplete")
	}
	return strings.Replace(source, old.String(), strictAllowForwardSource(interfaces), 1)
}

func strictForwardFixtures(t *testing.T) []nftCurrentFileFixture {
	t.Helper()
	fixtures := fixtureNFTCurrentFiles(t)
	inetFixtures := fixtureNFTInetSources(t)
	for index := range fixtures {
		fixture := &fixtures[index]
		wanted := fixture.InetFixture.Flags
		wanted.Strict = true
		found := false
		for _, inet := range inetFixtures {
			if inet.Profile == "current" && inet.Flags == wanted && reflect.DeepEqual(inet.Parameters, fixture.InetFixture.Parameters) {
				if strings.Count(fixture.Source, fixture.InetFixture.Source) != 1 {
					t.Fatal("inet fixture anchor is ambiguous")
				}
				fixture.Source = strings.Replace(fixture.Source, fixture.InetFixture.Source, inet.Source, 1)
				fixture.InetFixture = inet
				found = true
				break
			}
		}
		if !found {
			t.Fatal("independent historical strict fixture is missing")
		}
	}
	return fixtures
}

func TestStrictAllowForwardOwnership_SW_GEO_001(t *testing.T) {
	covered := 0
	for _, fixture := range strictForwardFixtures(t) {
		if !fixture.inputs().Base.Inet.Strict {
			continue
		}
		covered++
		source := scopedForwardFixture(t, fixture.Source, fixture.Interfaces)
		generation := fixtureNFTPolicyGeneration(t, fixture)
		generation.ForwardStrictAllow = strictAllowForwardVersion
		receipt, err := prepareNFTPolicyOwnership([]byte(source), generation, recoveryFixtureTransactionID)
		if err != nil {
			t.Fatal(err)
		}
		input, err := currentNFTInputsFromOwnership([]byte(source), receipt)
		if err != nil || input.ForwardStrictAllow != strictAllowForwardVersion {
			t.Fatalf("scoped source lost its ownership binding: %v", err)
		}
		if _, err := inspectNFTCurrentPersistentFile([]byte(source), fixture.inputs()); err == nil {
			t.Fatal("unmarked scoped source was adopted")
		}
		for _, changed := range []string{
			strings.Replace(source, "iifname {", "oifname {", 1),
			strings.Replace(source, "iifname {", "iifname != {", 1),
			strings.Replace(source, strictAllowForwardSource(fixture.Interfaces), strictAllowForwardSource([]string{"other0"}), 1),
			strings.Replace(source, "@syswarden_zt_allowed counter drop", "@syswarden_zt_allowed counter accept", 1),
			source + strictAllowForwardSource(fixture.Interfaces),
		} {
			if _, err := inspectNFTCurrentPersistentFile([]byte(changed), input); err == nil {
				t.Fatal("modified forward policy was adopted")
			}
		}
		input.ForwardStrictAllow = "unreviewed-generation"
		if _, err := inspectNFTCurrentPersistentFile([]byte(source), input); err == nil {
			t.Fatal("unknown forward generation was adopted")
		}
	}
	if covered == 0 {
		t.Fatal("no strict allow ownership fixture exercised")
	}
	for _, base := range []nftV4028PersistenceInputs{
		{}, {Inet: nftInetTemplateInputs{Strict: true}},
		{Interfaces: []string{"eth0"}},
		{Interfaces: []string{"eth0", "eth0"}, Inet: nftInetTemplateInputs{Strict: true}},
		{Interfaces: []string{"bad;"}, Inet: nftInetTemplateInputs{Strict: true}},
	} {
		if validateStrictAllowForwardGeneration(strictAllowForwardVersion, base) == nil {
			t.Fatal("ambiguous scope authorized a forward generation")
		}
	}
}

func TestStrictAllowForwardPostcheck_SW_GEO_001(t *testing.T) {
	for _, interfaces := range [][]string{{"eth0"}, {"eth2", "eth0"}} {
		plan := minimalVerificationPlan(0)
		base := nftV4028PersistenceInputs{Interfaces: interfaces, Inet: nftInetTemplateInputs{Strict: true}}
		plan.generation = &nftPolicyGeneration{Base: base, ForwardStrictAllow: strictAllowForwardVersion}
		wire := nftVerificationJSON(plan, 0)
		document, err := decodeNFTJSON(wire)
		if err != nil || verifyStrictAllowForward(document, strictAllowForwardVersion, base) != nil {
			t.Fatalf("valid scoped runtime rejected: %v", err)
		}
		before, _ := json.Marshal(document)
		for _, duplicateHandle := range []bool{false, true} {
			changed, _ := decodeNFTJSON(wire)
			for _, entry := range changed.NFTables {
				if entry.Rule != nil && entry.Rule.Chain == "docker_protect" {
					extra := *entry.Rule
					if !duplicateHandle {
						extra.Handle += 1000
					}
					entry.Rule = &extra
					changed.NFTables = append([]nftJSONEntry{entry}, changed.NFTables...)
					break
				}
			}
			if verifyStrictAllowForward(changed, strictAllowForwardVersion, base) == nil {
				t.Fatal("extra or duplicated runtime rule passed postcheck")
			}
		}
		for _, mutation := range []func(*nftJSONRule){
			func(r *nftJSONRule) { r.Expressions = r.Expressions[1:] },
			func(r *nftJSONRule) {
				r.Expressions[0] = json.RawMessage(`{"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"other0"}}`)
			},
			func(r *nftJSONRule) { r.Expressions[3] = json.RawMessage(`{"accept":null}`) },
			func(r *nftJSONRule) { r.Handle = 0 },
			func(r *nftJSONRule) { r.Comment = "modified" },
		} {
			for _, familyIndex := range []int{0, 1} {
				changed, _ := decodeNFTJSON(wire)
				index := 0
				for _, entry := range changed.NFTables {
					if rule := entry.Rule; rule != nil && rule.Chain == "docker_protect" {
						if index == familyIndex {
							mutation(rule)
						}
						index++
					}
				}
				if verifyStrictAllowForward(changed, strictAllowForwardVersion, base) == nil {
					t.Fatal("modified scoped runtime passed postcheck")
				}
			}
		}
		after, _ := json.Marshal(document)
		if !bytes.Equal(before, after) {
			t.Fatal("verification changed its observation")
		}
	}
}

func TestStrictAllowForwardKernel_SW_GEO_001(t *testing.T) {
	const helper = "SYSWARDEN_FORWARD_KERNEL_HELPER"
	if os.Getenv(helper) == "1" {
		current, err := os.Readlink("/proc/self/ns/net")
		if err != nil || current == os.Getenv("SYSWARDEN_FORWARD_PARENT_NETNS") || os.Getenv("SYSWARDEN_FORWARD_PARENT_NETNS") == "" || os.Geteuid() != 0 {
			t.Fatal("refusing kernel test outside isolated user and network namespaces")
		}
		runStrictAllowForwardKernel(t)
		return
	}
	for _, tool := range []string{"nft", "ip", "unshare"} {
		if _, err := exec.LookPath(tool); err != nil {
			if os.Getenv("SYSWARDEN_REQUIRE_FORWARD_KERNEL") == "1" {
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
		if os.Getenv("SYSWARDEN_REQUIRE_FORWARD_KERNEL") == "1" {
			t.Fatalf("kernel namespace required: %v: %s", err, output)
		}
		t.Skipf("kernel namespace unavailable: %s", output)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(ctx, "unshare", "--user", "--map-root-user", "--net", "--", executable, "-test.run=^TestStrictAllowForwardKernel_SW_GEO_001$", "-test.v") // #nosec G204 -- fixed helper in fresh namespaces using the current test executable
	command.Env = append(os.Environ(), helper+"=1", "SYSWARDEN_FORWARD_PARENT_NETNS="+parent)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("isolated forward regression: %v\n%s", err, output)
	}
	t.Log(string(output))
}

func runStrictAllowForwardKernel(t *testing.T) {
	nft := func(source string, args ...string) []byte {
		t.Helper()
		command := exec.Command("nft", args...) // #nosec G204 -- fixed test commands inside the attested private network namespace
		command.Stdin = strings.NewReader(source)
		out, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("nft %v: %v: %s", args, err, out)
		}
		return out
	}
	for _, fixture := range strictForwardFixtures(t) {
		if !fixture.inputs().Base.Inet.Strict {
			continue
		}
		for _, interfaces := range [][]string{{"eth0"}, {"eth2", "eth0"}} {
			base := fixture.inputs().Base
			base.Interfaces = interfaces
			source := scopedForwardFixture(t, fixture.Source, interfaces)
			// Inspect the complete inet table, including unchanged ban precedence.
			start := strings.Index(source, "table inet syswarden {")
			if start < 0 {
				t.Fatal("inet fixture missing")
			}
			end := start + strings.Index(source[start:], "\n}\n\n") + len("\n}\n")
			nft("flush ruleset\n"+source[start:end], "-f", "-")
			observed := nft("", "-j", "list", "table", "inet", "syswarden")
			document, err := decodeNFTJSON(observed)
			if err != nil || verifyStrictAllowForward(document, strictAllowForwardVersion, base) != nil {
				t.Fatalf("actual nft runtime rejected: %v; verify=%v", err, verifyStrictAllowForward(document, strictAllowForwardVersion, base))
			}
			original := append([]byte(nil), observed...)
			normalized, err := normalizeStrictAllowForwardRuntime(observed, strictAllowForwardVersion, base)
			if err != nil || !reflect.DeepEqual(observed, original) {
				t.Fatalf("runtime normalization changed evidence: %v", err)
			}
			legacyStart := strings.Index(fixture.Source, "table inet syswarden {")
			legacyEnd := legacyStart + strings.Index(fixture.Source[legacyStart:], "\n}\n\n") + len("\n}")
			if _, err := inspectNFTInetTemplateTopology([]byte(fixture.Source[legacyStart:legacyEnd]), normalized, base.Inet); err != nil {
				t.Fatalf("scoped runtime cannot be retired through its exact historical model: %v", err)
			}
		}
	}
	runStrictAllowForwardPackets(t, nft)
}
