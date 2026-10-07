//go:build linux

package firewall

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fixtureNFTHistoricalGraph(t *testing.T) (nftPersistenceFilesystem, nftHistoricalPersistencePlan, func(string, string) error) {
	t.Helper()
	host, _, _ := fixtureNFTPersistenceGraphRecord(t)
	fixture := fixtureNFTHistoricalFiles(t)[39]
	if err := host.root.WriteFile(legacyNFTIncludePath[1:], []byte(fixture.Source), 0600); err != nil {
		t.Fatal(err)
	}
	if err := host.root.MkdirAll("var/backups", 0700); err != nil {
		t.Fatal(err)
	}
	// These are synthetic fixture authorities, never production attestation.
	origins, producers := strings.Repeat("a", 64), strings.Repeat("b", 64)
	plan, err := prepareNFTHistoricalPersistencePlan(host, []string{nftSharedFixturePath}, fixture.Inet, &fixture.Ingress, origins, producers)
	if err != nil {
		t.Fatal(err)
	}
	guard := func(actualOrigins, actualProducers string) error {
		if actualOrigins != origins || actualProducers != producers {
			return fmt.Errorf("independent fixture authority changed")
		}
		return nil
	}
	return host, plan, guard
}

func TestNFTHistoricalGraphRetiresOnlyReviewedSourceAndInclude(t *testing.T) {
	host, plan, guard := fixtureNFTHistoricalGraph(t)
	if _, err := host.root.Stat("var/backups/syswarden-retired-v1"); !os.IsNotExist(err) {
		t.Fatal("read-only preparation created a journal")
	}
	if err := applyNFTHistoricalPersistencePlan(host, plan, plan.sha256, guard, defaultLegacyRetirementFileOps()); err != nil {
		t.Fatal(err)
	}
	assertNFTPersistenceRecoveryComplete(t, host, plan.graph, plan.sha256)
	// Resume from on-disk evidence instead of trusting caller memory.
	restored, err := readNFTHistoricalPersistencePlan(host, plan.sha256)
	if err != nil {
		t.Fatal(err)
	}
	if err := applyNFTHistoricalPersistencePlan(host, restored, restored.sha256, guard, defaultLegacyRetirementFileOps()); err != nil {
		t.Fatal(err)
	}
	assertNFTPersistenceRecoveryComplete(t, host, plan.graph, plan.sha256)
}

func TestNFTHistoricalGraphResumesDurabilityBoundaries(t *testing.T) {
	for _, phase := range []string{"graph-plan-durable", "historical-source-staged", "historical-source-binding-durable", "shared-edit-exchanged", "shared-edit-original-retained", "graph-shared-edits-durable", "intent-published", "source-retired", "graph-retirement-durable"} {
		t.Run(phase, func(t *testing.T) {
			host, plan, guard := fixtureNFTHistoricalGraph(t)
			interrupted := errors.New("fixture interruption")
			ops := defaultLegacyRetirementFileOps()
			ops.checkpoint = func(actual string) error {
				if actual == phase {
					return interrupted
				}
				return nil
			}
			if err := applyNFTHistoricalPersistencePlan(host, plan, plan.sha256, guard, ops); !errors.Is(err, interrupted) {
				t.Fatal("expected interruption was not reached", err)
			}
			if phase != "graph-plan-durable" && phase != "historical-source-staged" {
				var err error
				plan, err = readNFTHistoricalPersistencePlan(host, plan.sha256)
				if err != nil {
					t.Fatal("durable binding did not survive an interrupted invocation", err)
				}
			}
			if err := applyNFTHistoricalPersistencePlan(host, plan, plan.sha256, guard, defaultLegacyRetirementFileOps()); err != nil {
				t.Fatal("interrupted whole-file retirement did not resume", err)
			}
			assertNFTPersistenceRecoveryComplete(t, host, plan.graph, plan.sha256)
		})
	}
}

func TestNFTHistoricalGraphRefusesLostOrChangedAuthority(t *testing.T) {
	for _, kind := range []string{"missing-binding", "changed-binding", "public-binding", "modified-backup", "recreated-source", "origins", "producers", "nil-guard", "wrong-review", "administrator-source"} {
		t.Run(kind, func(t *testing.T) {
			host, plan, guard := fixtureNFTHistoricalGraph(t)
			ops := defaultLegacyRetirementFileOps()
			interrupted := errors.New("fixture interruption")
			ops.checkpoint = func(phase string) error {
				if phase == "source-retired" {
					return interrupted
				}
				return nil
			}
			if err := applyNFTHistoricalPersistencePlan(host, plan, plan.sha256, guard, ops); !errors.Is(err, interrupted) {
				t.Fatal("fixture did not interrupt after source movement", err)
			}
			journal := legacyFail2banPlanPath(plan.sha256) + "/historical-source.json"
			write := func(path, content string) {
				t.Helper()
				if err := host.root.WriteFile(path[1:], []byte(content), 0600); err != nil {
					t.Fatal(err)
				}
			}
			reviewed := plan.sha256
			switch kind {
			case "missing-binding":
				if err := host.root.Remove(journal[1:]); err != nil {
					t.Fatal(err)
				}
			case "changed-binding":
				write(journal, "{}")
			case "public-binding":
				if err := host.root.Chmod(journal[1:], 0640); err != nil {
					t.Fatal(err)
				}
			case "modified-backup":
				write(legacyRetirementBackupDirectory(nftPersistenceGraphFileRecord(plan.binding.Source, plan.sha256))+"/original", "table inet custom {}\n")
			case "recreated-source":
				write(legacyNFTIncludePath, "table inet custom {}\n")
			case "origins":
				guard = func(string, string) error { return fmt.Errorf("input provenance changed") }
			case "producers":
				guard = func(string, string) error { return fmt.Errorf("producer resumed") }
			case "nil-guard":
				guard = nil
			case "wrong-review":
				reviewed = strings.Repeat("f", 64)
			case "administrator-source":
				write("/root/operator-policy.nft", "table inet administrator_modified {}\n")
			}
			admin, err := host.read("/root/operator-policy.nft")
			if err != nil {
				t.Fatal(err)
			}
			if err := applyNFTHistoricalPersistencePlan(host, plan, reviewed, guard, defaultLegacyRetirementFileOps()); err == nil {
				t.Fatal("changed authority or retained evidence accepted")
			}
			after, err := host.read("/root/operator-policy.nft")
			if err != nil || !bytes.Equal(admin, after) {
				t.Fatal("administrator content changed on refusal", err)
			}
		})
	}
}

func TestNFTHistoricalGraphFreezesInputsAndRefusesCustomSource(t *testing.T) {
	host, _, _ := fixtureNFTPersistenceGraphRecord(t)
	fixture := fixtureNFTHistoricalFiles(t)[39]
	if err := host.root.WriteFile(legacyNFTIncludePath[1:], []byte(fixture.Source), 0600); err != nil {
		t.Fatal(err)
	}
	plan, err := prepareNFTHistoricalPersistencePlan(host, []string{nftSharedFixturePath}, fixture.Inet, &fixture.Ingress, strings.Repeat("a", 64), strings.Repeat("b", 64))
	if err != nil {
		t.Fatal(err)
	}
	before, _, err := encodeNFTHistoricalPersistenceBinding(plan.binding)
	if err != nil {
		t.Fatal(err)
	}
	fixture.Inet.Whitelist[0] = "203.0.113.199"
	fixture.Ingress.Populations["syswarden_blacklist"][0] = "203.0.113.199"
	fixture.Ingress.Interface = "changed"
	after, _, err := encodeNFTHistoricalPersistenceBinding(plan.binding)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("plan retained mutable input aliases", err)
	}
	custom := fixture.Source + "table inet administrator {}\n"
	if err := host.root.WriteFile(legacyNFTIncludePath[1:], []byte(custom), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := prepareNFTHistoricalPersistencePlan(host, []string{nftSharedFixturePath}, plan.binding.Inet, plan.binding.Ingress, plan.binding.Origins, plan.binding.Producers); err == nil {
		t.Fatal("custom source admitted to generated-file retirement")
	}
	actual, err := host.read(legacyNFTIncludePath)
	if err != nil || string(actual) != custom {
		t.Fatal("custom source changed during preparation", err)
	}
}

func TestNFTHistoricalGraphRequiresDurableBindingAfterUncertainPublication(t *testing.T) {
	host, plan, guard := fixtureNFTHistoricalGraph(t)
	original, err := host.read(nftSharedFixturePath)
	if err != nil {
		t.Fatal(err)
	}
	failure := errors.New("fixture sync failure")
	ops := defaultLegacyRetirementFileOps()
	rename, published := ops.rename, false
	ops.rename = func(a int, b string, c int, d string, e uint) error {
		err := rename(a, b, c, d, e)
		if err == nil && d == "historical-source.json" {
			published = true
		}
		return err
	}
	ops.sync = func(file *os.File) error {
		if published {
			return failure
		}
		return file.Sync()
	}
	if err := applyNFTHistoricalPersistencePlan(host, plan, plan.sha256, guard, ops); !errors.Is(err, failure) || !published {
		t.Fatal("uncertain source-binding publication was not exercised", err)
	}
	assertActive := func() {
		t.Helper()
		actual, err := host.read(nftSharedFixturePath)
		if err != nil || !bytes.Equal(original, actual) {
			t.Fatal("active include changed before durable binding", err)
		}
		if _, err := host.snapshot(legacyNFTIncludePath); err != nil {
			t.Fatal("source moved before durable binding", err)
		}
	}
	assertActive()
	ops = defaultLegacyRetirementFileOps()
	checked := false
	ops.sync = func(file *os.File) error {
		if filepath.Base(file.Name()) == "historical-source.json" {
			checked = true
			return failure
		}
		return file.Sync()
	}
	if err := applyNFTHistoricalPersistencePlan(host, plan, plan.sha256, guard, ops); !errors.Is(err, failure) || !checked {
		t.Fatal("retry did not resynchronize the retained source binding", err)
	}
	assertActive()
	if err := applyNFTHistoricalPersistencePlan(host, plan, plan.sha256, guard, defaultLegacyRetirementFileOps()); err != nil {
		t.Fatal(err)
	}
	assertNFTPersistenceRecoveryComplete(t, host, plan.graph, plan.sha256)
}

func TestNFTHistoricalGraphLiveFixture(t *testing.T) {
	if os.Getenv("SYSWARDEN_TEST_NFT_HISTORICAL_GRAPH_LIVE") != "1" {
		t.Skip("requires an isolated historical graph fixture")
	}
	parent := os.Getenv("SYSWARDEN_TEST_PARENT_NETNS")
	current, err := os.Readlink("/proc/self/ns/net")
	mapping, mapErr := os.ReadFile("/proc/self/uid_map")
	fields := strings.Fields(string(mapping))
	if err != nil || mapErr != nil || parent == "" || parent == current || os.Geteuid() != 0 || len(fields) != 3 || fields[0] != "0" || fields[2] != "1" {
		t.Fatal("fixture requires a distinct single-user network namespace")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	command := func(binary string, input []byte, args ...string) []byte {
		t.Helper()
		if binary != "/usr/bin/nft" && binary != "/usr/bin/ip" {
			t.Fatal("unsupported fixture binary")
		}
		cmd := exec.CommandContext(ctx, binary, args...) // #nosec G204 -- Fixed fixture binaries and synthetic arguments in a verified disposable network namespace.
		cmd.Stdin = bytes.NewReader(input)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("fixture command failed: %v: %s", err, out)
		}
		return out
	}
	nft := func(input []byte, args ...string) []byte { return command("/usr/bin/nft", input, args...) }
	if strings.Contains(string(nft(nil, "-j", "list", "tables")), `"table"`) {
		t.Fatal("fixture namespace is not empty")
	}
	command("/usr/bin/ip", nil, "link", "set", "lo", "up")
	command("/usr/bin/ip", nil, "link", "add", "swv0", "type", "veth", "peer", "name", "swv1")
	allowed, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = allowed.Close() }()
	blocked, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = blocked.Close() }()
	port := blocked.Addr().(*net.TCPAddr).Port
	admin := fmt.Sprintf("table inet administrator {\n chain input {\n type filter hook input priority -50; policy accept;\n tcp dport %d drop\n }\n}\n", port)
	host, _, _ := fixtureNFTPersistenceGraphRecord(t)
	if err := host.root.WriteFile("root/operator-policy.nft", []byte(admin), 0600); err != nil {
		t.Fatal(err)
	}
	fixture := fixtureNFTHistoricalFiles(t)[39]
	if err := host.root.WriteFile(legacyNFTIncludePath[1:], []byte(fixture.Source), 0600); err != nil {
		t.Fatal(err)
	}
	if err := host.root.MkdirAll("var/backups", 0700); err != nil {
		t.Fatal(err)
	}
	plan, err := prepareNFTHistoricalPersistencePlan(host, []string{nftSharedFixturePath}, fixture.Inet, &fixture.Ingress, strings.Repeat("a", 64), strings.Repeat("b", 64))
	if err != nil {
		t.Fatal(err)
	}
	guard := func(origins, producers string) error {
		if origins != strings.Repeat("a", 64) || producers != strings.Repeat("b", 64) {
			return fmt.Errorf("synthetic fixture authority changed")
		}
		return nil
	}
	nft([]byte(admin+fixture.Source), "-f", "-")
	traffic := func() {
		t.Helper()
		conn, err := net.DialTimeout("tcp4", allowed.Addr().String(), time.Second)
		if err != nil {
			t.Fatal("unrelated allowed traffic failed", err)
		}
		_ = conn.Close()
		conn, err = net.DialTimeout("tcp4", blocked.Addr().String(), 200*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			t.Fatal("administrator block was lost")
		}
	}
	traffic()
	if err := applyNFTHistoricalPersistencePlan(host, plan, plan.sha256, guard, defaultLegacyRetirementFileOps()); err != nil {
		t.Fatal(err)
	}
	assertNFTPersistenceRecoveryComplete(t, host, plan.graph, plan.sha256)
	traffic()
	// File retirement does not claim runtime removal. Independently reattest
	// both complete fixture tables before using the atomic generation fence.
	document, err := inspectNFTPersistence([]byte(fixture.Source))
	if err != nil {
		t.Fatal(err)
	}
	fence, err := newNFTGenerationFence(ctx, func(context.Context) ([]nftTableTarget, error) {
		part := document.tables[0]
		if _, err := inspectNFTShellPersistentTable([]byte(fixture.Source[part.start:part.end]), nft(nil, "-t", "-j", "list", "table", "inet", "syswarden_table"), fixture.Inet); err != nil {
			return nil, err
		}
		part = document.tables[1]
		if _, err := inspectNFTHistoricalIngressPersistence([]byte(fixture.Source[part.start:part.end]), nft(nil, "-j", "list", "table", "netdev", "syswarden_hw_drop"), fixture.Ingress.Interface, fixture.Ingress.Geo, fixture.Ingress.ASN, fixture.Ingress.Populations); err != nil {
			return nil, err
		}
		return []nftTableTarget{{family: "inet", name: "syswarden_table"}, {family: "netdev", name: "syswarden_hw_drop"}}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer fence.close()
	if err := fence.apply(ctx, func() error { return verifyNFTHistoricalPersistencePlan(host, plan) }); err != nil {
		t.Fatal(err)
	}
	traffic()
	graph, err := inspectNFTPersistenceGraph([]string{nftSharedFixturePath}, host.reader())
	if err != nil {
		t.Fatal(err)
	}
	for _, source := range graph.sources {
		if source.path == legacyNFTIncludePath {
			t.Fatal("retired source remains reachable")
		}
	}
	retained, err := host.read("/root/operator-policy.nft")
	if err != nil || string(retained) != admin {
		t.Fatal("administrator source changed", err)
	}
	// A fresh load models persistence replay inside this disposable namespace.
	// It is not a host reboot qualification.
	nft(nil, "delete", "table", "inet", "administrator")
	nft(retained, "-f", "-")
	traffic()
	if strings.Contains(string(nft(nil, "-j", "list", "tables")), "syswarden") {
		t.Fatal("retired tables reappeared after persistent replay")
	}
	t.Log("Historical file and exact runtime retirements preserve administrator source, allowed TCP traffic and blocked TCP traffic; replay does not recreate the retired tables.")
}
