//go:build linux

package firewall

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
)

const nftOwnedPolicyAdministratorSource = "table inet administrator { chain input { type filter hook input priority -50; policy accept; } }\n"

func fixtureNFTOwnedPolicyPlan(t *testing.T, fixture nftCurrentFileFixture, shared string, administrator ...string) (nftPersistenceFilesystem, nftHistoricalPersistencePlan, func(string, string) error) {
	t.Helper()
	_, host := fixtureNFTPersistenceFilesystem(t)
	if err := host.root.MkdirAll("var/backups", 0700); err != nil {
		t.Fatal(err)
	}
	if err := host.root.WriteFile(legacyNFTIncludePath[1:], []byte(fixture.Source), 0600); err != nil {
		t.Fatal(err)
	}
	receipt, err := prepareNFTPolicyOwnership([]byte(fixture.Source), fixtureNFTPolicyGeneration(t, fixture), recoveryFixtureTransactionID)
	if err != nil {
		t.Fatal(err)
	}
	if err := host.root.WriteFile((nftStateDirectory + "/" + nftPolicyOwnershipName)[1:], receipt, 0600); err != nil {
		t.Fatal(err)
	}
	var entries []string
	adminSource := nftOwnedPolicyAdministratorSource
	if len(administrator) > 1 {
		t.Fatal("ambiguous administrator fixture input")
	}
	if len(administrator) == 1 {
		adminSource = administrator[0]
	}
	if shared != "none" {
		content := "include \"/etc/nftables.d/administrator.nft\"\n"
		if shared == "include" {
			content += legacyNFTIncludeMarker + "\n" + legacyNFTIncludeLine + "\n"
		}
		if err := host.root.WriteFile("etc/nftables.conf", []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
		if err := host.root.WriteFile("etc/nftables.d/administrator.nft", []byte(adminSource), 0600); err != nil {
			t.Fatal(err)
		}
		entries = []string{"/etc/nftables.conf"}
	}
	// Writer ownership is inspected through the real filesystem adapter.
	// Product-loader quiescence is synthetic here, not a host qualification.
	producers := strings.Repeat("b", 64)
	plan, origin, err := prepareNFTOwnedCurrentPersistencePlan(host, entries, producers)
	if err != nil {
		t.Fatal(err)
	}
	guard := func(a, b string) error {
		if a != origin.digest || b != producers {
			return fmt.Errorf("fixture producer or ownership binding changed")
		}
		return origin.verify(host)
	}
	return host, plan, guard
}

func TestNFTOwnedPolicyRetiresDedicatedEntryAndPreservesSharedSources(t *testing.T) {
	for _, shared := range []string{"none", "independent", "include"} {
		for _, phase := range []string{"none", "source-retired", "graph-retirement-durable"} {
			t.Run(shared+"/"+phase, func(t *testing.T) {
				host, plan, guard := fixtureNFTOwnedPolicyPlan(t, fixtureNFTCurrentFiles(t)[7], shared)
				if !plan.graph.ProductEntry || !plan.binding.ProductEntry {
					t.Fatal("dedicated entry is not bound in both durable records")
				}
				if _, err := host.root.Stat("var/backups/syswarden-retired-v1"); !os.IsNotExist(err) {
					t.Fatal("read-only ownership inspection created a journal")
				}
				ops := defaultLegacyRetirementFileOps()
				sentinel := errors.New("simulated interruption")
				ops.checkpoint = func(at string) error {
					if at == phase {
						return sentinel
					}
					return nil
				}
				err := applyNFTHistoricalPersistencePlan(host, plan, plan.sha256, guard, ops)
				if phase == "none" && err != nil || phase != "none" && !errors.Is(err, sentinel) {
					t.Fatal("unexpected retirement result", err)
				}
				recovered, err := readNFTHistoricalPersistencePlan(host, plan.sha256)
				if err != nil {
					t.Fatal(err)
				}
				if err := applyNFTHistoricalPersistencePlan(host, recovered, recovered.sha256, guard, defaultLegacyRetirementFileOps()); err != nil {
					t.Fatal(err)
				}
				if _, err := host.root.Stat(legacyNFTIncludePath[1:]); !os.IsNotExist(err) {
					t.Fatal("active product policy remained", err)
				}
				if _, err := currentNFTRetiredSource(host, recovered); err != nil {
					t.Fatal("runtime coordinator cannot consume the dedicated retired source", err)
				}
				if shared != "none" {
					got, err := host.root.ReadFile("etc/nftables.d/administrator.nft")
					if err != nil || !bytes.Equal(got, []byte(nftOwnedPolicyAdministratorSource)) {
						t.Fatal("administrator policy changed", err)
					}
					got, err = host.root.ReadFile("etc/nftables.conf")
					if err != nil || string(got) != "include \"/etc/nftables.d/administrator.nft\"\n" {
						t.Fatal("shared entry point did not retain its administrator dependency", err)
					}
				}
			})
		}
	}
}

func TestNFTOwnedPolicyRejectsSharedEntryAndChangedOrigin(t *testing.T) {
	for _, change := range []string{"missing-receipt", "changed-receipt", "public-receipt", "changed-source", "shared-entry", "changed-producers"} {
		t.Run(change, func(t *testing.T) {
			host, plan, guard := fixtureNFTOwnedPolicyPlan(t, fixtureNFTCurrentFiles(t)[1], "independent")
			path := (nftStateDirectory + "/" + nftPolicyOwnershipName)[1:]
			switch change {
			case "missing-receipt":
				if err := host.root.Remove(path); err != nil {
					t.Fatal(err)
				}
			case "changed-receipt":
				if err := host.root.WriteFile(path, []byte("{}\n"), 0600); err != nil {
					t.Fatal(err)
				}
			case "public-receipt":
				if err := host.root.Chmod(path, 0644); err != nil {
					t.Fatal(err)
				}
			case "changed-source":
				if err := host.root.WriteFile(legacyNFTIncludePath[1:], []byte("# administrator replacement\n"), 0600); err != nil {
					t.Fatal(err)
				}
			case "shared-entry":
				if _, _, err := prepareNFTOwnedCurrentPersistencePlan(host, []string{legacyNFTIncludePath}, plan.binding.Producers); err == nil {
					t.Fatal("a shared loader entry point became retireable")
				}
				return
			case "changed-producers":
				guard = func(string, string) error { return fmt.Errorf("product loader is no longer quiescent") }
			}
			if err := applyNFTHistoricalPersistencePlan(host, plan, plan.sha256, guard, defaultLegacyRetirementFileOps()); err == nil {
				t.Fatal("changed ownership or authority was adopted")
			}
			if _, err := host.root.Stat(legacyNFTIncludePath[1:]); err != nil {
				t.Fatal("refused retirement moved the active source", err)
			}
		})
	}
}

func TestNFTOwnedPolicyCannotDetachAdministratorDependencies(t *testing.T) {
	files := map[string]string{
		legacyNFTIncludePath:     "include \"/etc/administrator.nft\"\n",
		"/etc/administrator.nft": nftOwnedPolicyAdministratorSource,
	}
	graph, err := inspectNFTPersistenceGraph([]string{legacyNFTIncludePath}, fixtureNFTPersistenceReader(files, make(map[string]int)))
	if err != nil {
		t.Fatal(err)
	}
	var retired []nftPersistenceRetiredSource
	for _, source := range graph.sources {
		if source.path == legacyNFTIncludePath {
			retired = append(retired, nftPersistenceRetiredSource{source.path, source.sha256})
		}
	}
	if err := verifyNFTPersistenceRetirementCoverageWithProductEntry(graph, retired, true); err == nil {
		t.Fatal("dedicated entry retirement detached an administrator source")
	}
	if err := verifyNFTPersistenceRetirementCoverage(graph, retired); err == nil {
		t.Fatal("ordinary include retirement acquired dedicated-loader authority")
	}
}
