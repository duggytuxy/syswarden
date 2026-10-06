//go:build linux

package firewall

import (
	"bytes"
	"context"
	"errors"
	"os"
	"reflect"
	"testing"
)

func fixtureNFTRemovalSession(t *testing.T, shared string) *nftRemovalSession {
	t.Helper()
	host, plan, _ := fixtureNFTOwnedPolicyPlan(t, fixtureNFTCurrentFiles(t)[7], shared)
	var entries []string
	if shared != "none" {
		entries = []string{"/etc/nftables.conf"}
	}
	// This callback stands for an independently attested producer in component
	// tests. Production uses the actual service, process and scheduling adapters.
	producers := nftRemovalProducerInspection{entries: entries, digest: plan.binding.Producers, verify: func(context.Context) error { return nil }}
	session, err := prepareNFTRemovalSession(context.Background(), host, producers)
	if err != nil {
		t.Fatal(err)
	}
	return session
}

func TestNFTRemovalProgressResumesEverySourceTransition(t *testing.T) {
	for _, shared := range []string{"none", "independent", "include"} {
		for _, phase := range []string{"historical-source-binding-durable", "nft-removal-progress-staged", "edit-staged", "source-retired", "graph-retirement-durable", "none"} {
			t.Run(shared+"/"+phase, func(t *testing.T) {
				session := fixtureNFTRemovalSession(t, shared)
				ctx := context.Background()
				if err := preflightKnownNFTPersistenceRemoval(session.host); err != nil {
					t.Fatal("writer-owned include cannot reach production cleanup", err)
				}
				if _, err := session.host.root.Stat(nftRemovalProgressPath[1:]); !os.IsNotExist(err) {
					t.Fatal("read-only preparation created progress")
				}
				sentinel := errors.New("synthetic process exit")
				reached := false
				ops := defaultLegacyRetirementFileOps()
				ops.checkpoint = func(at string) error {
					if at == phase {
						reached = true
						return sentinel
					}
					return nil
				}
				err := applyNFTOwnedRemovalSources(session.host, session.plan, session.guard(ctx), ops)
				if reached && !errors.Is(err, sentinel) || !reached && err != nil {
					t.Fatal("unexpected first invocation", err)
				}
				if phase == "nft-removal-progress-staged" {
					if _, err := session.host.root.Stat(legacyNFTIncludePath[1:]); err != nil {
						t.Fatal("unpublished progress changed active sources", err)
					}
				}
				resumed, err := prepareNFTRemovalSession(ctx, session.host, session.producers)
				if err != nil {
					t.Fatal("fresh invocation could not select its exact durable plan", err)
				}
				if !reflect.DeepEqual(resumed.plan, session.plan) {
					t.Fatal("resumed graph changed")
				}
				if err := applyNFTOwnedRemovalSources(resumed.host, resumed.plan, resumed.guard(ctx), defaultLegacyRetirementFileOps()); err != nil {
					t.Fatal(err)
				}
				disk, _, present, err := readNFTRemovalProgress(session.host)
				if err != nil || !present || !reflect.DeepEqual(disk, session.plan) {
					t.Fatal("durable selected plan missing", err)
				}
				if _, err := currentNFTRetiredSource(session.host, disk); err != nil {
					t.Fatal(err)
				}
				if shared != "none" {
					content, err := session.host.root.ReadFile("etc/nftables.d/administrator.nft")
					if err != nil || !bytes.Equal(content, []byte(nftOwnedPolicyAdministratorSource)) {
						t.Fatal("administrator source changed", err)
					}
				}
			})
		}
	}
}

func TestNFTRemovalProgressRejectsChangedAuthorityAndMissingReference(t *testing.T) {
	for _, change := range []string{"missing-progress", "modified-progress", "public-progress", "modified-receipt", "missing-journal", "changed-producers", "changed-entries"} {
		t.Run(change, func(t *testing.T) {
			session := fixtureNFTRemovalSession(t, "include")
			ctx := context.Background()
			if err := applyNFTOwnedRemovalSources(session.host, session.plan, session.guard(ctx), defaultLegacyRetirementFileOps()); err != nil {
				t.Fatal(err)
			}
			switch change {
			case "missing-progress":
				if err := session.host.root.Remove(nftRemovalProgressPath[1:]); err != nil {
					t.Fatal(err)
				}
			case "modified-progress":
				if err := session.host.root.WriteFile(nftRemovalProgressPath[1:], []byte("{}"), 0600); err != nil {
					t.Fatal(err)
				}
			case "public-progress":
				if err := session.host.root.Chmod(nftRemovalProgressPath[1:], 0644); err != nil {
					t.Fatal(err)
				}
			case "modified-receipt":
				if err := session.host.root.WriteFile((nftStateDirectory + "/" + nftPolicyOwnershipName)[1:], []byte("{}"), 0600); err != nil {
					t.Fatal(err)
				}
			case "missing-journal":
				if err := session.host.root.Remove((legacyFail2banPlanPath(session.plan.sha256) + "/historical-source.json")[1:]); err != nil {
					t.Fatal(err)
				}
			case "changed-producers":
				session.producers.digest = session.origin.digest
			case "changed-entries":
				session.producers.entries = []string{"/etc/other.nft"}
			}
			if _, err := prepareNFTRemovalSession(ctx, session.host, session.producers); err == nil {
				t.Fatal("changed authority was adopted")
			}
			content, err := session.host.root.ReadFile("etc/nftables.d/administrator.nft")
			if err != nil || !bytes.Equal(content, []byte(nftOwnedPolicyAdministratorSource)) {
				t.Fatal("administrator policy changed", err)
			}
		})
	}
}

func TestNFTRemovalProgressCannotPrecedeDurableEvidence(t *testing.T) {
	session := fixtureNFTRemovalSession(t, "independent")
	if err := bindNFTRemovalProgress(session.host, session.plan, func() error { return nil }, defaultLegacyRetirementFileOps()); err == nil {
		t.Fatal("progress published without durable source evidence")
	}
	if _, err := session.host.root.Stat(nftRemovalProgressPath[1:]); !os.IsNotExist(err) {
		t.Fatal("unbound progress was published")
	}
}

func TestNFTRemovalProgressRejectsProducerChangeBeforeSourceEdit(t *testing.T) {
	session := fixtureNFTRemovalSession(t, "include")
	ctx := context.Background()
	failed := false
	session.producers.verify = func(context.Context) error {
		if failed {
			return errors.New("producer restarted")
		}
		return nil
	}
	ops := defaultLegacyRetirementFileOps()
	ops.checkpoint = func(phase string) error {
		if phase == "historical-source-binding-durable" {
			failed = true
		}
		return nil
	}
	if err := applyNFTOwnedRemovalSources(session.host, session.plan, session.guard(ctx), ops); err == nil {
		t.Fatal("changed producers were accepted")
	}
	if _, err := session.host.root.Stat(legacyNFTIncludePath[1:]); err != nil {
		t.Fatal("unverified source was retired", err)
	}
	content, err := session.host.root.ReadFile("etc/nftables.conf")
	if err != nil || !bytes.Contains(content, []byte(legacyNFTIncludeLine)) {
		t.Fatal("shared source changed after producer failure", err)
	}
}

func TestNFTRemovalPreparationFailurePreservesCompatibilityPermissions(t *testing.T) {
	previousUID, previousReattest := firewallCleanupEffectiveUserID, firewallRemovalServiceReattest
	previousRunner, previousPrepare, previousWrapper := uninstallNFTRunnerFactory, prepareNFTCleanupForUninstall, applyLinuxFirewallWrappersForUninstall
	t.Cleanup(func() {
		firewallCleanupEffectiveUserID, firewallRemovalServiceReattest = previousUID, previousReattest
		uninstallNFTRunnerFactory, prepareNFTCleanupForUninstall, applyLinuxFirewallWrappersForUninstall = previousRunner, previousPrepare, previousWrapper
	})
	firewallCleanupEffectiveUserID = func() int { return 0 }
	firewallRemovalServiceReattest = func() error { return nil }
	uninstallNFTRunnerFactory = func() (nftCommandRunner, error) { return &fakeUninstallNFTRunner{}, nil }
	sentinel := errors.New("runtime ownership is unproven")
	prepareNFTCleanupForUninstall = func(context.Context, nftCommandRunner) (func() error, func(), error) { return nil, nil, sentinel }
	applyLinuxFirewallWrappersForUninstall = func([]string, []string) error {
		t.Fatal("compatibility permissions changed before ownership validation")
		return nil
	}
	if err := CleanupOwnedCompatibilityRulesForUninstall(); !errors.Is(err, sentinel) {
		t.Fatal("unexpected preparation result", err)
	}
}
