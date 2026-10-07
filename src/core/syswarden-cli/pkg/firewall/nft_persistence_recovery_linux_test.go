//go:build linux

package firewall

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func fixtureNFTPersistenceRecovery(t *testing.T) (nftPersistenceFilesystem, nftPersistenceGraphRecord, string, func(string, string) error) {
	t.Helper()
	host, _, retiring := fixtureNFTPersistenceGraphRecord(t)
	if err := host.root.MkdirAll("var/backups", 0700); err != nil {
		t.Fatal(err)
	}
	// Also bind a currently empty wildcard. Adding a file there must require
	// a new review even though it was not reachable in the original graph.
	file, err := host.root.OpenFile("etc/nftables.conf", os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, err = file.WriteString("include \"/etc/nftables.d/unused/*.nft\"\n")
	_ = file.Close()
	if err != nil {
		t.Fatal(err)
	}
	// These digests are synthetic fixture authorizations only. Production
	// requires independently attested ownership and quiescent producers.
	ownership, producers := strings.Repeat("a", 64), strings.Repeat("b", 64)
	record, digest, err := prepareNFTPersistenceGraphRecord(host, []string{nftSharedFixturePath}, retiring, ownership, producers)
	if err != nil {
		t.Fatal(err)
	}
	guard := func(actualOwnership, actualProducers string) error {
		if actualOwnership != ownership || actualProducers != producers {
			return fmt.Errorf("fixture authority differs from reviewed evidence")
		}
		return nil
	}
	return host, record, digest, guard
}

func assertNFTPersistenceRecoveryComplete(t *testing.T, host nftPersistenceFilesystem, record nftPersistenceGraphRecord, digest string) {
	t.Helper()
	state, err := inspectNFTPersistenceGraphState(host, record)
	if err != nil || len(state.retired) != 1 || len(state.edited) != 1 {
		t.Fatal("graph recovery is incomplete", err)
	}
	for _, source := range record.Sources {
		path := source.Artifact.Path
		location := path
		if state.retired[path] {
			if _, err := host.root.Lstat(path[1:]); !os.IsNotExist(err) {
				t.Fatal("owned source remains active", err)
			}
			location = legacyRetirementBackupDirectory(nftPersistenceGraphFileRecord(source, digest)) + "/original"
		} else if state.edited[path] {
			shared := state.shared[path]
			sharedState, err := inspectNFTPersistenceSharedState(host, shared)
			if err != nil || sharedState.phase != 2 {
				t.Fatal("original shared file is not durably retained", err)
			}
			location = nftPersistenceSharedDirectory(shared) + "/original"
		}
		snapshot, attrs, err := snapshotNFTPersistenceMetadata(host, location)
		if err != nil || !matchesNFTPersistenceGraphSource(source, snapshot, attrs) {
			t.Fatal("original bytes, inode or metadata were not preserved", path, err)
		}
	}
	if _, err := readNFTPersistenceGraphRecord(host, digest); err != nil {
		t.Fatal("exact graph journal is unavailable", err)
	}
}

func TestNFTPersistenceGraphRecoveryPreservesAdministratorSources(t *testing.T) {
	host, record, digest, guard := fixtureNFTPersistenceRecovery(t)
	if err := applyNFTPersistenceGraphRecord(host, record, digest, guard, defaultLegacyRetirementFileOps()); err != nil {
		t.Fatal(err)
	}
	assertNFTPersistenceRecoveryComplete(t, host, record, digest)
	if err := applyNFTPersistenceGraphRecord(host, record, digest, guard, defaultLegacyRetirementFileOps()); err != nil {
		t.Fatal("completed graph recovery is not idempotent", err)
	}
	assertNFTPersistenceRecoveryComplete(t, host, record, digest)
}

func TestNFTPersistenceGraphRecoveryResumesEachDurabilityBoundary(t *testing.T) {
	for _, phase := range []string{"backup-directory-durable", "graph-plan-published", "graph-plan-durable", "shared-edit-intent-durable", "shared-edit-exchanged", "shared-edit-original-retained", "shared-edit-durable", "graph-shared-edits-durable", "intent-published", "source-retired", "retirement-durable", "graph-retirement-durable"} {
		t.Run(phase, func(t *testing.T) {
			host, record, digest, guard := fixtureNFTPersistenceRecovery(t)
			ops, reached := defaultLegacyRetirementFileOps(), false
			interrupted := errors.New("fixture interruption")
			ops.checkpoint = func(actual string) error {
				if actual == phase {
					reached = true
					return interrupted
				}
				return nil
			}
			if err := applyNFTPersistenceGraphRecord(host, record, digest, guard, ops); !errors.Is(err, interrupted) || !reached {
				t.Fatal("expected interruption was not reached", err)
			}
			if err := applyNFTPersistenceGraphRecord(host, record, digest, guard, defaultLegacyRetirementFileOps()); err != nil {
				t.Fatal("interrupted graph did not resume", err)
			}
			assertNFTPersistenceRecoveryComplete(t, host, record, digest)
		})
	}
}

func TestNFTPersistenceGraphRecoveryRejectsUnreviewedChanges(t *testing.T) {
	for _, change := range []string{"administrator-bytes", "administrator-mode", "administrator-xattr", "wildcard", "empty-wildcard", "owned-bytes", "retired-recreated", "retained-absent", "changed-original", "missing-graph", "changed-graph", "missing-edit", "wrong-digest", "ownership", "producer", "nil-guard"} {
		t.Run(change, func(t *testing.T) {
			host, record, digest, guard := fixtureNFTPersistenceRecovery(t)
			ops := defaultLegacyRetirementFileOps()
			ops.checkpoint = func(phase string) error {
				if phase == "shared-edit-original-retained" {
					return errors.New("fixture interruption")
				}
				return nil
			}
			if err := applyNFTPersistenceGraphRecord(host, record, digest, guard, ops); err == nil {
				t.Fatal("fixture did not interrupt")
			}
			state, err := inspectNFTPersistenceGraphState(host, record)
			if err != nil {
				t.Fatal(err)
			}
			write := func(path, content string) {
				t.Helper()
				if err := host.root.WriteFile(path[1:], []byte(content), 0600); err != nil {
					t.Fatal(err)
				}
			}
			switch change {
			case "administrator-bytes":
				write("/root/operator-policy.nft", "table inet changed { }\n")
			case "administrator-mode":
				if err := host.root.Chmod("root/operator-policy.nft", 0640); err != nil {
					t.Fatal(err)
				}
			case "administrator-xattr":
				file, err := host.root.Open("root/operator-policy.nft")
				if err != nil {
					t.Fatal(err)
				}
				err = unix.Fsetxattr(int(file.Fd()), "user.operator", []byte("changed"), 0)
				_ = file.Close()
				if err != nil {
					t.Fatal(err)
				}
			case "wildcard":
				write("/etc/nftables.d/new.nft", "table inet new { }\n")
			case "empty-wildcard":
				if err := host.root.MkdirAll("etc/nftables.d/unused", 0700); err != nil {
					t.Fatal(err)
				}
				write("/etc/nftables.d/unused/new.nft", "table inet new { }\n")
			case "owned-bytes":
				write(legacyNFTIncludePath, "table inet operator { }\n")
			case "retired-recreated":
				if err := applyNFTPersistenceGraphRecord(host, record, digest, guard, defaultLegacyRetirementFileOps()); err != nil {
					t.Fatal(err)
				}
				write(legacyNFTIncludePath, "table inet operator { }\n")
			case "retained-absent":
				if err := host.root.Rename("root/operator-policy.nft", "root/retained-private.nft"); err != nil {
					t.Fatal(err)
				}
			case "changed-original":
				write(nftPersistenceSharedDirectory(state.shared[nftSharedFixturePath])+"/original", "table inet operator { }\n")
			case "missing-graph":
				if err := host.root.Remove(legacyFail2banPlanPath(digest)[1:] + "/plan.json"); err != nil {
					t.Fatal(err)
				}
			case "changed-graph":
				write(legacyFail2banPlanPath(digest)+"/plan.json", "{}")
			case "missing-edit":
				if err := host.root.Remove(nftPersistenceSharedDirectory(state.shared[nftSharedFixturePath])[1:] + "/edit.json"); err != nil {
					t.Fatal(err)
				}
			case "wrong-digest":
				digest = strings.Repeat("c", 64)
			case "ownership":
				record.Ownership = strings.Repeat("c", 64)
			case "producer":
				guard = func(string, string) error { return errors.New("fixture producer reactivated") }
			case "nil-guard":
				guard = nil
			}
			before, err := host.root.ReadFile("etc/nftables.conf")
			if err != nil {
				t.Fatal(err)
			}
			if err := applyNFTPersistenceGraphRecord(host, record, digest, guard, defaultLegacyRetirementFileOps()); err == nil {
				t.Fatal("changed graph accepted", change)
			}
			after, err := host.root.ReadFile("etc/nftables.conf")
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("refusal changed shared administrator configuration", err)
			}
		})
	}
}

func TestNFTPersistenceGraphRecoveryAbruptExitChild(t *testing.T) {
	path := os.Getenv("SYSWARDEN_NFT_GRAPH_TEST_ROOT")
	if path == "" {
		t.Skip("private graph recovery subprocess only")
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	host := fixtureNFTPersistencePinnedRoot(t, root)
	digest := os.Getenv("SYSWARDEN_NFT_GRAPH_TEST_DIGEST")
	record, err := readNFTPersistenceGraphRecord(host, digest)
	if err != nil {
		t.Fatal(err)
	}
	ops := defaultLegacyRetirementFileOps()
	ops.checkpoint = func(phase string) error {
		if phase == os.Getenv("SYSWARDEN_NFT_GRAPH_TEST_PHASE") {
			os.Exit(79)
		}
		return nil
	}
	// Synthetic source ownership and producer evidence, confined to the
	// parent's disposable root. This is not production authorization.
	guard := func(ownership, producers string) error {
		if ownership != strings.Repeat("a", 64) || producers != strings.Repeat("b", 64) {
			return errors.New("unexpected fixture evidence")
		}
		return nil
	}
	if err := applyNFTPersistenceGraphRecord(host, record, digest, guard, ops); err != nil {
		t.Fatal(err)
	}
	t.Fatal("child did not reach its expected abrupt exit")
}

func TestNFTPersistenceGraphRecoveryResumesAbruptProcessExit(t *testing.T) {
	for _, phase := range []string{"graph-plan-durable", "shared-edit-intent-durable", "shared-edit-exchanged", "shared-edit-original-retained", "graph-shared-edits-durable", "intent-published", "source-retired", "retirement-durable", "graph-retirement-durable"} {
		t.Run(phase, func(t *testing.T) {
			host, record, digest, guard := fixtureNFTPersistenceRecovery(t)
			if err := persistNFTPersistenceGraphRecord(host, record, digest, func() error { return guard(record.Ownership, record.Producers) }, defaultLegacyRetirementFileOps()); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestNFTPersistenceGraphRecoveryAbruptExitChild$") // #nosec G204 G702 -- Reexecutes only this test binary with a fixed helper selector and private fixture environment.
			command.Env = append(os.Environ(), "SYSWARDEN_NFT_GRAPH_TEST_ROOT="+host.root.Name(), "SYSWARDEN_NFT_GRAPH_TEST_DIGEST="+digest, "SYSWARDEN_NFT_GRAPH_TEST_PHASE="+phase)
			output, err := command.CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 79 {
				t.Fatalf("child did not terminate at the required boundary: %v %s", err, output)
			}
			if err := applyNFTPersistenceGraphRecord(host, record, digest, guard, defaultLegacyRetirementFileOps()); err != nil {
				t.Fatal("abruptly interrupted graph did not resume", err)
			}
			assertNFTPersistenceRecoveryComplete(t, host, record, digest)
		})
	}
}

func TestNFTPersistenceGraphRecoveryReattestsCompletion(t *testing.T) {
	host, record, digest, guard := fixtureNFTPersistenceRecovery(t)
	ops := defaultLegacyRetirementFileOps()
	ops.checkpoint = func(phase string) error {
		if phase == "graph-retirement-durable" {
			return host.root.WriteFile(legacyNFTIncludePath[1:], []byte("table inet administrator { }\n"), 0600)
		}
		return nil
	}
	if err := applyNFTPersistenceGraphRecord(host, record, digest, guard, ops); err == nil {
		t.Fatal("reappearing source was reported as complete retirement")
	}
}
