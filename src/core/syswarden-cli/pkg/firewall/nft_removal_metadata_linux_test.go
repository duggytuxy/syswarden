//go:build linux

package firewall

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"testing"
)

func TestNFTRemovalMetadataRetiresLastAndResumesInterruptedReceipt(t *testing.T) {
	for _, shared := range []string{"none", "independent", "include"} {
		for _, phase := range []string{"none", "metadata-writer-intent-published", "metadata-writer-source-retired", "metadata-writer-retirement-durable", "metadata-progress-intent-published", "metadata-progress-source-retired", "metadata-progress-retirement-durable"} {
			t.Run(shared+"/"+phase, func(t *testing.T) {
				session := fixtureNFTRemovalSession(t, shared)
				ctx := context.Background()
				if err := applyNFTOwnedRemovalSources(session.host, session.plan, session.guard(ctx), defaultLegacyRetirementFileOps()); err != nil {
					t.Fatal(err)
				}
				receiptPath := nftStateDirectory + "/" + nftPolicyOwnershipName
				receipt, err := session.host.read(receiptPath)
				if err != nil {
					t.Fatal(err)
				}
				progress, err := session.host.snapshot(nftRemovalProgressPath)
				if err != nil {
					t.Fatal(err)
				}
				progressFile, err := makeLegacyRetirementFileRecord(nftRemovalProgressPath, session.plan.sha256, progress)
				if err != nil {
					t.Fatal(err)
				}
				runner := &nftRemovalFixtureRunner{}
				sentinel := errors.New("synthetic interruption")
				ops := defaultLegacyRetirementFileOps()
				reached := false
				ops.checkpoint = func(at string) error {
					if at == phase {
						reached = true
						return sentinel
					}
					return nil
				}
				err = session.retireMetadata(ctx, runner, ops)
				if phase == "none" && err != nil || phase != "none" && (!reached || !errors.Is(err, sentinel)) {
					t.Fatal("unexpected metadata retirement result", err)
				}
				_, _, present, err := readNFTRemovalProgress(session.host)
				if err != nil {
					t.Fatal("exact receipt backup cannot be recovered", err)
				}
				if present {
					resumed, err := prepareNFTRemovalSession(ctx, session.host, session.producers)
					if err != nil {
						t.Fatal("fresh invocation could not resume", err)
					}
					if err := resumed.retire(ctx, runner, defaultLegacyRetirementFileOps()); err != nil {
						t.Fatal("complete firewall coordinator failed to resume", err)
					}
				}
				for _, path := range []string{receiptPath, nftRemovalProgressPath, legacyNFTIncludePath} {
					if _, err := session.host.snapshot(path); !errors.Is(err, fs.ErrNotExist) {
						t.Fatalf("active product source remains at %s: %v", path, err)
					}
				}
				for _, original := range []struct {
					record  legacyRetirementFileRecord
					content []byte
				}{{nftPersistenceGraphFileRecord(session.origin.record, session.plan.sha256), receipt}, {progressFile, progress.content}} {
					path := legacyRetirementBackupDirectory(original.record) + "/original"
					actual, err := session.host.read(path)
					if err != nil || !bytes.Equal(actual, original.content) {
						t.Fatal("private original was not retained exactly", err)
					}
				}
				if shared != "none" {
					actual, err := session.host.read("/etc/nftables.d/administrator.nft")
					if err != nil || string(actual) != nftOwnedPolicyAdministratorSource {
						t.Fatal("administrator source changed", err)
					}
				}
			})
		}
	}
}

func TestNFTRemovalMetadataRejectsIncompleteOrChangedState(t *testing.T) {
	for _, change := range []string{"active-source", "live-table", "producer", "receipt-after-move", "progress-after-move"} {
		t.Run(change, func(t *testing.T) {
			session := fixtureNFTRemovalSession(t, "include")
			ctx := context.Background()
			if change != "active-source" {
				if err := applyNFTOwnedRemovalSources(session.host, session.plan, session.guard(ctx), defaultLegacyRetirementFileOps()); err != nil {
					t.Fatal(err)
				}
			}
			runner := &nftRemovalFixtureRunner{}
			ops := defaultLegacyRetirementFileOps()
			switch change {
			case "live-table":
				runner.tables = map[nftTableTarget][]byte{{family: "inet", name: "syswarden"}: []byte(`{}`)}
			case "producer":
				session.producers.verify = func(context.Context) error { return errors.New("producer restarted") }
			case "receipt-after-move", "progress-after-move":
				ops.checkpoint = func(at string) error {
					if at == "metadata-writer-source-retired" {
						path := nftRemovalProgressPath
						if change == "receipt-after-move" {
							path = legacyRetirementBackupDirectory(nftPersistenceGraphFileRecord(session.origin.record, session.plan.sha256)) + "/original"
						}
						return session.host.root.WriteFile(path[1:], []byte("{}"), 0600)
					}
					return nil
				}
			}
			if err := session.retireMetadata(ctx, runner, ops); err == nil {
				t.Fatal("unverified terminal state accepted")
			}
			if change != "active-source" {
				if _, err := session.host.snapshot(nftRemovalProgressPath); err != nil {
					t.Fatal("progress removed despite incomplete recovery", err)
				}
			}
		})
	}
}
