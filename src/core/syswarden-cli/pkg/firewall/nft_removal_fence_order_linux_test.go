//go:build linux

package firewall

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"testing"
)

func TestNFTRuntimeRetirementRejectsIntentChangesAfterDurability(t *testing.T) {
	for _, phase := range []string{"kernel-retirement-intent-durable", "kernel-retirement-inspected"} {
		for _, change := range []string{"bytes", "inode", "mode", "missing", "symlink"} {
			t.Run(phase+"/"+change, func(t *testing.T) {
				fixture := fixtureNFTCurrentFiles(t)[7]
				host, plan, guard := fixtureNFTCurrentRuntimePlan(t, fixture, true)
				runner := fixtureNFTCurrentRuntimeRunner(fixture)
				path := (legacyFail2banPlanPath(plan.sha256) + "/kernel-retirement.json")[1:]
				ops := defaultLegacyRetirementFileOps()
				ops.checkpoint = func(at string) error {
					if at != phase {
						return nil
					}
					before, err := host.root.ReadFile(path)
					if err != nil {
						return err
					}
					switch change {
					case "bytes":
						return host.root.WriteFile(path, bytes.Replace(before, []byte("syswarden-nft"), []byte("different-nft"), 1), 0600)
					case "mode":
						return host.root.Chmod(path, 0644)
					default:
						if err := host.root.Rename(path, path+".old"); err != nil {
							return err
						}
						if change == "inode" {
							return host.root.WriteFile(path, before, 0600)
						}
						if change == "symlink" {
							return host.root.Symlink("kernel-retirement.json.old", path)
						}
					}
					return nil
				}
				factory := func(ctx context.Context, inspect func(context.Context) ([]nftTableTarget, error)) (nftRemovalFence, error) {
					if _, err := inspect(ctx); err != nil {
						return nil, err
					}
					return &nftRemovalFixtureFence{run: func(_ context.Context, check func() error) error {
						if err := check(); err != nil {
							return err
						}
						t.Fatal("changed durable intent reached a kernel mutation")
						return nil
					}}, nil
				}
				if err := retireNFTCurrentRuntimeUsing(context.Background(), host, plan, plan.sha256, guard, runner, ops, factory); err == nil {
					t.Fatal("modified or replaced durable evidence was accepted")
				}
			})
		}
	}
}

func TestNFTRuntimeRetirementDurabilityPrecedesShortLivedFence(t *testing.T) {
	fixture := fixtureNFTCurrentFiles(t)[7]
	host, plan, guard := fixtureNFTCurrentRuntimePlan(t, fixture, true)
	runner := fixtureNFTCurrentRuntimeRunner(fixture)
	issued, synchronized := false, false
	ops := defaultLegacyRetirementFileOps()
	ops.sync = func(file *os.File) error {
		if issued {
			return fmt.Errorf("durability work consumed the live generation fence")
		}
		synchronized = true
		return file.Sync()
	}
	factory := func(ctx context.Context, inspect func(context.Context) ([]nftTableTarget, error)) (nftRemovalFence, error) {
		if !synchronized {
			return nil, fmt.Errorf("generation fence opened before durable intent")
		}
		targets, err := inspect(ctx)
		if err != nil {
			return nil, err
		}
		issued = true
		return &nftRemovalFixtureFence{run: func(_ context.Context, check func() error) error {
			if err := check(); err != nil {
				return err
			}
			for _, target := range targets {
				delete(runner.tables, target)
			}
			return nil
		}}, nil
	}
	if err := retireNFTCurrentRuntimeUsing(context.Background(), host, plan, plan.sha256, guard, runner, ops, factory); err != nil {
		t.Fatal("bounded retirement did not finish after durable preparation", err)
	}
	if !issued || len(runner.tables) != 1 || runner.tables[nftTableTarget{family: "inet", name: "administrator"}] == nil {
		t.Fatal("retirement did not preserve the unrelated table")
	}
}
