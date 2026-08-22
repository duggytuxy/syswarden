package cmd

import (
	"errors"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func syntheticCommandPath(names ...string) *cobra.Command {
	root := &cobra.Command{Use: "syswarden"}
	parent := root
	for _, name := range names {
		command := &cobra.Command{Use: name}
		parent.AddCommand(command)
		parent = command
	}
	return parent
}

func TestRemovalTombstoneBlocksEveryOperationalMutatorFamily_SW2_FWBACKEND_001(t *testing.T) {
	previous := inspectRemovalTombstone
	t.Cleanup(func() { inspectRemovalTombstone = previous })
	inspectRemovalTombstone = func() (bool, error) { return true, nil }

	mutators := [][]string{
		{"allow-ssh"},
		{"block"},
		{"config"},
		{"ha-fence", "engage"},
		{"ha-fence", "manifest", "create"},
		{"ha-fence", "recover"},
		{"ha-fence", "release"},
		{"ha-sync"},
		{"install"},
		{"migrate-config"},
		{"reload"},
		{"revoke-ssh"},
		{"tui"},
		{"unblock"},
		{"unwhitelist"},
		{"update"},
		{"update-feeds"},
		{"whitelist"},
		{"whitelist-infra"},
	}
	for _, path := range mutators {
		t.Run(strings.Join(path, "-"), func(t *testing.T) {
			err := enforceRemovalState(syntheticCommandPath(path...))
			if err == nil || !strings.Contains(err.Error(), "refusing operational mutation") {
				t.Fatalf("mutator %v was not blocked: %v", path, err)
			}
		})
	}
}

func TestRemovalTombstoneKeepsReadOnlyAndRemovalRecoveryCommandsUsable_SW2_FWBACKEND_001(t *testing.T) {
	previous := inspectRemovalTombstone
	t.Cleanup(func() { inspectRemovalTombstone = previous })
	calls := 0
	inspectRemovalTombstone = func() (bool, error) {
		calls++
		return true, errors.New("unsafe test tombstone")
	}

	allowed := [][]string{
		{"alerts"},
		{"audit"},
		{"check"},
		{"completion"},
		{"config-get"},
		{"help"},
		{"list"},
		{"manual"},
		{"ha-fence", "status"},
		{"ha-fence", "manifest", "verify"},
		{"prepare-package-removal"},
		{"uninstall"},
	}
	for _, path := range allowed {
		t.Run(strings.Join(path, "-"), func(t *testing.T) {
			if err := enforceRemovalState(syntheticCommandPath(path...)); err != nil {
				t.Fatalf("recovery/read-only path %v was blocked: %v", path, err)
			}
		})
	}
	if calls != 0 {
		t.Fatalf("allowed recovery/read-only commands inspected unsafe evidence %d times", calls)
	}
}

func TestUnsafeRemovalEvidenceFailsClosedForMutation_SW2_FWBACKEND_001(t *testing.T) {
	previous := inspectRemovalTombstone
	t.Cleanup(func() { inspectRemovalTombstone = previous })
	sentinel := errors.New("modified or symlinked tombstone")
	inspectRemovalTombstone = func() (bool, error) { return true, sentinel }
	err := enforceRemovalState(syntheticCommandPath("reload"))
	if err == nil || !errors.Is(err, sentinel) || !strings.Contains(err.Error(), "removal state is unsafe") {
		t.Fatalf("unsafe evidence guard = %v", err)
	}
}
