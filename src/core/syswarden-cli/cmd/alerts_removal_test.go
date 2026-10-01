package cmd

import (
	"bytes"
	"context"
	"errors"
	"github.com/spf13/cobra"
	"strings"
	"testing"
)

func TestAlertsExplainsInterruptedRemovalBeforeWaiting(t *testing.T) {
	previous := inspectRemovalTombstone
	t.Cleanup(func() { inspectRemovalTombstone = previous })
	for _, unsafe := range []bool{false, true} {
		inspectRemovalTombstone = func() (bool, error) {
			if unsafe {
				return false, errors.New("unsafe tombstone")
			}
			return true, nil
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		cmd := &cobra.Command{}
		cmd.SetContext(ctx)
		var output bytes.Buffer
		cmd.SetErr(&output)
		if err := alertsCmd.RunE(cmd, nil); err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{"Removal is incomplete", "empty stream", "recover-wireguard", "uninstall"} {
			if !strings.Contains(output.String(), want) {
				t.Fatalf("missing %s in %s", want, output.String())
			}
		}
	}
}
