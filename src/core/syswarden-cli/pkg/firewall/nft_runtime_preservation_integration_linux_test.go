//go:build linux && integration

package firewall

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

type runtimePreservationNativeRunner struct {
	delayValidation  time.Duration
	failVerification bool
	failRollback     bool
	applied          bool
	rollbackApplies  int
}

func (runner *runtimePreservationNativeRunner) Run(ctx context.Context, stdin []byte, args ...string) ([]byte, error) {
	if runner.applied && runner.failVerification && strings.Join(args, " ") == "-j list ruleset" {
		runner.failVerification = false
		return nil, errors.New("injected post-apply observation failure")
	}
	if runner.failRollback && len(args) == 2 && args[0] == "-f" && filepath.Base(args[1]) == "rollback.nft" {
		runner.failRollback = false
		return nil, errors.New("injected interrupted rollback")
	}
	command := exec.CommandContext(ctx, "/usr/bin/nft", args...)
	command.Stdin = bytes.NewReader(stdin)
	wire, err := command.CombinedOutput()
	if err == nil && len(args) == 3 && args[0] == "-c" {
		select {
		case <-time.After(runner.delayValidation):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if err == nil && len(args) == 2 && args[0] == "-f" && filepath.Base(args[1]) == "candidate.nft" {
		runner.applied = true
	}
	if err == nil && len(args) == 2 && args[0] == "-f" && filepath.Base(args[1]) == "rollback.nft" {
		runner.rollbackApplies++
	}
	return wire, err
}

func TestNativeReloadPreservesRuntimeExpiryThroughValidationAndRollback(t *testing.T) {
	parentNamespace := os.Getenv("SYSWARDEN_TEST_PARENT_NETNS")
	if parentNamespace == "" {
		t.Skip("requires an explicitly isolated network namespace")
	}
	currentNamespace, err := os.Readlink("/proc/self/ns/net")
	if err != nil || currentNamespace == parentNamespace || os.Geteuid() != 0 {
		t.Fatal("native firewall test requires root inside a distinct network namespace")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	runner := &runtimePreservationNativeRunner{}
	const policy = `table inet syswarden {
 set fixture_set { type ipv4_addr; }
 set banned_ips { type ipv4_addr; flags interval,timeout; }
 set banned_ips6 { type ipv6_addr; flags interval,timeout; }
 chain operator-policy { return; }
 chain input { type filter hook input priority 0; policy accept; jump operator-policy; ip saddr @banned_ips drop; ip6 saddr @banned_ips6 drop; }
}
table netdev syswarden_hw_drop {
 set banned_ips { type ipv4_addr; flags interval,timeout; }
 set banned_ips6 { type ipv6_addr; flags interval,timeout; }
 chain runtime_probe { ip saddr @banned_ips drop; ip6 saddr @banned_ips6 drop; }
}
`
	setup := policy + "table inet operator_keep {\n set sample { type ipv4_addr; elements = { 203.0.113.44 }; }\n}\n"
	for _, key := range nftDynamicBanSets {
		long, short := "192.0.2.44", "192.0.2.45"
		if strings.HasSuffix(key.name, "6") {
			long, short = "2001:db8::44", "2001:db8::45"
		}
		setup += fmt.Sprintf("add element %s %s %s { %s timeout 60s, %s timeout 1s }\n", key.family, key.table, key.name, long, short)
	}
	if output, err := runner.Run(ctx, []byte(setup), "-f", "-"); err != nil {
		t.Fatalf("native setup: %s, %v", output, err)
	}
	readHandles := func() map[string]uint64 {
		t.Helper()
		wire, err := runner.Run(ctx, nil, "-j", "list", "ruleset")
		if err != nil {
			t.Fatal(err)
		}
		var document struct {
			NFTables []struct {
				Set *struct {
					Family string `json:"family"`
					Table  string `json:"table"`
					Name   string `json:"name"`
					Handle uint64 `json:"handle"`
				} `json:"set"`
			} `json:"nftables"`
		}
		if err := json.Unmarshal(wire, &document); err != nil {
			t.Fatal(err)
		}
		result := make(map[string]uint64)
		for _, item := range document.NFTables {
			if item.Set != nil && strings.HasPrefix(item.Set.Name, "banned_ips") {
				result[item.Set.Family+" "+item.Set.Table+" "+item.Set.Name] = item.Set.Handle
			}
		}
		if len(result) != 4 {
			t.Fatalf("native runtime inventory is incomplete: %v", result)
		}
		return result
	}
	before, err := snapshotNFTDynamicBans(ctx, runner, time.Now())
	if err != nil {
		t.Fatalf("native preservation preflight: %v", err)
	}
	handles := readHandles()
	operator, err := runner.Run(ctx, nil, "list", "table", "inet", "operator_keep")
	if err != nil {
		t.Fatal(err)
	}
	stateDirectory := t.TempDir()
	runner.delayValidation = 3 * time.Second
	for cycle := 0; cycle < 4; cycle++ {
		runner.applied = false
		runner.failVerification = cycle == 1 || cycle == 2
		runner.failRollback = cycle == 2
		_, err := applyNftablesTransactionLocked(ctx, runner, stateDirectory, policy, nil, recoveryPlanWithDynamicSets(), fmt.Sprintf("%016x", cycle+1), nil)
		if cycle == 1 {
			if err == nil || !strings.Contains(err.Error(), "post-apply verification failed") || runner.rollbackApplies != 1 {
				t.Fatalf("native fault did not restore policy: %v", err)
			}
		} else if cycle == 2 {
			if err == nil || !strings.Contains(err.Error(), "rollback failed") {
				t.Fatalf("native interruption did not retain recovery evidence: %v", err)
			}
			if _, err := readNFTTransactionJournal(stateDirectory); err != nil {
				t.Fatalf("native interrupted transaction lost its journal: %v", err)
			}
			if err := recoverPendingNftablesTransaction(ctx, runner, stateDirectory); err != nil {
				t.Fatalf("native durable recovery: %v", err)
			}
			if _, err := readNFTTransactionJournal(stateDirectory); !errors.Is(err, os.ErrNotExist) || runner.rollbackApplies != 2 {
				t.Fatalf("native recovery did not finish its rollback: %v", err)
			}
		} else if err != nil {
			t.Fatalf("native policy cycle %d: %v", cycle, err)
		}
		if !reflect.DeepEqual(handles, readHandles()) {
			t.Fatal("runtime sets were recreated during policy replacement or rollback")
		}
		after, err := snapshotNFTDynamicBans(ctx, runner, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if err := compareNFTDynamicSnapshots(before, after, time.Now()); err != nil {
			t.Fatalf("native expiry changed across delayed policy cycle %d: %v", cycle, err)
		}
		currentOperator, err := runner.Run(ctx, nil, "list", "table", "inet", "operator_keep")
		if err != nil || !bytes.Equal(operator, currentOperator) {
			t.Fatal("unrelated operator policy changed")
		}
	}
}
