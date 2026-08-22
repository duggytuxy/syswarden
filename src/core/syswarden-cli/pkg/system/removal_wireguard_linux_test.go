//go:build linux

package system

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"syswarden-cli/pkg/wireguardstate"
	"testing"
	"time"
)

const wireGuardRemovalCrashWorkerEnvironment = "SYSWARDEN_WG_REMOVAL_CRASH_WORKER"

func appendWireGuardRemovalTestMarker(path, value string) error {
	// #nosec G304 G703 -- path is one of the private marker files passed to the isolated crash worker
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	_, writeErr := file.WriteString(value + "\n")
	syncErr := file.Sync()
	closeErr := file.Close()
	return errors.Join(writeErr, syncErr, closeErr)
}

func signalWireGuardRemovalCrash(path string) error {
	// #nosec G703 -- path is the private readiness marker passed to the isolated crash worker
	if err := os.WriteFile(path, []byte("ready\n"), 0600); err != nil {
		return err
	}
	select {}
}

func runWireGuardRemovalCrashWorker(t *testing.T) {
	t.Helper()
	root := os.Getenv("SYSWARDEN_WG_REMOVAL_ROOT")
	phase := os.Getenv("SYSWARDEN_WG_REMOVAL_PHASE")
	ready := os.Getenv("SYSWARDEN_WG_REMOVAL_READY")
	nftMarker := os.Getenv("SYSWARDEN_WG_REMOVAL_NFT_MARKER")
	reloadMarker := os.Getenv("SYSWARDEN_WG_REMOVAL_RELOAD_MARKER")
	uidValue, uidErr := strconv.ParseUint(os.Getenv("SYSWARDEN_WG_REMOVAL_UID"), 10, 32)
	gidValue, gidErr := strconv.ParseUint(os.Getenv("SYSWARDEN_WG_REMOVAL_GID"), 10, 32)
	if root == "" || ready == "" || nftMarker == "" || reloadMarker == "" || uidErr != nil || gidErr != nil {
		t.Fatalf("invalid WireGuard removal crash worker environment: uid=%v gid=%v", uidErr, gidErr)
	}
	uid := uint32(uidValue)
	gid := uint32(gidValue)
	tail := wireGuardRemovalTail{
		requireBarrier:   func() error { return nil },
		reattestServices: func() error { return nil },
		cleanupOwnedNFT: func() error {
			return appendWireGuardRemovalTestMarker(nftMarker, "nft")
		},
		inspectTransaction: func() (wireguardstate.TransactionOperation, bool, error) {
			return wireguardstate.InspectTransaction(root, uid, gid)
		},
		inspectOwnedState: func() (bool, error) {
			inventory, err := wireguardstate.Inspect(root)
			if err != nil {
				return false, err
			}
			return !inventory.Empty(), nil
		},
		prepareOwnedArtifacts: func() (bool, error) {
			return wireguardstate.PrepareRemoval(root, uid, gid)
		},
		finalizeOwnedArtifacts: func() (bool, error) {
			if phase == "before-finalize" {
				return false, signalWireGuardRemovalCrash(ready)
			}
			return wireguardstate.FinalizeRemoval(root, uid, gid)
		},
		classifyRuntime: func(bool) (serviceManagerState, error) { return serviceManagerActive, nil },
		isAlpine:        func() bool { return false },
		reloadSysctl: func() error {
			if phase == "before-reload" {
				return signalWireGuardRemovalCrash(ready)
			}
			if err := appendWireGuardRemovalTestMarker(reloadMarker, "reload"); err != nil {
				return err
			}
			if phase == "before-finalize" {
				return nil
			}
			return fmt.Errorf("unexpected crash phase %q", phase)
		},
	}
	if err := tail.remove(); err != nil {
		t.Fatal(err)
	}
	t.Fatal("WireGuard removal crash worker completed without reaching its crash boundary")
}

func prepareWireGuardRemovalCrashRoot(t *testing.T) (string, uint32, uint32, string) {
	t.Helper()
	root := t.TempDir()
	for path, mode := range map[string]os.FileMode{
		"etc/wireguard/clients": 0700,
		"etc/sysctl.d":          0755,
	} {
		full := filepath.Join(root, path)
		if err := os.MkdirAll(full, mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(full, mode); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(filepath.Join(root, "etc/wireguard"), 0700); err != nil { // #nosec G302 -- owner-only mode secures private WireGuard fixture material
		t.Fatal(err)
	}
	uid, gid := systemTestIdentity(t)
	contents := map[string][]byte{
		wireguardstate.ServerConfigurationPath:     []byte("server-private-material\n"),
		wireguardstate.ClientConfigurationPath:     []byte("client-private-material\n"),
		wireguardstate.ForwardingConfigurationPath: []byte("net.ipv4.ip_forward = 1\n"),
	}
	publication, err := wireguardstate.StageOwnedArtifacts(root, contents, uid, gid)
	if err != nil {
		t.Fatal(err)
	}
	if err := publication.Publish(); err != nil {
		t.Fatal(err)
	}
	manifest, err := wireguardstate.CaptureManifest(root, uid, gid)
	if err != nil {
		t.Fatal(err)
	}
	manifestPublication, err := publication.StageManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := manifestPublication.Publish(); err != nil {
		t.Fatal(err)
	}
	if err := publication.Commit(); err != nil {
		t.Fatal(err)
	}
	neighbor := filepath.Join(root, "etc/wireguard/operator-neighbor.conf")
	if err := os.WriteFile(neighbor, []byte("operator-owned\n"), 0600); err != nil {
		t.Fatal(err)
	}
	return root, uid, gid, neighbor
}

func testWireGuardRemovalTail(order *[]string) wireGuardRemovalTail {
	return wireGuardRemovalTail{
		requireBarrier: func() error {
			*order = append(*order, "barrier")
			return nil
		},
		reattestServices: func() error {
			*order = append(*order, "services")
			return nil
		},
		cleanupOwnedNFT: func() error {
			*order = append(*order, "nft")
			return nil
		},
		inspectTransaction: func() (wireguardstate.TransactionOperation, bool, error) {
			*order = append(*order, "transaction")
			return wireguardstate.TransactionOperationNone, false, nil
		},
		inspectOwnedState: func() (bool, error) {
			*order = append(*order, "inspect")
			return true, nil
		},
		prepareOwnedArtifacts: func() (bool, error) {
			*order = append(*order, "prepare")
			return true, nil
		},
		finalizeOwnedArtifacts: func() (bool, error) {
			*order = append(*order, "finalize")
			return true, nil
		},
		classifyRuntime: func(bool) (serviceManagerState, error) {
			*order = append(*order, "manager")
			return serviceManagerActive, nil
		},
		isAlpine: func() bool { return false },
		reloadSysctl: func() error {
			*order = append(*order, "sysctl")
			return nil
		},
	}
}

func TestWireGuardRemovalTailKeepsManifestUntilNFTCleanup_SW2_FWBACKEND_001(t *testing.T) {
	var order []string
	tail := testWireGuardRemovalTail(&order)
	if err := tail.remove(); err != nil {
		t.Fatal(err)
	}
	want := "barrier,services,transaction,inspect,manager,nft,barrier,services,prepare,sysctl,finalize,services,barrier"
	if got := strings.Join(order, ","); got != want {
		t.Fatalf("WireGuard removal order = %q, want %q", got, want)
	}
}

func TestWireGuardRemovalTailSkipsNFTCleanupWithoutOwnedState_SW2_FWBACKEND_001(t *testing.T) {
	var order []string
	tail := testWireGuardRemovalTail(&order)
	tail.inspectOwnedState = func() (bool, error) {
		order = append(order, "inspect")
		return false, nil
	}
	tail.prepareOwnedArtifacts = func() (bool, error) {
		order = append(order, "prepare")
		return false, nil
	}
	if err := tail.remove(); err != nil {
		t.Fatal(err)
	}
	got := strings.Join(order, ",")
	if strings.Contains(got, "nft") || strings.Contains(got, "sysctl") {
		t.Fatalf("absent WireGuard state invoked runtime cleanup: %q", got)
	}
}

func TestWireGuardRemovalTailRetainsEvidenceOnNFTOrArtifactFailure_SW2_FWBACKEND_001(t *testing.T) {
	for _, phase := range []string{"nft", "prepare", "sysctl", "finalize"} {
		t.Run(phase, func(t *testing.T) {
			var order []string
			tail := testWireGuardRemovalTail(&order)
			sentinel := errors.New("synthetic " + phase + " failure")
			if phase == "nft" {
				tail.cleanupOwnedNFT = func() error {
					order = append(order, "nft")
					return sentinel
				}
			} else if phase == "prepare" {
				tail.prepareOwnedArtifacts = func() (bool, error) {
					order = append(order, "prepare")
					return false, sentinel
				}
			} else if phase == "sysctl" {
				tail.reloadSysctl = func() error {
					order = append(order, "sysctl")
					return sentinel
				}
			} else {
				tail.finalizeOwnedArtifacts = func() (bool, error) {
					order = append(order, "finalize")
					return false, sentinel
				}
			}
			err := tail.remove()
			if err == nil || !errors.Is(err, sentinel) {
				t.Fatalf("%s failure = %v", phase, err)
			}
			wantState := "tombstone"
			if phase == "sysctl" || phase == "finalize" {
				wantState = "debt"
			}
			if !strings.Contains(err.Error(), wantState) {
				t.Fatalf("%s failure %q does not report retained %s", phase, err, wantState)
			}
			if (phase == "nft" || phase == "prepare") && strings.Contains(strings.Join(order, ","), "sysctl") {
				t.Fatalf("%s failure reached sysctl reload: %v", phase, order)
			}
			if phase == "nft" && strings.Contains(strings.Join(order, ","), "prepare") {
				t.Fatalf("nft failure removed ownership evidence: %v", order)
			}
			if (phase == "nft" || phase == "prepare" || phase == "sysctl") &&
				strings.Contains(strings.Join(order, ","), "finalize") {
				t.Fatalf("%s failure finalized removal debt: %v", phase, order)
			}
		})
	}
}

func TestWireGuardRemovalTailOfflineSkipsRuntimeAndPreservesUnownedOpenRCLink_SW2_FWBACKEND_001(t *testing.T) {
	var order []string
	tail := testWireGuardRemovalTail(&order)
	tail.inspectOwnedState = func() (bool, error) {
		order = append(order, "inspect")
		return false, nil
	}
	tail.prepareOwnedArtifacts = func() (bool, error) {
		order = append(order, "prepare")
		return false, nil
	}
	tail.isAlpine = func() bool { return true }
	tail.classifyRuntime = func(bool) (serviceManagerState, error) {
		order = append(order, "manager")
		return serviceManagerOffline, nil
	}
	if err := tail.remove(); err != nil {
		t.Fatal(err)
	}
	got := strings.Join(order, ",")
	if strings.Contains(got, "nft") || strings.Contains(got, "sysctl") || !strings.Contains(got, "prepare,services") {
		t.Fatalf("offline OpenRC removal order = %q", got)
	}
}

func TestWireGuardRemovalTailResumesRemovalDebtWithoutRepeatingNFTCleanup_SW2_FWBACKEND_001(t *testing.T) {
	var first []string
	firstTail := testWireGuardRemovalTail(&first)
	sentinel := errors.New("synthetic sysctl reload failure")
	firstTail.reloadSysctl = func() error {
		first = append(first, "sysctl")
		return sentinel
	}
	if err := firstTail.remove(); err == nil || !errors.Is(err, sentinel) {
		t.Fatalf("first removal error = %v", err)
	}
	if strings.Contains(strings.Join(first, ","), "finalize") {
		t.Fatalf("failed reload finalized removal debt: %v", first)
	}

	var retry []string
	retryTail := testWireGuardRemovalTail(&retry)
	retryTail.inspectTransaction = func() (wireguardstate.TransactionOperation, bool, error) {
		retry = append(retry, "transaction")
		return wireguardstate.TransactionOperationRemovePendingReload, true, nil
	}
	retryTail.inspectOwnedState = func() (bool, error) {
		t.Fatal("retry must not require removed manifest state")
		return false, nil
	}
	retryTail.cleanupOwnedNFT = func() error {
		t.Fatal("retry must not repeat manifest-bound nftables cleanup")
		return nil
	}
	if err := retryTail.remove(); err != nil {
		t.Fatal(err)
	}
	want := "barrier,services,transaction,manager,barrier,services,prepare,sysctl,finalize,services,barrier"
	if got := strings.Join(retry, ","); got != want {
		t.Fatalf("WireGuard removal retry order = %q, want %q", got, want)
	}
}

func TestWireGuardRemovalTailRejectsUnprovenTransactionsWithoutMutation_SW2_FWBACKEND_001(t *testing.T) {
	for _, test := range []struct {
		name      string
		operation wireguardstate.TransactionOperation
		want      string
	}{
		{name: "publication", operation: wireguardstate.TransactionOperationPublish, want: "publication transaction"},
		{name: "immediate removal", operation: wireguardstate.TransactionOperationRemove, want: "without durable nftables-cleanup evidence"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var order []string
			tail := testWireGuardRemovalTail(&order)
			tail.inspectTransaction = func() (wireguardstate.TransactionOperation, bool, error) {
				order = append(order, "transaction")
				return test.operation, true, nil
			}
			err := tail.remove()
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("transaction %q refusal = %v", test.operation, err)
			}
			if got := strings.Join(order, ","); got != "barrier,services,transaction" {
				t.Fatalf("transaction %q reached mutation: %q", test.operation, got)
			}
		})
	}
}

func TestWireGuardRemovalTailRecoversRealSIGKILLBoundaries_SW2_FWBACKEND_001(t *testing.T) {
	if os.Getenv(wireGuardRemovalCrashWorkerEnvironment) == "1" {
		runWireGuardRemovalCrashWorker(t)
		return
	}
	markerCount := func(t *testing.T, path string) int {
		t.Helper()
		wire, err := os.ReadFile(path) // #nosec G304 -- path is one of the private marker files created beneath the fixture root
		if errors.Is(err, os.ErrNotExist) {
			return 0
		}
		if err != nil {
			t.Fatal(err)
		}
		count := 0
		for _, line := range strings.Split(string(wire), "\n") {
			if line != "" {
				count++
			}
		}
		return count
	}

	for _, phase := range []string{"before-reload", "before-finalize"} {
		t.Run(phase, func(t *testing.T) {
			root, uid, gid, neighbor := prepareWireGuardRemovalCrashRoot(t)
			ready := filepath.Join(root, "worker-ready")
			nftMarker := filepath.Join(root, "nft-cleanup.log")
			reloadMarker := filepath.Join(root, "sysctl-reload.log")
			logPath := filepath.Join(root, "worker.log")
			logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600) // #nosec G304 -- logPath is confined to this private test root
			if err != nil {
				t.Fatal(err)
			}
			// #nosec G204 G702 -- executable is the current test binary and phase comes from the fixed two-value table above
			command := exec.Command(os.Args[0], "-test.run=^TestWireGuardRemovalTailRecoversRealSIGKILLBoundaries_SW2_FWBACKEND_001$/"+phase+"$")
			command.Env = append(os.Environ(),
				wireGuardRemovalCrashWorkerEnvironment+"=1",
				"SYSWARDEN_WG_REMOVAL_ROOT="+root,
				"SYSWARDEN_WG_REMOVAL_PHASE="+phase,
				"SYSWARDEN_WG_REMOVAL_READY="+ready,
				"SYSWARDEN_WG_REMOVAL_NFT_MARKER="+nftMarker,
				"SYSWARDEN_WG_REMOVAL_RELOAD_MARKER="+reloadMarker,
				"SYSWARDEN_WG_REMOVAL_UID="+strconv.FormatUint(uint64(uid), 10),
				"SYSWARDEN_WG_REMOVAL_GID="+strconv.FormatUint(uint64(gid), 10),
			)
			command.Stdout = logFile
			command.Stderr = logFile
			if err := command.Start(); err != nil {
				_ = logFile.Close()
				t.Fatal(err)
			}
			waitResult := make(chan error, 1)
			go func() { waitResult <- command.Wait() }()
			deadline := time.NewTimer(10 * time.Second)
			poll := time.NewTicker(10 * time.Millisecond)
			readyObserved := false
			for !readyObserved {
				select {
				case waitErr := <-waitResult:
					_ = logFile.Close()
					logWire, _ := os.ReadFile(logPath) // #nosec G304 -- logPath is confined to this private test root
					t.Fatalf("crash worker exited before boundary: %v: %s", waitErr, logWire)
				case <-deadline.C:
					_ = command.Process.Kill()
					<-waitResult
					_ = logFile.Close()
					logWire, _ := os.ReadFile(logPath) // #nosec G304 -- logPath is confined to this private test root
					t.Fatalf("crash worker did not reach boundary: %s", logWire)
				case <-poll.C:
					if _, err := os.Lstat(ready); err == nil {
						readyObserved = true
					} else if !errors.Is(err, os.ErrNotExist) {
						t.Fatal(err)
					}
				}
			}
			deadline.Stop()
			poll.Stop()
			if err := command.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			waitErr := <-waitResult
			if err := logFile.Close(); err != nil {
				t.Fatal(err)
			}
			exitError, ok := waitErr.(*exec.ExitError)
			status, statusOK := exitError.Sys().(syscall.WaitStatus)
			if !ok || !statusOK || !status.Signaled() || status.Signal() != syscall.SIGKILL {
				logWire, _ := os.ReadFile(logPath) // #nosec G304 -- logPath is confined to this private test root
				t.Fatalf("crash worker termination = %v: %s", waitErr, logWire)
			}

			operation, pending, err := wireguardstate.InspectTransaction(root, uid, gid)
			if err != nil || !pending || operation != wireguardstate.TransactionOperationRemovePendingReload {
				t.Fatalf("post-SIGKILL transaction = %q present=%v err=%v", operation, pending, err)
			}
			if got := markerCount(t, nftMarker); got != 1 {
				t.Fatalf("nft cleanup count after SIGKILL = %d, want 1", got)
			}
			initialReloads := 0
			if phase == "before-finalize" {
				initialReloads = 1
			}
			if got := markerCount(t, reloadMarker); got != initialReloads {
				t.Fatalf("sysctl reload count after SIGKILL = %d, want %d", got, initialReloads)
			}

			retry := wireGuardRemovalTail{
				requireBarrier:   func() error { return nil },
				reattestServices: func() error { return nil },
				cleanupOwnedNFT: func() error {
					return fmt.Errorf("retry repeated nftables cleanup")
				},
				inspectTransaction: func() (wireguardstate.TransactionOperation, bool, error) {
					return wireguardstate.InspectTransaction(root, uid, gid)
				},
				inspectOwnedState: func() (bool, error) {
					return false, fmt.Errorf("retry inspected removed manifest state")
				},
				prepareOwnedArtifacts: func() (bool, error) {
					return wireguardstate.PrepareRemoval(root, uid, gid)
				},
				finalizeOwnedArtifacts: func() (bool, error) {
					return wireguardstate.FinalizeRemoval(root, uid, gid)
				},
				classifyRuntime: func(bool) (serviceManagerState, error) {
					return serviceManagerActive, nil
				},
				isAlpine: func() bool { return false },
				reloadSysctl: func() error {
					return appendWireGuardRemovalTestMarker(reloadMarker, "reload")
				},
			}
			if err := retry.remove(); err != nil {
				t.Fatal(err)
			}
			if _, pending, err := wireguardstate.InspectTransaction(root, uid, gid); err != nil || pending {
				t.Fatalf("transaction after recovery present=%v err=%v", pending, err)
			}
			inventory, err := wireguardstate.Inspect(root)
			if err != nil || !inventory.Empty() {
				t.Fatalf("WireGuard inventory after recovery = %#v err=%v", inventory, err)
			}
			if got := markerCount(t, nftMarker); got != 1 {
				t.Fatalf("retry nft cleanup count = %d, want 1", got)
			}
			if got := markerCount(t, reloadMarker); got != initialReloads+1 {
				t.Fatalf("retry sysctl reload count = %d, want %d", got, initialReloads+1)
			}
			neighborWire, err := os.ReadFile(neighbor) // #nosec G304 -- neighbor is confined to the private WireGuard fixture root
			if err != nil || string(neighborWire) != "operator-owned\n" {
				t.Fatalf("operator neighbor after recovery = %q err=%v", neighborWire, err)
			}
		})
	}
}

func TestWireGuardRemovalTailOfflineRetainsOwnedRuntimeEvidenceWithoutNFT_SW2_FWBACKEND_001(t *testing.T) {
	var order []string
	tail := testWireGuardRemovalTail(&order)
	tail.classifyRuntime = func(bool) (serviceManagerState, error) {
		order = append(order, "manager")
		return serviceManagerOffline, nil
	}
	err := tail.remove()
	if err == nil || !strings.Contains(err.Error(), "without an active service-manager runtime") {
		t.Fatalf("offline owned WireGuard refusal = %v", err)
	}
	got := strings.Join(order, ",")
	for _, forbidden := range []string{"nft", "artifacts", "sysctl"} {
		if strings.Contains(got, forbidden) {
			t.Fatalf("offline owned state invoked %s: %q", forbidden, got)
		}
	}
}
