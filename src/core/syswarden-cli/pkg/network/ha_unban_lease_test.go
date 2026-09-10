package network

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"

	"syswarden-cli/config"
)

func TestHAUnbanLeaseRejectsUnsupportedOwnershipBeforeOpeningFence(t *testing.T) {
	for _, cfg := range []*config.Config{nil, {HAV2Enabled: true}, {HAEnabled: true, HAV2Enabled: true}, {HAEnabled: true}} {
		if release, err := acquireHAUnbanLease(cfg, nil); err == nil || release != nil {
			t.Fatalf("unsupported ownership acquired a lease: release present=%t err=%v", release != nil, err)
		}
	}
	release, err := acquireHAUnbanLease(&config.Config{}, nil)
	if err != nil || release == nil {
		t.Fatalf("standalone unblock requires HA infrastructure: %v", err)
	}
	release()
}

func TestHAUnbanLeasePreventsFenceTransitionUntilLocalAndPeerWorkEnds(t *testing.T) {
	directory := haFenceTestDirectory(t)
	fence := newHALegacyWriterFence(directory, os.Geteuid())
	wire, err := jsonMarshalLine(cliHAFenceDiskState{Version: cliHAFenceVersion, State: cliHAFenceStateInactive, Generation: 1})
	if err != nil {
		t.Fatal(err)
	}
	writeHAFenceTestFile(t, filepath.Join(directory, cliHAFenceStateName), wire)
	release, err := acquireHAUnbanLease(&config.Config{HAEnabled: true}, fence)
	if err != nil {
		t.Fatal(err)
	}
	released := false
	defer func() {
		if !released {
			release()
		}
	}()
	root, err := openCLIHAFenceDirectory(fence)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	coreLease, err := openCLIHAFenceLockMode(root, os.Geteuid(), false, true)
	if err != nil {
		t.Fatalf("authenticated core cannot share the CLI unblock fence lease: %v", err)
	}
	closeCLIHAFenceLock(coreLease)
	transition, err := openCLIHAFenceLockMode(root, os.Geteuid(), true, true)
	if err == nil {
		closeCLIHAFenceLock(transition)
		t.Fatal("fence transition raced the protected local unblock")
	}
	if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
		t.Fatalf("unexpected transition refusal: %v", err)
	}
	var requests atomic.Int32
	server := newLoopbackTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		if request.Method != http.MethodDelete || request.Header.Get("Authorization") != "Bearer test-unban" {
			t.Error("unexpected HA unban request")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	host, port := splitTestServerAddress(t, server.Listener.Addr().String())
	cfg := &config.Config{HAEnabled: true, HAPeerIP: host, HAPeerPort: port, HAToken: "test-unban"}
	options := testHASyncOptions(t, server.Client())
	options.legacyFence = fence
	if err := syncHAUnbanUnderLease(context.Background(), cfg, []string{"198.51.100.7"}, options); err != nil {
		t.Fatalf("peer synchronization failed under the retained fence lease: %v", err)
	}
	if requests.Load() != 1 {
		t.Fatalf("unban requests=%d", requests.Load())
	}
	release()
	released = true
	transition, err = openCLIHAFenceLockMode(root, os.Geteuid(), true, true)
	if err != nil {
		t.Fatalf("fence remains locked after unblock completion: %v", err)
	}
	closeCLIHAFenceLock(transition)
}

func TestHAUnbanLeaseRejectsActiveAndUnavailableFence(t *testing.T) {
	for _, state := range []string{"missing", cliHAFenceStateActiveDrained, cliHAFenceStateEngaging, cliHAFenceStateRecovering, cliHAFenceStateError} {
		t.Run(state, func(t *testing.T) {
			directory := haFenceTestDirectory(t)
			if state != "missing" {
				value := cliHAFenceDiskState{Version: cliHAFenceVersion, State: state, Generation: 1}
				if state != cliHAFenceStateError {
					value.Epoch = "native-unban-test"
					value.MembershipSHA256 = strings.Repeat("a", 64)
					value.LegacyWriterInventorySHA256 = strings.Repeat("b", 64)
				}
				if state == cliHAFenceStateActiveDrained {
					drained := "2026-09-10T12:00:00Z"
					value.DrainedAt = &drained
					value.Condition = "sw-fence-v1-" + strings.Repeat("A", 43)
				}
				if err := validateCLIHAFenceState(value); err != nil {
					t.Fatal(err)
				}
				wire, err := jsonMarshalLine(value)
				if err != nil {
					t.Fatal(err)
				}
				writeHAFenceTestFile(t, filepath.Join(directory, cliHAFenceStateName), wire)
			}
			release, err := acquireHAUnbanLease(&config.Config{HAEnabled: true}, newHALegacyWriterFence(directory, os.Geteuid()))
			if release != nil || err == nil || !strings.Contains(err.Error(), "fence") {
				t.Fatalf("unblock passed an unavailable or non-inactive fence: %v", err)
			}
		})
	}
}
