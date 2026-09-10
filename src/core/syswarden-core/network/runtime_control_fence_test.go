package network

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRuntimeOperatorReadLeasesPreventExclusiveFenceTransition(t *testing.T) {
	fence := newHAFenceTombstoneTestController(t, filepath.Join(t.TempDir(), "fence"))
	if err := fence.prepareForServer(); err != nil {
		t.Fatal(err)
	}
	if err := fence.withLocalOperatorMutation(func() error {
		// The inner lease represents the other end of the CLI/core socket.
		return fence.withLocalOperatorMutation(func() error {
			root, err := fence.openDirectory(false)
			if err != nil {
				return err
			}
			defer root.Close()
			if lease, err := openHAFenceLockMode(root, fence.expectedOwnerUID, true, true); err == nil {
				closeHAFenceLock(lease)
				t.Fatal("exclusive transition entered a coordinated operator mutation")
			}
			return nil
		})
	}); err != nil {
		t.Fatal(err)
	}
	if err := fence.withLock(true, false, func(*os.Root) error { return nil }); err != nil {
		t.Fatalf("released operator leases still block transition: %v", err)
	}
	publishHAFenceTestState(t, fence, activeHAFenceTestState(2))
	called := false
	if err := fence.withLocalOperatorMutation(func() error { called = true; return nil }); err == nil || called {
		t.Fatal("fenced state admitted local operator mutation")
	}
}
