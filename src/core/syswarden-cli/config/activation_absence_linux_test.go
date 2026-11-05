//go:build linux

package config

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"golang.org/x/sys/unix"
)

func TestActivationAbsenceExcludesPublicationWithoutCreatingAuthority(t *testing.T) {
	policy, store, request := activationApprovalFixture(t)
	before := intentFixtureFiles(t, policy.root)
	global, load := GlobalConfig, CurrentLoadState()
	absence, err := policy.holdActivationAbsentAt(t.Context(), store)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = absence.Close() })
	if !activationHex(absence.SHA256()) {
		t.Fatal("absence did not bind a canonical observation")
	}
	if _, err := policy.holdActivationAbsentAt(t.Context(), store); err == nil {
		t.Fatal("second exclusive owner acquired custody")
	}
	if _, err := policy.approveAt(t.Context(), store, request, func() error { return nil }); err == nil {
		t.Fatal("approval published during inactive-preservation custody")
	}
	if _, err := os.Lstat(store.path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("absence custody or excluded publication created state", err)
	}
	if err := absence.Revalidate(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := policy.verifyApprovedAt(t.Context(), store); err == nil {
		t.Fatal("absence was accepted as approval")
	}
	if GlobalConfig != global || !reflect.DeepEqual(load, CurrentLoadState()) || !reflect.DeepEqual(before, intentFixtureFiles(t, policy.root)) {
		t.Fatal("read-only absence custody changed configuration")
	}
	digest := absence.SHA256()
	if err := absence.Close(); err != nil {
		t.Fatal(err)
	}
	if absence.SHA256() != "" || absence.Revalidate(t.Context()) == nil {
		t.Fatal("closed custody remained usable")
	}
	again, err := policy.holdActivationAbsentAt(t.Context(), store)
	if err != nil || again.SHA256() != digest {
		t.Fatal("unchanged absence could not be reconstructed", err)
	}
	if err := again.Close(); err != nil {
		t.Fatal(err)
	}
	approval := approveActivationFixture(t, policy, store, request)
	if approval.Review().Applied {
		t.Fatal("publication implied application")
	}
	if _, err := policy.holdActivationAbsentAt(t.Context(), store); err == nil {
		t.Fatal("existing approval became inactive authority")
	}
}

func TestActivationAbsenceRefusesUnresolvedStoreHistory(t *testing.T) {
	for _, kind := range []string{"empty", "publication-lock", "orphan-applied", "approval", "applied", "reload", "unknown", "retirement", "symlink", "unsafe", "cancelled"} {
		t.Run(kind, func(t *testing.T) {
			policy, store, request := activationApprovalFixture(t)
			ctx := t.Context()
			switch kind {
			case "approval", "applied", "reload":
				if kind == "reload" {
					request.Operation = "reload"
				}
				approval := approveActivationFixture(t, policy, store, request)
				if kind == "applied" {
					if err := approval.MarkApplied(ctx); err != nil {
						t.Fatal(err)
					}
				}
			case "cancelled":
				cancelled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = cancelled
			case "retirement":
				if err := os.WriteFile(filepath.Join(filepath.Dir(store.path), activationRetirementName), []byte("retained unresolved fixture\n"), 0600); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Symlink(t.TempDir(), store.path); err != nil {
					t.Fatal(err)
				}
			default:
				if err := os.Mkdir(store.path, 0700); err != nil {
					t.Fatal(err)
				}
				switch kind {
				case "unsafe":
					if err := os.Chmod(store.path, 0777); err != nil { // #nosec G302 -- deliberate unsafe mode in a t.TempDir-owned refusal fixture
						t.Fatal(err)
					}
				case "publication-lock", "orphan-applied", "unknown":
					name := map[string]string{"publication-lock": activationLockName, "orphan-applied": activationAppliedName, "unknown": "retained"}[kind]
					if err := os.WriteFile(filepath.Join(store.path, name), nil, 0600); err != nil {
						t.Fatal(err)
					}
				}
			}
			if observation, err := policy.observeActivationAbsentAt(ctx, store); err == nil {
				_ = observation.Close()
				t.Fatal("independent reader accepted unresolved source history")
			}
			if _, err := policy.holdActivationAbsentAt(ctx, store); err == nil {
				t.Fatal("unresolved source history accepted")
			}
			// An error must release the descriptor, not strand the policy lock.
			lease, err := policy.lockActivationPolicy(t.Context(), store.uid, unix.LOCK_EX)
			if err != nil {
				t.Fatal("failed capture leaked exclusion", err)
			}
			if err := lease.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestActivationAbsenceRefusesCapturedSourceAndAncestorDrift(t *testing.T) {
	for _, kind := range []string{"state-appeared", "parent-appeared", "ancestor-replaced", "ancestor-mode", "retirement", "module-replaced", "root-replaced", "cancelled"} {
		t.Run(kind, func(t *testing.T) {
			policy, store, _ := activationApprovalFixture(t)
			if kind == "parent-appeared" {
				store.path = filepath.Join(filepath.Dir(store.path), "missing", "activation")
			}
			absence, err := policy.holdActivationAbsentAt(t.Context(), store)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = absence.Close() })
			observation, err := policy.observeActivationAbsentAt(t.Context(), store)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = observation.Close() })
			ctx := t.Context()
			switch kind {
			case "state-appeared":
				err = os.Mkdir(store.path, 0700)
			case "parent-appeared":
				err = os.Mkdir(filepath.Dir(store.path), 0700)
			case "ancestor-replaced", "root-replaced":
				path := filepath.Dir(store.path)
				if kind == "root-replaced" {
					path = policy.root
				}
				if err = os.Rename(path, path+".retained"); err == nil {
					err = os.Mkdir(path, 0700)
				}
			case "ancestor-mode":
				err = os.Chmod(filepath.Dir(store.path), 0750) // #nosec G302 -- deliberate protected-directory metadata drift in the temporary fixture
			case "retirement":
				err = os.WriteFile(filepath.Join(filepath.Dir(store.path), activationRetirementName), []byte("retain\n"), 0600)
			case "module-replaced":
				path := filepath.Join(policy.root, "modules", "99-user.toml")
				raw, readErr := os.ReadFile(path) // #nosec G304 -- fixed modules/99-user.toml inside the configuration created by this test
				if readErr != nil {
					t.Fatal(readErr)
				}
				if err = os.Rename(path, path+".retained"); err == nil {
					err = os.WriteFile(path, raw, 0600) // #nosec G703 -- replace only the fixed module in this test-owned configuration to exercise same-byte inode drift
				}
			case "cancelled":
				cancelled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = cancelled
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := observation.Revalidate(ctx); err == nil {
				t.Fatal("independent reader accepted source drift")
			}
			if err := absence.Revalidate(ctx); err == nil {
				t.Fatal("captured source drift accepted")
			}
		})
	}
}

func TestActivationPublicationAlreadyInProgressExcludesAbsence(t *testing.T) {
	policy, store, request := activationApprovalFixture(t)
	calls := 0
	_, err := policy.approveAt(t.Context(), store, request, func() error {
		calls++
		if _, err := policy.holdActivationAbsentAt(t.Context(), store); err == nil {
			t.Error("absence custody raced an in-progress publication")
		}
		return nil
	})
	if err != nil || calls == 0 {
		t.Fatal("publication did not exercise its guarded boundary", err)
	}
}
