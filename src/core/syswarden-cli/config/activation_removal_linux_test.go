//go:build linux

package config

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func TestActivationRemovalRetiresOnlyVerifiedStateWithoutCurrentTOML(t *testing.T) {
	policy, store, request := activationApprovalFixture(t)
	approval := approveActivationFixture(t, policy, store, request)
	if err := approval.MarkApplied(t.Context()); err != nil {
		t.Fatal(err)
	}
	sibling := filepath.Join(filepath.Dir(store.path), "administrator-policy")
	if err := os.WriteFile(sibling, []byte("preserve"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(policy.root); err != nil {
		t.Fatal(err)
	}
	removal, err := inspectActivationStateRemovalAt(store)
	if err != nil || removal == nil {
		t.Fatal("valid state could not be classified independently of TOML", err)
	}
	defer removal.Close()
	if err := removal.Revalidate(); err != nil {
		t.Fatal(err)
	}
	if err := removal.Retire(); err != nil {
		t.Fatal(err)
	}
	if err := removal.Retire(); err != nil {
		t.Fatal("same-handle retirement retry failed", err)
	}
	if _, err := os.Lstat(store.path); !os.IsNotExist(err) {
		t.Fatal("active approval state remained", err)
	}
	if _, err := os.Lstat(filepath.Join(filepath.Dir(store.path), activationRetirementName)); !os.IsNotExist(err) {
		t.Fatal("completed retirement intent remained", err)
	}
	// #nosec G304 -- sibling is the unrelated fixture file created under this test's private store parent.
	raw, err := os.ReadFile(sibling)
	if err != nil || string(raw) != "preserve" {
		t.Fatal("unrelated administrator state changed", err)
	}
	absent, err := inspectActivationStateRemovalAt(store)
	if err != nil || absent != nil {
		t.Fatal("complete absence did not remain absent", err)
	}
}

func TestActivationRemovalUnknownAndChangedArtifactsRemain(t *testing.T) {
	for _, change := range []string{"unknown", "changed-before", "changed-after", "foreign-marker", "lock-only"} {
		t.Run(change, func(t *testing.T) {
			policy, store, request := activationApprovalFixture(t)
			approveActivationFixture(t, policy, store, request)
			receipt := filepath.Join(store.path, activationApprovedName)
			var removal *ActivationStateRemoval
			var err error
			if change == "changed-after" {
				removal, err = inspectActivationStateRemovalAt(store)
				if err != nil {
					t.Fatal(err)
				}
				defer removal.Close()
			}
			switch change {
			case "unknown":
				err = os.WriteFile(filepath.Join(store.path, "administrator-file"), []byte("preserve"), 0600)
			case "changed-before", "changed-after":
				err = os.WriteFile(receipt, []byte("unproven bytes\n"), 0600)
			case "foreign-marker":
				err = os.WriteFile(filepath.Join(filepath.Dir(store.path), activationRetirementName), []byte("{}\n"), 0600)
			case "lock-only":
				err = os.Remove(receipt)
			}
			if err != nil {
				t.Fatal(err)
			}
			if removal != nil {
				if err := removal.Retire(); err == nil {
					t.Fatal("changed artifact retired")
				}
			} else {
				removal, err = inspectActivationStateRemovalAt(store)
				if err == nil {
					if removal != nil {
						_ = removal.Close()
					}
					t.Fatal("unproven state granted removal")
				}
			}
			if _, err := os.Lstat(store.path); err != nil {
				t.Fatal("refusal removed active directory", err)
			}
		})
	}
}

func TestActivationRemovalResumesEveryDurableDeletionBoundary(t *testing.T) {
	for removed := 0; removed <= 4; removed++ {
		t.Run(strconv.Itoa(removed), func(t *testing.T) {
			policy, store, request := activationApprovalFixture(t)
			approval := approveActivationFixture(t, policy, store, request)
			if err := approval.MarkApplied(t.Context()); err != nil {
				t.Fatal(err)
			}
			inspection, err := inspectActivationStateRemovalAt(store)
			if err != nil {
				t.Fatal(err)
			}
			record := inspection.record
			if err := inspection.Close(); err != nil {
				t.Fatal(err)
			}
			raw, err := activationCanonical(record)
			if err != nil {
				t.Fatal(err)
			}
			marker := filepath.Join(filepath.Dir(store.path), activationRetirementName)
			if err := os.WriteFile(marker, raw, 0600); err != nil {
				t.Fatal(err)
			}
			for index := 0; index < removed && index < len(record.Entries); index++ {
				if err := os.Remove(filepath.Join(store.path, record.Entries[index].Name)); err != nil {
					t.Fatal(err)
				}
			}
			if removed == 4 {
				if err := os.Remove(store.path); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := policy.verifyApprovedAt(t.Context(), store); err == nil {
				t.Fatal("pending retirement retained activation authority")
			}
			retry, err := inspectActivationStateRemovalAt(store)
			if err != nil || retry == nil {
				t.Fatal("durable retirement could not resume", err)
			}
			defer retry.Close()
			if err := retry.Retire(); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Lstat(store.path); !os.IsNotExist(err) {
				t.Fatal("retired directory remains", err)
			}
			if _, err := os.Lstat(marker); !os.IsNotExist(err) {
				t.Fatal("retired intent remains", err)
			}
		})
	}
}

func TestActivationRemovalRecoveryRefusesReplacementDuringPartialCleanup(t *testing.T) {
	policy, store, request := activationApprovalFixture(t)
	approveActivationFixture(t, policy, store, request)
	inspection, err := inspectActivationStateRemovalAt(store)
	if err != nil {
		t.Fatal(err)
	}
	record := inspection.record
	_ = inspection.Close()
	raw, err := activationCanonical(record)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(filepath.Dir(store.path), activationRetirementName), raw, 0600); err != nil {
		t.Fatal(err)
	}
	receipt := filepath.Join(store.path, activationApprovedName)
	// #nosec G304 -- receipt is the fixed approval file in this test's private temporary store.
	before, err := os.ReadFile(receipt)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(receipt, filepath.Join(t.TempDir(), "saved")); err != nil {
		t.Fatal(err)
	}
	// #nosec G703 -- recreating this exact fixture receipt exercises same-byte replacement during retirement.
	if err := os.WriteFile(receipt, before, 0600); err != nil {
		t.Fatal(err)
	}
	if removal, err := inspectActivationStateRemovalAt(store); err == nil {
		if removal != nil {
			_ = removal.Close()
		}
		t.Fatal("same-byte replacement was adopted during retirement")
	}
	// #nosec G304 -- reread only the fixture replacement to verify refusal preserved its bytes.
	after, err := os.ReadFile(receipt)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("refused replacement was altered", err)
	}
}
