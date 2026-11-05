//go:build linux

package config

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestActivationAbsenceObservationPreservesOriginalCustody(t *testing.T) {
	policy, store, request := activationApprovalFixture(t)
	before := intentFixtureFiles(t, policy.root)
	holder, err := policy.holdActivationAbsentAt(t.Context(), store)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = holder.Close() }()
	// Capture independently, without sharing the coordinator's policy object.
	terminalPolicy, err := CaptureActivationPolicy(t.Context(), policy.root)
	if err != nil {
		t.Fatal(err)
	}
	observer, err := terminalPolicy.observeActivationAbsentAt(t.Context(), store)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = observer.Close() }()
	raw, err := activationCanonical(holder.observation.witness)
	if err != nil || activationDigest(raw) != observer.SHA256() || holder.SHA256() != observer.SHA256() {
		t.Fatal("independent observation changed the original canonical witness", err)
	}
	if !strings.Contains(string(raw), `"schema":"syswarden-activation-absence-v1"`) {
		t.Fatal("existing witness schema was rewritten")
	}
	if err := observer.Revalidate(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := observer.Close(); err != nil {
		t.Fatal(err)
	}
	if observer.SHA256() != "" || observer.Revalidate(t.Context()) == nil {
		t.Fatal("closed observer remained usable")
	}
	if err := holder.Revalidate(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := policy.approveAt(t.Context(), store, request, func() error { return nil }); err == nil {
		t.Fatal("closing an observer released the original publication lock")
	}
	if _, err := os.Lstat(store.path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("read-only terminal observation created activation state", err)
	}
	if !reflect.DeepEqual(before, intentFixtureFiles(t, policy.root)) {
		t.Fatal("read-only terminal observation changed TOML")
	}
}

func TestActivationAbsenceObservationAloneDoesNotExcludePublication(t *testing.T) {
	policy, store, request := activationApprovalFixture(t)
	observer, err := policy.observeActivationAbsentAt(t.Context(), store)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = observer.Close() }()
	approval := approveActivationFixture(t, policy, store, request)
	if approval.Review().Applied {
		t.Fatal("read-only observer implied application")
	}
	if err := observer.Revalidate(t.Context()); err == nil {
		t.Fatal("stale absence remained usable after publication")
	}
}

func TestActivationAbsenceObservationAcrossIndependentProcess(t *testing.T) {
	if os.Getenv("SYSWARDEN_TEST_ABSENCE_READER") == "1" {
		marker := -1
		for i, arg := range os.Args {
			if arg == "--" {
				marker = i
				break
			}
		}
		if marker < 0 || len(os.Args) != marker+4 {
			t.Fatal("invalid reader fixture arguments")
		}
		root, path, original := os.Args[marker+1], os.Args[marker+2], os.Args[marker+3]
		policy, err := CaptureActivationPolicy(t.Context(), root)
		if err != nil {
			t.Fatal(err)
		}
		store := activationApprovalStore{path: path, uid: activationFixtureOwnerUID(t)}
		observer, err := policy.observeActivationAbsentAt(t.Context(), store)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = observer.Close() }()
		if observer.SHA256() != original || observer.Revalidate(t.Context()) != nil {
			t.Fatal("independent process did not reconstruct the original witness")
		}
		if held, err := policy.holdActivationAbsentAt(t.Context(), store); err == nil {
			_ = held.Close()
			t.Fatal("independent process acquired an already held exclusive lease")
		}
		return
	}
	policy, store, _ := activationApprovalFixture(t)
	holder, err := policy.holdActivationAbsentAt(t.Context(), store)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = holder.Close() }()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, executable, "-test.run=^TestActivationAbsenceObservationAcrossIndependentProcess$", "--", policy.root, store.path, holder.SHA256()) // #nosec G204 -- re-execute only this test binary and fixed test case with private fixture paths
	command.Env = append(os.Environ(), "SYSWARDEN_TEST_ABSENCE_READER=1")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("independent read-only verifier failed: %v\n%s", err, output)
	}
	if err := holder.Revalidate(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func TestActivationAbsenceObservationRejectsMissingAuthorityAndContext(t *testing.T) {
	var missing *ActivationAbsenceObservation
	if missing.SHA256() != "" || missing.Revalidate(t.Context()) == nil || missing.Close() != nil {
		t.Fatal("nil observer contract")
	}
	empty := &ActivationAbsenceObservation{}
	if empty.SHA256() != "" || empty.Revalidate(t.Context()) == nil || empty.Close() != nil || empty.Close() != nil {
		t.Fatal("empty observer contract")
	}
	if _, err := (*ActivationPolicy)(nil).ObserveActivationAbsent(t.Context()); err == nil {
		t.Fatal("nil policy accepted")
	}
	policy, store, _ := activationApprovalFixture(t)
	if _, err := policy.ObserveActivationAbsent(t.Context()); err == nil {
		t.Fatal("nonproduction root accepted")
	}
	var missingContext context.Context // Deliberately absent context exercises refusal without a production operation.
	if _, err := policy.observeActivationAbsentAt(missingContext, store); err == nil {
		t.Fatal("nil context accepted")
	}
	observer, err := policy.observeActivationAbsentAt(t.Context(), store)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = observer.Close() }()
	if err := observer.Revalidate(missingContext); err == nil {
		t.Fatal("nil revalidation context accepted")
	}
}
