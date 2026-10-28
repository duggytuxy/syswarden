//go:build linux

package system

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAPKActivationPreflightRefusesDurableGatesWithoutExecution(t *testing.T) {
	for _, relative := range []string{
		strings.TrimPrefix(apkTransitionRoot, "/") + "/active-hook",
		apkTransitionGateDirectory + "/" + apkTransitionGateName,
		apkTransitionGateDirectory + "/.syswarden-apk-retired-" + strings.Repeat("a", 32),
		strings.TrimPrefix(apkTransitionRoot, "/") + "/.syswarden-apk-retired-" + strings.Repeat("b", 32),
	} {
		for _, kind := range []string{"regular", "symlink", "directory"} {
			t.Run(filepath.Base(relative)+"/"+kind, func(t *testing.T) {
				root := t.TempDir()
				if err := preflightAPKConfigurationActivationAt(t.Context(), root); err != nil {
					t.Fatal(err)
				}
				path := filepath.Join(root, relative)
				if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
					t.Fatal(err)
				}
				var err error
				switch kind {
				case "regular":
					err = os.WriteFile(path, []byte("private retained recovery fixture\n"), 0600)
				case "symlink":
					err = os.Symlink("absent", path)
				case "directory":
					err = os.Mkdir(path, 0700)
				}
				if err != nil {
					t.Fatal(err)
				}
				if err := preflightAPKConfigurationActivationAt(t.Context(), root); err == nil {
					t.Fatal("retained gate authorized activation")
				}
				if _, err := os.Lstat(path); err != nil {
					t.Fatal("read-only preflight removed recovery evidence", err)
				}
			})
		}
	}
}

func TestAPKActivationPreflightRequiresPositiveTerminalClosureAfterGateRemoval(t *testing.T) {
	f, factory := apkTerminalCompleteFixture(t)
	if err := preflightAPKConfigurationActivationAt(t.Context(), f.services.hostRoot); err == nil {
		t.Fatal("in-flight native transaction authorized activation")
	}
	closedFailure := errors.New("fixture closure publication unavailable")
	err := finalizeAPKTransitionUsing(t.Context(), f.review.PlanSHA256, f.candidate.keys, f.candidate.attestInstalled, f.services, factory, writeAPKTransitionBytes,
		func(context.Context, string, apkTransitionIdentity, []byte, []byte) error { return closedFailure })
	if !errors.Is(err, closedFailure) {
		t.Fatal(err)
	}
	for _, relative := range []string{strings.TrimPrefix(apkTransitionRoot, "/") + "/active-hook", apkTransitionGateDirectory + "/" + apkTransitionGateName} {
		if _, err := os.Lstat(filepath.Join(f.services.hostRoot, relative)); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("fixture did not exercise the gap after hook retirement", err)
		}
	}
	if err := preflightAPKConfigurationActivationAt(t.Context(), f.services.hostRoot); err == nil {
		t.Fatal("missing positive terminal closure authorized activation")
	}
}

func TestAPKActivationPreflightAcceptsVerifiedTerminalClosure(t *testing.T) {
	f, factory := apkTerminalCompleteFixture(t)
	if err := finalizeAPKTransitionWith(t.Context(), f.review.PlanSHA256, f.candidate.keys, f.candidate.attestInstalled, f.services, factory); err != nil {
		t.Fatal(err)
	}
	if err := preflightAPKConfigurationActivationAt(t.Context(), f.services.hostRoot); err != nil {
		t.Fatal("independently closed component fixture remained blocked", err)
	}
}
