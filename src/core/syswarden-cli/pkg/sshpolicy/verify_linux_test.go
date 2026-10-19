//go:build linux

package sshpolicy

import (
	"context"
	"errors"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestVerifyPlanChecksLiveBaselineAndEveryContextWithoutPublication(t *testing.T) {
	f := planFixture(t, includeDropIns)
	plan := f.plan()
	var calls, checks int
	run := func(_ context.Context, image *parserImage, mode, access string) ([]byte, error) {
		calls++
		if mode == "syntax" {
			return nil, nil
		}
		if access != "" && access != plan.intent.Contexts[0].sshdArgument() {
			t.Fatal("unexpected connection context")
		}
		forwarding := "yes"
		if image != nil && len(image.files) == 2 {
			forwarding = "no"
		}
		return []byte("port 2222\nauthenticationmethods publickey\nallowtcpforwarding " + forwarding + "\n"), nil
	}
	summary, err := verifyPlan(context.Background(), plan, strings.Repeat("a", 64), run, func() error { checks++; return nil })
	if err != nil || !summary.ParserVerified || summary.RuntimeActivated || summary.Plan.ApplyAvailable || summary.ContextsVerified != 1 || calls != 9 || checks != 19 {
		t.Fatalf("incomplete verification: %+v calls=%d checks=%d err=%v", summary, calls, checks, err)
	}
	if !reflect.DeepEqual(plan.inventory, f.plan().inventory) {
		t.Fatal("verification changed filesystem inputs")
	}
}

func TestVerifyPlanRejectsEveryParserAndRecheckFailureWithoutPartialResult(t *testing.T) {
	plan := planFixture(t, includeDropIns).plan()
	for _, failure := range []string{"syntax", "live-disagreement", "candidate-context", "unrelated-context", "malformed", "missing-policy", "before", "after", "final", "cancelled"} {
		t.Run(failure, func(t *testing.T) {
			calls, checks := 0, 0
			run := func(_ context.Context, image *parserImage, mode, access string) ([]byte, error) {
				calls++
				if mode == "syntax" {
					if failure == "syntax" {
						return nil, errors.New("fixture syntax failure")
					}
					return nil, nil
				}
				candidate := image != nil && len(image.files) == 2
				forwarding, port := "yes", "2222"
				if candidate {
					forwarding = "no"
				}
				if failure == "live-disagreement" && image == nil {
					port = "3333"
				}
				if failure == "candidate-context" && candidate && access != "" {
					forwarding = "yes"
				}
				if failure == "unrelated-context" && candidate && access != "" {
					port = "3333"
				}
				if failure == "malformed" {
					return []byte("\x00"), nil
				}
				if failure == "missing-policy" && candidate {
					return []byte("port 2222\n"), nil
				}
				return []byte("port " + port + "\nallowtcpforwarding " + forwarding + "\n"), nil
			}
			recheck := func() error {
				checks++
				if (failure == "before" && checks == 1) || (failure == "after" && checks == 2) || (failure == "final" && checks == 19) {
					return ErrInventoryChanged
				}
				return nil
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if failure == "cancelled" {
				cancel()
			}
			summary, err := verifyPlan(ctx, plan, strings.Repeat("a", 64), run, recheck)
			if err == nil || summary != (VerificationSummary{}) {
				t.Fatal("returned verification after failure")
			}
			if (failure == "cancelled" || failure == "before") && calls != 0 {
				t.Fatal("executed parser after preflight failure")
			}
		})
	}
}

func TestPinnedSSHParserRefusesUnsafeExecutablesAndDetectsReplacement(t *testing.T) {
	for _, scenario := range []string{"merged", "separate", "symlink", "directory-alias", "writable", "non-executable", "hardlink", "replacement", "shadow", "missing"} {
		t.Run(scenario, func(t *testing.T) {
			f := newInventoryFixture(t, includeDropIns)
			logical := "/usr/bin/sshd"
			if scenario == "separate" {
				logical = "/usr/sbin/sshd"
			}
			if scenario != "missing" {
				f.write(logical, "\x7fELF\x02\x01\x01"+strings.Repeat("\x00", 11)+"\x3e\x00fixture")
				if err := f.chmod(logical, 0755); err != nil {
					t.Fatal(err)
				}
			}
			switch scenario {
			case "symlink":
				if err := os.Rename(f.path(logical), f.path(logical+"-target")); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("sshd-target", f.path(logical)); err != nil {
					t.Fatal(err)
				}
			case "directory-alias":
				if err := os.Rename(f.path("/usr/bin"), f.path("/usr/elsewhere")); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("elsewhere", f.path("/usr/bin")); err != nil {
					t.Fatal(err)
				}
			case "writable":
				if err := f.chmod(logical, 0775); err != nil {
					t.Fatal(err)
				}
			case "non-executable":
				if err := f.chmod(logical, 0644); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(f.path(logical), f.path(logical+"-alias")); err != nil {
					t.Fatal(err)
				}
			}
			daemon, err := openSSHD(f.root, os.Geteuid())
			valid := scenario == "merged" || scenario == "separate" || scenario == "replacement" || scenario == "shadow"
			if !valid {
				if err == nil {
					if closeErr := daemon.file.Close(); closeErr != nil {
						t.Fatal(closeErr)
					}
					t.Fatal("accepted unsafe executable")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer daemon.file.Close()
			if err := daemon.recheck(f.root, os.Geteuid()); err != nil {
				t.Fatal(err)
			}
			if scenario == "replacement" {
				f.write(logical+"-new", "replacement executable\n")
				if err := f.chmod(logical+"-new", 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(f.path(logical+"-new"), f.path(logical)); err != nil {
					t.Fatal(err)
				}
				if err := daemon.recheck(f.root, os.Geteuid()); err == nil {
					t.Fatal("missed daemon replacement")
				}
			}
			if scenario == "shadow" {
				if err := os.Remove(f.path(logical)); err != nil {
					t.Fatal(err)
				}
				f.write("/usr/sbin/sshd", "\x7fELF\x02\x01\x01"+strings.Repeat("\x00", 11)+"\x3e\x00fixture")
				if err := f.chmod("/usr/sbin/sshd", 0755); err != nil {
					t.Fatal(err)
				}
				if err := daemon.recheck(f.root, os.Geteuid()); err == nil {
					t.Fatal("missed changed daemon selection")
				}
			}
		})
	}
}

func TestParserOutputIsBounded(t *testing.T) {
	var output parserOutput
	if n, err := output.Write(make([]byte, MaxBytes)); err != nil || n != MaxBytes {
		t.Fatal(err)
	}
	if _, err := output.Write([]byte("x")); !errors.Is(err, ErrInventoryBounds) || output.Len() != MaxBytes {
		t.Fatal("accepted oversized parser output")
	}
	var copied parserOutput
	if _, err := io.Copy(&copied, strings.NewReader(strings.Repeat("x", MaxBytes+1))); !errors.Is(err, ErrInventoryBounds) || copied.Len() > MaxBytes {
		t.Fatal("copy bypassed the output limit")
	}
}
