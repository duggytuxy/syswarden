package cmd

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

const feedExitHelperEnvironment = "SYSWARDEN_FEED_EXIT_HELPER"

func TestFeedUpdateProcessReportsFailuresOnce(t *testing.T) {
	for _, scenario := range []string{"download", "apply", "both", "preflight", "success"} {
		t.Run(scenario, func(t *testing.T) {
			command := exec.Command(os.Args[0], "-test.run=^TestFeedUpdateExitHelperProcess$") // #nosec G204 G702 -- fixed current test binary and static arguments
			command.Env = append(os.Environ(), feedExitHelperEnvironment+"="+scenario)
			stdout, stderr := &strings.Builder{}, &strings.Builder{}
			command.Stdout, command.Stderr = stdout, stderr
			err := command.Run()
			if scenario == "success" {
				if err != nil || stderr.Len() != 0 || !strings.Contains(stdout.String(), "[SUCCESS]") {
					t.Fatalf("successful update: err=%v stdout=%s stderr=%s", err, stdout, stderr)
				}
				return
			}
			var exitError *exec.ExitError
			if !errors.As(err, &exitError) || exitError.ExitCode() != 1 {
				t.Fatalf("failed update must exit 1: err=%v stdout=%s stderr=%s", err, stdout, stderr)
			}
			if strings.Count(stderr.String(), "Usage:") != 1 {
				t.Fatalf("failed update must retain one usage block: %s", stderr)
			}
			for _, diagnostic := range []struct {
				text string
				want bool
			}{
				{"invalid CIDR at line 5", scenario == "download" || scenario == "both"},
				{"synthetic policy failure", scenario == "apply" || scenario == "both"},
				{"synthetic preflight refusal", scenario == "preflight"},
			} {
				wantCount := 0
				if diagnostic.want {
					wantCount = 1
				}
				if got := strings.Count(stderr.String(), diagnostic.text); got != wantCount {
					t.Fatalf("stderr diagnostic %q count=%d, want %d: %s", diagnostic.text, got, wantCount, stderr)
				}
			}
			if scenario == "download" || scenario == "both" {
				if strings.Count(stdout.String(), "invalid CIDR at line 5") != 1 || !strings.Contains(stdout.String(), "Reapplying configured policy") {
					t.Fatalf("download failure must retain progress and policy recovery: %s", stdout)
				}
			}
		})
	}
}

func TestFeedUpdateExitHelperProcess(t *testing.T) {
	scenario, enabled := os.LookupEnv(feedExitHelperEnvironment)
	if !enabled {
		return
	}
	rootCmd = &cobra.Command{Use: "syswarden"}
	rootCmd.AddCommand(&cobra.Command{
		Use: "update-feeds",
		RunE: func(command *cobra.Command, args []string) error {
			return runFeedUpdateCommand(command,
				func() error {
					if scenario == "preflight" {
						return errors.New("synthetic preflight refusal")
					}
					return nil
				},
				func() error {
					if scenario == "download" || scenario == "both" {
						fmt.Println("FAILED (invalid CIDR at line 5)")
						return errors.New("invalid CIDR at line 5")
					}
					return nil
				},
				func() error {
					if scenario == "apply" || scenario == "both" {
						return errors.New("synthetic policy failure")
					}
					return nil
				})
		},
	})
	os.Args = []string{"syswarden", "update-feeds"}
	Execute()
	os.Exit(0)
}

func TestRunFeedUpdateRejectsBackendBeforeDownload_SW2_FWBACKEND_001(t *testing.T) {
	sentinel := errors.New("synthetic firewall backend refusal")
	downloadCalls := 0
	applyCalls := 0
	err := runFeedUpdateGuarded(
		func() error { return sentinel },
		func() error {
			downloadCalls++
			return nil
		},
		func() error {
			applyCalls++
			return nil
		},
	)
	if err == nil || !errors.Is(err, sentinel) || !strings.Contains(err.Error(), "before feed mutation") {
		t.Fatalf("guarded feed update error = %v", err)
	}
	if downloadCalls != 0 || applyCalls != 0 {
		t.Fatalf("backend refusal reached download/apply: %d/%d", downloadCalls, applyCalls)
	}
}

func TestRunFeedUpdateReappliesPolicyAfterPartialDownloadFailure_SW2_H3(t *testing.T) {
	downloadFailure := errors.New("authoritative mirror failed")
	applyCalls := 0
	err := runFeedUpdate(
		func() error { return downloadFailure },
		func() error {
			applyCalls++
			return nil
		},
	)
	if err == nil || !errors.Is(err, downloadFailure) {
		t.Fatalf("runFeedUpdate() error = %v, want download failure", err)
	}
	if applyCalls != 1 {
		t.Fatalf("policy apply calls = %d, want 1", applyCalls)
	}
}

func TestRunFeedUpdateReportsDownloadAndPolicyFailures_SW2_H3(t *testing.T) {
	downloadFailure := errors.New("download failed")
	applyFailure := errors.New("policy failed")
	err := runFeedUpdate(
		func() error { return downloadFailure },
		func() error { return applyFailure },
	)
	if err == nil || !errors.Is(err, downloadFailure) || !errors.Is(err, applyFailure) {
		t.Fatalf("runFeedUpdate() error = %v, want both failures", err)
	}
	if !strings.Contains(err.Error(), "update threat intelligence feeds") || !strings.Contains(err.Error(), "apply updated threat intelligence policy") {
		t.Fatalf("runFeedUpdate() lost failure context: %v", err)
	}
}

func TestRunFeedUpdateSucceedsOnlyWhenDownloadAndApplySucceed_SW2_H3(t *testing.T) {
	if err := runFeedUpdate(func() error { return nil }, func() error { return nil }); err != nil {
		t.Fatalf("runFeedUpdate() error = %v", err)
	}
	applyFailure := errors.New("policy failed")
	if err := runFeedUpdate(func() error { return nil }, func() error { return applyFailure }); !errors.Is(err, applyFailure) {
		t.Fatalf("runFeedUpdate() error = %v, want policy failure", err)
	}
}
