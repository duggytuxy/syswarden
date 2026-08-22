package cmd

import (
	"errors"
	"strings"
	"testing"
)

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
