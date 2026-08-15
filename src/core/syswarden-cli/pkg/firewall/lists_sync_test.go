package firewall

import (
	"bytes"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestCompleteBlocklistRemovalAggregatesFailuresWithoutFalseSuccess(t *testing.T) {
	applyErr := errors.New("nft verification failed")
	syncErr := errors.New("HA peer rejected unban")
	var output bytes.Buffer
	var calls []string

	err := completeBlocklistRemoval(
		"198.51.100.7",
		&output,
		func() error {
			calls = append(calls, "apply")
			return applyErr
		},
		func(ips []string) error {
			calls = append(calls, "sync:"+strings.Join(ips, ","))
			return syncErr
		},
	)

	if !errors.Is(err, applyErr) || !errors.Is(err, syncErr) {
		t.Fatalf("completeBlocklistRemoval() error = %v, want both operation failures", err)
	}
	if output.Len() != 0 {
		t.Fatalf("failure emitted a false-success message: %q", output.String())
	}
	wantCalls := []string{"apply", "sync:198.51.100.7"}
	if !reflect.DeepEqual(calls, wantCalls) {
		t.Fatalf("operation calls = %#v, want %#v", calls, wantCalls)
	}
}

func TestCompleteBlocklistRemovalReportsSuccessOnlyAfterVerificationAndHASync(t *testing.T) {
	var output bytes.Buffer
	var calls []string

	err := completeBlocklistRemoval(
		"2001:db8::7",
		&output,
		func() error {
			if output.Len() != 0 {
				t.Fatal("success was reported before firewall verification")
			}
			calls = append(calls, "apply")
			return nil
		},
		func(ips []string) error {
			if output.Len() != 0 {
				t.Fatal("success was reported before HA synchronization")
			}
			calls = append(calls, "sync:"+strings.Join(ips, ","))
			return nil
		},
	)
	if err != nil {
		t.Fatalf("completeBlocklistRemoval() error = %v", err)
	}
	wantCalls := []string{"apply", "sync:2001:db8::7"}
	if !reflect.DeepEqual(calls, wantCalls) {
		t.Fatalf("operation calls = %#v, want %#v", calls, wantCalls)
	}
	if got := output.String(); got != "[SUCCESS] IP 2001:db8::7 removed from blocklist.\n" {
		t.Fatalf("success output = %q", got)
	}
}
