//go:build linux

package firewall

import (
	"errors"
	"reflect"
	"testing"
)

func TestAuthoritativeUnbanPreservesTransactionOrderingAndPartialCommit(t *testing.T) {
	for _, failAt := range []string{"", "preflight", "policy", "runtime"} {
		t.Run(failAt, func(t *testing.T) {
			var calls []string
			sentinel := errors.New("injected operation refusal")
			run := func(stage string) error {
				calls = append(calls, stage)
				if stage == failAt {
					return sentinel
				}
				return nil
			}
			err := applyPoliciesWithAuthoritativeUnban("192.0.2.70",
				func(string) error { return run("preflight") }, func() error { return run("policy") }, func(string) error { return run("runtime") })
			wanted := []string{"preflight", "policy", "runtime"}
			if failAt == "preflight" {
				wanted = wanted[:1]
			}
			if failAt == "policy" {
				wanted = wanted[:2]
			}
			if !reflect.DeepEqual(calls, wanted) {
				t.Fatalf("unban ordering = %v, want %v", calls, wanted)
			}
			if (err != nil) != (failAt != "") || failAt != "" && !errors.Is(err, sentinel) {
				t.Fatalf("operation error: %v", err)
			}
			if isCommittedFirewallPolicyError(err) != (failAt == "runtime") {
				t.Fatal("runtime failure could roll back an already committed persistent policy")
			}
		})
	}
}
