//go:build linux

package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"syswarden-cli/pkg/sshpolicy"
)

// Separate factories exercise the restored command wiring, including the extra
// independent recovery approval, without target services or configuration.
func restoredAccessCommandFixture(t *testing.T, operations sshRestoredAccessOperations) *cobra.Command {
	t.Helper()
	root := &cobra.Command{Use: "syswarden", SilenceErrors: true, SilenceUsage: true}
	root.PersistentFlags().String("config", "", "fixture")
	policy := newSSHPolicyCommand(nil, nil, nil)
	policy.AddCommand(newSSHRestoredAccessCommands(operations)...)
	root.AddCommand(policy)
	return root
}

func TestSSHRestoredAccessCommandApprovalsAndPartialIssuance(t *testing.T) {
	digest := strings.Repeat("a", 64)
	for _, scenario := range []string{"request", "issue", "record", "missing-approval", "missing-recovery", "invalid-recovery", "config", "lifetime", "existing-output", "partial-issue"} {
		t.Run(scenario, func(t *testing.T) {
			dir := privateSSHExchangeTestDir(t)
			calls := 0
			ops := sshRestoredAccessOperations{
				prepare: func(_ context.Context, plan, recovery, enrollment string) (sshpolicy.AccessRequestPreview, error) {
					calls++
					if plan != digest || recovery != strings.Repeat("b", 64) || enrollment != digest {
						t.Fatal("approval lost")
					}
					return sshpolicy.AccessRequestPreview{Request: []byte("private-route"), RequestSHA256: sshAccessDigest([]byte("private-route")), RecoveryRequired: true}, nil
				},
				issue: func(_ context.Context, plan, recovery, enrollment, request string, lifetime time.Duration) (sshpolicy.AccessChallengePublication, error) {
					calls++
					if plan != digest || recovery != strings.Repeat("b", 64) || enrollment != digest || request != sshAccessDigest([]byte("request")) || lifetime != 180*time.Second {
						t.Fatal("issuance approval lost")
					}
					result := sshpolicy.AccessChallengePublication{Request: []byte("request"), Challenge: []byte("private-challenge"), IssuanceSHA256: digest, IssuanceImageSHA256: digest, IssuanceDurable: true, RecoveryRequired: true}
					if scenario == "partial-issue" {
						return result, errors.New("durability refused")
					}
					return result, nil
				},
				record: func(_ context.Context, plan, recovery, enrollment, issuance, image string, receipt []byte) (sshpolicy.AccessReceiptPublication, error) {
					calls++
					if plan != digest || recovery != strings.Repeat("b", 64) || enrollment != digest || issuance != digest || image != digest || string(receipt) != "signed-receipt" {
						t.Fatal("receipt approval lost")
					}
					return sshpolicy.AccessReceiptPublication{RecordSHA256: digest, RecordDurable: true, RecoveryRequired: true}, nil
				},
			}
			operation := "restoration-access-request"
			if scenario == "issue" || scenario == "partial-issue" || scenario == "lifetime" {
				operation = "restoration-access-issue"
			}
			if scenario == "record" {
				operation = "restoration-access-record"
			}
			args := []string{"ssh-policy", operation, "--exchange-dir", dir, "--plan-sha256", digest, "--recovery-sha256", strings.Repeat("b", 64), "--enrollment-sha256", digest}
			if operation == "restoration-access-issue" {
				args = append(args, "--request-sha256", sshAccessDigest([]byte("request")))
			}
			if scenario == "record" {
				if err := os.WriteFile(filepath.Join(dir, "receipt.json"), []byte("signed-receipt"), 0600); err != nil {
					t.Fatal(err)
				}
				args = append(args, "--issuance-sha256", digest, "--issuance-image-sha256", digest)
			}
			if scenario == "missing-approval" {
				args = args[:len(args)-2]
			}
			if scenario == "missing-recovery" {
				args = append(args[:6], args[8:]...)
			}
			if scenario == "invalid-recovery" {
				args[7] = strings.Repeat("B", 64)
			}
			if scenario == "config" {
				args = append(args, "--config", "ignored.conf")
			}
			if scenario == "lifetime" {
				args = append(args, "--lifetime-seconds", "301")
			}
			if scenario == "existing-output" {
				if err := os.WriteFile(filepath.Join(dir, "request.json"), []byte("keep"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			root := restoredAccessCommandFixture(t, ops)
			var output bytes.Buffer
			root.SetOut(&output)
			root.SetErr(&output)
			root.SetArgs(args)
			err := root.Execute()
			success := scenario == "request" || scenario == "issue" || scenario == "record"
			if (err == nil) != success {
				t.Fatal("unexpected command result", err)
			}
			expected := 0
			if success || scenario == "partial-issue" {
				expected = 1
			}
			if calls != expected {
				t.Fatal("unexpected target calls", calls)
			}
			if strings.Contains(output.String(), "private-") || strings.Contains(output.String(), "signed-receipt") {
				t.Fatal("private output escaped")
			}
			if scenario == "partial-issue" {
				info, err := os.Stat(filepath.Join(dir, "delivery.json"))
				if err != nil || info.Size() != 0 {
					t.Fatal("uncertain delivery was exposed or erased", err)
				}
			}
		})
	}
}

func TestSSHRestoredAccessControllerCommandIsolation(t *testing.T) {
	for _, operation := range []string{"restoration-access-request", "restoration-access-issue", "restoration-access-record", "restoration-access-probe"} {
		root := restoredAccessCommandFixture(t, sshRestoredAccessOperations{})
		cmd, _, err := root.Find([]string{"ssh-policy", operation})
		if err != nil || commandRequiresAutomaticConfigLoad(cmd) || commandRequiresEarlyFirewallRecovery(cmd) || commandAllowedDuringRemoval(cmd) {
			t.Fatal("SSH command crossed configuration/removal boundary", operation, err)
		}
		if err := enforceValidatedConfiguration(cmd); err != nil {
			t.Fatal(err)
		}
	}
	previousLoad, previousRecovery, previousRemoval := initConfigHook, recoverPendingFirewallTransactionHook, inspectRemovalTombstone
	t.Cleanup(func() {
		initConfigHook = previousLoad
		recoverPendingFirewallTransactionHook = previousRecovery
		inspectRemovalTombstone = previousRemoval
	})
	initConfigHook = func() { t.Fatal("controller loaded target config") }
	recoverPendingFirewallTransactionHook = func() error { t.Fatal("controller recovered target firewall"); return nil }
	inspectRemovalTombstone = func() (bool, error) { t.Fatal("controller inspected local target removal"); return false, nil }
	root := restoredAccessCommandFixture(t, sshRestoredAccessOperations{})
	cmd, _, _ := root.Find([]string{"ssh-policy", "restoration-access-probe"})
	if err := rootCmd.PersistentPreRunE(cmd, nil); err != nil {
		t.Fatal(err)
	}
}

func TestSSHRestoredAccessControllerDeliveryGuard(t *testing.T) {
	for _, scenario := range []string{"success", "wrong-request", "wrong-challenge", "wrong-secret", "changed-secret", "changed-delivery", "same-byte-secret", "unknown-field", "oversized-receipt"} {
		t.Run(scenario, func(t *testing.T) {
			dir := privateSSHExchangeTestDir(t)
			digest := strings.Repeat("a", 64)
			delivery := sshAccessDelivery{1, []byte("request"), []byte("challenge"), digest, digest}
			wire, _ := json.Marshal(delivery)
			if scenario == "unknown-field" {
				wire = append(wire[:len(wire)-1], []byte(`,"extra":true}`)...)
			}
			secret := []byte("local-secret")
			for name, data := range map[string][]byte{"delivery.json": wire, "credentials.json": secret} {
				if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			request, challenge, credentials := sshAccessDigest(delivery.Request), sshAccessDigest(delivery.Challenge), sshAccessDigest(secret)
			if scenario == "wrong-request" {
				request = digest
			}
			if scenario == "wrong-challenge" {
				challenge = digest
			}
			if scenario == "wrong-secret" {
				credentials = digest
			}
			calls := 0
			ops := sshRestoredAccessOperations{probe: func(_ context.Context, r, c []byte, rs, cs string, s []byte, guard func() error) ([]byte, error) {
				calls++
				if !bytes.Equal(s, secret) || rs != request || cs != challenge || !bytes.Equal(r, delivery.Request) || !bytes.Equal(c, delivery.Challenge) {
					t.Fatal("controller bindings lost")
				}
				if scenario == "same-byte-secret" {
					if err := os.Rename(filepath.Join(dir, "credentials.json"), filepath.Join(dir, "old-secret")); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(dir, "credentials.json"), secret, 0600); err != nil {
						t.Fatal(err)
					}
				}
				if scenario == "changed-secret" || scenario == "changed-delivery" {
					name := "credentials.json"
					if scenario == "changed-delivery" {
						name = "delivery.json"
					}
					if err := os.WriteFile(filepath.Join(dir, name), []byte("revoked"), 0600); err != nil {
						t.Fatal(err)
					}
				}
				if err := guard(); err != nil {
					return nil, err
				}
				if scenario == "oversized-receipt" {
					return bytes.Repeat([]byte("x"), 16385), nil
				}
				return []byte("signed-observation"), nil
			}}
			root := restoredAccessCommandFixture(t, ops)
			var output bytes.Buffer
			root.SetOut(&output)
			root.SetErr(&output)
			root.SetArgs([]string{"ssh-policy", "restoration-access-probe", "--exchange-dir", dir, "--request-sha256", request, "--challenge-sha256", challenge, "--credentials-sha256", credentials})
			err := root.Execute()
			if (err == nil) != (scenario == "success") {
				t.Fatal("unexpected probe result", err)
			}
			if strings.HasPrefix(scenario, "wrong-") || scenario == "unknown-field" {
				if calls != 0 {
					t.Fatal("unapproved input reached transport")
				}
			}
			if strings.Contains(output.String(), "local-secret") || strings.Contains(output.String(), "signed-observation") {
				t.Fatal("private bytes printed")
			}
		})
	}
}

func TestSSHRestoredAccessRecordRequiresDurableUncertainResult(t *testing.T) {
	digest := strings.Repeat("a", 64)
	for _, scenario := range []string{"not-durable", "cleared-recovery", "bad-record", "partial-error"} {
		t.Run(scenario, func(t *testing.T) {
			dir := privateSSHExchangeTestDir(t)
			if err := os.WriteFile(filepath.Join(dir, "receipt.json"), []byte("signed-receipt"), 0600); err != nil {
				t.Fatal(err)
			}
			calls := 0
			ops := sshRestoredAccessOperations{record: func(context.Context, string, string, string, string, string, []byte) (sshpolicy.AccessReceiptPublication, error) {
				calls++
				result := sshpolicy.AccessReceiptPublication{RecordSHA256: digest, RecordDurable: true, RecoveryRequired: true}
				switch scenario {
				case "not-durable":
					result.RecordDurable = false
				case "cleared-recovery":
					result.RecoveryRequired = false
				case "bad-record":
					result.RecordSHA256 = "unknown"
				case "partial-error":
					return result, errors.New("late refusal")
				}
				return result, nil
			}}
			root := restoredAccessCommandFixture(t, ops)
			var output bytes.Buffer
			root.SetOut(&output)
			root.SetErr(&output)
			root.SetArgs([]string{"ssh-policy", "restoration-access-record", "--exchange-dir", dir, "--plan-sha256", digest, "--recovery-sha256", digest, "--enrollment-sha256", digest, "--issuance-sha256", digest, "--issuance-image-sha256", digest})
			if err := root.Execute(); err == nil || calls != 1 {
				t.Fatal("invalid receipt result succeeded", calls, err)
			}
			if strings.Contains(output.String(), "signed-receipt") {
				t.Fatal("private receipt escaped")
			}
		})
	}
}

func TestSSHRestoredAccessInspectionRequiresExactApprovals(t *testing.T) {
	plan, recovery, enrollment, issuance, image, record := strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64), strings.Repeat("d", 64), strings.Repeat("e", 64), strings.Repeat("f", 64)
	for _, scenario := range []string{"issuance", "receipt", "missing-recovery", "missing-image", "empty-record", "bad-record", "config", "not-observed", "cleared-recovery", "wrong-image", "wrong-receipt", "unexpected-receipt", "partial-error"} {
		t.Run(scenario, func(t *testing.T) {
			calls := 0
			inspect := func(_ context.Context, p, r, e, i, im, rec string) (sshpolicy.RestoredAccessInspection, error) {
				calls++
				if p != plan || r != recovery || e != enrollment || i != issuance || im != image {
					t.Fatal("inspection approval lost")
				}
				result := sshpolicy.RestoredAccessInspection{Transaction: strings.Repeat("a", 32), IssuanceSHA256: issuance, IssuanceImageSHA256: image, RecordSHA256: rec, IssuanceObserved: true, ReceiptObserved: rec != "", RecoveryRequired: true}
				switch scenario {
				case "not-observed":
					result.IssuanceObserved = false
				case "cleared-recovery":
					result.RecoveryRequired = false
				case "wrong-image":
					result.IssuanceImageSHA256 = plan
				case "wrong-receipt":
					result.RecordSHA256 = plan
				case "unexpected-receipt":
					result.ReceiptObserved = true
					result.RecordSHA256 = record
				case "partial-error":
					return result, errors.New("changed observation")
				}
				return result, nil
			}
			root := restoredAccessCommandFixture(t, sshRestoredAccessOperations{})
			policy, _, err := root.Find([]string{"ssh-policy"})
			if err != nil {
				t.Fatal(err)
			}
			policy.AddCommand(newSSHRestoredAccessInspectionCommand(inspect))
			args := []string{"ssh-policy", "restoration-access-inspect", "--plan-sha256", plan, "--recovery-sha256", recovery, "--enrollment-sha256", enrollment, "--issuance-sha256", issuance, "--issuance-image-sha256", image}
			switch scenario {
			case "receipt", "wrong-receipt":
				args = append(args, "--record-sha256", record)
			case "missing-recovery":
				args = append(args[:4], args[6:]...)
			case "missing-image":
				args = args[:10]
			case "empty-record":
				args = append(args, "--record-sha256", "")
			case "bad-record":
				args = append(args, "--record-sha256", "bad")
			case "config":
				args = append(args, "--config", "ignored.conf")
			}
			var output bytes.Buffer
			root.SetOut(&output)
			root.SetErr(&output)
			root.SetArgs(args)
			err = root.Execute()
			success := scenario == "issuance" || scenario == "receipt"
			if (err == nil) != success {
				t.Fatal("unexpected inspection result", err)
			}
			preflight := scenario == "missing-recovery" || scenario == "missing-image" || scenario == "empty-record" || scenario == "bad-record" || scenario == "config"
			if (calls == 0) != preflight {
				t.Fatal("incorrect inspection boundary", calls)
			}
			if success && (!strings.Contains(output.String(), `"recovery_required":true`) || strings.Contains(output.String(), "request")) {
				t.Fatal("inspection output lost uncertainty or exposed private request", output.String())
			}
		})
	}
}
