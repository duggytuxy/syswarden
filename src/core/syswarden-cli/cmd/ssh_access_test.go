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

	"syswarden-cli/pkg/sshpolicy"

	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"
)

func accessCommandFixture(t *testing.T, operations sshAccessOperations) *cobra.Command {
	t.Helper()
	root := &cobra.Command{Use: "syswarden", SilenceErrors: true, SilenceUsage: true}
	root.PersistentFlags().String("config", "", "fixture")
	policy := newSSHPolicyCommand(nil, nil, nil)
	policy.AddCommand(newSSHAccessCommands(operations)...)
	root.AddCommand(policy)
	return root
}

func TestSSHExchangePrivateFiles(t *testing.T) {
	for _, scenario := range []string{"success", "directory-mode", "directory-link", "ancestor-link", "file-link", "hardlink", "file-mode", "fifo", "too-large", "directory-replaced", "no-clobber", "output-replaced", "output-linked", "output-mode"} {
		t.Run(scenario, func(t *testing.T) {
			parent := t.TempDir()
			dir := filepath.Join(parent, "exchange")
			if err := os.Mkdir(dir, 0700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "input")
			if err := os.WriteFile(path, []byte("private input"), 0600); err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "directory-mode":
				// #nosec G302 -- deliberately unsafe test directory must be refused.
				if err := os.Chmod(dir, 0755); err != nil {
					t.Fatal(err)
				}
			case "directory-link":
				link := filepath.Join(parent, "link")
				if err := os.Symlink(dir, link); err != nil {
					t.Fatal(err)
				}
				dir = link
			case "ancestor-link":
				link := filepath.Join(parent, "link")
				if err := os.Symlink(parent, link); err != nil {
					t.Fatal(err)
				}
				dir = filepath.Join(link, "exchange")
			case "file-link", "fifo":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if scenario == "fifo" {
					if err := unix.Mkfifo(path, 0600); err != nil {
						t.Fatal(err)
					}
				} else if err := os.Symlink("missing", path); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(path, filepath.Join(dir, "alias")); err != nil {
					t.Fatal(err)
				}
			case "file-mode":
				// #nosec G302 -- deliberately unsafe test file must be refused.
				if err := os.Chmod(path, 0644); err != nil {
					t.Fatal(err)
				}
			}
			handle, err := openSSHExchangeDirectory(dir)
			if strings.HasPrefix(scenario, "directory-") && scenario != "directory-replaced" || scenario == "ancestor-link" {
				if err == nil {
					_ = handle.close()
					t.Fatal("unsafe directory accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer handle.close()
			if scenario == "directory-replaced" {
				if err := os.Rename(dir, dir+"-old"); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(dir, 0700); err != nil {
					t.Fatal(err)
				}
			}
			limit := 100
			if scenario == "too-large" {
				limit = 2
			}
			_, err = handle.read("input", limit)
			if scenario != "success" && scenario != "no-clobber" && !strings.HasPrefix(scenario, "output-") {
				if err == nil {
					t.Fatal("unsafe file accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			output, err := handle.reserve("output")
			if err != nil {
				t.Fatal(err)
			}
			defer output.Close()
			if scenario == "no-clobber" {
				if _, err := handle.reserve("output"); err == nil {
					t.Fatal("overwrote existing output")
				}
				return
			}
			if scenario == "output-replaced" {
				if err := os.Rename(filepath.Join(dir, "output"), filepath.Join(dir, "retained")); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, "output"), []byte("other"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "output-linked" {
				if err := os.Link(filepath.Join(dir, "output"), filepath.Join(parent, "linked-output")); err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "output-mode" {
				// #nosec G302 -- changed output must be refused before any private write.
				if err := os.Chmod(filepath.Join(dir, "output"), 0644); err != nil {
					t.Fatal(err)
				}
			}
			err = handle.publish(output, "output", []byte("public observation"))
			if strings.HasPrefix(scenario, "output-") {
				info, statErr := output.Stat()
				if statErr != nil || info.Size() != 0 {
					t.Fatal("private bytes reached changed output", statErr)
				}
			}
			if (err != nil) != strings.HasPrefix(scenario, "output-") {
				t.Fatal("wrong publication result", err)
			}
		})
	}
}

func TestSSHAccessCommandApprovalsAndPartialIssuance(t *testing.T) {
	digest := strings.Repeat("a", 64)
	for _, scenario := range []string{"request", "issue", "record", "missing-approval", "config", "lifetime", "existing-output", "partial-issue"} {
		t.Run(scenario, func(t *testing.T) {
			dir := privateSSHExchangeTestDir(t)
			calls := 0
			ops := sshAccessOperations{
				prepare: func(_ context.Context, plan, enrollment string) (sshpolicy.AccessRequestPreview, error) {
					calls++
					if plan != digest || enrollment != digest {
						t.Fatal("approval lost")
					}
					return sshpolicy.AccessRequestPreview{Request: []byte("private-route"), RequestSHA256: sshAccessDigest([]byte("private-route")), RecoveryRequired: true}, nil
				},
				issue: func(_ context.Context, plan, enrollment, request string, lifetime time.Duration) (sshpolicy.AccessChallengePublication, error) {
					calls++
					if plan != digest || enrollment != digest || request != sshAccessDigest([]byte("request")) || lifetime != 180*time.Second {
						t.Fatal("issuance approval lost")
					}
					result := sshpolicy.AccessChallengePublication{Request: []byte("request"), Challenge: []byte("private-challenge"), IssuanceSHA256: digest, IssuanceImageSHA256: digest, IssuanceDurable: true, RecoveryRequired: true}
					if scenario == "partial-issue" {
						return result, errors.New("durability refused")
					}
					return result, nil
				},
				record: func(_ context.Context, plan, enrollment, issuance, image string, receipt []byte) (sshpolicy.AccessReceiptPublication, error) {
					calls++
					if plan != digest || enrollment != digest || issuance != digest || image != digest || string(receipt) != "signed-receipt" {
						t.Fatal("receipt approval lost")
					}
					return sshpolicy.AccessReceiptPublication{RecordSHA256: digest, RecordDurable: true, RecoveryRequired: true}, nil
				},
			}
			operation := "access-request"
			if scenario == "issue" || scenario == "partial-issue" || scenario == "lifetime" {
				operation = "access-issue"
			}
			if scenario == "record" {
				operation = "access-record"
			}
			args := []string{"ssh-policy", operation, "--exchange-dir", dir, "--plan-sha256", digest, "--enrollment-sha256", digest}
			if operation == "access-issue" {
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
			root := accessCommandFixture(t, ops)
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

func TestSSHAccessControllerCommandIsolation(t *testing.T) {
	for _, operation := range []string{"access-request", "access-issue", "access-record", "access-probe"} {
		root := accessCommandFixture(t, sshAccessOperations{})
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
	root := accessCommandFixture(t, sshAccessOperations{})
	cmd, _, _ := root.Find([]string{"ssh-policy", "access-probe"})
	if err := rootCmd.PersistentPreRunE(cmd, nil); err != nil {
		t.Fatal(err)
	}
}

func TestSSHAccessControllerDeliveryGuard(t *testing.T) {
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
			ops := sshAccessOperations{probe: func(_ context.Context, r, c []byte, rs, cs string, s []byte, guard func() error) ([]byte, error) {
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
			root := accessCommandFixture(t, ops)
			var output bytes.Buffer
			root.SetOut(&output)
			root.SetErr(&output)
			root.SetArgs([]string{"ssh-policy", "access-probe", "--exchange-dir", dir, "--request-sha256", request, "--challenge-sha256", challenge, "--credentials-sha256", credentials})
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

func privateSSHExchangeTestDir(t *testing.T) string {
	t.Helper()
	path := t.TempDir()
	// #nosec G302 -- owner-only searchable test directory, not a regular file.
	if err := os.Chmod(path, 0700); err != nil {
		t.Fatal(err)
	}
	return path
}
