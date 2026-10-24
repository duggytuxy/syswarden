//go:build linux

package sshpolicy

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

type isolatedAccessEnrollment struct {
	approval    string
	key         ed25519.PrivateKey
	credentials []sshAccessCredentials
}

// This fixture exercises fixed production target adapters. Its synthetic
// controller runs in the same isolated test process, not an independent host.
// No host credentials or configuration enter this disposable container.
func isolatedSSHEnrollAccess(t *testing.T, plan string) *isolatedAccessEnrollment {
	t.Helper()
	requireSSHIsolatedSystemdFixture(t)
	public, key := receiptController(t)
	identity, err := os.ReadFile("/run/syswarden-ssh-native-oracle/client")
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.ParsePrivateKey(identity)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := os.ReadFile("/etc/ssh/ssh_host_ed25519_key.pub")
	if err != nil {
		t.Fatal(err)
	}
	host, _, _, _, err := ssh.ParseAuthorizedKey(wire)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	doc := sshAccessAuthorityDocument{1, sshAccessAuthorityDomain, "activation-access", plan, public,
		[]sshAccessAuthorityRoute{{ContextID: "administrator", Target: sshAccessPin{"127.0.0.1:22222", "root", host.Marshal(), signer.PublicKey().Marshal()}}},
		now.Add(-time.Minute).Unix(), now.Add(time.Hour).Unix()}
	wire, err = json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sshAccessAuthorityPath, wire, 0600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clear(key); clear(identity) })
	return &isolatedAccessEnrollment{digestBytes(wire), key, []sshAccessCredentials{{ContextID: "administrator", Target: identity}}}
}

func isolatedSSHExerciseAccessExchange(t *testing.T, ctx context.Context, plan string, x *isolatedAccessEnrollment) {
	t.Helper()
	before := isolatedSSHRecoveryHistory(t, ctx)
	request, err := PrepareSystemdAccessRequest(ctx, plan, x.approval)
	if err != nil || !request.RecoveryRequired || digestBytes(request.Request) != request.RequestSHA256 {
		t.Fatal("production private request failed", err)
	}
	issued, err := IssueSystemdAccessChallenge(ctx, plan, x.approval, request.RequestSHA256, 3*time.Minute)
	if err != nil || !issued.IssuanceDurable || !issued.RecoveryRequired || len(issued.Challenge) == 0 {
		t.Fatal("production issuance failed", err)
	}
	if _, err := IssueSystemdAccessChallenge(ctx, plan, x.approval, request.RequestSHA256, 3*time.Minute); err == nil {
		t.Fatal("production issuance replay")
	}
	receipt, err := probeSSHAccessChallenge(ctx, issued.Request, issued.Challenge, digestBytes(issued.Challenge), x.key, x.credentials, time.Now, func() error { return ctx.Err() })
	if err != nil {
		t.Fatal("fresh pinned controller fixture authentication failed", err)
	}
	recorded, err := RecordSystemdAccessReceipt(ctx, plan, x.approval, issued.IssuanceSHA256, issued.IssuanceImageSHA256, receipt)
	if err != nil || !recorded.RecordDurable || !recorded.RecoveryRequired {
		t.Fatal("production receipt recording failed", err)
	}
	if _, err := RecordSystemdAccessReceipt(ctx, plan, x.approval, issued.IssuanceSHA256, issued.IssuanceImageSHA256, receipt); err == nil {
		t.Fatal("production receipt replay")
	}
	after := isolatedSSHRecoveryHistory(t, ctx)
	if len(after) != len(before)+2 {
		t.Fatal("unexpected access exchange membership")
	}
	for name, hash := range before {
		if after[name] != hash {
			t.Fatal("access exchange changed original history", name)
		}
	}
	// Revocation must stop new access authority without blocking the independently
	// approved original-restoration operation exercised by the surrounding test.
	if err := os.WriteFile(sshAccessAuthorityPath, []byte("revoked synthetic enrollment"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := PrepareSystemdAccessRequest(ctx, plan, x.approval); err == nil {
		t.Fatal("revoked production enrollment accepted")
	}
	t.Log("production target enrollment, durable issuance, fresh fixture authentication, one-time receipt and revocation passed")
}
