//go:build linux

package sshpolicy

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// All keys and endpoints are synthetic and confined to the explicitly guarded
// disposable container. This enrollment has independent recovery authority.
func isolatedSSHEnrollRestoredAccess(t *testing.T, plan, recovery string) *isolatedAccessEnrollment {
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
	doc := sshRestoredAccessAuthorityDocument{
		Schema: 1, Domain: sshRestoredAccessAuthorityDomain, Scope: "restoration-access",
		PlanSHA256: plan, RecoverySHA256: recovery, Controller: public,
		Routes:    []sshAccessAuthorityRoute{{ContextID: "administrator", Target: sshAccessPin{"127.0.0.1:22222", "root", host.Marshal(), signer.PublicKey().Marshal()}}},
		NotBefore: now.Add(-time.Minute).Unix(), ExpiresAt: now.Add(time.Hour).Unix(),
	}
	wire, err = json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sshRestoredAccessAuthorityPath, wire, 0600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clear(key); clear(identity) })
	return &isolatedAccessEnrollment{digestBytes(wire), key, []sshAccessCredentials{{ContextID: "administrator", Target: identity}}}
}

func isolatedSSHExerciseRestoredAccessExchange(t *testing.T, ctx context.Context, plan, recovery string) {
	t.Helper()
	before := isolatedSSHRecoveryHistory(t, ctx)
	x := isolatedSSHEnrollRestoredAccess(t, plan, recovery)
	request, err := PrepareSystemdRestoredAccessRequest(ctx, plan, recovery, x.approval)
	if err != nil || !request.RecoveryRequired || digestBytes(request.Request) != request.RequestSHA256 {
		t.Fatal("production restored request failed", err)
	}
	issued, err := IssueSystemdRestoredAccessChallenge(ctx, plan, recovery, x.approval, request.RequestSHA256, 3*time.Minute)
	if err != nil || !issued.IssuanceDurable || !issued.RecoveryRequired || len(issued.Challenge) == 0 {
		t.Fatal("production restored issuance failed", err)
	}
	if _, err := IssueSystemdRestoredAccessChallenge(ctx, plan, recovery, x.approval, request.RequestSHA256, 3*time.Minute); err == nil {
		t.Fatal("restored issuance replay accepted")
	}
	secret, err := json.Marshal(ControllerAccessCredentials{Schema: 1, SigningSeed: x.key.Seed(), Routes: []ControllerAccessCredential{{ContextID: "administrator", Target: x.credentials[0].Target}}})
	if err != nil {
		t.Fatal(err)
	}
	defer clear(secret)
	guard := func() error { return ctx.Err() }
	// An activation controller must reject this request before any authentication.
	if _, err := ProbeAccessChallenge(ctx, issued.Request, issued.Challenge, request.RequestSHA256, digestBytes(issued.Challenge), secret, guard); err == nil {
		t.Fatal("restoration request crossed activation domain")
	}
	receipt, err := ProbeRestoredAccessChallenge(ctx, issued.Request, issued.Challenge, request.RequestSHA256, digestBytes(issued.Challenge), secret, guard)
	if err != nil {
		t.Fatal("production restored controller authentication failed", err)
	}
	recorded, err := RecordSystemdRestoredAccessReceipt(ctx, plan, recovery, x.approval, issued.IssuanceSHA256, issued.IssuanceImageSHA256, receipt)
	if err != nil || !recorded.RecordDurable || !recorded.RecoveryRequired {
		t.Fatal("production restored receipt failed", err)
	}
	if _, err := RecordSystemdRestoredAccessReceipt(ctx, plan, recovery, x.approval, issued.IssuanceSHA256, issued.IssuanceImageSHA256, receipt); err == nil {
		t.Fatal("restored receipt replay accepted")
	}
	inspected, err := InspectSystemdRestoredAccess(ctx, plan, recovery, x.approval, issued.IssuanceSHA256, issued.IssuanceImageSHA256, recorded.RecordSHA256)
	if err != nil || !inspected.IssuanceObserved || !inspected.ReceiptObserved || !inspected.RecoveryRequired {
		t.Fatal("production restored inspection failed", inspected, err)
	}
	after := isolatedSSHRestoredAccessHistory(t, ctx)
	if len(after) != len(before)+2 {
		t.Fatal("unexpected restored exchange membership")
	}
	for name, hash := range before {
		if after[name] != hash {
			t.Fatal("restored exchange rewrote original history", name)
		}
	}
	for _, name := range []string{sshRestoredAccessIssuanceName, sshRestoredAccessEvidenceName} {
		if !lowerDigest.MatchString(after[name]) {
			t.Fatal("missing restored exchange record", name)
		}
	}
	// Fresh login says nothing about forwarding-policy consumption. The caller
	// separately checks actual forwarding and unchanged listening socket identity.
	if _, err := RestoreOriginalSystemd(ctx, plan, recovery); err == nil {
		t.Fatal("restored access cleared the recovery replay fence")
	}
	if err := os.WriteFile(sshRestoredAccessAuthorityPath, []byte("revoked synthetic restoration enrollment"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := PrepareSystemdRestoredAccessRequest(ctx, plan, recovery, x.approval); err == nil {
		t.Fatal("revoked restored authority accepted")
	}
	t.Log("production restored request, durable issuance, fresh authentication and one-time receipt passed; recovery remains required")
}

// Use the exact purpose-aware observer, without loosening the original recovery
// observer used by the existing independent restoration scenarios.
func isolatedSSHRestoredAccessHistory(t *testing.T, ctx context.Context) map[string]string {
	t.Helper()
	session, err := openSSHRecoverySession(ctx)
	if err != nil {
		t.Fatal(err)
	}
	issuance, issueErr := readSSHPrivateChild(session.journal.directory, sshRestoredAccessIssuanceName, session.journal.uid, maxSSHAccessIssuanceBytes)
	evidence, evidenceErr := readSSHPrivateChild(session.journal.directory, sshRestoredAccessEvidenceName, session.journal.uid, maxSSHAccessEvidenceBytes)
	if issueErr != nil || evidenceErr != nil {
		_ = session.close()
		t.Fatal("missing restored records", issueErr, evidenceErr)
	}
	records, err := observeSSHRuntimeRecoveryRecordsWithAccess(session.journal, &issuance, &evidence)
	if err == nil {
		records[sshRestoredAccessIssuanceName] = sshImageDigest(issuance)
		records[sshRestoredAccessEvidenceName] = sshImageDigest(evidence)
	}
	closeErr := session.close()
	if err != nil || closeErr != nil {
		t.Fatal("restored fixture history failed", err, closeErr)
	}
	return records
}
