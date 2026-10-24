//go:build linux

package sshpolicy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syswarden-cli/pkg/sshselection"
	"testing"
	"time"
)

// Each invocation owns a fresh disposable systemd container. Unlike the
// ordinary parser/lease fixtures, the recovery adapters select production paths,
// the installed parser, retained process descriptors and actual pidfd dispatch.
// Publication alone uses an explicit fixture label, not a production SELinux
// policy lookup. Host labels remain visible and are never stripped or concealed.
func TestSSHIsolatedSystemdRecoveryOracle(t *testing.T) {
	if os.Getenv("SYSWARDEN_SSH_ISOLATED_SYSTEMD_ORACLE_TEST") != "1" {
		t.Skip("requires the disposable rootless systemd SSH oracle")
	}
	requireSSHIsolatedSystemdFixture(t)
	noop := os.Getenv("SYSWARDEN_SSH_ISOLATED_RECOVERY_NOOP") == "1"
	profile := os.Getenv("SYSWARDEN_SSH_ISOLATED_RECOVERY_PROFILE")
	if (profile != "forwarding" && profile != "cis" && profile != "legacy-cis") || (noop && profile != "forwarding") {
		t.Fatal("explicit qualified recovery fixture profile required")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 150*time.Second)
	defer cancel()
	backend, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	probe := func(allowed bool) { isolatedSSHForwardProbe(t, backend.Addr().String(), allowed) }
	probe(true)
	for _, name := range []string{DropInPath, IntentPath, sshselection.Path, sshStateParent} {
		if _, err := os.Lstat(name); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("fixture path already exists", name, err)
		}
	}
	t.Cleanup(func() { isolatedSSHExportRecoveryHistory(t) })
	for _, name := range []string{filepath.Dir(sshselection.Path), sshStateParent} {
		if err := os.MkdirAll(name, 0700); err != nil {
			t.Fatal(err)
		}
	}
	declaration, err := parseIntent([]byte(validIntentJSON))
	if err != nil {
		t.Fatal(err)
	}
	declaration.Profile = profile
	declaration.Contexts = []accessContext{
		{"administrator", "direct", "root", "localhost", "127.0.0.1", "127.0.0.1", 22222},
		{"unrelated", "direct", "oracle-unrelated", "localhost", "127.0.0.1", "127.0.0.1", 22222},
	}
	original, err := os.ReadFile(MainPath)
	if err != nil {
		t.Fatal(err)
	}
	original = append(original, []byte("Match User oracle-unrelated\n MaxSessions 12\n PermitTTY no\nMatch all\n")...)
	if profile == "legacy-cis" {
		declaration.Profile = "cis"
		marker, rest, found := bytes.Cut(original, []byte("\n"))
		if !found {
			t.Fatal("fixture marker is missing")
		}
		block := "AllowTcpForwarding no\n" + strings.Join(legacyCISBlock, "\n") + "\n"
		original = append(append(append([]byte(nil), marker...), []byte("\n"+block)...), rest...)
		declaration.Legacy = &legacyIntent{Attribution: "operator-reviewed", MainSHA256: digestBytes(original)}
		for line := 2; line <= 8; line++ {
			declaration.Legacy.Edits = append(declaration.Legacy.Edits, legacyEdit{line, "remove"})
		}
	}
	if err := os.WriteFile(MainPath, original, 0644); err != nil { // #nosec G703 G306 -- Constant destination in a guarded disposable container; 0644 is the public synthetic sshd configuration mode, and tainted input affects content only.
		t.Fatal(err)
	}
	// Qualify the original loaded fixture before testing the migration. The
	// container setup owns this first reload; no product history exists yet.
	isolatedSSHReload(t, ctx)
	probe(profile != "legacy-cis")
	wire, err := json.Marshal(declaration)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(IntentPath, wire, 0600); err != nil {
		t.Fatal(err)
	}
	// An exact plan and role do not bypass the independent disabled TOML choice.
	if err := os.WriteFile(sshselection.Path, []byte("[ssh]\nhardening = \"disabled\"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	disabled, err := InspectPlan()
	if err != nil {
		t.Fatal(err)
	}
	selectionErr := (sshselection.Config{Hardening: "disabled"}).Authorize("syswarden", declaration.Profile)
	if _, err := applySSHTransaction(ctx, disabled.PlanSHA256); err == nil || selectionErr == nil || err.Error() != selectionErr.Error() {
		t.Fatal("disabled TOML did not stop at its explicit authorization boundary", err)
	}
	for _, name := range []string{DropInPath, sshJournalDirectory} {
		if _, err := os.Lstat(name); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("disabled selection created policy or history", name, err)
		}
	}
	if err := os.WriteFile(sshselection.Path, []byte("[ssh]\nhardening = \""+declaration.Profile+"\"\n"), 0600); err != nil { // #nosec G703 -- Constant destination in a guarded disposable container; the allowlisted profile changes TOML content, never the pathname.
		t.Fatal(err)
	}
	before := isolatedSSHMainImage(t)
	label := isolatedSSHFixtureLabel(t)
	plan, err := InspectPlan()
	if err != nil {
		t.Fatal(err)
	}
	published, err := isolatedSSHPublish(t, ctx, plan.PlanSHA256, label)
	if err != nil || !published.Published || published.RecoveryRequired || published.Verification.RuntimeActivated {
		t.Fatal("production publication failed", published, err)
	}
	drop, err := os.Open(DropInPath)
	if err != nil {
		t.Fatal(err)
	}
	actualLabel, labelErr := readSSHAttributes(int(drop.Fd()))
	labelCloseErr := drop.Close()
	if labelErr != nil || labelCloseErr != nil || !reflect.DeepEqual(actualLabel, label) {
		t.Fatal("published fixture label differs", labelErr, labelCloseErr)
	}
	probe(profile != "legacy-cis") // Publication did not signal the daemon.
	session, err := openSSHRecoverySession(ctx)
	if err != nil {
		t.Fatal(err)
	}
	activation, activationErr := attemptSSHActivation(ctx, session.journal, plan.PlanSHA256,
		session.parser, session.run, session.check, session.bind)
	closeErr := session.close()
	if activationErr != nil || closeErr != nil || !activation.IntentDurable || !activation.RequestReturned || !activation.RecoveryRequired {
		t.Fatal("production activation boundary failed", activation, activationErr, closeErr)
	}
	probe(false)
	history := isolatedSSHRecoveryHistory(t, ctx)
	inspection, err := InspectSystemdRecovery(ctx, plan.PlanSHA256)
	if err != nil || !lowerDigest.MatchString(inspection.RecoverySHA256) || !inspection.RecoveryRequired ||
		inspection.IntentDurable || inspection.ConfigurationRestored || inspection.RequestReturned {
		t.Fatal("production recovery inspection failed", inspection, err)
	}
	if again, err := InspectSystemdRecovery(ctx, plan.PlanSHA256); err != nil || again != inspection {
		t.Fatal("unchanged recovery approval is not repeatable", again, err)
	}
	if _, err := RestoreOriginalSystemd(ctx, plan.PlanSHA256, plan.PlanSHA256); err == nil {
		t.Fatal("original approval authorized restoration")
	}
	if !reflect.DeepEqual(history, isolatedSSHRecoveryHistory(t, ctx)) {
		t.Fatal("inspection or rejected approval changed history")
	}
	probe(false)
	var restored RuntimeRecoverySummary
	noopCalls := 0
	if noop {
		// Retain the actual production process/listener observer and fixed-path
		// opener. Only suppress the single test dispatch, never its validation.
		opener := func(ctx context.Context) (*sshRecoverySession, error) {
			session, err := openSSHRecoverySession(ctx)
			if err != nil {
				return session, err
			}
			session.bind = func(ctx context.Context, guard func() error) (sshActivationLease, error) {
				lease, err := bindSSHSystemdActivation(ctx, guard)
				if err == nil {
					lease.(*sshActivationTarget).send = func() error { noopCalls++; return nil }
				}
				return lease, err
			}
			return session, nil
		}
		restored, err = runSSHRecoverySession(ctx, plan.PlanSHA256, inspection.RecoverySHA256, true, opener)
		if err == nil || noopCalls != 1 || ctx.Err() != nil || (!errors.Is(err, context.DeadlineExceeded) && !strings.Contains(err.Error(), "SSH listener replacement was not observed")) {
			t.Fatal("no-op restoration was not rejected by listener observation", err)
		}
	} else {
		restored, err = RestoreOriginalSystemd(ctx, plan.PlanSHA256, inspection.RecoverySHA256)
	}
	if (!noop && err != nil) || !restored.IntentDurable || !restored.ConfigurationRestored || restored.RequestReturned == noop ||
		!restored.RecoveryRequired || restored.RuntimeActivated || restored.AccessVerified {
		t.Fatal("production original restoration failed", restored, err)
	}
	probe(!noop && profile != "legacy-cis")
	after := isolatedSSHMainImage(t)
	// Rename changes ctime. The original inode, metadata, xattrs and bytes must
	// nevertheless be recovered, not a newly generated equivalent file.
	after.state.changed = before.state.changed
	if !reflect.DeepEqual(before, after) {
		t.Fatal("original inode, policy bytes or metadata were not restored")
	}
	if _, err := os.Lstat(DropInPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("active product drop-in remains", err)
	}
	isolatedSSHRetainedCandidates(t, ctx)
	recoveredHistory := isolatedSSHRecoveryHistory(t, ctx)
	if len(recoveredHistory) != len(history)+6 {
		t.Fatal("incomplete inverse/reload history")
	}
	for name, digest := range history {
		if recoveredHistory[name] != digest {
			t.Fatal("original activation evidence changed", name)
		}
	}
	listenersBefore, err := ObserveSystemdListeners()
	if err != nil {
		t.Fatal(err)
	}
	assessment, err := AssessSystemdRecovery(ctx, plan.PlanSHA256, inspection.RecoverySHA256)
	if err != nil || !assessment.ConfigurationRestored || !assessment.ParserVerified || !assessment.ReloadIntentObserved ||
		!assessment.RecoveryRequired || assessment.RuntimeActivated || assessment.AccessVerified {
		t.Fatal("production post-reload assessment failed", assessment, err)
	}
	if _, err := RestoreOriginalSystemd(ctx, plan.PlanSHA256, inspection.RecoverySHA256); err == nil {
		t.Fatal("restoring reload replay accepted")
	}
	if !reflect.DeepEqual(recoveredHistory, isolatedSSHRecoveryHistory(t, ctx)) {
		t.Fatal("assessment or replay changed history")
	}
	// A rejection after accidentally signalling would otherwise look like a
	// passing replay refusal. Require the same kernel socket generation across
	// assessment, replay and fresh traffic, including a bounded settling window.
	probe(!noop && profile != "legacy-cis")
	for range 2 {
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(250 * time.Millisecond):
		}
		listenersAfter, err := ObserveSystemdListeners()
		if err != nil || listenersAfter.SocketsSHA256 != listenersBefore.SocketsSHA256 ||
			listenersAfter.Process.IdentitySHA256 != listenersBefore.Process.IdentitySHA256 {
			t.Fatal("read-only assessment or rejected replay changed the daemon/listeners", err)
		}
	}
	t.Log("real parser/publication, production activation/recovery and assessment checks passed with fixture-only label preparation; recovery fence retained")
}

func isolatedSSHReload(t *testing.T, ctx context.Context) {
	t.Helper()
	inventory, err := OpenInventory()
	if err != nil {
		t.Fatal(err)
	}
	lease, err := bindSSHSystemdActivation(ctx, inventory.Recheck)
	if err != nil {
		_ = inventory.Close()
		t.Fatal(err)
	}
	requestErr := lease.request(ctx, inventory.Recheck)
	closeErr := errors.Join(lease.Close(), inventory.Close())
	if requestErr != nil || closeErr != nil {
		t.Fatal("fixture baseline reload failed", requestErr, closeErr)
	}
}

func isolatedSSHMainImage(t *testing.T) sshFileImage {
	t.Helper()
	file, err := os.Open(MainPath)
	if err != nil {
		t.Fatal(err)
	}
	image, err := readSSHImage(file, 0, 1, MaxBytes)
	closeErr := file.Close()
	if err != nil || closeErr != nil {
		t.Fatal("fixture main inventory failed", err, closeErr)
	}
	return image
}

func isolatedSSHRecoveryHistory(t *testing.T, ctx context.Context) map[string]string {
	t.Helper()
	session, err := openSSHRecoverySession(ctx)
	if err != nil {
		t.Fatal(err)
	}
	history, err := observeSSHRuntimeRecoveryRecords(session.journal)
	closeErr := session.close()
	if err != nil || closeErr != nil {
		t.Fatal("fixture journal inventory failed", err, closeErr)
	}
	return history
}

// The recovery test must prepare attributable candidate inodes without claiming
// SELinux policy resolution in a container whose host policy is unavailable.
// Capture the actual label of a new private file in the fixture destination.
// This test-only dependency is never exposed by a product API or installer.
func isolatedSSHFixtureLabel(t *testing.T) map[string][]byte {
	t.Helper()
	file, err := os.CreateTemp(filepath.Dir(DropInPath), ".oracle-label-")
	if err != nil {
		t.Fatal(err)
	}
	attrs, attrErr := readSSHAttributes(int(file.Fd()))
	closeErr := file.Close()
	removeErr := os.Remove(file.Name())
	if err := errors.Join(attrErr, closeErr, removeErr); err != nil {
		t.Fatal(err)
	}
	result := map[string][]byte{}
	if value, exists := attrs["security.selinux"]; exists {
		result["security.selinux"] = bytes.Clone(value)
	}
	return result
}

func isolatedSSHPublish(t *testing.T, ctx context.Context, approved string, label map[string][]byte) (result sshTransactionResult, err error) {
	t.Helper()
	root, err := os.Open("/")
	if err != nil {
		return result, err
	}
	defer func() { err = errors.Join(err, root.Close()) }()
	daemon, err := openSSHD(root, 0)
	if err != nil {
		return result, err
	}
	defer func() { err = errors.Join(err, daemon.file.Close()) }()
	sourceLabel := isolatedSSHMainImage(t).attrs["security.selinux"]
	labelCheck := func(ctx context.Context) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		file, err := os.Open(MainPath)
		if err != nil {
			return err
		}
		attrs, attrErr := readSSHAttributes(int(file.Fd()))
		closeErr := file.Close()
		if !bytes.Equal(sourceLabel, attrs["security.selinux"]) {
			return errors.Join(ErrInventoryChanged, attrErr, closeErr)
		}
		return errors.Join(attrErr, closeErr, ctx.Err())
	}
	deps := sshTransactionDependencies{
		parserDigest: daemon.digest, run: daemon.run,
		checkParser: func() error { return daemon.recheck(root, 0) },
		resolveLabel: func(context.Context, inventorySnapshot) (*sshTargetLabel, error) {
			return &sshTargetLabel{label, labelCheck, func() error { return nil }}, nil
		},
		provision: sshProvisionDefaults(), publication: sshPublicationDefaults(),
	}
	return executeSSHTransaction(ctx, root, 0, approved, deps)
}

func isolatedSSHRetainedCandidates(t *testing.T, ctx context.Context) {
	t.Helper()
	session, err := openSSHRecoverySession(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := session.close(); err != nil {
			t.Error(err)
		}
	}()
	record, err := session.journal.read()
	if err != nil {
		t.Fatal(err)
	}
	current, err := stableSSHRollback(session.journal, record.Transaction)
	if err != nil {
		t.Fatal(err)
	}
	mainStage, err := sshMainStagePath(record.Transaction)
	if err != nil {
		t.Fatal(err)
	}
	dropStage, err := sshDropStagePath(record.Transaction)
	if err != nil {
		t.Fatal(err)
	}
	if !matchesSSHRecovery(current, mainStage, record.MainAfter) || !matchesSSHRecovery(current, dropStage, record.DropIn) {
		t.Fatal("candidate recovery inodes or attributes changed")
	}
}

// Keep exact synthetic journal bytes in the private runner log before disposable
// container cleanup, including failed or incomplete transactions. This export
// never runs in the product and does not copy keys or unrelated files.
func isolatedSSHExportRecoveryHistory(t *testing.T) {
	t.Helper()
	entries, err := os.ReadDir(sshJournalDirectory)
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	if err != nil || len(entries) > 16 {
		t.Error("cannot export bounded fixture journal", err)
		return
	}
	records := map[string][]byte{}
	for _, entry := range entries {
		if !entry.Type().IsRegular() || (entry.Name() != sshMarkerName && !sshRecordName(entry.Name())) {
			t.Error("unexpected fixture journal entry")
			return
		}
		file, err := os.Open(filepath.Join(sshJournalDirectory, entry.Name()))
		if err != nil {
			t.Error(err)
			return
		}
		data, readErr := io.ReadAll(io.LimitReader(file, maxSSHJournalBytes+1))
		closeErr := file.Close()
		if readErr != nil || closeErr != nil || len(data) > maxSSHJournalBytes {
			t.Error("fixture journal export failed", readErr, closeErr)
			return
		}
		records[entry.Name()] = data
	}
	wire, err := json.Marshal(records)
	if err != nil {
		t.Error(err)
		return
	}
	fmt.Printf("SYSWARDEN_PRIVATE_FIXTURE_JOURNAL_BASE64_JSON %s\n", wire)
}

// A distinct bounded entry point lets the runner attempt private evidence export
// even when Go's primary watchdog bypasses test cleanup. No mutations are made.
func TestSSHIsolatedSystemdJournalExport(t *testing.T) {
	if os.Getenv("SYSWARDEN_SSH_ISOLATED_SYSTEMD_ORACLE_TEST") != "1" {
		t.Skip("requires the disposable rootless systemd SSH oracle")
	}
	requireSSHIsolatedSystemdFixture(t)
	isolatedSSHExportRecoveryHistory(t)
}
