//go:build linux

package system

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type apkExecutionTestBoundary struct {
	factory   func(context.Context, string, apkLauncherCustodyBinding, []apkTransitionHostEntry) (apkExecutionLaunchers, error)
	digest    string
	before    func(context.Context) error
	after     func(context.Context) error
	prepare   func() error
	closeErr  error
	launchers *apkExecutionTestLaunchers
	calls     []string
}

func (b *apkExecutionTestBoundary) EffectPlanSHA256() string { return b.digest }
func (b *apkExecutionTestBoundary) Revalidate(ctx context.Context) error {
	b.calls = append(b.calls, "before")
	if b.before != nil {
		return b.before(ctx)
	}
	return ctx.Err()
}
func (b *apkExecutionTestBoundary) PrepareLaunchers(ctx context.Context, path string, binding apkLauncherCustodyBinding, original []apkTransitionHostEntry) (apkExecutionLaunchers, error) {
	b.calls = append(b.calls, "launchers")
	if filepath.Base(path) != "execution-"+binding.PlanSHA256 || len(original) != 6 || !validSHA256(binding.ApprovalSHA256) || !validSHA256(binding.CandidateCapabilitySHA256) {
		return nil, errors.New("incomplete engine launcher binding")
	}
	data, err := apkExecutionJSON(original)
	if err != nil || apkTransitionDigest(data) != binding.OriginalSnapshotSHA256 {
		return nil, errors.New("wrong engine launcher snapshot")
	}
	if b.factory != nil {
		return b.factory(ctx, path, binding, original)
	}
	if b.prepare != nil {
		if err := b.prepare(); err != nil {
			return nil, err
		}
	}
	return b.launchers, ctx.Err()
}
func (b *apkExecutionTestBoundary) AttestResult(ctx context.Context) error {
	b.calls = append(b.calls, "after")
	if b.after != nil {
		return b.after(ctx)
	}
	return ctx.Err()
}
func (b *apkExecutionTestBoundary) Close() error {
	b.calls = append(b.calls, "close")
	return b.closeErr
}

type apkExecutionTestLaunchers struct {
	revalidateErr, dependencyErr, targetErr, commitErr, closeErr error
	receipt                                                      string
	commits                                                      int
}

func (l *apkExecutionTestLaunchers) AttestUpgradeTargets() error            { return l.targetErr }
func (l *apkExecutionTestLaunchers) Revalidate() error                      { return l.revalidateErr }
func (l *apkExecutionTestLaunchers) RefuseProductTargetDependencies() error { return l.dependencyErr }
func (l *apkExecutionTestLaunchers) Commit() (string, error) {
	l.commits++
	return l.receipt, l.commitErr
}
func (l *apkExecutionTestLaunchers) Close() error { return l.closeErr }
func apkExecutionTestAuthority() *apkExecutionTestBoundary {
	return &apkExecutionTestBoundary{digest: strings.Repeat("e", 64), launchers: &apkExecutionTestLaunchers{receipt: strings.Repeat("f", 64)}}
}

type apkExecutionTestFixture struct {
	candidate   authenticatedAPKCandidate
	services    apkTransitionServices
	preparation *APKTransitionApprovalRequiredError
	review      *APKTransitionExecutionReview
	post        bool
	installed   installedQualificationEvidence
	installErr  error
	calls       int
}

func newAPKExecutionTestFixture(t *testing.T, setup ...func(*testing.T, *apkTransitionServices)) *apkExecutionTestFixture {
	t.Helper()
	candidate, services, _ := apkTransitionFixture(t)
	for _, prepare := range setup {
		prepare(t, &services)
	}
	f := &apkExecutionTestFixture{candidate: candidate, services: services, installed: installedQualificationEvidence{version: candidate.version, cliSHA256: candidate.cliSHA256}}
	old := candidate.attestInstalled
	f.candidate.attestInstalled = func(ctx context.Context, target packageTarget, uid int) (installedQualificationEvidence, error) {
		if f.post {
			return f.installed, f.installErr
		}
		return old(ctx, target, uid)
	}
	err := prepareAPKTransition(t.Context(), f.candidate, f.services)
	if !errors.As(err, &f.preparation) {
		t.Fatal("prepare", err)
	}
	f.review, err = planAPKTransitionExecution(t.Context(), f.preparation.PlanSHA256, f.candidate.keys, f.candidate.attestInstalled, f.services, apkExecutionTestAuthority())
	if err != nil {
		t.Fatal("execution proposal", err)
	}
	return f
}
func (f *apkExecutionTestFixture) run(ctx context.Context, prepared *verifiedPreparedAPKTransition, overlay *os.File, args []string, output io.Writer) error {
	f.calls++
	contents, err := io.ReadAll(overlay)
	if err != nil {
		return err
	}
	expected, err := apkExecutionArguments(prepared.candidate.path, prepared.plan.RetainedDependencyNames)
	if err != nil || !reflect.DeepEqual(args, expected) || string(contents) != apkExecutionOverlay {
		return errors.New("engine changed fixed overlay or command")
	}
	_, err = io.WriteString(output, "inert native transaction fixture\n")
	if err != nil {
		return err
	}
	f.post = true
	world := "syswarden><" + prepared.plan.CandidateAPKChecksum + "\nwireguard-tools\nrsyslog\n"
	database := strings.Replace(apkRetentionFixtureDatabase(), "V:4.10.4-r0", "V:5.00.0-r0", 1)
	database = strings.Replace(database, "C:"+apkRetentionFixtureChecksum, "C:"+prepared.plan.CandidateAPKChecksum, 1)
	// These are precreated inert fixture files, never the host native database.
	if err := os.WriteFile(filepath.Join(f.services.hostRoot, "etc/apk/world"), []byte(world), 0600); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(f.services.hostRoot, "lib/apk/db/installed"), []byte(database), 0600); err != nil {
		return err
	}
	return ctx.Err()
}
func (f *apkExecutionTestFixture) execute(ctx context.Context, boundary *apkExecutionTestBoundary, services apkExecutionServices) error {
	if services.run == nil {
		services.run = f.run
	}
	return executeAPKTransitionWith(ctx, f.preparation.PlanSHA256, f.review.PlanSHA256, f.candidate.keys, f.candidate.attestInstalled, f.services, boundary, services)
}
func assertAPKExecutionState(t *testing.T, f *apkExecutionTestFixture, name string, want bool) {
	t.Helper()
	_, err := os.Lstat(filepath.Join(f.review.Directory, name+".json"))
	if want && err != nil || !want && !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("state %s exists=%t, error=%v", name, want, err)
	}
}

func TestAPKExecutionOverlayIsExactSealedAndNotAnInputPipe(t *testing.T) {
	file, err := openAPKExecutionOverlay()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = file.Close() })
	status, err := file.Stat()
	if err != nil || !status.Mode().IsRegular() {
		t.Fatal("overlay is not preexisting complete regular input", err)
	}
	seals, err := unix.FcntlInt(file.Fd(), unix.F_GET_SEALS, 0)
	if err != nil || seals != unix.F_SEAL_WRITE|unix.F_SEAL_GROW|unix.F_SEAL_SHRINK|unix.F_SEAL_SEAL {
		t.Fatal("missing overlay seals", err)
	}
	if _, err := file.WriteAt([]byte("x"), 0); !errors.Is(err, syscall.EPERM) {
		t.Fatal("overlay permits mutation", err)
	}
	if err := file.Truncate(0); !errors.Is(err, syscall.EPERM) {
		t.Fatal("overlay permits truncation", err)
	}
	data, err := io.ReadAll(file)
	if err != nil || string(data) != apkExecutionOverlay {
		t.Fatal("overlay differs", err)
	}
}

func TestAPKExecutionArgumentsRefuseCallerOptionsOrDependencyReordering(t *testing.T) {
	for _, dependencies := range [][]string{{"--allow-untrusted"}, {"syswarden-base"}, {"wireguard-tools", "rsyslog"}, {"rsyslog", "rsyslog"}, {"rsyslog@alternate"}} {
		if _, err := apkExecutionArguments("/private/candidate.apk", dependencies); err == nil {
			t.Fatal("unsafe arguments accepted", dependencies)
		}
	}
	for _, path := range []string{"candidate.apk", "/private/../candidate.apk", "/private/candidate", "/private/--option"} {
		if _, err := apkExecutionArguments(path, nil); err == nil {
			t.Fatal("unsafe path accepted", path)
		}
	}
	got, err := apkExecutionArguments("/private/candidate.apk", []string{"rsyslog", "wireguard-tools"})
	want := []string{"--no-network", "--no-cache", "--repositories-file", "/dev/null", "--overlay-from-stdin", "add", "/private/candidate.apk", "rsyslog", "wireguard-tools"}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatal("closed native arguments differ", got, err)
	}
}

func TestAPKExecutionRequiresSeparateExactApprovalAndQualifiedBoundary(t *testing.T) {
	for _, kind := range []string{"preparation-review", "wrong-digest", "missing-boundary", "effect-drift", "before-refusal", "missing-proposal"} {
		t.Run(kind, func(t *testing.T) {
			f := newAPKExecutionTestFixture(t)
			boundary := apkExecutionTestAuthority()
			digest := f.review.PlanSHA256
			switch kind {
			case "preparation-review":
				digest = f.preparation.PlanSHA256
			case "wrong-digest":
				digest = strings.Repeat("a", 64)
			case "missing-boundary":
				boundary = nil
			case "effect-drift":
				boundary.digest = strings.Repeat("a", 64)
			case "before-refusal":
				boundary.before = func(context.Context) error { return errors.New("hooks unqualified") }
			case "missing-proposal":
				if err := os.Rename(f.review.Directory, f.review.Directory+".retained"); err != nil {
					t.Fatal(err)
				}
			}
			err := executeAPKTransitionWith(t.Context(), f.preparation.PlanSHA256, digest, f.candidate.keys, f.candidate.attestInstalled, f.services, boundary, apkExecutionServices{run: f.run})
			if err == nil || f.calls != 0 {
				t.Fatal("unapproved native dispatch", err, f.calls)
			}
		})
	}
}

func TestAPKExecutionQualifiedFixtureCompletesOnlyAfterIndependentAttestation(t *testing.T) {
	f := newAPKExecutionTestFixture(t)
	original, err := os.ReadFile(filepath.Join(f.preparation.Directory, "host-snapshot.json"))
	if err != nil {
		t.Fatal(err)
	}
	boundary := apkExecutionTestAuthority()
	if err := f.execute(t.Context(), boundary, apkExecutionServices{}); err != nil {
		t.Fatal(err)
	}
	if f.calls != 1 || boundary.launchers.commits != 1 {
		t.Fatal("missing native observation or custody receipt")
	}
	for _, state := range []string{"execution-approval", "armed", "native-started", "observed", "post-attestation", "completed"} {
		assertAPKExecutionState(t, f, state, true)
	}
	assertAPKExecutionState(t, f, "unresolved", false)
	data, err := os.ReadFile(filepath.Join(f.review.Directory, "completed.json"))
	if err != nil || !bytes.Contains(data, []byte(`"product_accepted":false`)) {
		t.Fatal("component completion claimed product acceptance", err)
	}
	unchanged, err := os.ReadFile(filepath.Join(f.preparation.Directory, "host-snapshot.json"))
	if err != nil || !bytes.Equal(original, unchanged) {
		t.Fatal("original evidence rewritten", err)
	}
	if err := f.execute(t.Context(), apkExecutionTestAuthority(), apkExecutionServices{}); err == nil || f.calls != 1 {
		t.Fatal("completed native attempt replayed", err)
	}
}

func TestAPKExecutionAdversarialNativeOutcomesRemainUnresolved(t *testing.T) {
	for _, kind := range []string{"native-exit", "zero-without-install", "cancel", "wrong-version", "wrong-cli", "wrong-registration", "broken-registration", "wrong-checksum", "alias-owner", "world-loss", "unrelated-package", "configuration-edit", "alias-edit", "runtime-refusal", "hook-refusal", "target-refusal", "launcher-refusal", "launcher-commit", "empty-receipt", "launcher-close", "boundary-close", "output-overflow"} {
		t.Run(kind, func(t *testing.T) {
			f := newAPKExecutionTestFixture(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			boundary := apkExecutionTestAuthority()
			runner := func(ctx context.Context, p *verifiedPreparedAPKTransition, overlay *os.File, args []string, out io.Writer) error {
				if kind == "zero-without-install" {
					f.calls++
					return nil
				}
				if err := f.run(ctx, p, overlay, args, out); err != nil {
					return err
				}
				switch kind {
				case "native-exit":
					return errors.New("inert native failure")
				case "cancel":
					cancel()
					return nil
				case "wrong-version":
					f.installed.version = "v4.10.4"
				case "wrong-cli":
					f.installed.cliSHA256 = strings.Repeat("a", 64)
				case "wrong-registration":
					f.installErr = errors.New("wrong selected native identity")
				case "broken-registration":
					return rewriteAPKExecutionFixture(t, f, "lib/apk/db/installed", func(s string) string { return strings.Replace(s, "f:S", "f:s", 1) })
				case "wrong-checksum":
					if err := rewriteAPKExecutionFixture(t, f, "lib/apk/db/installed", func(s string) string {
						return strings.Replace(s, "C:"+p.plan.CandidateAPKChecksum, "C:"+apkRetentionFixtureChecksum, 1)
					}); err != nil {
						return err
					}
					return rewriteAPKExecutionFixture(t, f, "etc/apk/world", func(s string) string {
						return strings.Replace(s, p.plan.CandidateAPKChecksum, apkRetentionFixtureChecksum, 1)
					})
				case "alias-owner":
					return rewriteAPKExecutionFixture(t, f, "lib/apk/db/installed", func(s string) string {
						return strings.Replace(s, "F:opt/syswarden\nR:fixture", "F:usr/local/bin\nR:syswarden", 1)
					})
				case "world-loss":
					return rewriteAPKExecutionFixture(t, f, "etc/apk/world", func(s string) string { return strings.Replace(s, "wireguard-tools\n", "", 1) })
				case "unrelated-package":
					return rewriteAPKExecutionFixture(t, f, "lib/apk/db/installed", func(s string) string { return strings.Replace(s, "P:unrelated\nV:1.0-r0", "P:unrelated\nV:2.0-r0", 1) })
				case "configuration-edit":
					return rewriteAPKExecutionFixture(t, f, "etc/syswarden/config/modules/99-user.toml", func(string) string { return "changed by package\n" })
				case "alias-edit":
					return rewriteAPKExecutionFixture(t, f, "usr/local/bin/syswarden", func(string) string { return "changed by package\n" })
				case "hook-refusal":
					boundary.after = func(context.Context) error { return errors.New("hook effects incomplete") }
				case "target-refusal":
					boundary.launchers.targetErr = errors.New("retained alias target does not match approved candidate bytes")
				case "launcher-refusal":
					boundary.launchers.revalidateErr = errors.New("alias changed")
				case "launcher-commit":
					boundary.launchers.commitErr = errors.New("custody commit failed")
				case "empty-receipt":
					boundary.launchers.receipt = ""
				case "launcher-close":
					boundary.launchers.closeErr = errors.New("custody close failed")
				case "boundary-close":
					boundary.closeErr = errors.New("boundary close failed")
				case "runtime-refusal":
					p.activation = apkExecutionRejectedActivation{}
				case "output-overflow":
					_, err := out.Write(bytes.Repeat([]byte("x"), 1<<20))
					return err
				}
				return nil
			}
			err := f.execute(ctx, boundary, apkExecutionServices{run: runner})
			var failure *APKTransitionExecutionError
			if !errors.As(err, &failure) || !failure.Unresolved || f.calls != 1 {
				t.Fatal("native outcome did not retain unresolved custody", err, f.calls)
			}
			assertAPKExecutionState(t, f, "unresolved", true)
			assertAPKExecutionState(t, f, "completed", false)
			if f.calls != 1 {
				t.Fatal("native attempt repeated")
			}
		})
	}
}

func rewriteAPKExecutionFixture(t *testing.T, f *apkExecutionTestFixture, name string, change func(string) string) error {
	t.Helper()
	// Callers supply only fixed names of precreated private fixture files.
	path := filepath.Join(f.services.hostRoot, name)
	data, err := os.ReadFile(path) // #nosec G304 -- fixed test case names under this test's temporary native host
	if err != nil {
		return err
	}
	return os.WriteFile(path, []byte(change(string(data))), 0600)
}

type apkExecutionRejectedActivation struct{ apkTransitionTestActivation }

func (apkExecutionRejectedActivation) VerifyInstalledCandidate(context.Context) error {
	return errors.New("candidate runtime descriptor or core differs")
}

func TestAPKExecutionJournalFaultsRetainEvidenceAndNeverReplay(t *testing.T) {
	for _, name := range []string{"execution-approval.json", "armed.json", "native-started.json", "native-output.txt", "observed-host-snapshot.json", "observed.json", "post-attestation.json", "completed.json"} {
		t.Run(name, func(t *testing.T) {
			f := newAPKExecutionTestFixture(t)
			write := func(directory *pinnedServiceDirectory, path string, data []byte) error {
				if path == name {
					return syscall.ENOSPC
				}
				return writeAPKTransitionBytes(directory, path, data)
			}
			err := f.execute(t.Context(), apkExecutionTestAuthority(), apkExecutionServices{write: write})
			var failure *APKTransitionExecutionError
			if !errors.As(err, &failure) || !errors.Is(err, syscall.ENOSPC) {
				t.Fatal("fault lost retained error", err)
			}
			wantStarted := name != "execution-approval.json" && name != "armed.json"
			if failure.Unresolved != wantStarted {
				t.Fatal("wrong durable uncertainty", err)
			}
			if wantStarted {
				assertAPKExecutionState(t, f, "unresolved", true)
			}
			if _, err := os.Stat(filepath.Join(f.preparation.Directory, f.candidate.artifact.Filename)); err != nil {
				t.Fatal("original candidate lost", err)
			}
			calls := f.calls
			retryErr := f.execute(t.Context(), apkExecutionTestAuthority(), apkExecutionServices{})
			// A failure before an approval file exists has performed no transition and
			// may still be reviewed. Every persisted approval/attempt blocks replay.
			if name != "execution-approval.json" && (retryErr == nil || f.calls != calls) {
				t.Fatal("durable attempt replayed", retryErr)
			}
		})
	}
}

func TestAPKExecutionPreDispatchCustodyFailureNeverInvokesAPK(t *testing.T) {
	for _, kind := range []string{"helper-bytes", "helper-symlink", "launcher-dependency", "launcher-prepare", "nil-launcher", "candidate-bytes"} {
		t.Run(kind, func(t *testing.T) {
			f := newAPKExecutionTestFixture(t)
			boundary := apkExecutionTestAuthority()
			switch kind {
			case "helper-bytes":
				if err := os.WriteFile(filepath.Join(f.review.Directory, apkExecutionHelper), []byte("altered candidate helper"), 0700); err != nil { // #nosec G306 -- Private inert helper fixture retains executable mode while the byte-tamper refusal is tested.
					t.Fatal(err)
				}
			case "helper-symlink":
				path := filepath.Join(f.review.Directory, apkExecutionHelper)
				if err := os.Rename(path, path+".original"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(path+".original", path); err != nil {
					t.Fatal(err)
				}
			case "launcher-dependency":
				boundary.launchers.dependencyErr = errors.New("retained alias resolves into replaced payload")
			case "nil-launcher":
				boundary.launchers = nil
			case "launcher-prepare":
				boundary.prepare = func() error { return errors.New("launcher snapshot differs") }
			case "candidate-bytes":
				if err := os.WriteFile(filepath.Join(f.preparation.Directory, f.candidate.artifact.Filename), []byte("altered package"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := f.execute(t.Context(), boundary, apkExecutionServices{}); err == nil || f.calls != 0 {
				t.Fatal("unsafe dispatch", err, f.calls)
			}
			assertAPKExecutionState(t, f, "native-started", false)
		})
	}
}

func TestAPKExecutionNativeDatabaseChecksAliasItselfAndPreservesTargetOwnership(t *testing.T) {
	safe := strings.Replace(apkRetentionFixtureDatabase(), "V:4.10.4-r0", "V:5.00.0-r0", 1)
	safe = strings.Replace(safe, "F:opt/syswarden\nR:fixture", "F:opt/syswarden/bin\nR:syswarden-cli", 1)
	if _, _, err := apkExecutionDatabase([]byte(safe)); err != nil {
		t.Fatal("target ownership was mistaken for alias ownership", err)
	}
	for _, record := range []string{"F:usr/local/bin\nR:syswarden", "F:usr/local/bin\nR:syswarden-tui", "F:usr/local/../local/bin\nR:syswarden", "F:usr/local/bin\nR:../syswarden", "P:syswarden\nP:syswarden\nV:5.00.0-r0"} {
		if _, _, err := apkExecutionDatabase([]byte(safe + "\nP:extra\nV:1.0-r0\n" + record + "\n\n")); err == nil {
			t.Fatal("ambiguous or alias-owning native record accepted", record)
		}
	}
}

func TestAPKExecutionOverlayValidationRejectsPartialMutableConsumedAndForeignInput(t *testing.T) {
	for _, kind := range []string{"nil", "closed", "consumed", "mutable", "wrong-bytes", "partial"} {
		t.Run(kind, func(t *testing.T) {
			var file *os.File
			var err error
			switch kind {
			case "nil":
			case "closed", "consumed":
				file, err = openAPKExecutionOverlay()
				if err != nil {
					t.Fatal(err)
				}
				if kind == "closed" {
					err = file.Close()
				} else {
					_, err = file.Seek(1, io.SeekStart)
				}
				if err != nil {
					t.Fatal(err)
				}
			default:
				fd, createErr := unix.MemfdCreate("inert-apk-overlay-fixture", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
				if createErr != nil {
					t.Fatal(createErr)
				}
				file = os.NewFile(uintptr(fd), "inert-apk-overlay-fixture")
				data := apkExecutionOverlay
				if kind == "wrong-bytes" {
					data = strings.Repeat("x", len(data))
				}
				if kind == "partial" {
					data = "usr/local/bin/syswarden\n"
				}
				if _, err = file.WriteString(data); err != nil {
					t.Fatal(err)
				}
				if _, err = file.Seek(0, io.SeekStart); err != nil {
					t.Fatal(err)
				}
				if kind != "mutable" {
					if _, err = unix.FcntlInt(file.Fd(), unix.F_ADD_SEALS, unix.F_SEAL_WRITE|unix.F_SEAL_GROW|unix.F_SEAL_SHRINK|unix.F_SEAL_SEAL); err != nil {
						t.Fatal(err)
					}
				}
			}
			if file != nil {
				t.Cleanup(func() { _ = file.Close() })
			}
			if err := validateAPKExecutionOverlay(file); err == nil {
				t.Fatal("unsafe overlay accepted")
			}
		})
	}
}

func TestAPKExecutionProductionEntryCannotMintMissingLifecycleAuthority(t *testing.T) {
	f := newAPKExecutionTestFixture(t)
	if _, err := planAPKTransitionExecution(t.Context(), f.preparation.PlanSHA256, f.candidate.keys, f.candidate.attestInstalled, f.services, nil); err == nil {
		t.Fatal("missing native authority accepted")
	}
	if err := executeAPKTransition(t.Context(), f.preparation.PlanSHA256, f.review.PlanSHA256, f.candidate.keys, f.candidate.attestInstalled, f.services, nil); err == nil {
		t.Fatal("production adapter dispatched without authority")
	}
	assertAPKExecutionState(t, f, "native-started", false)
}

func TestAPKExecutionRevalidatesAllAuthorityAfterDurableNativeStartIntent(t *testing.T) {
	for _, kind := range []string{"lifecycle", "launcher", "target-dependency", "helper", "cancel"} {
		t.Run(kind, func(t *testing.T) {
			f := newAPKExecutionTestFixture(t)
			boundary := apkExecutionTestAuthority()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			write := func(directory *pinnedServiceDirectory, name string, data []byte) error {
				if err := writeAPKTransitionBytes(directory, name, data); err != nil {
					return err
				}
				if name == "native-started.json" {
					switch kind {
					case "lifecycle":
						boundary.before = func(context.Context) error { return errors.New("hook authority changed during publication") }
					case "launcher":
						boundary.launchers.revalidateErr = errors.New("launcher changed during publication")
					case "target-dependency":
						boundary.launchers.dependencyErr = errors.New("retained target now depends on product")
					case "helper":
						return os.WriteFile(filepath.Join(f.review.Directory, apkExecutionHelper), []byte("changed helper"), 0700) // #nosec G306 -- Private inert helper fixture models executable custody drift during native-start publication.
					case "cancel":
						cancel()
					}
				}
				return nil
			}
			err := f.execute(ctx, boundary, apkExecutionServices{write: write})
			var failure *APKTransitionExecutionError
			if !errors.As(err, &failure) || !failure.Unresolved || f.calls != 0 {
				t.Fatal("stale authority reached native dispatch", err, f.calls)
			}
			assertAPKExecutionState(t, f, "native-started", true)
			assertAPKExecutionState(t, f, "unresolved", true)
			assertAPKExecutionState(t, f, "completed", false)
			if err := f.execute(t.Context(), apkExecutionTestAuthority(), apkExecutionServices{}); err == nil || f.calls != 0 {
				t.Fatal("uncertain intent replayed", err)
			}
		})
	}
}

func TestAPKExecutionLateCancellationSupersedesCompletedRecord(t *testing.T) {
	f := newAPKExecutionTestFixture(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	write := func(directory *pinnedServiceDirectory, name string, data []byte) error {
		if err := writeAPKTransitionBytes(directory, name, data); err != nil {
			return err
		}
		if name == "completed.json" {
			cancel()
		}
		return nil
	}
	err := f.execute(ctx, apkExecutionTestAuthority(), apkExecutionServices{write: write})
	var failure *APKTransitionExecutionError
	if !errors.As(err, &failure) || !failure.Unresolved || !errors.Is(err, context.Canceled) {
		t.Fatal("late cancellation reported success", err)
	}
	assertAPKExecutionState(t, f, "completed", true)
	assertAPKExecutionState(t, f, "unresolved", true)
	if err := f.execute(t.Context(), apkExecutionTestAuthority(), apkExecutionServices{}); err == nil || f.calls != 1 {
		t.Fatal("completed plus unresolved was accepted or replayed", err)
	}
}

func TestAPKExecutionIndependentAttestationFollowsLifecycleObservation(t *testing.T) {
	for _, kind := range []string{"installed-runtime", "configuration", "helper"} {
		t.Run(kind, func(t *testing.T) {
			f := newAPKExecutionTestFixture(t)
			boundary := apkExecutionTestAuthority()
			boundary.after = func(context.Context) error {
				switch kind {
				case "installed-runtime":
					f.installed.cliSHA256 = strings.Repeat("b", 64)
				case "configuration":
					return rewriteAPKExecutionFixture(t, f, "etc/syswarden/config/modules/99-user.toml", func(string) string { return "late changed configuration\n" })
				case "helper":
					return os.WriteFile(filepath.Join(f.review.Directory, apkExecutionHelper), []byte("late changed helper"), 0700) // #nosec G306 -- Private inert helper fixture models executable custody drift after lifecycle observation.
				}
				return nil
			}
			if err := f.execute(t.Context(), boundary, apkExecutionServices{}); err == nil {
				t.Fatal("lifecycle observation hid changed evidence")
			}
			assertAPKExecutionState(t, f, "unresolved", true)
			assertAPKExecutionState(t, f, "completed", false)
		})
	}
}

func TestAPKExecutionNilContextCannotDispatchOrInvokeAuthority(t *testing.T) {
	f := newAPKExecutionTestFixture(t)
	boundary := apkExecutionTestAuthority()
	if _, err := planAPKTransitionExecution(nil, f.preparation.PlanSHA256, f.candidate.keys, f.candidate.attestInstalled, f.services, boundary); err == nil { //nolint:staticcheck // SA1012: Deliberate invalid input verifies rejection before authority or native dispatch.
		t.Fatal("nil planning context accepted")
	}
	if err := executeAPKTransitionWith(nil, f.preparation.PlanSHA256, f.review.PlanSHA256, f.candidate.keys, f.candidate.attestInstalled, f.services, boundary, apkExecutionServices{run: f.run}); err == nil { //nolint:staticcheck // SA1012: Deliberate invalid input verifies rejection before authority or native dispatch.
		t.Fatal("nil execution context accepted")
	}
	if f.calls != 0 || len(boundary.calls) != 0 {
		t.Fatal("nil context reached manager or authority")
	}
	assertAPKExecutionState(t, f, "native-started", false)
}

func TestAPKExecutionNativeDispatchUsesCompiledDeadlineAndCannotHideCancellation(t *testing.T) {
	for _, kind := range []string{"unbounded-parent", "shorter-parent", "cancelled-before", "cancelled-during", "dispatch-error"} {
		t.Run(kind, func(t *testing.T) {
			parent, cancel := context.WithCancel(context.Background())
			defer cancel()
			if kind == "shorter-parent" {
				var shorterCancel context.CancelFunc
				parent, shorterCancel = context.WithTimeout(parent, time.Minute)
				defer shorterCancel()
			}
			if kind == "cancelled-before" {
				cancel()
			}
			calls := 0
			before := time.Now()
			sentinel := errors.New("inert process dispatch error")
			err := dispatchAPKExecution(parent, &exec.Cmd{}, func(ctx context.Context, cmd *exec.Cmd) error {
				calls++
				deadline, ok := ctx.Deadline()
				if !ok || deadline.After(time.Now().Add(packageInstallationTimeout)) || deadline.Before(before) {
					t.Fatal("missing compiled native bound")
				}
				if inherited, ok := parent.Deadline(); ok {
					if !deadline.Equal(inherited) {
						t.Fatal("shorter caller deadline lost")
					}
				} else if time.Until(deadline) < packageInstallationTimeout-time.Second {
					t.Fatal("compiled installation maximum changed")
				}
				if kind == "cancelled-during" {
					cancel()
					return nil
				}
				if kind == "dispatch-error" {
					return sentinel
				}
				return nil
			})
			if kind == "cancelled-before" || kind == "cancelled-during" {
				if !errors.Is(err, context.Canceled) {
					t.Fatal("cancellation hidden", err)
				}
			} else if kind == "dispatch-error" {
				if !errors.Is(err, sentinel) {
					t.Fatal("native failure hidden", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			if kind == "cancelled-before" && calls != 0 || kind != "cancelled-before" && calls != 1 {
				t.Fatal("unexpected native dispatch count", calls)
			}
		})
	}
}

func apkExecutionOriginalTargetFixture(t *testing.T, services *apkTransitionServices) {
	t.Helper()
	for _, name := range []string{"opt", "opt/syswarden", "opt/syswarden/bin"} {
		if err := os.Mkdir(filepath.Join(services.hostRoot, name), 0755); err != nil { // #nosec G301 -- Fixed opt ancestors beneath t.TempDir deliberately model native package directory modes.
			t.Fatal(err)
		}
	}
	for index, name := range []string{"syswarden-cli", "syswarden-tui"} {
		path := filepath.Join(services.hostRoot, "opt/syswarden/bin", name)
		if err := os.WriteFile(path, []byte("original inert "+name+" bytes\n"), 0750); err != nil { // #nosec G306 -- Fixed CLI/TUI paths beneath t.TempDir model executable metadata; these inert bytes are never executed.
			t.Fatal(err)
		}
		alias := filepath.Join(services.hostRoot, apkLauncherPaths[index])
		if err := os.Remove(alias); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("/opt/syswarden/bin/"+name, alias); err != nil {
			t.Fatal(err)
		}
	}
}

func TestAPKExecutionTargetProposalIsEmbeddedBeforeApprovalAndRejectsDrift(t *testing.T) {
	for _, kind := range []string{"bytes", "metadata", "same-bytes-replacement"} {
		t.Run(kind, func(t *testing.T) {
			f := newAPKExecutionTestFixture(t, apkExecutionOriginalTargetFixture)
			planPath := filepath.Join(f.review.Directory, "execution-plan.json")
			raw, err := os.ReadFile(planPath) // #nosec G304 -- Reads only execution-plan.json created by this test in its private temporary custody directory.
			if err != nil {
				t.Fatal(err)
			}
			var plan apkExecutionPlan
			if err := decodeAPKTransitionJSON(raw, &plan); err != nil {
				t.Fatal(err)
			}
			if plan.LauncherTargets == nil || !validSHA256(plan.LauncherTargetsSHA256) {
				t.Fatal("original target proposal omitted from reviewed execution plan")
			}
			proposal, err := apkExecutionJSON(plan.LauncherTargets)
			if err != nil || apkTransitionDigest(proposal) != plan.LauncherTargetsSHA256 || apkTransitionDigest(raw) != f.review.PlanSHA256 {
				t.Fatal("target proposal digest is not bound to exact execution review", err)
			}
			target := filepath.Join(f.services.hostRoot, "opt/syswarden/bin/syswarden-tui")
			switch kind {
			case "bytes":
				err = os.WriteFile(target, []byte("unreviewed changed target bytes\n"), 0750) // #nosec G306 -- Fixed temporary TUI fixture preserves executable mode to isolate the changed-byte refusal.
			case "metadata":
				err = os.Chmod(target, 0700) // #nosec G302 -- Deliberate executable-mode drift on the fixed temporary TUI fixture verifies metadata refusal.
			case "same-bytes-replacement":
				var data []byte
				data, err = os.ReadFile(target) // #nosec G304 -- Reads only opt/syswarden/bin/syswarden-tui created beneath this test's t.TempDir.
				if err == nil {
					err = os.Rename(target, target+".original")
				}
				if err == nil {
					err = os.WriteFile(target, data, 0750) // #nosec G703 G306 -- Fixed TUI path beneath t.TempDir; inert fixture bytes and executable mode isolate inode-replacement refusal.
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := f.execute(t.Context(), apkExecutionTestAuthority(), apkExecutionServices{}); err == nil || f.calls != 0 {
				t.Fatal("target drift adopted under existing execution approval", err, f.calls)
			}
			preserved, err := os.ReadFile(planPath) // #nosec G304 -- Rereads only this test's private execution-plan.json to prove rejected target drift cannot rewrite it.
			if err != nil || !bytes.Equal(raw, preserved) {
				t.Fatal("original target proposal rewritten", err)
			}
			assertAPKExecutionState(t, f, "execution-approval", false)
			assertAPKExecutionState(t, f, "native-started", false)
		})
	}
}

func TestAPKExecutionComposesRealTargetCustodyAndRetainsRemovalDebt(t *testing.T) {
	f := newAPKExecutionTestFixture(t, func(t *testing.T, services *apkTransitionServices) {
		apkExecutionOriginalTargetFixture(t, services)
		services.root = filepath.Join(services.hostRoot, strings.TrimPrefix(apkTransitionRoot, "/"))
		if err := os.MkdirAll(filepath.Dir(services.root), 0700); err != nil {
			t.Fatal(err)
		}
	})
	inventory, _, err := readAPKTransitionInventory(t.Context(), f.candidate.file)
	if err != nil {
		t.Fatal(err)
	}
	boundary := apkExecutionTestAuthority()
	boundary.factory = func(ctx context.Context, path string, binding apkLauncherCustodyBinding, original []apkTransitionHostEntry) (apkExecutionLaunchers, error) {
		return prepareAPKLauncherCustodyWithTargetsAt(ctx, f.services.hostRoot, path, binding, original, inventory, boundary.EffectPlanSHA256())
	}
	runner := func(ctx context.Context, prepared *verifiedPreparedAPKTransition, overlay *os.File, args []string, out io.Writer) error {
		if err := f.run(ctx, prepared, overlay, args, out); err != nil {
			return err
		}
		for _, target := range apkLauncherTargets {
			path := filepath.Join(f.services.hostRoot, strings.TrimPrefix(target, "/"))
			content := []byte("public inert fixture: " + strings.TrimPrefix(target, "/") + "\n")
			if err := os.WriteFile(path+".candidate", content, 0750); err != nil { // #nosec G306 -- Compiled CLI/TUI roles beneath t.TempDir model executable payload replacement without executing fixture bytes.
				return err
			}
			if err := os.Rename(path+".candidate", path); err != nil {
				return err
			}
		}
		return nil
	}
	if err := f.execute(t.Context(), boundary, apkExecutionServices{run: runner}); err != nil {
		t.Fatal("real target custody composition", err)
	}
	raw, err := os.ReadFile(filepath.Join(f.review.Directory, "completed.json"))
	if err != nil {
		t.Fatal(err)
	}
	var completed apkExecutionEvent
	if err := decodeAPKTransitionJSON(raw, &completed); err != nil {
		t.Fatal(err)
	}
	if completed.ProductAccepted || !validSHA256(completed.LauncherReceiptSHA256) {
		t.Fatal("component receipt missing or promoted to acceptance")
	}
	inspected, err := inspectAPKLaunchersForRemovalAt(t.Context(), f.services.hostRoot, f.review.PlanSHA256, completed.LauncherReceiptSHA256)
	if err != nil {
		t.Fatal("exact committed custody cannot be independently reopened", err)
	}
	t.Cleanup(func() {
		if err := inspected.Close(); err != nil {
			t.Error(err)
		}
	})
	if err := inspected.Revalidate(); err != nil {
		t.Fatal(err)
	}
	if inspected.targetAuthority != nil || inspected.RefuseProductTargetDependencies() == nil {
		t.Fatal("upgrade target authority escaped into removal")
	}
	for _, alias := range inspected.record.Aliases {
		if alias.Disposition != "retained-administrator" || alias.Original != alias.Committed || alias.CreationSHA256 != "" {
			t.Fatal("engine adopted or changed an inherited administrator alias")
		}
	}
	assertAPKExecutionState(t, f, "unresolved", false)
}

func TestAPKExecutionRefusesPreparedRecordsMissingNewProofOrWrongNativeChecksum(t *testing.T) {
	for _, kind := range []string{"capability", "effect", "native-checksum", "wrong-native-checksum"} {
		t.Run(kind, func(t *testing.T) {
			f := newAPKExecutionTestFixture(t)
			raw, err := os.ReadFile(filepath.Join(f.preparation.Directory, "plan.json"))
			if err != nil {
				t.Fatal(err)
			}
			var plan apkTransitionPlan
			if err := decodeAPKTransitionJSON(raw, &plan); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "capability":
				plan.CandidateCapabilitySHA256 = ""
			case "effect":
				plan.EffectPlanSHA256 = ""
			case "native-checksum":
				plan.CandidateAPKChecksum = ""
			case "wrong-native-checksum":
				plan.CandidateAPKChecksum = apkRetentionFixtureChecksum
			}
			changed, err := apkExecutionJSON(plan)
			if err != nil {
				t.Fatal(err)
			}
			digest := apkTransitionDigest(changed)
			retained := filepath.Join(f.services.root, digest)
			if err := os.Rename(f.preparation.Directory, retained); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(retained, "plan.json"), changed, 0600); err != nil {
				t.Fatal(err)
			}
			record := []byte("{\"schema\":\"" + apkTransitionSchema + "\",\"state\":\"prepared-only\",\"plan_sha256\":\"" + digest + "\"}\n")
			if err := os.WriteFile(filepath.Join(retained, "prepared.json"), record, 0600); err != nil {
				t.Fatal(err)
			}
			if err := approvePreparedAPKTransition(t.Context(), digest, f.candidate.keys, f.candidate.attestInstalled, f.services); err == nil || errors.Is(err, errAPKTransitionExecutionUnavailable) {
				t.Fatal("unproven prepared record was reviewed", err)
			}
			if _, err := os.Lstat(filepath.Join(retained, "approval.json")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("missing or mismatched evidence gained review", err)
			}
			preserved, err := os.ReadFile(filepath.Join(retained, "plan.json")) // #nosec G304 -- Reads the digest-named plan created and renamed solely within this test's temporary custody root.
			if err != nil || !bytes.Equal(preserved, changed) {
				t.Fatal("rejected original evidence was rewritten", err)
			}
		})
	}
}
