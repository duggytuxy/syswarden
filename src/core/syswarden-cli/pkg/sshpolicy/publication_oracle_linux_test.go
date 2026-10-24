//go:build linux

package sshpolicy

import (
	"bytes"
	"context"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syswarden-cli/pkg/sshselection"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestOpenSSHPublicationOracle(t *testing.T) {
	testOpenSSHPublicationOracle(t, "publication")
}

func TestOpenSSHTransactionOracle(t *testing.T) {
	testOpenSSHPublicationOracle(t, "transaction")
}

func TestOpenSSHPreparationAbortOracle(t *testing.T) {
	testOpenSSHPublicationOracle(t, "abort")
}

func TestOpenSSHAbortedRetirementOracle(t *testing.T) {
	testOpenSSHPublicationOracle(t, "retire")
}

func TestOpenSSHRestoredRetirementOracle(t *testing.T) {
	testOpenSSHPublicationOracle(t, "retire-restored")
}

func TestOpenSSHOwnedPublicationOracle(t *testing.T) {
	testOpenSSHPublicationOracle(t, "owned")
}

func TestOpenSSHOwnedEndpointOracle(t *testing.T) {
	testOpenSSHPublicationOracle(t, "owned-endpoints")
}

func TestOpenSSHActivationAssessmentOracle(t *testing.T) {
	testOpenSSHPublicationOracle(t, "activation-assessment")
}

func TestOpenSSHRuntimeRecoveryParserOracle(t *testing.T) {
	testOpenSSHPublicationOracle(t, "runtime-recovery")
}

func testOpenSSHPublicationOracle(t *testing.T, operation string) {
	t.Helper()
	transaction := operation == "transaction" || operation == "retire-restored" || operation == "owned" || operation == "owned-endpoints" || operation == "activation-assessment" || operation == "runtime-recovery"
	if os.Getenv("SYSWARDEN_SSH_ORACLE_TEST") != "1" {
		t.Skip("set SYSWARDEN_SSH_ORACLE_TEST=1 for the installed OpenSSH parser oracle")
	}
	root, err := os.Open("/")
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	daemon, err := openSSHD(root, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer daemon.file.Close()
	directory := t.TempDir()
	scratch, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer scratch.Close()
	key := filepath.Join(directory, "fixture-key")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if output, err := exec.CommandContext(ctx, "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", key).CombinedOutput(); err != nil { // #nosec G204 -- Fixed fixture-only host key generation; no production path or secret.
		t.Fatalf("fixture key: %v %s", err, output)
	}
	for _, profile := range []string{"forwarding", "cis", "legacy-cis"} {
		t.Run(profile, func(t *testing.T) {
			// Each independent scenario owns its deadline. Earlier profiles
			// must not consume the next profile's parser verification budget.
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()
			content := includeDropIns + "HostKey " + key + "\nPort 2222\nUsePAM no\nPasswordAuthentication no\nAuthenticationMethods publickey\nInclude /etc/ssh/access.conf\n"
			var listenerFD int
			var listenerInode uint64
			if operation == "owned-endpoints" || operation == "activation-assessment" {
				listenerFD, listenerInode = sshTestTCPListener(t, unix.AF_INET)
				socket, listening, err := inspectSSHSocket(listenerFD, listenerInode)
				if err != nil || !listening {
					t.Fatal(err)
				}
				content += "AddressFamily inet\nListenAddress " + netip.AddrPortFrom(socket.Address, socket.Port).String() + "\n"
			}
			if profile == "legacy-cis" {
				content = "AllowTcpForwarding no\n" + strings.Join(legacyCISBlock, "\n") + "\n" + content
			}
			f := planFixture(t, content)
			f.write("/etc/ssh/access.conf", "Match User administrator\n MaxSessions 12\n PermitTTY no\nMatch all\n")
			declaration, err := parseIntent([]byte(validIntentJSON))
			if err != nil {
				t.Fatal(err)
			}
			declaration.Profile = profile
			if profile == "legacy-cis" {
				declaration.Profile = "cis"
				declaration.Legacy = &legacyIntent{Attribution: "operator-reviewed", MainSHA256: digestBytes([]byte(content))}
				for line := 1; line <= 7; line++ {
					declaration.Legacy.Edits = append(declaration.Legacy.Edits, legacyEdit{line, "remove"})
				}
			}
			for _, route := range []string{"proxyjump", "ansible"} {
				access := declaration.Contexts[0]
				access.ID, access.Route = route, route
				declaration.Contexts = append(declaration.Contexts, access)
			}
			f.intent(declaration)
			f.write(sshselection.Path, "[ssh]\nhardening = \""+declaration.Profile+"\"\n")
			if err := os.MkdirAll(f.path(sshStateParent), 0700); err != nil {
				t.Fatal(err)
			}
			plan := f.plan()
			before := fixtureMainImage(t, f)
			// Read current main bytes on every live invocation. Only fixture
			// Include paths are translated; their files are the actual published
			// inodes. The same pinned installed parser handles sealed candidates.
			livePath := filepath.Join(directory, "live-"+profile)
			run := func(ctx context.Context, image *parserImage, mode, access string) ([]byte, error) {
				if image != nil {
					return daemon.run(ctx, image, mode, access)
				}
				live, err := os.ReadFile(f.path(MainPath))
				if err != nil {
					return nil, err
				}
				translated := strings.ReplaceAll(string(live), "/etc/ssh/", f.path("/etc/ssh/")+"/")
				if err := scratch.WriteFile("live-"+profile, []byte(translated), 0600); err != nil {
					return nil, err
				}
				flag := "-T"
				if mode == "syntax" {
					flag = "-t"
				}
				args := []string{flag, "-f", livePath}
				if access != "" {
					args = append(args, "-C", access)
				}
				process := exec.CommandContext(ctx, "/proc/self/fd/3", args...) // #nosec G204 -- Pinned installed parser, fixed syntax/effective modes, temporary fixture configuration; never a listener.
				process.ExtraFiles = []*os.File{daemon.file}
				process.Env = []string{"LC_ALL=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
				return process.CombinedOutput()
			}
			var journal *sshJournal
			var record sshPreparation
			if transaction {
				deps := transactionFixtureDependencies(f)
				deps.parserDigest, deps.run = daemon.digest, run
				deps.checkParser = func() error { return daemon.recheck(root, 0) }
				result, err := executeSSHTransaction(ctx, f.root, os.Geteuid(), plan.summary.PlanSHA256, deps)
				if err != nil || !result.Published || result.RecoveryRequired || result.Verification.RuntimeActivated {
					t.Fatal("shared transaction failed installed parser verification", result, err)
				}
				journal = fixtureJournal(t, f)
				record, err = journal.read()
				if err != nil {
					t.Fatal(err)
				}
			} else {
				if err := provisionSSHState(f.root, os.Geteuid(), sshProvisionDefaults()); err != nil {
					t.Fatal(err)
				}
				main, err := newSSHAnonymousStage(fixtureDirectory(t, f, "/etc/ssh"), plan.main,
					before.state.mode&0777, before.state.gid, before.attrs, os.Geteuid())
				if err != nil {
					t.Fatal(err)
				}
				defer main.Close()
				drop, err := newSSHAnonymousStage(fixtureDirectory(t, f, "/etc/ssh/sshd_config.d"), plan.candidate.Bytes(),
					0600, before.state.gid, before.attrs, os.Geteuid())
				if err != nil {
					t.Fatal(err)
				}
				defer drop.Close()
				record, err = prepareSSHRecord(plan, plan.summary.PlanSHA256, daemon.digest, before, main, drop, os.Geteuid())
				if err != nil {
					t.Fatal(err)
				}
				journal = fixtureJournal(t, f)
				if err := journal.write(record); err != nil {
					t.Fatal(err)
				}
				if operation == "abort" || operation == "retire" {
					if err := main.Close(); err != nil {
						t.Fatal(err)
					}
					if err := drop.Close(); err != nil {
						t.Fatal(err)
					}
					if err := journal.Close(); err != nil {
						t.Fatal(err)
					}
					for attempt := 0; attempt < 2; attempt++ {
						result, err := recoverSSHTransaction(ctx, f.root, os.Geteuid(), plan.summary.PlanSHA256,
							daemon.digest, run, func() error { return daemon.recheck(root, 0) }, sshPublicationDefaults())
						if err != nil || !result.Aborted || result.Restored || result.Published || result.RecoveryRequired ||
							result.Verification.RuntimeActivated {
							t.Fatal("preparation abort failed installed parser verification", result, err)
						}
					}
					after := fixtureMainImage(t, f)
					if before.state != after.state || !bytes.Equal(before.data, after.data) {
						t.Fatal("preparation abort changed original SSH configuration")
					}
					if operation == "retire" {
						owner := fixtureOwner(t, f)
						check := func() error { return daemon.recheck(root, 0) }
						for range 2 {
							if err := retireSSHAbortedPreparation(ctx, f.root, os.Geteuid(), owner.Instance,
								plan.summary.PlanSHA256, daemon.digest, run, check, sshProvisionDefaults()); err != nil {
								t.Fatal(err)
							}
						}
						deps := transactionFixtureDependencies(f)
						deps.parserDigest, deps.run, deps.checkParser = daemon.digest, run, check
						result, err := executeSSHTransaction(ctx, f.root, os.Geteuid(), plan.summary.PlanSHA256, deps)
						if err != nil || !result.Published || result.RecoveryRequired || result.Verification.RuntimeActivated {
							t.Fatal("cannot publish a new verified transaction after retirement", result, err)
						}
						result, err = recoverSSHTransaction(ctx, f.root, os.Geteuid(), plan.summary.PlanSHA256,
							daemon.digest, run, check, sshPublicationDefaults())
						if err != nil || !result.Restored || result.RecoveryRequired {
							t.Fatal("cannot restore the new transaction", result, err)
						}
					}
					return
				}
				if err := publishSSHConfiguration(ctx, journal, plan, main, drop, run,
					func() error { return daemon.recheck(root, 0) }, sshPublicationDefaults()); err != nil {
					t.Fatal(err)
				}
			}
			if profile == "legacy-cis" && bytes.Equal(before.data, fixtureMainImage(t, f).data) {
				t.Fatal("legacy directives were not migrated")
			}
			position, err := inspectSSHPublication(journal)
			if err != nil || position != (sshPublicationPosition{3, "complete"}) {
				t.Fatal("publication evidence cannot be verified", position, err)
			}
			if err := journal.Close(); err != nil {
				t.Fatal(err)
			}
			journal = fixtureJournal(t, f)
			if operation == "runtime-recovery" {
				check := func() error { return daemon.recheck(root, 0) }
				calls, closed := 0, 0
				activation, err := attemptSSHActivation(ctx, journal, plan.summary.PlanSHA256, daemon.digest,
					run, check, activationTestBinder(t, journal, &calls, &closed))
				if err != nil || !activation.RecoveryRequired || calls != 1 {
					t.Fatal("cannot establish fixture activation", activation, err)
				}
				if err := journal.Close(); err != nil {
					t.Fatal(err)
				}
				journal = fixtureJournal(t, f)
				deps := transactionFixtureDependencies(f)
				deps.parserDigest, deps.run, deps.checkParser = daemon.digest, run, check
				bind := runtimeRecoveryBinder(t, journal, &calls, &closed)
				approved := runtimeRecoveryPlan(t, journal, plan, deps, bind)
				result, err := recoverSSHActivatedConfiguration(ctx, journal, plan.summary.PlanSHA256, daemon.digest, approved,
					run, check, bind, sshPublicationDefaults())
				if err != nil || !result.ConfigurationRestored || !result.RequestReturned || !result.RecoveryRequired || calls != 2 {
					t.Fatal("installed parser recovery failed", result, err)
				}
				after := fixtureMainImage(t, f)
				if after.state.ino != before.state.ino || !bytes.Equal(after.data, before.data) || !reflect.DeepEqual(after.attrs, before.attrs) {
					t.Fatal("runtime recovery lost original main inode or metadata")
				}
				return
			}
			if operation == "activation-assessment" {
				check := func() error { return daemon.recheck(root, 0) }
				calls, closed := 0, 0
				result, err := attemptSSHActivation(ctx, journal, plan.summary.PlanSHA256, daemon.digest,
					run, check, activationTestBinder(t, journal, &calls, &closed))
				if err != nil || !result.RecoveryRequired || calls != 1 || closed != 1 {
					t.Fatal(result, err)
				}
				if err := journal.Close(); err != nil {
					t.Fatal(err)
				}
				journal = fixtureJournal(t, f)
				for range 2 {
					assessment, err := assessSSHActivation(ctx, journal, plan.summary.PlanSHA256, daemon.digest,
						run, check, ownedEndpointOracleObserver(t, daemon, listenerFD, listenerInode))
					if err != nil || !assessment.RecoveryRequired || !assessment.IntentObserved ||
						!assessment.Endpoints.ConfiguredEndpointsMatched || assessment.Publication.ContextsVerified != 3 ||
						assessment.Publication.RuntimeActivated || assessment.Publication.AccessVerified {
						t.Fatal("installed parser activation assessment failed", assessment, err)
					}
				}
				if err := rollbackSSHConfiguration(ctx, journal, plan.summary.PlanSHA256, run, check, sshPublicationDefaults()); err == nil {
					t.Fatal("assessment cleared the runtime recovery fence")
				}
				return
			}
			if operation == "owned" {
				for range 2 {
					result, err := verifySSHOwnedPublication(ctx, journal, plan.summary.PlanSHA256, daemon.digest,
						run, func() error { return daemon.recheck(root, 0) })
					if err != nil || !result.OwnershipVerified || !result.PublicationObserved || !result.ParserVerified ||
						result.RuntimeActivated || result.AccessVerified || result.ContextsVerified != 3 {
						t.Fatal("installed parser could not revalidate the owned publication", result, err)
					}
				}
			}
			if operation == "owned-endpoints" {
				checkOwnedEndpointOracle(t, ctx, journal, plan, daemon, run,
					func() error { return daemon.recheck(root, 0) }, listenerFD, listenerInode)
			}
			if transaction {
				if err := journal.Close(); err != nil {
					t.Fatal(err)
				}
				result, err := recoverSSHTransaction(ctx, f.root, os.Geteuid(), plan.summary.PlanSHA256,
					daemon.digest, run, func() error { return daemon.recheck(root, 0) }, sshPublicationDefaults())
				if err != nil || !result.Restored || result.RecoveryRequired {
					t.Fatal("shared transaction rollback failed installed parser verification", result, err)
				}
				journal = fixtureJournal(t, f)
			} else {
				if err := rollbackSSHConfiguration(ctx, journal, plan.summary.PlanSHA256, run,
					func() error { return daemon.recheck(root, 0) }, sshPublicationDefaults()); err != nil {
					t.Fatal(err)
				}
			}
			assertSSHRestored(t, f, record, journal)
			if operation == "retire-restored" {
				if err := journal.Close(); err != nil {
					t.Fatal(err)
				}
				owner := fixtureOwner(t, f)
				check := func() error { return daemon.recheck(root, 0) }
				for range 2 {
					if err := retireSSHRestoredTransaction(ctx, f.root, os.Geteuid(), owner.Instance,
						plan.summary.PlanSHA256, daemon.digest, run, check, sshProvisionDefaults()); err != nil {
						t.Fatal("cannot retire restored transaction with installed parser", err)
					}
				}
				next := f.plan()
				deps := transactionFixtureDependencies(f)
				deps.parserDigest, deps.run, deps.checkParser = daemon.digest, run, check
				result, err := executeSSHTransaction(ctx, f.root, os.Geteuid(), next.summary.PlanSHA256, deps)
				if err != nil || !result.Published || result.RecoveryRequired || result.Verification.RuntimeActivated {
					t.Fatal("cannot publish after verified restoration retirement", result, err)
				}
				result, err = recoverSSHTransaction(ctx, f.root, os.Geteuid(), next.summary.PlanSHA256,
					daemon.digest, run, check, sshPublicationDefaults())
				if err != nil || !result.Restored || result.RecoveryRequired {
					t.Fatal("cannot restore independently approved retry", result, err)
				}
			}
		})
	}
}
