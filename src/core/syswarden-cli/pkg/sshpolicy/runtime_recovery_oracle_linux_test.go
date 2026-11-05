//go:build linux

package sshpolicy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/user"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// Exercise actual retained-inode recovery and a separate real reload using
// disposable daemons, generated identities and loopback direct/bastion access.
// The fixture lease is not the production systemd binder or enrolled authority.
func TestOpenSSHRuntimeRecoveryOracle(t *testing.T) {
	if os.Getenv("SYSWARDEN_SSH_RUNTIME_ORACLE_TEST") != "1" {
		t.Skip("set SYSWARDEN_SSH_RUNTIME_ORACLE_TEST=1 for disposable authenticated SSH recovery")
	}
	for _, dispatch := range []bool{false, true} {
		t.Run(fmt.Sprintf("reload-dispatched-%v", dispatch), func(t *testing.T) { testOpenSSHRecoveryAssessment(t, dispatch) })
	}
}

func testOpenSSHRecoveryAssessment(t *testing.T, dispatch bool) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Fatal("the runtime recovery oracle requires an ordinary local test account")
	}
	account, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	f, plan, deps, journal := runtimeRecoveryFixture(t, true, false)
	runtime := newSSHRuntimeFixture(t, account)
	target := runtime.startDaemon("target", "Include "+strconv.Quote(f.path(DropInPath))+"\n")
	jump := runtime.startDaemon("bastion", "AllowTcpForwarding local\nPermitOpen "+target.address+"\n")
	runtime.writeClient(target, jump)
	backend := runtime.backend()
	runtime.expectForward(target, backend, false)
	runtime.expectAccess("target", true)
	runtime.expectAccess("via-bastion", true)
	bastionBefore := runtime.read("bastion.conf")
	requests := 0
	bind := func(ctx context.Context, guard func() error, _ *sshRecoveryPolicyAnchor) (sshActivationLease, error) {
		if err := errors.Join(ctx.Err(), guard()); err != nil {
			return nil, err
		}
		return &sshActivationTarget{
			ctx: ctx, target: strings.Repeat("d", 64),
			verify: func(context.Context) error { return unix.PidfdSendSignal(target.pidfd, 0, nil, 0) },
			send: func() error {
				if _, err := os.Lstat(f.path(DropInPath)); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("restoring request preceded drop-in retirement", err)
				}
				if _, err := journal.readRecord(sshRuntimeRecoveryReloadName); err != nil {
					t.Fatal("restoring request preceded separate durable intent", err)
				}
				// Real sshd still enforces the former policy after both inverse
				// file transitions. Only the separately requested reload changes it.
				runtime.expectForward(target, backend, false)
				requests++
				if !dispatch {
					return unix.EIO
				}
				runtime.reload(target)
				return nil
			},
			after: func(ctx context.Context, guard func() error) error {
				runtime.expectForward(target, backend, true)
				runtime.expectFreshTransport(target, jump)
				runtime.expectAccess("target", true)
				runtime.expectAccess("via-bastion", true)
				return errors.Join(ctx.Err(), guard())
			},
			closeFn: func() error { return nil },
		}, nil
	}
	approved := runtimeRecoveryPlan(t, journal, plan, deps, bind)
	result, err := recoverSSHActivatedConfiguration(t.Context(), journal, plan.summary.PlanSHA256, deps.parserDigest, approved,
		deps.run, deps.checkParser, bind, sshPublicationDefaults())
	if (err != nil) != !dispatch || !result.ConfigurationRestored || result.RequestReturned != dispatch || !result.RecoveryRequired || requests != 1 {
		t.Fatal("runtime restoration boundary failed", result, requests, err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	journal = fixtureJournal(t, f)
	// The fixture parser/process observer does not qualify the live systemd
	// binder. Real traffic independently proves why matching files/endpoints
	// and even fresh authentication cannot establish consumed forwarding policy.
	assessment, err := assessSSHRuntimeRecovery(t.Context(), journal, plan.summary.PlanSHA256, approved, deps.parserDigest,
		ownedEndpointParser(deps.run), deps.checkParser, ownedEndpointListener(deps.parserDigest))
	if err != nil || !assessment.ConfigurationRestored || !assessment.RecoveryRequired || assessment.RuntimeActivated || assessment.AccessVerified {
		t.Fatal("assessment lost uncertainty after the recorded reload intent", assessment, err)
	}
	runtime.expectForward(target, backend, dispatch)
	runtime.expectFreshTransport(target, jump)
	if !bytes.Equal(bastionBefore, runtime.read("bastion.conf")) {
		t.Fatal("target restoration changed the independent bastion")
	}
}
