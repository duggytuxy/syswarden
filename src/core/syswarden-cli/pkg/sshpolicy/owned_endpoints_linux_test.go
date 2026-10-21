//go:build linux

package sshpolicy

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"reflect"
	"strings"
	"syswarden-cli/pkg/sshselection"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func ownedEndpointParser(run sshParserRun) sshParserRun {
	return func(ctx context.Context, image *parserImage, mode, access string) ([]byte, error) {
		output, err := run(ctx, image, mode, access)
		if mode == "effective" && err == nil {
			output = append(output, []byte("addressfamily inet\nlistenaddress 192.0.2.1:2222\n")...)
		}
		return output, err
	}
}

func ownedEndpointListener(digest string) sshEndpointObserver {
	return func(ctx context.Context, expected []netip.AddrPort, guard func() error) (ListenerSummary, error) {
		if err := errors.Join(ctx.Err(), guard(), matchSSHEndpoints(expected, []sshListenerSocket{sshListenerFixture(3, 33)}, 7)); err != nil {
			return ListenerSummary{}, err
		}
		return ListenerSummary{TCPListenersObserved: true, ListenerCount: 1,
			SocketsSHA256: strings.Repeat("b", 64), Process: ProcessSummary{
				ProcessObserved: true, ExecutableVerified: true, ExecutableSHA256: digest}}, nil
	}
}

func TestSSHOwnedEndpointsRetainOneLockedObservation(t *testing.T) {
	f, plan, deps, journal := ownedPublicationFixture(t)
	prepared, err := journal.read()
	if err != nil {
		t.Fatal(err)
	}
	before, err := stableSSHRollback(journal, prepared.Transaction)
	if err != nil {
		t.Fatal(err)
	}
	records, err := observeSSHOwnedRecords(journal)
	if err != nil {
		t.Fatal(err)
	}
	journal.syncDirectory = func(*os.File) error {
		t.Fatal("observation attempted durability repair")
		return unix.EIO
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	deadline, _ := ctx.Deadline()
	observer := ownedEndpointListener(deps.parserDigest)
	calls := 0
	observe := func(ctx context.Context, expected []netip.AddrPort, guard func() error) (ListenerSummary, error) {
		calls++
		if end, exists := ctx.Deadline(); !exists || end.After(deadline) {
			t.Fatal("dependent observation escaped the original deadline")
		}
		competing, err := openSSHJournal(f.root, os.Geteuid())
		if err == nil {
			_ = competing.Close()
			t.Fatal("journal lock was released before endpoint observation")
		}
		return observer(ctx, expected, guard)
	}
	for range 2 {
		got, err := observeSSHOwnedEndpoints(ctx, journal, plan.summary.PlanSHA256, deps.parserDigest,
			ownedEndpointParser(deps.run), deps.checkParser, observe)
		if err != nil || got.Schema != 1 || got.Publication.PlanSHA256 != plan.summary.PlanSHA256 ||
			got.Publication.Transaction != prepared.Transaction || !got.Publication.OwnershipVerified ||
			!got.Publication.PublicationObserved || !got.Publication.ParserVerified || !got.Endpoints.ConfiguredEndpointsMatched ||
			got.Endpoints.ParserSHA256 != got.Publication.ParserSHA256 || got.Publication.RuntimeActivated ||
			got.Publication.AccessVerified || got.Endpoints.RuntimeActivated || got.Endpoints.ConfigurationVerified || got.Endpoints.AccessVerified {
			t.Fatal("lost ownership binding or exceeded the evidence boundary", got, err)
		}
		wire, err := json.Marshal(got)
		if err != nil || strings.Contains(string(wire), "192.0.2.1") || strings.Contains(string(wire), "allowtcpforwarding") {
			t.Fatal("summary disclosed configuration", err)
		}
		after, stateErr := stableSSHRollback(journal, prepared.Transaction)
		afterRecords, recordsErr := observeSSHOwnedRecords(journal)
		if errors.Join(stateErr, recordsErr) != nil || !reflect.DeepEqual(before, after) || !reflect.DeepEqual(records, afterRecords) {
			t.Fatal("observation modified configuration or history", stateErr, recordsErr)
		}
	}
	if calls != 2 {
		t.Fatal("observation reused a saved listener result")
	}
}

func TestSSHOwnedEndpointsRequireAuthorizationBeforeRuntime(t *testing.T) {
	for _, scenario := range []string{"missing-approval", "other-approval", "other-parser", "disabled-selection", "changed-policy", "unknown-history", "parser-failure", "nil-observer", "nil-context", "cancelled"} {
		t.Run(scenario, func(t *testing.T) {
			f, plan, deps, journal := ownedPublicationFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var input context.Context = ctx
			approved := plan.summary.PlanSHA256
			calls := 0
			observer := func(context.Context, []netip.AddrPort, func() error) (ListenerSummary, error) {
				calls++
				return ListenerSummary{}, nil
			}
			switch scenario {
			case "missing-approval":
				approved = ""
			case "other-approval":
				approved = strings.Repeat("b", 64)
			case "other-parser":
				deps.parserDigest = strings.Repeat("c", 64)
			case "disabled-selection":
				f.write(sshselection.Path, "[ssh]\nhardening = \"disabled\"\n")
			case "changed-policy":
				f.write(DropInPath, "AllowTcpForwarding yes\n")
			case "unknown-history":
				f.write(sshJournalDirectory+"/extra.json", "{}")
			case "parser-failure":
				deps.run = func(context.Context, *parserImage, string, string) ([]byte, error) { return nil, unix.EIO }
			case "nil-observer":
				observer = nil
			case "nil-context":
				input = nil
			case "cancelled":
				cancel()
			}
			got, err := observeSSHOwnedEndpoints(input, journal, approved, deps.parserDigest,
				ownedEndpointParser(deps.run), deps.checkParser, observer)
			if err == nil || !reflect.DeepEqual(got, OwnedEndpointSummary{}) || calls != 0 {
				t.Fatal("invalid ownership reached runtime or produced partial success", got, calls, err)
			}
		})
	}
}

func TestSSHOwnedEndpointsRejectDriftDuringRuntime(t *testing.T) {
	for _, scenario := range []string{"selection", "intent", "main", "policy", "recovery", "record-replacement", "record-added", "owner", "parser", "cancel", "observer-failure", "wrong-endpoint"} {
		t.Run(scenario, func(t *testing.T) {
			f, plan, deps, journal := ownedPublicationFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			changed := false
			check := func() error {
				if changed && scenario == "parser" {
					return ErrInventoryChanged
				}
				return nil
			}
			observer := ownedEndpointListener(deps.parserDigest)
			observe := func(ctx context.Context, expected []netip.AddrPort, guard func() error) (ListenerSummary, error) {
				result, err := observer(ctx, expected, guard)
				if err != nil {
					t.Fatal("fixture was not valid before mutation", err)
				}
				changed = true
				switch scenario {
				case "selection":
					f.write(sshselection.Path, "[ssh]\nhardening = \"disabled\"\n")
				case "intent":
					f.write(IntentPath, strings.ReplaceAll(validIntentJSON, "forwarding", "cis"))
				case "main":
					f.write(MainPath, includeDropIns+"PasswordAuthentication yes\n")
				case "policy":
					f.write(DropInPath, "AllowTcpForwarding yes\n")
				case "recovery":
					p, err := journal.read()
					if err != nil {
						t.Fatal(err)
					}
					stage, err := sshMainStagePath(p.Transaction)
					if err != nil {
						t.Fatal(err)
					}
					f.write(stage, "# changed original\n")
				case "record-replacement":
					replaceRestoredFixtureRecord(t, f, sshJournalDirectory+"/"+sshPublicationName(1, true))
				case "record-added":
					f.write(sshJournalDirectory+"/extra.json", "{}")
				case "owner":
					f.write(sshStateParent+"/"+sshOwnerName, "{}")
				case "cancel":
					cancel()
				case "observer-failure":
					return result, unix.EIO
				case "wrong-endpoint":
					socket := sshListenerFixture(3, 33)
					socket.Address = netip.MustParseAddr("0.0.0.0")
					return result, matchSSHEndpoints(expected, []sshListenerSocket{socket}, 7)
				}
				return result, nil // The final guard must reject changed state.
			}
			got, err := observeSSHOwnedEndpoints(ctx, journal, plan.summary.PlanSHA256, deps.parserDigest,
				ownedEndpointParser(deps.run), check, observe)
			if !changed || err == nil || !reflect.DeepEqual(got, OwnedEndpointSummary{}) {
				t.Fatal("accepted drift between publication and runtime", got, err)
			}
		})
	}
}

func TestSSHOwnedEndpointProductionRequiresIndependentApproval(t *testing.T) {
	for _, approved := range []string{"", "invalid", strings.Repeat("A", 64)} {
		if got, err := ObserveOwnedSystemdEndpoints(approved); err == nil || !reflect.DeepEqual(got, OwnedEndpointSummary{}) {
			t.Fatal("invalid production approval accepted", got, err)
		}
	}
	if os.Geteuid() != 0 {
		if got, err := ObserveOwnedSystemdEndpoints(strings.Repeat("a", 64)); err == nil || !reflect.DeepEqual(got, OwnedEndpointSummary{}) {
			t.Fatal("unprivileged production entry accepted", got, err)
		}
	}
}

func checkOwnedEndpointOracle(t *testing.T, ctx context.Context, journal *sshJournal, plan migrationPlan,
	daemon *pinnedSSHD, run sshParserRun, check func() error, fd int, inode uint64) {
	t.Helper()
	observe := func(ctx context.Context, expected []netip.AddrPort, guard func() error) (ListenerSummary, error) {
		if err := errors.Join(ctx.Err(), guard()); err != nil {
			return ListenerSummary{}, err
		}
		socket, listening, err := inspectSSHSocket(fd, inode)
		if err != nil || !listening {
			return ListenerSummary{}, errors.Join(ErrInventoryUnsafe, err)
		}
		socket.FD = fd
		if err := errors.Join(matchSSHEndpoints(expected, []sshListenerSocket{socket}, socket.NetNSCookie), guard()); err != nil {
			return ListenerSummary{}, err
		}
		wire, err := json.Marshal(socket)
		if err != nil {
			return ListenerSummary{}, err
		}
		// The installed parser and kernel socket are real; the process/manager
		// summary is a fixture. This oracle does not start or qualify SSH.
		return ListenerSummary{TCPListenersObserved: true, ListenerCount: 1, SocketsSHA256: digestBytes(wire),
			Process: ProcessSummary{ProcessObserved: true, ExecutableVerified: true, ExecutableSHA256: daemon.digest}}, nil
	}
	for range 2 {
		got, err := observeSSHOwnedEndpoints(ctx, journal, plan.summary.PlanSHA256, daemon.digest,
			run, check, observe)
		if err != nil || !got.Publication.OwnershipVerified || got.Publication.ContextsVerified != 3 ||
			!got.Endpoints.ConfiguredEndpointsMatched || got.Endpoints.ConfigurationVerified ||
			got.Publication.RuntimeActivated || got.Endpoints.RuntimeActivated || got.Endpoints.AccessVerified {
			t.Fatal("owned native parser/socket composition failed", got, err)
		}
	}
}
