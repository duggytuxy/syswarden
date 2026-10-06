//go:build linux

package firewall

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"reflect"
	"slices"
	"time"
)

type nftRemovalSession struct {
	host      nftPersistenceFilesystem
	plan      nftHistoricalPersistencePlan
	origin    nftPolicyOwnershipInspection
	producers nftRemovalProducerInspection
	history   *nftRuntimeHistoryLease
}

// Reopen only the exact selected progress record, or prepare a new source
// plan from the private writer receipt. Preparation never changes live state.
func prepareNFTRemovalSession(ctx context.Context, host nftPersistenceFilesystem, producers nftRemovalProducerInspection) (*nftRemovalSession, error) {
	if producers.verify == nil || !validLegacyRetirementDigest(producers.digest) {
		return nil, fmt.Errorf("removal session requires independently attested producers")
	}
	if err := producers.verify(ctx); err != nil {
		return nil, err
	}
	plan, origin, present, err := readNFTRemovalProgress(host)
	if err != nil {
		return nil, err
	}
	if !present {
		plan, origin, err = prepareNFTOwnedCurrentPersistencePlan(host, producers.entries, producers.digest)
		if err != nil {
			return nil, err
		}
	}
	wanted := append(append([]string(nil), producers.entries...), legacyNFTIncludePath)
	slices.Sort(wanted)
	if plan.binding.Producers != producers.digest || !slices.Equal(plan.graph.Entries, wanted) {
		return nil, fmt.Errorf("current loader or producer evidence differs from the selected removal plan")
	}
	session := &nftRemovalSession{host: host, plan: plan, origin: origin, producers: producers}
	return session, session.check(ctx)
}

func (session *nftRemovalSession) check(ctx context.Context) error {
	if session == nil || session.producers.verify == nil {
		return fmt.Errorf("missing removal session")
	}
	if err := session.history.verify(); err != nil {
		return err
	}
	if err := session.producers.verify(ctx); err != nil {
		return err
	}
	if err := session.origin.verify(session.host); err != nil {
		return err
	}
	if err := verifyNFTHistoricalPersistencePlan(session.host, session.plan); err != nil {
		return err
	}
	selected, _, present, err := readNFTRemovalProgress(session.host)
	if err != nil {
		return err
	}
	if present && !reflect.DeepEqual(selected, session.plan) {
		return fmt.Errorf("removal progress changed during the operation")
	}
	if !present {
		state, err := inspectNFTPersistenceGraphState(session.host, session.plan.graph)
		if err != nil || len(state.edited) != 0 || len(state.retired) != 0 {
			return fmt.Errorf("durable removal progress is missing after source changes")
		}
	}
	return nil
}

func (session *nftRemovalSession) guard(ctx context.Context) func(string, string) error {
	return func(origin, producers string) error {
		if origin != session.origin.digest || producers != session.producers.digest {
			return fmt.Errorf("removal authority differs from its prepared session")
		}
		return session.check(ctx)
	}
}

// Validate all live product tables before changing compatibility permissions
// or persistent sources. Atomic deletion later repeats this inspection under
// the kernel generation fence, including detection of concurrent rule edits.
func (session *nftRemovalSession) inspectRuntime(ctx context.Context, runner nftCommandRunner) error {
	if err := session.check(ctx); err != nil {
		return err
	}
	targets, err := observeNFTRemovalTargets(ctx, runner)
	if err != nil {
		return err
	}
	input := *session.plan.binding.Current
	expected := map[nftTableTarget]bool{{family: "inet", name: "syswarden"}: true, {family: "netdev", name: "syswarden_hw_drop"}: true}
	if input.Base.ARP {
		expected[nftTableTarget{family: "arp", name: "syswarden_arp"}] = true
	}
	if len(targets) == 0 {
		return session.check(ctx)
	}
	if !reflect.DeepEqual(targets, expected) {
		return fmt.Errorf("incomplete or unproven product runtime table coverage; preserve it for recovery")
	}
	state, err := inspectNFTPersistenceGraphState(session.host, session.plan.graph)
	if err != nil {
		return err
	}
	path := legacyNFTIncludePath
	if state.retired[path] {
		path = legacyRetirementBackupDirectory(nftPersistenceGraphFileRecord(session.plan.binding.Source, session.plan.sha256)) + "/original"
	}
	source, err := session.host.read(path)
	if err != nil {
		return err
	}
	windows := map[string]nftRuntimeCapture{}
	start := time.Now().UTC()
	inet, err := runner.Run(ctx, nil, "-j", "list", "table", "inet", "syswarden")
	windows["inet"] = nftRuntimeCapture{start, time.Now().UTC()}
	if err != nil {
		return err
	}
	start = time.Now().UTC()
	ingress, err := runner.Run(ctx, nil, "-j", "list", "table", "netdev", "syswarden_hw_drop")
	windows["netdev"] = nftRuntimeCapture{start, time.Now().UTC()}
	if err != nil {
		return err
	}
	var arp []byte
	if input.Base.ARP {
		arp, err = runner.Run(ctx, nil, "-j", "list", "table", "arp", "syswarden_arp")
		if err != nil {
			return err
		}
	}
	claims, err := newNFTRuntimeClaimProof(session.history, windows)
	if err != nil {
		return err
	}
	if _, err := inspectNFTCurrentRuntimeWithClaims(source, inet, ingress, arp, input, claims); err != nil {
		return err
	}
	return session.check(ctx)
}

func (session *nftRemovalSession) retire(ctx context.Context, runner nftCommandRunner, ops legacyRetirementFileOps) error {
	if err := session.inspectRuntime(ctx, runner); err != nil {
		return err
	}
	guard := session.guard(ctx)
	if err := applyNFTOwnedRemovalSources(session.host, session.plan, guard, ops); err != nil {
		return err
	}
	if err := retireNFTCurrentRuntime(ctx, session.host, session.plan, session.plan.sha256, guard, runner, ops, session.history); err != nil {
		return err
	}
	return session.retireMetadata(ctx, runner, ops)
}

func prepareOwnedNFTCleanup(ctx context.Context, runner nftCommandRunner) (func() error, func(), error) {
	root, err := os.OpenRoot("/")
	if err != nil {
		return nil, nil, err
	}
	host := nftPersistenceFilesystem{root: root}
	closeRoot := func() { _ = root.Close() }
	fail := func(err error) (func() error, func(), error) { closeRoot(); return nil, nil, err }
	var found bool
	for _, path := range []string{legacyNFTIncludePath, nftStateDirectory + "/" + nftPolicyOwnershipName, nftRemovalProgressPath} {
		_, err := host.snapshot(path)
		if err == nil {
			found = true
		} else if !errors.Is(err, fs.ErrNotExist) {
			return fail(err)
		}
	}
	if !found {
		// Absence is the only successful path without writer authority. The
		// fallback never deletes a table based on a reserved-looking name.
		if err := cleanupReservedNFTablesForUninstall(ctx, runner); err != nil {
			return fail(err)
		}
		return func() error { return cleanupReservedNFTablesForUninstall(ctx, runner) }, closeRoot, nil
	}
	producers, err := inspectNFTRemovalProducers(ctx, host)
	if err != nil {
		return fail(err)
	}
	session, err := prepareNFTRemovalSession(ctx, host, producers)
	if err != nil {
		return fail(err)
	}
	history, err := acquireNFTRuntimeHistory(host)
	if err != nil {
		return fail(err)
	}
	priorClose := closeRoot
	closeRoot = func() { history.close(); priorClose() }
	session.history = history
	if err := session.inspectRuntime(ctx, runner); err != nil {
		return fail(err)
	}
	return func() error { return session.retire(ctx, runner, defaultLegacyRetirementFileOps()) }, closeRoot, nil
}
