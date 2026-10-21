//go:build linux

package sshpolicy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path"
	"reflect"
	"time"
)

// This shared engine deliberately remains internal until the product adapter
// also handles activation, already-owned updates and complete removal. Its
// success means verified configuration publication, never a successful login.
type sshTransactionResult struct {
	Verification     VerificationSummary
	Transaction      string
	Published        bool
	Restored         bool
	Aborted          bool
	RecoveryRequired bool
}

type sshTransactionDependencies struct {
	parserDigest string
	run          sshParserRun
	checkParser  func() error
	resolveLabel func(context.Context, inventorySnapshot) (*sshTargetLabel, error)
	provision    sshProvisionOps
	publication  sshPublicationOps
}

func applySSHTransaction(ctx context.Context, approved string) (result sshTransactionResult, err error) {
	if ctx == nil || os.Geteuid() != 0 || !lowerDigest.MatchString(approved) {
		return result, ErrInventoryUnsafe
	}
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
	deps := sshTransactionDependencies{
		parserDigest: daemon.digest, run: daemon.run,
		checkParser: func() error { return daemon.recheck(root, 0) },
		resolveLabel: func(ctx context.Context, snapshot inventorySnapshot) (*sshTargetLabel, error) {
			return resolveSSHTargetLabel(ctx, root, 0, snapshot)
		},
		provision: sshProvisionDefaults(), publication: sshPublicationDefaults(),
	}
	return executeSSHTransaction(ctx, root, 0, approved, deps)
}

func executeSSHTransaction(ctx context.Context, root *os.File, uid int, approved string, deps sshTransactionDependencies) (result sshTransactionResult, err error) {
	if ctx == nil || root == nil || !lowerDigest.MatchString(approved) ||
		!lowerDigest.MatchString(deps.parserDigest) || deps.run == nil || deps.checkParser == nil ||
		deps.resolveLabel == nil || deps.provision.sync == nil || deps.provision.rename == nil ||
		deps.publication.sync == nil || deps.publication.link == nil || deps.publication.rename == nil {
		return result, ErrInventoryUnsafe
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return result, err
	}
	plan, err := inspectPlan(root, uid)
	if err != nil {
		return result, err
	}
	if approved != plan.summary.PlanSHA256 || approved != planDigest(plan) {
		return result, fmt.Errorf("SSH inputs no longer match the explicitly approved plan")
	}
	if err := plan.selection.Authorize(plan.intent.Owner, plan.intent.Profile); err != nil {
		return result, err
	}
	guard := func() error {
		if err := errors.Join(ctx.Err(), deps.checkParser()); err != nil {
			return err
		}
		current, err := collectPlanInventory(root, uid)
		if err != nil || !reflect.DeepEqual(current, plan.inventory) {
			return errors.Join(ErrInventoryChanged, err)
		}
		return nil
	}
	result.Verification, err = verifyPlan(ctx, plan, deps.parserDigest, deps.run, guard)
	if err != nil || plan.intent.Owner == "external" {
		// External ownership is observation only. Do not provision even an
		// empty journal, resolve a new label, stage a file or call a manager.
		return result, err
	}
	label, err := deps.resolveLabel(ctx, plan.inventory)
	if err != nil {
		return result, err
	}
	if label == nil || label.close == nil {
		return result, ErrInventoryUnsafe
	}
	defer func() { err = errors.Join(err, label.close()) }()
	if label.recheck == nil || label.attributes == nil || len(label.attributes) > 1 {
		return result, ErrInventoryUnsafe
	}
	for name := range label.attributes {
		if name != "security.selinux" {
			return result, ErrInventoryUnsafe
		}
	}
	check := func() error { return errors.Join(ctx.Err(), deps.checkParser(), label.recheck(ctx)) }
	if err := errors.Join(guard(), check()); err != nil {
		return result, err
	}
	if err := provisionSSHState(root, uid, deps.provision); err != nil {
		return result, err
	}
	if err := errors.Join(guard(), check()); err != nil {
		return result, err
	}
	journal, err := openSSHJournal(root, uid)
	if err != nil {
		return result, err
	}
	defer func() { err = errors.Join(err, journal.Close()) }()
	if err := requireFreshSSHJournal(journal); err != nil {
		return result, err
	}
	main, drop, err := stageSSHTransaction(root, uid, plan, label.attributes)
	if err != nil {
		return result, err
	}
	defer func() { err = errors.Join(err, main.Close(), drop.Close()) }()
	if err := errors.Join(guard(), check()); err != nil {
		return result, err
	}
	before := sshFileImage{state: plan.inventory.nodes[MainPath], data: plan.inventory.files[MainPath],
		attrs: plan.inventory.attributes[MainPath]}
	record, err := prepareSSHRecord(plan, approved, deps.parserDigest, before, main, drop, uid)
	if err != nil {
		return result, err
	}
	result.Transaction = record.Transaction
	// An uncertain write must retain evidence; it does not establish either
	// publication or a reusable preparation. No automatic retry or adoption.
	result.RecoveryRequired = true
	if err := journal.write(record); err != nil {
		return result, err
	}
	if err := publishSSHConfiguration(ctx, journal, plan, main, drop, deps.run, check, deps.publication); err != nil {
		return result, err
	}
	result.Published, result.RecoveryRequired = true, false
	return result, nil
}

func requireFreshSSHJournal(journal *sshJournal) error {
	if err := journal.recheck(); err != nil {
		return err
	}
	// The handle is newly opened and has not enumerated entries. Only the
	// independently attested marker may exist before a fresh transaction.
	names, err := journal.directory.Readdirnames(2)
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	if len(names) != 1 || names[0] != sshMarkerName {
		return fmt.Errorf("SSH transaction evidence already exists; inspect recovery or verified lifecycle reuse")
	}
	return journal.recheck()
}

func stageSSHTransaction(root *os.File, uid int, plan migrationPlan, attrs map[string][]byte) (*sshAnonymousStage, *sshAnonymousStage, error) {
	if uid < 0 || uid > math.MaxUint32 {
		return nil, nil, ErrInventoryUnsafe
	}
	reader := inventoryReader{root: root, uid: uid, state: inventorySnapshot{nodes: make(map[string]inventoryStamp)}}
	mainDirectory, err := reader.openDirectory(path.Dir(MainPath))
	if err != nil || mainDirectory == nil {
		return nil, nil, errors.Join(ErrInventoryUnsafe, err)
	}
	defer mainDirectory.Close()
	dropDirectory, err := reader.openDirectory(path.Dir(DropInPath))
	if err != nil || dropDirectory == nil {
		return nil, nil, errors.Join(ErrInventoryUnsafe, err)
	}
	defer dropDirectory.Close()
	for _, name := range []string{path.Dir(MainPath), path.Dir(DropInPath)} {
		if reader.state.nodes[name] != plan.inventory.nodes[name] {
			return nil, nil, ErrInventoryChanged
		}
	}
	before := plan.inventory.nodes[MainPath]
	main, err := newSSHAnonymousStage(mainDirectory, plan.main, before.mode&0777, before.gid,
		plan.inventory.attributes[MainPath], uid)
	if err != nil {
		return nil, nil, err
	}
	// The new policy has private permissions and no inherited discretionary
	// ACL or unrelated source xattr. Its SELinux label is target-policy data.
	drop, err := newSSHAnonymousStage(dropDirectory, plan.candidate.Bytes(), 0600, uint32(uid), attrs, uid)
	if err != nil {
		return nil, nil, errors.Join(err, main.Close())
	}
	return main, drop, nil
}

func recoverSSHTransaction(ctx context.Context, root *os.File, uid int, approved string,
	parserDigest string, run sshParserRun, checkParser func() error, ops sshPublicationOps) (result sshTransactionResult, err error) {
	if ctx == nil || root == nil || !lowerDigest.MatchString(approved) || !lowerDigest.MatchString(parserDigest) ||
		run == nil || checkParser == nil {
		return result, ErrInventoryUnsafe
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	if err := errors.Join(ctx.Err(), checkParser()); err != nil {
		return result, err
	}
	journal, err := openSSHJournal(root, uid)
	if err != nil {
		return result, err
	}
	defer func() { err = errors.Join(err, journal.Close()) }()
	record, err := journal.read()
	if err != nil {
		return result, err
	}
	if record.ParserSHA256 != parserDigest || record.PlanSHA256 != approved {
		return result, fmt.Errorf("SSH recovery requires the original approved plan and installed parser identity")
	}
	result.Transaction, result.RecoveryRequired = record.Transaction, true
	if err := journal.requireNoSSHActivation(); err != nil {
		return result, err
	}
	if _, readErr := journal.readRecord(sshPublicationName(1, false)); errors.Is(readErr, os.ErrNotExist) {
		if err := abortSSHPreparation(ctx, journal, record, run, checkParser); err != nil {
			return result, err
		}
		result.Aborted, result.RecoveryRequired = true, false
		return result, nil
	} else if readErr != nil {
		return result, readErr
	}
	if err := rollbackSSHConfiguration(ctx, journal, approved, run, checkParser, ops); err != nil {
		return result, err
	}
	result.Restored, result.RecoveryRequired = true, false
	return result, nil
}
