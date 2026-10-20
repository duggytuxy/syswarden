//go:build linux

package sshpolicy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"reflect"

	"golang.org/x/sys/unix"
)

// The caller must explicitly authorize the original approved plan. This
// internal helper never reloads sshd, deletes retained images or silently
// falls back to content-based ownership. A failed handle must be reopened and
// inspected before an explicit resume with the same approval.
func rollbackSSHConfiguration(ctx context.Context, journal *sshJournal, approved string, run sshParserRun, parserCheck func() error, ops sshPublicationOps) (err error) {
	if ctx == nil || journal == nil || run == nil || parserCheck == nil || ops.sync == nil || ops.rename == nil || !lowerDigest.MatchString(approved) {
		return ErrInventoryUnsafe
	}
	prepared, err := journal.read()
	if err != nil {
		return err
	}
	if approved != prepared.PlanSHA256 {
		return ErrInventoryChanged
	}
	data, err := json.Marshal(prepared)
	if err != nil {
		return err
	}
	digest := digestBytes(data)
	plan, err := recoverSSHPlan(journal, prepared, digest)
	if err != nil {
		return err
	}
	current, err := stableSSHRollback(journal, prepared.Transaction)
	if err != nil {
		return err
	}
	start, err := journal.readRollbackStart(prepared, digest)
	fresh := errors.Is(err, unix.ENOENT)
	if fresh {
		if err := journal.requireNoRollbackRecords(); err != nil {
			return err
		}
		position, err := inspectSSHPublication(journal)
		if err != nil {
			return err
		}
		applied := position.Step
		if position.State == "before" {
			applied--
		}
		start = sshRollbackStart{1, prepared.Transaction, digest, applied, current}
		if err := start.validate(journal, prepared, digest); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	position, _, err := matchSSHRollback(journal, prepared, start, current)
	if err != nil {
		return err
	}
	guard := sshRollbackGuard(ctx, journal, prepared.Transaction, current, parserCheck)
	if err := verifySSHRollbackCandidates(ctx, plan, run, guard); err != nil {
		return err
	}
	if err := checkSSHRollbackBudget(current, prepared); err != nil {
		return err
	}
	defer func() {
		if err != nil {
			journal.poisoned = true
		}
	}()
	if fresh {
		data, err := json.Marshal(start)
		if err != nil {
			return err
		}
		if err := journal.writeRecord(sshRollbackStartName, data); err != nil {
			return err
		}
	}
	// A reopened intent/completion can have survived an uncertain sync. Repair
	// durability explicitly before using it, never infer durability from bytes.
	if err := syncSSHRollback(ctx, journal, prepared.Transaction, current, parserCheck, ops); err != nil {
		return err
	}
	next := position.Step + 1
	if position.State == "before" || position.State == "after" {
		next = position.Step
	}
	for step := next; step <= 2; step++ {
		phase, readErr := journal.readSSHPhase(sshRollbackName(step, false), step, false, prepared, digest)
		if errors.Is(readErr, unix.ENOENT) {
			phase = sshPublicationRecord{1, prepared.Transaction, digest, step, current, nil}
			if err := journal.writeSSHPhase(sshRollbackName(step, false), phase, false); err != nil {
				return err
			}
		} else if readErr != nil {
			return readErr
		}
		if reflect.DeepEqual(current, phase.Before) {
			current, err = executeSSHRollback(ctx, journal, phase, prepared, start.Applied, parserCheck, ops)
			if err != nil {
				return fmt.Errorf("SSH rollback step %d requires inspection; all files are retained: %w", step, err)
			}
		} else if err := checkSSHRollbackTransition(phase.Before, current, prepared, start.Applied, step); err != nil {
			return err
		}
		if err := syncSSHRollback(ctx, journal, prepared.Transaction, current, parserCheck, ops); err != nil {
			return err
		}
		phase.After = &current
		if err := journal.writeSSHPhase(sshRollbackName(step, true), phase, true); err != nil {
			return err
		}
		if err := sshRollbackGuard(ctx, journal, prepared.Transaction, current, parserCheck)(); err != nil {
			return err
		}
	}
	// This is configuration restoration only. A caller must independently
	// validate daemon activation and access before claiming operational recovery.
	return verifySSHRestored(ctx, journal, plan, prepared, current, run, parserCheck)
}

func sshRollbackGuard(ctx context.Context, journal *sshJournal, transaction string, expected sshStoredInventory, parserCheck func() error) func() error {
	return func() error {
		if err := errors.Join(ctx.Err(), journal.recheck(), parserCheck()); err != nil {
			return err
		}
		current, err := stableSSHRollback(journal, transaction)
		if err != nil || !reflect.DeepEqual(current, expected) {
			return errors.Join(ErrInventoryChanged, err)
		}
		return nil
	}
}

func syncSSHRollback(ctx context.Context, journal *sshJournal, transaction string, expected sshStoredInventory, parserCheck func() error, ops sshPublicationOps) error {
	guard := sshRollbackGuard(ctx, journal, transaction, expected, parserCheck)
	if err := guard(); err != nil {
		return err
	}
	for _, directory := range []string{path.Dir(MainPath), path.Dir(DropInPath)} {
		reader := inventoryReader{root: journal.root, uid: journal.uid, state: inventorySnapshot{nodes: make(map[string]inventoryStamp)}}
		parent, err := reader.openDirectory(directory)
		if err != nil {
			return err
		}
		if parent == nil {
			return ErrInventoryChanged
		}
		if reader.state.nodes[directory] != inventoryNode(expected.Nodes[directory]) {
			_ = parent.Close()
			return ErrInventoryChanged
		}
		syncErr := ops.sync(parent)
		closeErr := parent.Close()
		if err := errors.Join(syncErr, closeErr, guard()); err != nil {
			return err
		}
	}
	return errors.Join(journal.syncDirectory(journal.directory), guard())
}

func executeSSHRollback(ctx context.Context, journal *sshJournal, phase sshPublicationRecord, prepared sshPreparation, applied int, parserCheck func() error, ops sshPublicationOps) (sshStoredInventory, error) {
	guard := sshRollbackGuard(ctx, journal, prepared.Transaction, phase.Before, parserCheck)
	if err := guard(); err != nil {
		return sshStoredInventory{}, err
	}
	directory := path.Dir(MainPath)
	if phase.Step == 2 {
		directory = path.Dir(DropInPath)
	}
	reader := inventoryReader{root: journal.root, uid: journal.uid, state: inventorySnapshot{nodes: make(map[string]inventoryStamp)}}
	parent, err := reader.openDirectory(directory)
	if err != nil {
		return sshStoredInventory{}, err
	}
	if parent == nil {
		return sshStoredInventory{}, ErrInventoryChanged
	}
	defer parent.Close()
	if reader.state.nodes[directory] != inventoryNode(phase.Before.Nodes[directory]) {
		return sshStoredInventory{}, ErrInventoryChanged
	}
	if err := guard(); err != nil {
		return sshStoredInventory{}, err
	}
	if phase.Step == 1 && applied == 3 {
		stage, err := sshMainStagePath(prepared.Transaction)
		if err != nil {
			return sshStoredInventory{}, err
		}
		err = ops.rename(int(parent.Fd()), path.Base(stage), int(parent.Fd()), path.Base(MainPath), unix.RENAME_EXCHANGE)
		if err != nil {
			return sshStoredInventory{}, err
		}
	} else if phase.Step == 2 && applied >= 2 {
		stage, err := sshDropStagePath(prepared.Transaction)
		if err != nil {
			return sshStoredInventory{}, err
		}
		err = ops.rename(int(parent.Fd()), path.Base(DropInPath), int(parent.Fd()), path.Base(stage), unix.RENAME_NOREPLACE)
		if err != nil {
			return sshStoredInventory{}, err
		}
	}
	if err := ops.sync(parent); err != nil {
		return sshStoredInventory{}, err
	}
	after, err := stableSSHRollback(journal, prepared.Transaction)
	if err != nil {
		return sshStoredInventory{}, err
	}
	if err := errors.Join(checkSSHRollbackTransition(phase.Before, after, prepared, applied, phase.Step), ctx.Err(), parserCheck(), journal.recheck()); err != nil {
		return sshStoredInventory{}, err
	}
	return after, nil
}
