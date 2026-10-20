//go:build linux

package sshpolicy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"

	"golang.org/x/sys/unix"
)

const sshPreparationAbortName = "aborted-before-publication.json"

type sshPreparationAbort struct {
	Schema      int                `json:"schema"`
	Transaction string             `json:"transaction"`
	Prepared    string             `json:"prepared_sha256"`
	Original    sshStoredInventory `json:"original"`
}

// A preparation with no publication intent cannot resume lost anonymous
// inodes. It can only be aborted after proving that the full approved input
// inventory and original live policy remain unchanged. Keep all evidence.
func abortSSHPreparation(ctx context.Context, journal *sshJournal, prepared sshPreparation, run sshParserRun, parserCheck func() error) (err error) {
	if ctx == nil || journal == nil || run == nil || parserCheck == nil {
		return ErrInventoryUnsafe
	}
	if err := errors.Join(ctx.Err(), prepared.validate(journal.uid), journal.recheck(), parserCheck()); err != nil {
		return err
	}
	plan, err := inspectPlan(journal.root, journal.uid)
	if err != nil {
		return err
	}
	if plan.intent.Owner != "syswarden" || plan.summary.PlanSHA256 != prepared.PlanSHA256 ||
		!bytes.Equal(plan.main, prepared.MainAfter.Data) || !bytes.Equal(plan.candidate.Bytes(), prepared.DropIn.Data) {
		return ErrInventoryChanged
	}
	if err := checkSSHPublicationIsolation(plan, prepared.Transaction); err != nil {
		return err
	}
	current, err := stableSSHRollback(journal, prepared.Transaction)
	if err != nil {
		return err
	}
	mainStage, err := sshMainStagePath(prepared.Transaction)
	if err != nil {
		return err
	}
	dropStage, err := sshDropStagePath(prepared.Transaction)
	if err != nil {
		return err
	}
	if !matchesSSHRecovery(current, MainPath, prepared.MainBefore) ||
		current.Nodes[MainPath].Changed != prepared.MainBefore.Changed ||
		current.Nodes[DropInPath] != (sshStoredStamp{}) ||
		current.Nodes[mainStage] != (sshStoredStamp{}) || current.Nodes[dropStage] != (sshStoredStamp{}) {
		return ErrInventoryChanged
	}
	if err := current.validate(); err != nil {
		return err
	}
	preparation, err := json.Marshal(prepared)
	if err != nil {
		return err
	}
	record, err := json.Marshal(sshPreparationAbort{1, prepared.Transaction, digestBytes(preparation), current})
	if err != nil || len(record) > maxSSHJournalBytes {
		return errors.Join(ErrInventoryBounds, err)
	}
	existing, err := journal.readRecord(sshPreparationAbortName)
	fresh := errors.Is(err, unix.ENOENT)
	if !fresh && (err != nil || !bytes.Equal(existing, record)) {
		return errors.Join(ErrInventoryChanged, err)
	}
	var terminal []byte
	if !fresh {
		terminal = record
	}
	check := func() error {
		if err := errors.Join(ctx.Err(), parserCheck(), journal.checkPreparationOnly(preparation, terminal)); err != nil {
			return err
		}
		observed, err := stableSSHRollback(journal, prepared.Transaction)
		if err != nil || !reflect.DeepEqual(observed, current) {
			return errors.Join(ErrInventoryChanged, err)
		}
		// Rebind the full original inventory, including all negative inputs,
		// independently from the extra staging-path observations.
		original, err := collectPlanInventory(journal.root, journal.uid)
		if err != nil || !reflect.DeepEqual(original, plan.inventory) {
			return errors.Join(ErrInventoryChanged, err)
		}
		return nil
	}
	if err := verifySSHRestored(ctx, journal, plan, prepared, current, run, check); err != nil {
		return err
	}
	defer func() {
		if err != nil {
			journal.poisoned = true
		}
	}()
	if fresh {
		if err := check(); err != nil {
			return err
		}
		if err := journal.writeRecord(sshPreparationAbortName, record); err != nil {
			return err
		}
		terminal = record
	}
	// Reopening a visible terminal record is not proof that its directory sync
	// succeeded. Repair that durability explicitly, then recheck all inputs.
	if err := check(); err != nil {
		return err
	}
	return errors.Join(journal.syncDirectory(journal.directory), check())
}

func (journal *sshJournal) checkPreparationOnly(prepared, terminal []byte) error {
	if err := journal.recheck(); err != nil {
		return err
	}
	// Use a fresh directory description. Prior enumerations must not hide a
	// phase, unknown file or mixed history behind an exhausted cursor.
	fd, err := unix.Openat(int(journal.directory.Fd()), ".",
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	directory := os.NewFile(uintptr(fd), "ssh-preparation-journal")
	names, readErr := directory.Readdirnames(4)
	closeErr := directory.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return errors.Join(readErr, closeErr)
	}
	if closeErr != nil {
		return closeErr
	}
	want := 2
	if terminal != nil {
		want++
	}
	if len(names) != want {
		return fmt.Errorf("SSH preparation recovery requires an unmixed preparation-only journal")
	}
	for _, name := range names {
		switch name {
		case sshMarkerName, sshPreparedRecord:
		case sshPreparationAbortName:
			if terminal == nil {
				return ErrInventoryChanged
			}
		default:
			return ErrInventoryUnsafe
		}
	}
	data, err := journal.readRecord(sshPreparedRecord)
	if err != nil || !bytes.Equal(data, prepared) {
		return errors.Join(ErrInventoryChanged, err)
	}
	data, err = journal.readRecord(sshPreparationAbortName)
	if terminal == nil {
		if !errors.Is(err, unix.ENOENT) {
			return errors.Join(ErrInventoryChanged, err)
		}
	} else if err != nil || !bytes.Equal(data, terminal) {
		return errors.Join(ErrInventoryChanged, err)
	}
	return journal.recheck()
}

func (journal *sshJournal) requireNoPreparationAbort() error {
	_, err := journal.readRecord(sshPreparationAbortName)
	if !errors.Is(err, unix.ENOENT) {
		return errors.Join(fmt.Errorf("SSH preparation was aborted; preserve its terminal evidence"), err)
	}
	return nil
}
