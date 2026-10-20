//go:build linux

package sshpolicy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"reflect"

	"golang.org/x/sys/unix"
)

const sshRollbackStartName = "rollback-start.json"

type sshRollbackStart struct {
	Schema      int                `json:"schema"`
	Transaction string             `json:"transaction"`
	Prepared    string             `json:"prepared_sha256"`
	Applied     int                `json:"publication_steps_observed"`
	Before      sshStoredInventory `json:"before"`
}

func sshRollbackName(step int, done bool) string {
	suffix := "intent"
	if done {
		suffix = "complete"
	}
	return fmt.Sprintf("rollback-%02d-%s.json", step, suffix)
}

func (journal *sshJournal) requireNoRollbackRecords() error {
	names := []string{sshRollbackStartName}
	for step := 1; step <= 2; step++ {
		for _, done := range []bool{false, true} {
			names = append(names, sshRollbackName(step, done))
		}
	}
	for _, name := range names {
		_, err := journal.readRecord(name)
		if !errors.Is(err, unix.ENOENT) {
			return errors.Join(errors.New("SSH rollback evidence exists; inspect rollback recovery"), err)
		}
	}
	return nil
}

func (start sshRollbackStart) validate(journal *sshJournal, prepared sshPreparation, digest string) error {
	if start.Schema != 1 || start.Transaction != prepared.Transaction || start.Prepared != digest || start.Applied < 0 || start.Applied > 3 {
		return ErrInventoryUnsafe
	}
	if err := start.Before.validate(); err != nil {
		return err
	}
	dropStage, err := sshDropStagePath(prepared.Transaction)
	if err != nil {
		return err
	}
	if start.Before.Nodes[dropStage] != (sshStoredStamp{}) {
		return ErrInventoryChanged
	}
	baseline := start.Before
	baseline.Nodes = maps.Clone(start.Before.Nodes)
	delete(baseline.Nodes, dropStage)
	position, err := matchSSHPublication(journal, prepared, baseline)
	if err != nil {
		return err
	}
	applied := position.Step
	if position.State == "before" {
		applied--
	}
	if applied != start.Applied {
		return ErrInventoryChanged
	}
	return nil
}

func (journal *sshJournal) readRollbackStart(prepared sshPreparation, digest string) (sshRollbackStart, error) {
	data, err := journal.readRecord(sshRollbackStartName)
	if err != nil {
		return sshRollbackStart{}, err
	}
	var start sshRollbackStart
	if err := json.Unmarshal(data, &start); err != nil {
		return sshRollbackStart{}, ErrInventoryUnsafe
	}
	canonical, err := json.Marshal(start)
	if err != nil || !bytes.Equal(canonical, data) {
		return sshRollbackStart{}, ErrInventoryUnsafe
	}
	return start, start.validate(journal, prepared, digest)
}

// Inspection compares exact recorded images. An observed after-state never
// means that a previous failed sync succeeded, or that a daemon was reloaded.
func inspectSSHRollback(journal *sshJournal) (sshPublicationPosition, error) {
	prepared, err := journal.read()
	if err != nil {
		return sshPublicationPosition{}, err
	}
	data, err := json.Marshal(prepared)
	if err != nil {
		return sshPublicationPosition{}, err
	}
	start, err := journal.readRollbackStart(prepared, digestBytes(data))
	if err != nil {
		return sshPublicationPosition{}, err
	}
	if _, err := recoverSSHPlan(journal, prepared, start.Prepared); err != nil {
		return sshPublicationPosition{}, err
	}
	current, err := stableSSHRollback(journal, prepared.Transaction)
	if err != nil {
		return sshPublicationPosition{}, err
	}
	position, _, err := matchSSHRollback(journal, prepared, start, current)
	return position, errors.Join(err, journal.recheck())
}

func matchSSHRollback(journal *sshJournal, prepared sshPreparation, start sshRollbackStart, current sshStoredInventory) (sshPublicationPosition, sshStoredInventory, error) {
	previous := start.Before
	position := sshPublicationPosition{0, "complete"}
	gap := false
	var pending *sshPublicationRecord
	for step := 1; step <= 2; step++ {
		intent, intentErr := journal.readSSHPhase(sshRollbackName(step, false), step, false, prepared, start.Prepared)
		complete, completeErr := journal.readSSHPhase(sshRollbackName(step, true), step, true, prepared, start.Prepared)
		if errors.Is(intentErr, unix.ENOENT) {
			if !errors.Is(completeErr, unix.ENOENT) {
				return position, previous, ErrInventoryChanged
			}
			gap = true
			continue
		}
		if intentErr != nil || gap || pending != nil || !reflect.DeepEqual(intent.Before, previous) {
			return position, previous, errors.Join(ErrInventoryChanged, intentErr)
		}
		if errors.Is(completeErr, unix.ENOENT) {
			pending = &intent
			position = sshPublicationPosition{step, "pending"}
			continue
		}
		if completeErr != nil || !reflect.DeepEqual(complete.Before, intent.Before) {
			return position, previous, errors.Join(ErrInventoryChanged, completeErr)
		}
		if err := checkSSHRollbackTransition(intent.Before, *complete.After, prepared, start.Applied, step); err != nil {
			return position, previous, err
		}
		previous = *complete.After
		position = sshPublicationPosition{step, "complete"}
	}
	if pending != nil {
		if reflect.DeepEqual(current, pending.Before) {
			position.State = "before"
		} else if err := checkSSHRollbackTransition(pending.Before, current, prepared, start.Applied, pending.Step); err == nil {
			position.State = "after"
		} else {
			return position, previous, ErrInventoryChanged
		}
	} else if !reflect.DeepEqual(current, previous) {
		return position, previous, ErrInventoryChanged
	}
	return position, previous, nil
}
