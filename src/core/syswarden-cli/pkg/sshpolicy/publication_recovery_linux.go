//go:build linux

package sshpolicy

import (
	"encoding/json"
	"errors"
	"reflect"

	"golang.org/x/sys/unix"
)

// This internal inspection never completes, undoes or adopts a write. "after"
// means the intended inode transition is observed, not that a failed fsync has
// become durable or that sshd was activated. "complete" likewise describes only
// configuration publication.
type sshPublicationPosition struct {
	Step  int
	State string
}

func inspectSSHPublication(journal *sshJournal) (sshPublicationPosition, error) {
	prepared, err := journal.read()
	if err != nil {
		return sshPublicationPosition{}, err
	}
	data, err := json.Marshal(prepared)
	if err != nil {
		return sshPublicationPosition{}, err
	}
	digest := digestBytes(data)
	stage, err := sshMainStagePath(prepared.Transaction)
	if err != nil {
		return sshPublicationPosition{}, err
	}
	var previous *sshStoredInventory
	var pending *sshPublicationRecord
	position := sshPublicationPosition{0, "prepared"}
	gap := false
	for step := 1; step <= 3; step++ {
		intent, intentErr := journal.readPublication(step, false, prepared, digest)
		complete, completeErr := journal.readPublication(step, true, prepared, digest)
		if errors.Is(intentErr, unix.ENOENT) {
			if !errors.Is(completeErr, unix.ENOENT) {
				return sshPublicationPosition{}, ErrInventoryChanged
			}
			gap = true
			continue
		}
		if intentErr != nil || gap || pending != nil {
			return sshPublicationPosition{}, errors.Join(ErrInventoryChanged, intentErr)
		}
		if previous != nil && !reflect.DeepEqual(intent.Before, *previous) {
			return sshPublicationPosition{}, ErrInventoryChanged
		}
		if step == 1 && (!matchesSSHRecovery(intent.Before, MainPath, prepared.MainBefore) ||
			intent.Before.Nodes[MainPath].Changed != prepared.MainBefore.Changed ||
			intent.Before.Nodes[stage] != (sshStoredStamp{}) || intent.Before.Nodes[DropInPath] != (sshStoredStamp{})) {
			return sshPublicationPosition{}, ErrInventoryChanged
		}
		if errors.Is(completeErr, unix.ENOENT) {
			pending = &intent
			position = sshPublicationPosition{step, "pending"}
			continue
		}
		if completeErr != nil || !reflect.DeepEqual(complete.Before, intent.Before) {
			return sshPublicationPosition{}, errors.Join(ErrInventoryChanged, completeErr)
		}
		if err := checkSSHTransition(intent.Before, *complete.After, prepared, step); err != nil {
			return sshPublicationPosition{}, err
		}
		previous = complete.After
		position = sshPublicationPosition{step, "complete"}
	}
	current, err := stableSSHPublication(journal.root, journal.uid, stage)
	if err != nil {
		return sshPublicationPosition{}, err
	}
	switch {
	case pending != nil:
		if reflect.DeepEqual(pending.Before, current) {
			position.State = "before"
		} else if err := checkSSHTransition(pending.Before, current, prepared, pending.Step); err == nil {
			position.State = "after"
		} else {
			return sshPublicationPosition{}, ErrInventoryChanged
		}
	case previous != nil:
		if !reflect.DeepEqual(*previous, current) {
			return sshPublicationPosition{}, ErrInventoryChanged
		}
	default:
		// No publication intent exists. The full original inventory is not
		// stored in prepared.json, so do not claim it can be reconstructed.
		return sshPublicationPosition{}, errors.New("SSH publication has no phase inventory; inspect a fresh plan")
	}
	if err := journal.recheck(); err != nil {
		return sshPublicationPosition{}, err
	}
	return position, nil
}
