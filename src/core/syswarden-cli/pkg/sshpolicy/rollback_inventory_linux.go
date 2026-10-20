//go:build linux

package sshpolicy

import (
	"bytes"
	"encoding/json"
	"errors"
	"maps"
	"os"
	"path"
	"reflect"
	"slices"

	"golang.org/x/sys/unix"
)

func collectSSHRollback(root *os.File, uid int, transaction string) (sshStoredInventory, error) {
	mainStage, err := sshMainStagePath(transaction)
	if err != nil {
		return sshStoredInventory{}, err
	}
	dropStage, err := sshDropStagePath(transaction)
	if err != nil {
		return sshStoredInventory{}, err
	}
	snapshot, err := collectPlanInventory(root, uid)
	if err != nil {
		return sshStoredInventory{}, err
	}
	reader := inventoryReader{root: root, uid: uid, state: snapshot}
	for _, name := range []string{mainStage, dropStage} {
		if _, _, err := reader.readFile(name); err != nil {
			return sshStoredInventory{}, err
		}
	}
	return storeSSHInventory(reader.state), nil
}

func stableSSHRollback(journal *sshJournal, transaction string) (sshStoredInventory, error) {
	before, err := collectSSHRollback(journal.root, journal.uid, transaction)
	if err != nil {
		return sshStoredInventory{}, err
	}
	after, err := collectSSHRollback(journal.root, journal.uid, transaction)
	if err != nil || !reflect.DeepEqual(before, after) {
		return sshStoredInventory{}, errors.Join(ErrInventoryChanged, err)
	}
	return after, nil
}

// Rebuild the reviewed plan only from the first immutable publication intent.
// The original complete inventory, including negative observations, must hash
// to the preparation. This is not adoption of current files by content.
func recoverSSHPlan(journal *sshJournal, prepared sshPreparation, digest string) (migrationPlan, error) {
	if err := journal.requireNoPreparationAbort(); err != nil {
		return migrationPlan{}, err
	}
	first, err := journal.readPublication(1, false, prepared, digest)
	if err != nil {
		return migrationPlan{}, err
	}
	stage, err := sshMainStagePath(prepared.Transaction)
	if err != nil || first.Before.Nodes[stage] != (sshStoredStamp{}) {
		return migrationPlan{}, ErrInventoryChanged
	}
	nodes := make(map[string]inventoryStamp, len(first.Before.Nodes))
	for name, node := range first.Before.Nodes {
		if name != stage {
			nodes[name] = inventoryNode(node)
		}
	}
	snapshot := inventorySnapshot{files: first.Before.Files, nodes: nodes, entries: first.Before.Entries, links: first.Before.Links, attributes: first.Before.Attributes}
	declaration, err := parseIntent(snapshot.files[IntentPath])
	if err != nil {
		return migrationPlan{}, err
	}
	plan, err := preparePlan(snapshot, declaration)
	if err != nil {
		return migrationPlan{}, err
	}
	if plan.summary.PlanSHA256 != prepared.PlanSHA256 || plan.intent.Owner != "syswarden" ||
		!bytes.Equal(plan.main, prepared.MainAfter.Data) || !bytes.Equal(plan.candidate.Bytes(), prepared.DropIn.Data) ||
		!matchesSSHRecovery(first.Before, MainPath, prepared.MainBefore) || first.Before.Nodes[MainPath].Changed != prepared.MainBefore.Changed {
		return migrationPlan{}, ErrInventoryChanged
	}
	return plan, checkSSHPublicationIsolation(plan, prepared.Transaction)
}

// Reversal keeps every inode. Step 1 exchanges back the exact original main
// when it was replaced. Step 2 moves the exact policy to a nonincluded name.
// A phase that was never published has an explicit no-op inverse.
func checkSSHRollbackTransition(before, after sshStoredInventory, prepared sshPreparation, applied, step int) error {
	if applied < 0 || applied > 3 || step < 1 || step > 2 {
		return ErrInventoryUnsafe
	}
	if err := errors.Join(before.validate(), after.validate()); err != nil {
		return err
	}
	if (step == 1 && applied < 3) || (step == 2 && applied < 2) {
		if !reflect.DeepEqual(before, after) {
			return ErrInventoryChanged
		}
		return nil
	}
	mainStage, err := sshMainStagePath(prepared.Transaction)
	if err != nil {
		return err
	}
	dropStage, err := sshDropStagePath(prepared.Transaction)
	if err != nil {
		return err
	}
	expected := before
	expected.Files, expected.Nodes = maps.Clone(before.Files), maps.Clone(before.Nodes)
	expected.Attributes, expected.Entries = maps.Clone(before.Attributes), maps.Clone(before.Entries)
	put := func(name string, image sshRecoveryImage) {
		node := sshStoredImage(image, 1)
		node.Changed = after.Nodes[name].Changed
		expected.Nodes[name], expected.Files[name], expected.Attributes[name] = node, image.Data, image.Attributes
	}
	directory := path.Dir(MainPath)
	if step == 1 {
		if !matchesSSHRecovery(before, MainPath, prepared.MainAfter) || !matchesSSHRecovery(before, mainStage, prepared.MainBefore) {
			return ErrInventoryChanged
		}
		put(MainPath, prepared.MainBefore)
		put(mainStage, prepared.MainAfter)
	} else {
		if !matchesSSHRecovery(before, MainPath, prepared.MainBefore) || !matchesSSHRecovery(before, DropInPath, prepared.DropIn) || before.Nodes[dropStage] != (sshStoredStamp{}) {
			return ErrInventoryChanged
		}
		put(dropStage, prepared.DropIn)
		expected.Nodes[DropInPath] = sshStoredStamp{}
		delete(expected.Files, DropInPath)
		delete(expected.Attributes, DropInPath)
		directory = path.Dir(DropInPath)
		if names, ok := expected.Entries[directory]; ok {
			if !slices.Contains(names, path.Base(DropInPath)) || slices.Contains(names, path.Base(dropStage)) {
				return ErrInventoryChanged
			}
			names = slices.Clone(names)
			names = slices.DeleteFunc(names, func(name string) bool { return name == path.Base(DropInPath) })
			names = append(names, path.Base(dropStage))
			slices.Sort(names)
			expected.Entries[directory] = names
		}
	}
	parent, ok := expected.Nodes[directory]
	if !ok || !parent.Exists || parent.Mode&unix.S_IFMT != unix.S_IFDIR {
		return ErrInventoryUnsafe
	}
	observed := after.Nodes[directory]
	parent.Size, parent.Modified, parent.Changed = observed.Size, observed.Modified, observed.Changed
	expected.Nodes[directory] = parent
	if !reflect.DeepEqual(expected, after) {
		return ErrInventoryChanged
	}
	return nil
}

func checkSSHRollbackBudget(before sshStoredInventory, prepared sshPreparation) error {
	if err := before.validate(); err != nil {
		return err
	}
	// Moving the drop-in does not add file bytes, but its longer name occurs in
	// maps and directory membership. Leave bounded room for metadata changes.
	maximum := sshPublicationRecord{1, prepared.Transaction, prepared.PlanSHA256, 2, before, &before}
	data, err := json.Marshal(maximum)
	if err != nil || len(data) > maxSSHJournalBytes-4096 {
		return errors.Join(ErrInventoryBounds, err)
	}
	return nil
}
