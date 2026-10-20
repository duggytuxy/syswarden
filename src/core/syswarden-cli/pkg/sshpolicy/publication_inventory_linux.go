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

// These private records retain negative observations as well as complete
// inode metadata. Do not export them through operator summaries.
type sshStoredStamp struct {
	Exists   bool          `json:"exists"`
	Device   uint64        `json:"device"`
	Inode    uint64        `json:"inode"`
	Links    uint64        `json:"links"`
	Mode     uint32        `json:"mode"`
	UID      uint32        `json:"uid"`
	GID      uint32        `json:"gid"`
	Size     int64         `json:"size"`
	Modified unix.Timespec `json:"modified"`
	Changed  unix.Timespec `json:"changed"`
}

type sshStoredInventory struct {
	Files      map[string][]byte            `json:"files"`
	Nodes      map[string]sshStoredStamp    `json:"nodes"`
	Entries    map[string][]string          `json:"entries"`
	Links      map[string]string            `json:"links"`
	Attributes map[string]map[string][]byte `json:"attributes"`
}

func storeSSHInventory(value inventorySnapshot) sshStoredInventory {
	nodes := make(map[string]sshStoredStamp, len(value.nodes))
	for name, n := range value.nodes {
		nodes[name] = sshStoredStamp{n.exists, n.dev, n.ino, n.links, n.mode, n.uid, n.gid, n.size, n.modified, n.changed}
	}
	return sshStoredInventory{value.files, nodes, value.entries, value.links, value.attributes}
}

func (value sshStoredInventory) validate() error {
	if value.Files == nil || value.Nodes == nil || value.Entries == nil || value.Links == nil || value.Attributes == nil ||
		len(value.Files) > MaxFiles || len(value.Nodes) > MaxInventoryNodes ||
		len(value.Entries) > MaxInventoryNodes || len(value.Links) > MaxInventoryNodes || len(value.Attributes) > MaxInventoryNodes {
		return ErrInventoryBounds
	}
	remaining := MaxBytes
	for name, data := range value.Files {
		remaining -= len(data)
		if !safePath(name) || data == nil || remaining < 0 {
			return ErrInventoryBounds
		}
	}
	for name, node := range value.Nodes {
		if (name != "/" && !safePath(name)) || (!node.Exists && node != (sshStoredStamp{})) ||
			node.Modified.Nsec < 0 || node.Modified.Nsec >= 1e9 || node.Changed.Nsec < 0 || node.Changed.Nsec >= 1e9 {
			return ErrInventoryUnsafe
		}
	}
	for name, entries := range value.Entries {
		if (name != "/" && !safePath(name)) || len(entries) > MaxDirectoryEntries || !slices.IsSorted(entries) {
			return ErrInventoryBounds
		}
		for i, entry := range entries {
			if entry == "" || entry == "." || entry == ".." || path.Base(entry) != entry || !printableASCII(entry) || (i > 0 && entries[i-1] == entry) {
				return ErrInventoryUnsafe
			}
		}
	}
	for name, attrs := range value.Attributes {
		if (name != "/" && !safePath(name)) || attrs == nil {
			return ErrInventoryUnsafe
		}
		if err := validateSSHAttributes(attrs, false); err != nil {
			return err
		}
	}
	return nil
}

func collectSSHPublication(root *os.File, uid int, stage string) (sshStoredInventory, error) {
	snapshot, err := collectPlanInventory(root, uid)
	if err != nil {
		return sshStoredInventory{}, err
	}
	reader := inventoryReader{root: root, uid: uid, state: snapshot}
	if _, _, err := reader.readFile(stage); err != nil {
		return sshStoredInventory{}, err
	}
	return storeSSHInventory(reader.state), nil
}

func sshStoredImage(image sshRecoveryImage, links uint64) sshStoredStamp {
	return sshStoredStamp{true, image.Device, image.Inode, links, image.Mode, image.UID, image.GID,
		int64(len(image.Data)), image.Modified, image.Changed}
}

// Only the exact metadata fields changed by link/rename may differ during one
// transition. All other nodes, labels, ACLs, bytes, aliases and directory
// members remain exact. The resulting timestamps are frozen in the completion
// record and compared without exceptions before the next operation.
func checkSSHTransition(before, after sshStoredInventory, record sshPreparation, step int) error {
	if err := errors.Join(before.validate(), after.validate()); err != nil {
		return err
	}
	stage, err := sshMainStagePath(record.Transaction)
	if err != nil || step < 1 || step > 3 {
		return ErrInventoryUnsafe
	}
	expected := before
	expected.Files = maps.Clone(before.Files)
	expected.Nodes = maps.Clone(before.Nodes)
	expected.Attributes = maps.Clone(before.Attributes)
	expected.Entries = maps.Clone(before.Entries)
	put := func(name string, image sshRecoveryImage) {
		state := sshStoredImage(image, 1)
		// linkat/rename update ctime, but never mtime or security metadata.
		state.Changed = after.Nodes[name].Changed
		expected.Nodes[name] = state
		expected.Files[name] = image.Data
		expected.Attributes[name] = image.Attributes
	}
	var directory, added string
	switch step {
	case 1:
		if before.Nodes[stage].Exists {
			return ErrInventoryChanged
		}
		put(stage, record.MainAfter)
		directory, added = path.Dir(stage), path.Base(stage)
	case 2:
		if before.Nodes[DropInPath].Exists {
			return ErrInventoryChanged
		}
		put(DropInPath, record.DropIn)
		directory, added = path.Dir(DropInPath), path.Base(DropInPath)
	case 3:
		if !matchesSSHRecovery(before, MainPath, record.MainBefore) ||
			!matchesSSHRecovery(before, stage, record.MainAfter) {
			return ErrInventoryChanged
		}
		put(MainPath, record.MainAfter)
		put(stage, record.MainBefore)
		directory = path.Dir(MainPath)
	}
	parent, exists := expected.Nodes[directory]
	if !exists || !parent.Exists || parent.Mode&unix.S_IFMT != unix.S_IFDIR {
		return ErrInventoryUnsafe
	}
	observed := after.Nodes[directory]
	parent.Size, parent.Modified, parent.Changed = observed.Size, observed.Modified, observed.Changed
	expected.Nodes[directory] = parent
	if names, scanned := expected.Entries[directory]; scanned && added != "" {
		if slices.Contains(names, added) {
			return ErrInventoryChanged
		}
		names = append(slices.Clone(names), added)
		slices.Sort(names)
		expected.Entries[directory] = names
	}
	if !reflect.DeepEqual(expected, after) {
		return ErrInventoryChanged
	}
	return nil
}

func matchesSSHRecovery(snapshot sshStoredInventory, name string, image sshRecoveryImage) bool {
	want := sshStoredImage(image, 1)
	want.Changed = snapshot.Nodes[name].Changed
	return snapshot.Nodes[name] == want && bytes.Equal(snapshot.Files[name], image.Data) &&
		reflect.DeepEqual(snapshot.Attributes[name], image.Attributes)
}

func checkSSHInitialPublication(snapshot sshStoredInventory, plan migrationPlan, stage string) error {
	if snapshot.Nodes[stage] != (sshStoredStamp{}) {
		return ErrInventoryChanged
	}
	baseline := snapshot
	baseline.Nodes = maps.Clone(snapshot.Nodes)
	delete(baseline.Nodes, stage)
	if !reflect.DeepEqual(baseline, storeSSHInventory(plan.inventory)) {
		return ErrInventoryChanged
	}
	return nil
}

// Account for both published candidates and doubled before/after journal
// inventories before the first named write. Reserve room for timestamp and
// directory-size encoding changes rather than discovering a record-size limit
// halfway through publication.
func checkSSHPublicationBudget(before sshStoredInventory, record sshPreparation, stage string) error {
	largest := before
	largest.Files, largest.Nodes = maps.Clone(before.Files), maps.Clone(before.Nodes)
	largest.Attributes, largest.Entries = maps.Clone(before.Attributes), maps.Clone(before.Entries)
	for name, image := range map[string]sshRecoveryImage{stage: record.MainAfter, DropInPath: record.DropIn} {
		largest.Files[name], largest.Nodes[name], largest.Attributes[name] = image.Data, sshStoredImage(image, 1), image.Attributes
		directory := path.Dir(name)
		if entries, ok := largest.Entries[directory]; ok {
			entries = append(slices.Clone(entries), path.Base(name))
			slices.Sort(entries)
			largest.Entries[directory] = entries
		}
	}
	if err := largest.validate(); err != nil {
		return err
	}
	maximum := sshPublicationRecord{1, record.Transaction, record.PlanSHA256, 3, largest, &largest}
	data, err := json.Marshal(maximum)
	if err != nil || len(data) > maxSSHJournalBytes-2048 {
		return errors.Join(ErrInventoryBounds, err)
	}
	return nil
}

// Observe twice to reject a graph or directory modified while it is being
// captured. This does not claim to lock out a privileged administrator.
func stableSSHPublication(root *os.File, uid int, stage string) (sshStoredInventory, error) {
	before, err := collectSSHPublication(root, uid, stage)
	if err != nil {
		return sshStoredInventory{}, err
	}
	after, err := collectSSHPublication(root, uid, stage)
	if err != nil || !reflect.DeepEqual(before, after) {
		return sshStoredInventory{}, errors.Join(ErrInventoryChanged, err)
	}
	return after, nil
}
