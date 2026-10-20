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
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const sshAbortedPrefix = ".ssh-policy-aborted-"

// Retire only a verified preparation that never published a configuration.
// The original directory and independent owner receipt are moved, never copied
// or deleted. A durable intent makes either interrupted rename recoverable.
// This is internal lifecycle support, not a public apply or uninstall command.
type sshAbortedRetirement struct {
	Schema      int               `json:"schema"`
	Instance    string            `json:"instance"`
	Transaction string            `json:"transaction"`
	Plan        string            `json:"plan_sha256"`
	Parser      string            `json:"parser_sha256"`
	Owner       sshRecoveryImage  `json:"owner"`
	Files       map[string]string `json:"files"`
}

func (r sshAbortedRetirement) name(suffix string) string {
	return sshAbortedPrefix + r.Instance + suffix
}

func validSSHAbortedReceiptName(name string) bool {
	for _, suffix := range []string{".intent.json", ".complete.json"} {
		if strings.HasPrefix(name, sshAbortedPrefix) && strings.HasSuffix(name, suffix) &&
			lowerDigest.MatchString(strings.TrimSuffix(strings.TrimPrefix(name, sshAbortedPrefix), suffix)) {
			return true
		}
	}
	return false
}

func (r sshAbortedRetirement) validate(uid int) (sshStateOwner, error) {
	if r.Schema != 1 || !lowerDigest.MatchString(r.Instance) || !lowerDigest.MatchString(r.Transaction) ||
		!lowerDigest.MatchString(r.Plan) || !lowerDigest.MatchString(r.Parser) || len(r.Files) != 3 {
		return sshStateOwner{}, ErrInventoryUnsafe
	}
	if err := r.Owner.validate(uid, 1); err != nil {
		return sshStateOwner{}, err
	}
	if r.Owner.Mode&07777 != 0600 || int64(r.Owner.GID) != int64(uid) {
		return sshStateOwner{}, ErrInventoryUnsafe
	}
	for _, name := range []string{sshMarkerName, sshPreparedRecord, sshPreparationAbortName} {
		if !lowerDigest.MatchString(r.Files[name]) {
			return sshStateOwner{}, ErrInventoryUnsafe
		}
	}
	owner, err := decodeSSHOwner(r.Owner.Data, uid)
	if err != nil || owner.Instance != r.Instance {
		return sshStateOwner{}, errors.Join(ErrInventoryChanged, err)
	}
	return owner, nil
}

func decodeSSHAbortedRetirement(data []byte, uid int) (sshAbortedRetirement, error) {
	var r sshAbortedRetirement
	if len(data) == 0 || len(data) > maxSSHOwnerBytes {
		return r, ErrInventoryBounds
	}
	if err := json.Unmarshal(data, &r); err != nil {
		return r, ErrInventoryUnsafe
	}
	canonical, err := json.Marshal(r)
	if err != nil || !bytes.Equal(canonical, data) {
		return r, ErrInventoryUnsafe
	}
	_, err = r.validate(uid)
	return r, err
}

func sshImageDigest(image sshFileImage) string {
	data, _ := json.Marshal(recoveryImage(image))
	return digestBytes(data)
}

func sshDirectoryNames(directory *os.File, limit int) ([]string, error) {
	fd, err := unix.Openat(int(directory.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	fresh := os.NewFile(uintptr(fd), "ssh-private-directory-listing")
	defer fresh.Close()
	names, err := fresh.Readdirnames(limit + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if len(names) > limit {
		return nil, ErrInventoryBounds
	}
	return names, nil
}

// Snapshot all three records, including inodes, modes, labels and link counts.
// Unknown entries, copied receipts and hard links are not acceptable custody.
func observeSSHAbortedFiles(directory *os.File, uid int) (map[string]string, sshPreparation, sshPreparationAbort, error) {
	names, err := sshDirectoryNames(directory, 3)
	if err != nil || len(names) != 3 {
		return nil, sshPreparation{}, sshPreparationAbort{}, errors.Join(ErrInventoryUnsafe, err)
	}
	hashes := make(map[string]string)
	var prepared sshPreparation
	var terminal sshPreparationAbort
	for _, name := range names {
		if name != sshMarkerName && name != sshPreparedRecord && name != sshPreparationAbortName {
			return nil, prepared, terminal, ErrInventoryUnsafe
		}
		image, err := readSSHPrivateChild(directory, name, uid, maxSSHJournalBytes)
		if err != nil {
			return nil, prepared, terminal, err
		}
		hashes[name] = sshImageDigest(image)
		if name == sshPreparedRecord {
			prepared, err = decodeSSHPreparation(image.data, uid)
		} else if name == sshPreparationAbortName {
			err = json.Unmarshal(image.data, &terminal)
			canonical, marshalErr := json.Marshal(terminal)
			if marshalErr != nil || !bytes.Equal(canonical, image.data) {
				err = ErrInventoryUnsafe
			}
		}
		if err != nil {
			return nil, prepared, terminal, err
		}
	}
	encoded, err := json.Marshal(prepared)
	if err != nil || terminal.Schema != 1 || terminal.Transaction != prepared.Transaction || terminal.Prepared != digestBytes(encoded) {
		return nil, prepared, terminal, ErrInventoryChanged
	}
	if err := terminal.Original.validate(); err != nil {
		return nil, prepared, terminal, err
	}
	return hashes, prepared, terminal, nil
}

func attestSSHAbortedArchive(parent *os.File, r sshAbortedRetirement, uid, phase int) error {
	owner, err := r.validate(uid)
	if err != nil || phase < 0 || phase > 2 {
		return errors.Join(ErrInventoryUnsafe, err)
	}
	directoryName, ownerName := sshStateName, sshOwnerName
	if phase >= 1 {
		directoryName = r.name("")
	}
	if phase == 2 {
		ownerName = r.name(".owner.json")
	}
	if err := attestSSHStateDirectory(parent, directoryName, owner, uid, false); err != nil {
		return err
	}
	image, err := readSSHPrivateChild(parent, ownerName, uid, maxSSHOwnerBytes)
	if err != nil {
		return err
	}
	actual := recoveryImage(image)
	if phase == 2 {
		actual.Changed = r.Owner.Changed
	} // Only the receipt rename may change ctime.
	if !reflect.DeepEqual(actual, r.Owner) {
		return ErrInventoryChanged
	}
	fd, err := unix.Openat(int(parent.Fd()), directoryName, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	directory := os.NewFile(uintptr(fd), "ssh-retained-aborted-journal")
	defer directory.Close()
	hashes, prepared, _, err := observeSSHAbortedFiles(directory, uid)
	if err != nil || !reflect.DeepEqual(hashes, r.Files) || prepared.Transaction != r.Transaction || prepared.PlanSHA256 != r.Plan || prepared.ParserSHA256 != r.Parser {
		return errors.Join(ErrInventoryChanged, err)
	}
	return attestSSHStateDirectory(parent, directoryName, owner, uid, false)
}

func sshAbortedPhase(parent *os.File, r sshAbortedRetirement, uid int) (int, error) {
	for phase := 0; phase <= 2; phase++ {
		directoryAbsent, ownerAbsent := r.name(""), r.name(".owner.json")
		if phase >= 1 {
			directoryAbsent = sshStateName
		}
		if phase == 2 {
			ownerAbsent = sshOwnerName
		}
		if sshChildAbsent(parent, directoryAbsent) == nil && sshChildAbsent(parent, ownerAbsent) == nil {
			if err := attestSSHAbortedArchive(parent, r, uid, phase); err == nil {
				return phase, nil
			}
		}
	}
	return 0, ErrInventoryChanged
}

// Every interrupted retirement blocks provisioning until explicit completion.
// Completed evidence remains private and must retain its exact identities.
func checkSSHAbortedRetirements(parent *os.File, uid int) error {
	names, err := sshDirectoryNames(parent, MaxDirectoryEntries)
	if err != nil {
		return err
	}
	intents := make(map[string]bool)
	for _, name := range names {
		if strings.HasPrefix(name, sshAbortedPrefix) && strings.HasSuffix(name, ".intent.json") {
			if !validSSHAbortedReceiptName(name) {
				return ErrInventoryUnsafe
			}
			image, err := readSSHPrivateChild(parent, name, uid, maxSSHOwnerBytes)
			if err != nil {
				return err
			}
			r, err := decodeSSHAbortedRetirement(image.data, uid)
			if err != nil || name != r.name(".intent.json") {
				return errors.Join(ErrInventoryChanged, err)
			}
			completed, err := readSSHPrivateChild(parent, r.name(".complete.json"), uid, maxSSHOwnerBytes)
			if err != nil || !bytes.Equal(completed.data, image.data) {
				return errors.Join(ErrInventoryChanged, err)
			}
			if err := attestSSHAbortedArchive(parent, r, uid, 2); err != nil {
				return err
			}
			intents[r.Instance] = true
		}
	}
	for _, name := range names {
		if !strings.HasPrefix(name, sshAbortedPrefix) {
			continue
		}
		value := strings.TrimPrefix(name, sshAbortedPrefix)
		for _, suffix := range []string{".intent.json", ".complete.json", ".owner.json"} {
			value = strings.TrimSuffix(value, suffix)
		}
		if !lowerDigest.MatchString(value) || !intents[value] {
			return ErrInventoryUnsafe
		}
	}
	return nil
}

func retireSSHAbortedPreparation(ctx context.Context, root *os.File, uid int, instance, approved, parser string, run sshParserRun, parserCheck func() error, ops sshProvisionOps) error {
	if ctx == nil || run == nil || parserCheck == nil || ops.sync == nil || ops.rename == nil || !lowerDigest.MatchString(approved) || !lowerDigest.MatchString(parser) {
		return ErrInventoryUnsafe
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	parent, err := openSSHRetirementParent(root, uid, instance)
	if err != nil {
		return err
	}
	defer parent.Close()
	r := sshAbortedRetirement{Schema: 1, Instance: instance, Plan: approved, Parser: parser}
	receipt, err := readSSHPrivateChild(parent, r.name(".intent.json"), uid, maxSSHOwnerBytes)
	fresh := errors.Is(err, unix.ENOENT)
	if !fresh {
		if err != nil {
			return err
		}
		r, err = decodeSSHAbortedRetirement(receipt.data, uid)
		if err != nil || r.Instance != instance || r.Plan != approved || r.Parser != parser {
			return errors.Join(ErrInventoryChanged, err)
		}
	}
	directoryName := sshStateName
	if !fresh {
		phase, err := sshAbortedPhase(parent, r, uid)
		if err != nil {
			return err
		}
		if phase >= 1 {
			directoryName = r.name("")
		}
	}
	fd, err := unix.Openat(int(parent.Fd()), directoryName, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	directory := os.NewFile(uintptr(fd), "ssh-aborted-retirement-journal")
	defer directory.Close()
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return err
	}
	if fresh {
		original, err := verifySSHStateOwner(root, uid)
		if err != nil {
			return err
		}
		r.Owner = recoveryImage(original)
		hashes, prepared, _, err := observeSSHAbortedFiles(directory, uid)
		if err != nil {
			return err
		}
		r.Files, r.Transaction = hashes, prepared.Transaction
	}
	return finishSSHAbortedRetirement(ctx, root, parent, directory, uid, r, fresh, run, parserCheck, ops)
}

func finishSSHAbortedRetirement(ctx context.Context, root, parent, directory *os.File, uid int, r sshAbortedRetirement, fresh bool, run sshParserRun, parserCheck func() error, ops sshProvisionOps) error {
	owner, err := r.validate(uid)
	if err != nil {
		return err
	}
	_, prepared, terminal, err := observeSSHAbortedFiles(directory, uid)
	if err != nil {
		return err
	}
	plan, err := inspectPlan(root, uid)
	if err != nil || plan.summary.PlanSHA256 != r.Plan || plan.intent.Owner != "syswarden" {
		return errors.Join(ErrInventoryChanged, err)
	}
	record, err := json.Marshal(r)
	if err != nil {
		return err
	}
	hasIntent := !fresh
	guard := func() error {
		if err := errors.Join(ctx.Err(), parserCheck(), recheckSSHStateParent(root, parent, uid, owner.Parent)); err != nil {
			return err
		}
		if _, err := sshAbortedPhase(parent, r, uid); err != nil {
			return err
		}
		if hasIntent {
			image, err := readSSHPrivateChild(parent, r.name(".intent.json"), uid, maxSSHOwnerBytes)
			if err != nil || !bytes.Equal(image.data, record) {
				return errors.Join(ErrInventoryChanged, err)
			}
		} else if err := sshChildAbsent(parent, r.name(".intent.json")); err != nil {
			return err
		}
		snapshot, err := collectSSHRollback(root, uid, r.Transaction)
		if err != nil || !reflect.DeepEqual(snapshot, terminal.Original) {
			return errors.Join(ErrInventoryChanged, err)
		}
		current, err := collectPlanInventory(root, uid)
		if err != nil || !reflect.DeepEqual(current, plan.inventory) {
			return errors.Join(ErrInventoryChanged, err)
		}
		return nil
	}
	// Recompute the canonical abort: the retained record is evidence, not a
	// substitute for verifying the original plan, parser and absent stage names.
	current, err := collectSSHRollback(root, uid, r.Transaction)
	mainStage, stageErr := sshMainStagePath(r.Transaction)
	dropStage, dropErr := sshDropStagePath(r.Transaction)
	if err != nil || stageErr != nil || dropErr != nil || !matchesSSHRecovery(current, MainPath, prepared.MainBefore) ||
		current.Nodes[MainPath].Changed != prepared.MainBefore.Changed || current.Nodes[DropInPath] != (sshStoredStamp{}) ||
		current.Nodes[mainStage] != (sshStoredStamp{}) || current.Nodes[dropStage] != (sshStoredStamp{}) ||
		!bytes.Equal(plan.main, prepared.MainAfter.Data) || !bytes.Equal(plan.candidate.Bytes(), prepared.DropIn.Data) {
		return errors.Join(ErrInventoryChanged, err, stageErr, dropErr)
	}
	if err := verifySSHOriginal(ctx, plan, run, guard); err != nil {
		return err
	}
	complete, completeErr := readSSHPrivateChild(parent, r.name(".complete.json"), uid, maxSSHOwnerBytes)
	if !errors.Is(completeErr, unix.ENOENT) && (completeErr != nil || !bytes.Equal(complete.data, record)) {
		return errors.Join(ErrInventoryChanged, completeErr)
	}
	if completeErr == nil {
		phase, err := sshAbortedPhase(parent, r, uid)
		if fresh || err != nil || phase != 2 {
			return ErrInventoryChanged
		}
	}
	// The terminal record may be visible after an uncertain journal sync.
	// Sync the held journal itself before making retained custody durable;
	// syncing only its parent would not establish durability of its entries.
	if err := ops.sync(directory); err != nil {
		return err
	}
	if err := guard(); err != nil {
		return err
	}
	if fresh {
		if _, err := writeSSHPrivateChild(parent, r.name(".intent.json"), record, uid, ops.sync); err != nil {
			return err
		}
		hasIntent = true
	}
	// Every resumed call repairs visible intent/rename durability before moving
	// the next name. A completed record alone is not proof of successful fsync.
	for target := 1; target <= 2; target++ {
		if err := ops.sync(parent); err != nil {
			return err
		}
		if err := guard(); err != nil {
			return err
		}
		phase, err := sshAbortedPhase(parent, r, uid)
		if err != nil {
			return err
		}
		if phase >= target {
			continue
		}
		from, to := sshStateName, r.name("")
		if target == 2 {
			from, to = sshOwnerName, r.name(".owner.json")
		}
		if err := ops.rename(int(parent.Fd()), from, int(parent.Fd()), to, unix.RENAME_NOREPLACE); err != nil {
			return err
		}
		if err := guard(); err != nil {
			return err
		}
	}
	if err := ops.sync(parent); err != nil {
		return err
	}
	if err := guard(); err != nil {
		return err
	}
	if errors.Is(completeErr, unix.ENOENT) {
		if _, err := writeSSHPrivateChild(parent, r.name(".complete.json"), record, uid, ops.sync); err != nil {
			return err
		}
	}
	if err := ops.sync(parent); err != nil {
		return fmt.Errorf("SSH aborted retirement durability is uncertain: %w", err)
	}
	return errors.Join(guard(), checkSSHAbortedRetirements(parent, uid))
}
