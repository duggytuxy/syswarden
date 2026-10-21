//go:build linux

package sshpolicy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const sshRestoredPrefix = ".ssh-policy-restored-"

// A restored journal can leave active transaction storage only after its
// complete forward and inverse history, live parser results and retained
// candidate inodes have been verified. Candidates stay on their original
// filesystem at the isolated recovery names. Nothing is deleted or copied.
type sshRestoredRetirement struct {
	Schema      int               `json:"schema"`
	Instance    string            `json:"instance"`
	Transaction string            `json:"transaction"`
	Plan        string            `json:"plan_sha256"`
	Parser      string            `json:"parser_sha256"`
	Owner       sshRecoveryImage  `json:"owner"`
	Files       map[string]string `json:"files"`
}

func (r sshRestoredRetirement) name(suffix string) string {
	return sshRestoredPrefix + r.Instance + suffix
}

func validSSHRestoredReceiptName(name string) bool {
	for _, suffix := range []string{".intent.json", ".complete.json"} {
		if strings.HasPrefix(name, sshRestoredPrefix) && strings.HasSuffix(name, suffix) &&
			lowerDigest.MatchString(strings.TrimSuffix(strings.TrimPrefix(name, sshRestoredPrefix), suffix)) {
			return true
		}
	}
	return false
}

func (r sshRestoredRetirement) validate(uid int) (sshStateOwner, error) {
	if r.Schema != 1 || !lowerDigest.MatchString(r.Instance) || !lowerDigest.MatchString(r.Transaction) ||
		!lowerDigest.MatchString(r.Plan) || !lowerDigest.MatchString(r.Parser) || len(r.Files) < 8 || len(r.Files) > 13 {
		return sshStateOwner{}, ErrInventoryUnsafe
	}
	if err := r.Owner.validate(uid, 1); err != nil {
		return sshStateOwner{}, err
	}
	if r.Owner.Mode&07777 != 0600 || int64(r.Owner.GID) != int64(uid) {
		return sshStateOwner{}, ErrInventoryUnsafe
	}
	for name, digest := range r.Files {
		if !restoredSSHRecordName(name) || !lowerDigest.MatchString(digest) {
			return sshStateOwner{}, ErrInventoryUnsafe
		}
	}
	required := []string{sshMarkerName, sshPreparedRecord, sshPublicationName(1, false), sshRollbackStartName}
	for step := 1; step <= 2; step++ {
		required = append(required, sshRollbackName(step, false), sshRollbackName(step, true))
	}
	for _, name := range required {
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

func decodeSSHRestoredRetirement(data []byte, uid int) (sshRestoredRetirement, error) {
	var r sshRestoredRetirement
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

func restoredSSHRecordName(name string) bool {
	return name == sshMarkerName || (sshRecordName(name) && name != sshPreparationAbortName && name != sshActivationIntentName)
}

func observeSSHRestoredFiles(directory *os.File, uid int) (map[string]string, sshPreparation, error) {
	names, err := sshDirectoryNames(directory, 13)
	if err != nil || len(names) < 8 {
		return nil, sshPreparation{}, errors.Join(ErrInventoryUnsafe, err)
	}
	hashes := make(map[string]string)
	var prepared sshPreparation
	for _, name := range names {
		if !restoredSSHRecordName(name) {
			return nil, prepared, ErrInventoryUnsafe
		}
		image, err := readSSHPrivateChild(directory, name, uid, maxSSHJournalBytes)
		if err != nil {
			return nil, prepared, err
		}
		hashes[name] = sshImageDigest(image)
		if name == sshPreparedRecord {
			prepared, err = decodeSSHPreparation(image.data, uid)
			if err != nil {
				return nil, prepared, err
			}
		}
	}
	return hashes, prepared, prepared.validate(uid)
}

// This read-only capability allows the existing history validators to inspect
// an original directory during either rename. It cannot authorize publication,
// rollback or new records, even while the directory still has its active name.
type sshRetainedJournal struct {
	parent    *os.File
	record    sshRestoredRetirement
	completed bool
}

func (retained *sshRetainedJournal) recheck(journal *sshJournal) error {
	owner, err := retained.record.validate(journal.uid)
	if err != nil {
		return err
	}
	actual, err := sshDirectoryImage(journal.directory, journal.uid)
	if err != nil || !reflect.DeepEqual(actual, owner.Directory) {
		return errors.Join(ErrInventoryChanged, err)
	}
	if err := recheckSSHStateParent(journal.root, retained.parent, journal.uid, owner.Parent); err != nil {
		return err
	}
	if retained.completed {
		data, err := json.Marshal(retained.record)
		if err != nil {
			return err
		}
		for _, suffix := range []string{".intent.json", ".complete.json"} {
			image, err := readSSHPrivateChild(retained.parent, retained.record.name(suffix), journal.uid, maxSSHOwnerBytes)
			if err != nil || !bytes.Equal(image.data, data) {
				return errors.Join(ErrInventoryChanged, err)
			}
		}
		return attestSSHRestoredArchive(retained.parent, retained.record, journal.uid, 2)
	}
	_, err = sshRestoredPhase(retained.parent, retained.record, journal.uid)
	return err
}

func attestSSHRestoredArchive(parent *os.File, r sshRestoredRetirement, uid, phase int) error {
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
	}
	if !reflect.DeepEqual(actual, r.Owner) {
		return ErrInventoryChanged
	}
	directory, err := openSSHRetainedDirectory(parent, directoryName)
	if err != nil {
		return err
	}
	defer directory.Close()
	hashes, prepared, err := observeSSHRestoredFiles(directory, uid)
	if err != nil || !reflect.DeepEqual(hashes, r.Files) || prepared.Transaction != r.Transaction ||
		prepared.PlanSHA256 != r.Plan || prepared.ParserSHA256 != r.Parser {
		return errors.Join(ErrInventoryChanged, err)
	}
	return attestSSHStateDirectory(parent, directoryName, owner, uid, false)
}

func openSSHRetainedDirectory(parent *os.File, name string) (*os.File, error) {
	fd, err := unix.Openat(int(parent.Fd()), name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), "ssh-retained-restored-journal"), nil
}

func sshRestoredPhase(parent *os.File, r sshRestoredRetirement, uid int) (int, error) {
	for phase := 0; phase <= 2; phase++ {
		directoryAbsent, ownerAbsent := r.name(""), r.name(".owner.json")
		if phase >= 1 {
			directoryAbsent = sshStateName
		}
		if phase == 2 {
			ownerAbsent = sshOwnerName
		}
		if sshChildAbsent(parent, directoryAbsent) == nil && sshChildAbsent(parent, ownerAbsent) == nil {
			if err := attestSSHRestoredArchive(parent, r, uid, phase); err == nil {
				return phase, nil
			}
		}
	}
	return 0, ErrInventoryChanged
}

// Rebuild and verify every transition, not just the final completion filename.
func inspectSSHRestoredHistory(journal *sshJournal) (migrationPlan, sshStoredInventory, error) {
	prepared, err := journal.read()
	if err != nil {
		return migrationPlan{}, sshStoredInventory{}, err
	}
	data, err := json.Marshal(prepared)
	if err != nil {
		return migrationPlan{}, sshStoredInventory{}, err
	}
	digest := digestBytes(data)
	plan, err := recoverSSHPlan(journal, prepared, digest)
	if err != nil {
		return plan, sshStoredInventory{}, err
	}
	start, err := journal.readRollbackStart(prepared, digest)
	if err != nil {
		return plan, sshStoredInventory{}, err
	}
	terminal, err := journal.readSSHPhase(sshRollbackName(2, true), 2, true, prepared, digest)
	if err != nil || terminal.After == nil {
		return plan, sshStoredInventory{}, errors.Join(ErrInventoryChanged, err)
	}
	position, _, err := matchSSHRollback(journal, prepared, start, *terminal.After)
	if err != nil || position != (sshPublicationPosition{2, "complete"}) ||
		!matchesSSHRecovery(*terminal.After, MainPath, prepared.MainBefore) ||
		terminal.After.Nodes[DropInPath] != (sshStoredStamp{}) {
		return plan, sshStoredInventory{}, errors.Join(ErrInventoryChanged, err)
	}
	return plan, *terminal.After, journal.recheck()
}

// Only the retained candidate paths are compared here. Later transactions may
// legitimately change active SSH configuration, but cannot adopt, modify or
// make an old candidate part of any Include graph.
func checkSSHRetainedCandidates(root *os.File, uid int, transaction string, expected sshStoredInventory) error {
	current, err := collectSSHRollback(root, uid, transaction)
	if err != nil {
		return err
	}
	mainStage, err := sshMainStagePath(transaction)
	if err != nil {
		return err
	}
	dropStage, err := sshDropStagePath(transaction)
	if err != nil {
		return err
	}
	for _, name := range []string{mainStage, dropStage} {
		if current.Nodes[name] != expected.Nodes[name] || !bytes.Equal(current.Files[name], expected.Files[name]) ||
			!reflect.DeepEqual(current.Attributes[name], expected.Attributes[name]) {
			return ErrInventoryChanged
		}
	}
	snapshot, err := collectPlanInventory(root, uid)
	if err != nil {
		return err
	}
	return checkSSHStageIsolation(snapshot, nil, transaction)
}

func checkSSHRestoredRetirements(root, parent *os.File, uid int) error {
	names, err := sshDirectoryNames(parent, MaxDirectoryEntries)
	if err != nil {
		return err
	}
	intents := make(map[string]bool)
	for _, name := range names {
		if !strings.HasPrefix(name, sshRestoredPrefix) || !strings.HasSuffix(name, ".intent.json") {
			continue
		}
		if !validSSHRestoredReceiptName(name) {
			return ErrInventoryUnsafe
		}
		image, err := readSSHPrivateChild(parent, name, uid, maxSSHOwnerBytes)
		if err != nil {
			return err
		}
		r, err := decodeSSHRestoredRetirement(image.data, uid)
		if err != nil || name != r.name(".intent.json") {
			return errors.Join(ErrInventoryChanged, err)
		}
		complete, err := readSSHPrivateChild(parent, r.name(".complete.json"), uid, maxSSHOwnerBytes)
		if err != nil || !bytes.Equal(complete.data, image.data) {
			return errors.Join(ErrInventoryChanged, err)
		}
		if err := attestSSHRestoredArchive(parent, r, uid, 2); err != nil {
			return err
		}
		// Once completed, another active journal is allowed. Read history from
		// the retained original with archive-only custody, never active slots.
		if err := checkSSHCompletedRestoration(root, parent, uid, r); err != nil {
			return err
		}
		intents[r.Instance] = true
	}
	for _, name := range names {
		if !strings.HasPrefix(name, sshRestoredPrefix) {
			continue
		}
		value := strings.TrimPrefix(name, sshRestoredPrefix)
		for _, suffix := range []string{".intent.json", ".complete.json", ".owner.json"} {
			value = strings.TrimSuffix(value, suffix)
		}
		if !lowerDigest.MatchString(value) || !intents[value] {
			return ErrInventoryUnsafe
		}
	}
	return nil
}

func checkSSHCompletedRestoration(root, parent *os.File, uid int, r sshRestoredRetirement) error {
	directory, err := openSSHRetainedDirectory(parent, r.name(""))
	if err != nil {
		return err
	}
	defer directory.Close()
	journal := &sshJournal{root: root, directory: directory, uid: uid,
		retained: &sshRetainedJournal{parent: parent, record: r, completed: true}}
	_, terminal, err := inspectSSHRestoredHistory(journal)
	if err != nil {
		return err
	}
	return errors.Join(checkSSHRetainedCandidates(root, uid, r.Transaction, terminal), journal.recheck())
}

func retireSSHRestoredTransaction(ctx context.Context, root *os.File, uid int, instance, approved, parser string, run sshParserRun, parserCheck func() error, ops sshProvisionOps) error {
	if ctx == nil || run == nil || parserCheck == nil || ops.sync == nil || ops.rename == nil ||
		!lowerDigest.MatchString(approved) || !lowerDigest.MatchString(parser) {
		return ErrInventoryUnsafe
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	parent, err := openSSHRetirementParent(root, uid, instance)
	if err != nil {
		return err
	}
	defer parent.Close()
	r := sshRestoredRetirement{Schema: 1, Instance: instance, Plan: approved, Parser: parser}
	receipt, err := readSSHPrivateChild(parent, r.name(".intent.json"), uid, maxSSHOwnerBytes)
	fresh := errors.Is(err, unix.ENOENT)
	if !fresh {
		if err != nil {
			return err
		}
		r, err = decodeSSHRestoredRetirement(receipt.data, uid)
		if err != nil || r.Instance != instance || r.Plan != approved || r.Parser != parser {
			return errors.Join(ErrInventoryChanged, err)
		}
	}
	directoryName := sshStateName
	if !fresh {
		phase, err := sshRestoredPhase(parent, r, uid)
		if err != nil {
			return err
		}
		if phase >= 1 {
			directoryName = r.name("")
		}
	}
	directory, err := openSSHRetainedDirectory(parent, directoryName)
	if err != nil {
		return err
	}
	defer directory.Close()
	if err := unix.Flock(int(directory.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return err
	}
	if fresh {
		original, err := verifySSHStateOwner(root, uid)
		if err != nil {
			return err
		}
		r.Owner = recoveryImage(original)
		hashes, prepared, err := observeSSHRestoredFiles(directory, uid)
		if err != nil {
			return err
		}
		r.Files, r.Transaction = hashes, prepared.Transaction
	}
	return finishSSHRestoredRetirement(ctx, root, parent, directory, uid, r, fresh, run, parserCheck, ops)
}

func finishSSHRestoredRetirement(ctx context.Context, root, parent, directory *os.File, uid int, r sshRestoredRetirement, fresh bool, run sshParserRun, parserCheck func() error, ops sshProvisionOps) error {
	owner, err := r.validate(uid)
	if err != nil {
		return err
	}
	journal := &sshJournal{root: root, directory: directory, uid: uid, retained: &sshRetainedJournal{parent: parent, record: r}}
	plan, expected, err := inspectSSHRestoredHistory(journal)
	if err != nil {
		return err
	}
	record, err := json.Marshal(r)
	if err != nil {
		return err
	}
	hasIntent := !fresh
	guard := func() error {
		if err := errors.Join(ctx.Err(), parserCheck(), journal.recheck(),
			recheckSSHStateParent(root, parent, uid, owner.Parent)); err != nil {
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
		current, err := collectSSHRollback(root, uid, r.Transaction)
		if err != nil || !reflect.DeepEqual(current, expected) {
			return errors.Join(ErrInventoryChanged, err)
		}
		return checkSSHRetainedCandidates(root, uid, r.Transaction, expected)
	}
	if err := verifySSHOriginal(ctx, plan, run, guard); err != nil {
		return err
	}
	complete, completeErr := readSSHPrivateChild(parent, r.name(".complete.json"), uid, maxSSHOwnerBytes)
	if !errors.Is(completeErr, unix.ENOENT) && (completeErr != nil || !bytes.Equal(complete.data, record)) {
		return errors.Join(ErrInventoryChanged, completeErr)
	}
	if completeErr == nil {
		phase, err := sshRestoredPhase(parent, r, uid)
		if fresh || err != nil || phase != 2 {
			return ErrInventoryChanged
		}
	}
	// Repair uncertainty in the retained terminal records before transferring
	// custody. A completed inverse operation never proves successful fsync.
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
	for target := 1; target <= 2; target++ {
		if err := ops.sync(parent); err != nil {
			return err
		}
		if err := guard(); err != nil {
			return err
		}
		phase, err := sshRestoredPhase(parent, r, uid)
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
		return fmt.Errorf("SSH restored retirement durability is uncertain: %w", err)
	}
	return errors.Join(guard(), checkSSHRestoredRetirements(root, parent, uid))
}
