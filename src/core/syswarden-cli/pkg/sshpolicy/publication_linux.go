//go:build linux

package sshpolicy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"reflect"

	"golang.org/x/sys/unix"
)

// Publication remains internal until activation, rollback and the shared
// installation/removal adapter are complete. Three ordered filesystem writes
// are not an atomic two-file update and do not establish a successful login.
type sshPublicationRecord struct {
	Schema      int                 `json:"schema"`
	Transaction string              `json:"transaction"`
	Prepared    string              `json:"prepared_sha256"`
	Step        int                 `json:"step"`
	Before      sshStoredInventory  `json:"before"`
	After       *sshStoredInventory `json:"after"`
}

type sshPublicationOps struct {
	sync   func(*os.File) error
	link   func(int, string, int, string, int) error
	rename func(int, string, int, string, uint) error
}

func sshPublicationDefaults() sshPublicationOps {
	return sshPublicationOps{(*os.File).Sync, unix.Linkat, unix.Renameat2}
}

func sshPublicationName(step int, done bool) string {
	suffix := "intent"
	if done {
		suffix = "complete"
	}
	return fmt.Sprintf("publish-%02d-%s.json", step, suffix)
}

func (journal *sshJournal) writePublication(record sshPublicationRecord, done bool) error {
	if record.Schema != 1 || record.Step < 1 || record.Step > 3 ||
		!lowerDigest.MatchString(record.Transaction) || !lowerDigest.MatchString(record.Prepared) ||
		(record.After != nil) != done {
		return ErrInventoryUnsafe
	}
	if err := record.Before.validate(); err != nil {
		return err
	}
	if record.After != nil {
		if err := record.After.validate(); err != nil {
			return err
		}
	}
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	return journal.writeRecord(sshPublicationName(record.Step, done), data)
}

func (journal *sshJournal) readPublication(step int, done bool, prepared sshPreparation, digest string) (sshPublicationRecord, error) {
	data, err := journal.readRecord(sshPublicationName(step, done))
	if err != nil {
		return sshPublicationRecord{}, err
	}
	var record sshPublicationRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return sshPublicationRecord{}, ErrInventoryUnsafe
	}
	canonical, err := json.Marshal(record)
	if err != nil || !bytes.Equal(data, canonical) || record.Schema != 1 || record.Step != step ||
		record.Transaction != prepared.Transaction || record.Prepared != digest || (record.After != nil) != done {
		return sshPublicationRecord{}, ErrInventoryUnsafe
	}
	if err := record.Before.validate(); err != nil {
		return sshPublicationRecord{}, err
	}
	if record.After != nil {
		if err := record.After.validate(); err != nil {
			return sshPublicationRecord{}, err
		}
	}
	return record, nil
}

// publishSSHConfiguration verifies the installed parser again before the first
// write. Caller-owned descriptors, private journal and approved plan must refer
// to exactly the same preparation. Any partial failure retains all artifacts,
// poisons this handle, and requires inspection rather than blind retry.
func publishSSHConfiguration(ctx context.Context, journal *sshJournal, plan migrationPlan,
	main, drop *sshAnonymousStage, run sshParserRun, parserCheck func() error, ops sshPublicationOps) (err error) {
	if journal == nil || main == nil || drop == nil || run == nil || parserCheck == nil ||
		ops.sync == nil || ops.link == nil || ops.rename == nil || ctx == nil {
		return ErrInventoryUnsafe
	}
	record, err := journal.read()
	if err != nil {
		return err
	}
	if record.PlanSHA256 != plan.summary.PlanSHA256 || record.PlanSHA256 != planDigest(plan) ||
		plan.intent.Owner != "syswarden" || !bytes.Equal(record.MainAfter.Data, plan.main) ||
		!bytes.Equal(record.DropIn.Data, plan.candidate.Bytes()) ||
		!matchesSSHRecovery(storeSSHInventory(plan.inventory), MainPath, record.MainBefore) ||
		record.MainBefore.Changed != plan.inventory.nodes[MainPath].changed {
		return ErrInventoryChanged
	}
	if err := checkSSHPublicationIsolation(plan, record.Transaction); err != nil {
		return err
	}
	for i, candidate := range []*sshAnonymousStage{main, drop} {
		image, readErr := readSSHImage(candidate.file, journal.uid, 0, MaxBytes)
		want := record.MainAfter
		if i == 1 {
			want = record.DropIn
		}
		if readErr != nil || !reflect.DeepEqual(recoveryImage(image), want) {
			return errors.Join(ErrInventoryChanged, readErr)
		}
	}
	if err := journal.requireNoPublicationRecords(); err != nil {
		return err
	}
	stage, err := sshMainStagePath(record.Transaction)
	if err != nil {
		return err
	}
	guard := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := journal.recheck(); err != nil {
			return err
		}
		current, err := stableSSHPublication(journal.root, journal.uid, stage)
		if err != nil {
			return err
		}
		return errors.Join(checkSSHInitialPublication(current, plan, stage), parserCheck())
	}
	if _, err := verifyPlan(ctx, plan, record.ParserSHA256, run, guard); err != nil {
		return err
	}
	before, err := stableSSHPublication(journal.root, journal.uid, stage)
	if err != nil {
		return err
	}
	if err := checkSSHInitialPublication(before, plan, stage); err != nil {
		return err
	}
	if err := checkSSHPublicationBudget(before, record, stage); err != nil {
		return err
	}
	preparedBytes, err := json.Marshal(record)
	if err != nil {
		return err
	}
	// From the first durable intent onward every error needs recovery.
	defer func() {
		if err != nil {
			journal.poisoned = true
		}
	}()
	for step := 1; step <= 3; step++ {
		phase := sshPublicationRecord{1, record.Transaction, digestBytes(preparedBytes), step, before, nil}
		before, err = executeSSHPublication(ctx, journal, phase, record, stage, main, drop, parserCheck, ops)
		if err != nil {
			return fmt.Errorf("SSH publication step %d requires recovery; all evidence is retained: %w", step, err)
		}
	}
	if err := verifyPublishedSSH(ctx, journal, plan, stage, before, run, parserCheck); err != nil {
		return fmt.Errorf("SSH configuration is published but live verification failed; retain evidence for recovery: %w", err)
	}
	return nil
}

func (journal *sshJournal) requireNoPublicationRecords() error {
	for step := 1; step <= 3; step++ {
		for _, done := range []bool{false, true} {
			_, err := journal.readRecord(sshPublicationName(step, done))
			if !errors.Is(err, unix.ENOENT) {
				return errors.Join(fmt.Errorf("SSH publication already has evidence; inspect recovery"), err)
			}
		}
	}
	return nil
}

func executeSSHPublication(ctx context.Context, journal *sshJournal, phase sshPublicationRecord,
	record sshPreparation, stage string, main, drop *sshAnonymousStage,
	parserCheck func() error, ops sshPublicationOps) (sshStoredInventory, error) {
	if err := journal.writePublication(phase, false); err != nil {
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
	defer parent.Close()
	current, err := stableSSHPublication(journal.root, journal.uid, stage)
	if err != nil || !reflect.DeepEqual(current, phase.Before) {
		return sshStoredInventory{}, errors.Join(ErrInventoryChanged, err)
	}
	if err := errors.Join(ctx.Err(), journal.recheck(), parserCheck()); err != nil {
		return sshStoredInventory{}, err
	}
	// The held directory was opened before the final complete inventory.
	if reader.state.nodes[directory] != inventoryNode(phase.Before.Nodes[directory]) {
		return sshStoredInventory{}, ErrInventoryChanged
	}
	if phase.Step < 3 {
		candidate, expected := main, record.MainAfter
		if phase.Step == 2 {
			candidate, expected = drop, record.DropIn
		}
		image, err := readSSHImage(candidate.file, journal.uid, 0, MaxBytes)
		if err != nil || !reflect.DeepEqual(recoveryImage(image), expected) {
			return sshStoredInventory{}, errors.Join(ErrInventoryChanged, err)
		}
	}
	switch phase.Step {
	case 1:
		err = ops.link(unix.AT_FDCWD, fmt.Sprintf("/proc/self/fd/%d", main.file.Fd()),
			int(parent.Fd()), path.Base(stage), unix.AT_SYMLINK_FOLLOW)
	case 2:
		err = ops.link(unix.AT_FDCWD, fmt.Sprintf("/proc/self/fd/%d", drop.file.Fd()),
			int(parent.Fd()), path.Base(DropInPath), unix.AT_SYMLINK_FOLLOW)
	case 3:
		// Exchange preserves the displaced inode even if an administrator
		// races us. The following inventory check refuses unexpected changes;
		// no automatic deletion or blind compensating write is performed.
		err = ops.rename(int(parent.Fd()), path.Base(stage), int(parent.Fd()), path.Base(MainPath), unix.RENAME_EXCHANGE)
	default:
		return sshStoredInventory{}, ErrInventoryUnsafe
	}
	if err != nil {
		return sshStoredInventory{}, err
	}
	if err := ops.sync(parent); err != nil {
		return sshStoredInventory{}, err
	}
	after, err := stableSSHPublication(journal.root, journal.uid, stage)
	if err != nil {
		return sshStoredInventory{}, err
	}
	if err := errors.Join(checkSSHTransition(phase.Before, after, record, phase.Step), parserCheck(), ctx.Err()); err != nil {
		return sshStoredInventory{}, err
	}
	phase.After = &after
	if err := journal.writePublication(phase, true); err != nil {
		return sshStoredInventory{}, err
	}
	final, err := stableSSHPublication(journal.root, journal.uid, stage)
	if err != nil || !reflect.DeepEqual(final, after) {
		return sshStoredInventory{}, errors.Join(ErrInventoryChanged, err)
	}
	return after, nil
}

func inventoryNode(n sshStoredStamp) inventoryStamp {
	return inventoryStamp{n.Exists, n.Device, n.Inode, n.Links, n.Mode, n.UID, n.GID, n.Size, n.Modified, n.Changed}
}

func verifyPublishedSSH(ctx context.Context, journal *sshJournal, plan migrationPlan, stage string,
	expected sshStoredInventory, run sshParserRun, parserCheck func() error) error {
	files := make(map[string][]byte, len(plan.inventory.files))
	for name, data := range plan.inventory.files {
		if name != IntentPath {
			files[name] = data
		}
	}
	files[MainPath], files[DropInPath] = plan.main, plan.candidate.Bytes()
	image, err := newParserImage(files)
	if err != nil {
		return err
	}
	defer image.Close()
	guard := func() error {
		current, err := stableSSHPublication(journal.root, journal.uid, stage)
		if err != nil || !reflect.DeepEqual(current, expected) {
			return errors.Join(ErrInventoryChanged, err)
		}
		return errors.Join(ctx.Err(), journal.recheck(), parserCheck())
	}
	invoke := func(input *parserImage, mode, access string) ([]byte, error) {
		if err := guard(); err != nil {
			return nil, err
		}
		output, runErr := run(ctx, input, mode, access)
		return output, errors.Join(runErr, guard())
	}
	if _, err := invoke(nil, "syntax", ""); err != nil {
		return err
	}
	contexts := []string{""}
	for _, access := range plan.intent.Contexts {
		contexts = append(contexts, access.sshdArgument())
	}
	for _, access := range contexts {
		live, liveErr := invoke(nil, "effective", access)
		sealed, sealedErr := invoke(image, "effective", access)
		if err := errors.Join(liveErr, sealedErr); err != nil {
			return err
		}
		actual, actualErr := parseEffective(live)
		wanted, wantedErr := parseEffective(sealed)
		if err := errors.Join(actualErr, wantedErr); err != nil {
			return err
		}
		if err := errors.Join(compareEffective(actual, wanted, nil), plan.candidate.CheckEffective(live)); err != nil {
			return err
		}
	}
	return guard()
}
