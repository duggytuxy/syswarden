//go:build linux

package config

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
)

type moduleEditJournal struct {
	state    *moduleProposalState
	intent   *moduleEditIntent
	identity *secureFileIdentity
	// Tests may stop a child process at actual persisted states. Production
	// has no callback and never invokes an external command here.
	persisted      func(string)
	recoveryInputs func() error
}

func newModuleEditJournal(state *moduleProposalState) *moduleEditJournal {
	return &moduleEditJournal{state: state}
}

func (journal *moduleEditJournal) hooks() *configReplacementHooks {
	return &configReplacementHooks{
		prepare: journal.prepare, verify: journal.verify,
		commit:   func() error { return journal.transition("committed") },
		rollback: func() error { return journal.transition("rolled_back") },
		finish:   journal.finish,
	}
}

func (journal *moduleEditJournal) verify() error {
	if journal == nil || journal.state == nil || journal.state.snapshot == nil {
		return errors.New("configuration edit journal is unavailable")
	}
	snapshot := journal.state.snapshot
	expectedRoot, err := moduleEditDirectoryFrom(snapshot.configRootInfo)
	if err != nil {
		return err
	}
	expectedModules, err := moduleEditDirectoryFrom(snapshot.modulesRootInfo)
	if err != nil {
		return err
	}
	if err := recheckModuleEditDirectoryPath(journal.state.root, expectedRoot); err != nil {
		return err
	}
	if err := recheckModuleEditDirectoryPath(filepath.Join(journal.state.root, "modules"), expectedModules); err != nil {
		return err
	}
	root, err := openConfigDirectory(journal.state.root, false, 0)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	if journal.identity == nil {
		if _, err := root.Lstat(moduleEditIntentName); !errors.Is(err, fs.ErrNotExist) {
			return errors.New("configuration edit intent appeared; preserve it for recovery")
		}
		return nil
	}
	raw, info, err := readSecureRegularFileSnapshotBounded(root, moduleEditIntentName, moduleEditIntentName, maximumModuleEditIntentSize)
	if err != nil {
		return err
	}
	if !journal.identity.matches(raw, info) || !sameSecureFileMetadata(journal.identity.info, info) {
		return errors.New("configuration edit journal metadata changed; preserve evidence")
	}
	return nil
}

func (journal *moduleEditJournal) prepare(stage string, candidate *secureFileIdentity) error {
	if journal.intent != nil || journal.identity != nil {
		return errors.New("configuration edit journal was already prepared")
	}
	intent, err := newModuleEditIntent(journal.state, stage, candidate)
	if err != nil {
		return err
	}
	if err := journal.verify(); err != nil {
		return err
	}
	if err := journal.write(intent); err != nil {
		return err
	}
	return nil
}

func (journal *moduleEditJournal) transition(state string) error {
	if journal.intent == nil || journal.identity == nil || journal.intent.State != "prepared" || (state != "committed" && state != "rolled_back") {
		return errors.New("configuration edit state transition is invalid")
	}
	next := *journal.intent
	next.State = state
	// Diagnose the actual pair before granting committed or rollback cleanup.
	observed, err := observeModuleEdit(context.Background(), journal.state.root)
	if err != nil {
		return err
	}
	expected := "published_pending"
	if state == "rolled_back" {
		expected = "prepared"
	}
	if observed.observation.State != expected || observed.intent.ApprovalID != journal.intent.ApprovalID ||
		!sameUserModuleIdentity(journal.identity, observed.identity) || (state == "committed" && observed.observation.InputsChanged) {
		return errors.New("configuration edit pair or inputs do not permit the requested journal transition")
	}
	return journal.write(&next)
}

func (journal *moduleEditJournal) write(next *moduleEditIntent) error {
	raw, err := encodeModuleEditIntent(next)
	if err != nil {
		return err
	}
	expected := journal.identity
	if err := replaceSecureConfigFile(journal.state.root, moduleEditIntentName, raw, expected, journal.verify, nil, nil); err != nil {
		return err
	}
	root, err := openConfigDirectory(journal.state.root, false, 0)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	current, info, err := readSecureRegularFileSnapshotBounded(root, moduleEditIntentName, moduleEditIntentName, maximumModuleEditIntentSize)
	if err != nil {
		return err
	}
	if !bytes.Equal(raw, current) || info.Mode() != 0600 {
		return errors.New("configuration edit journal changed after persistence")
	}
	journal.intent = next
	journal.identity = newSecureFileIdentity(raw, info)
	if err := journal.verify(); err != nil {
		return err
	}
	if journal.persisted != nil {
		journal.persisted(next.State)
	}
	return nil
}

func (journal *moduleEditJournal) finish() error {
	if journal.intent == nil || journal.identity == nil || (journal.intent.State != "committed" && journal.intent.State != "rolled_back") {
		return errors.New("configuration edit finalization requires a durable terminal record")
	}
	if err := journal.verify(); err != nil {
		return err
	}
	observed, err := observeModuleEdit(context.Background(), journal.state.root)
	if err != nil {
		return err
	}
	expected := "committed_cleanup"
	if journal.intent.State == "rolled_back" {
		expected = "rolled_back_cleanup"
	}
	if observed.observation.State != expected || !sameUserModuleIdentity(journal.identity, observed.identity) {
		return errors.New("configuration edit finalization pair changed; record retained")
	}
	if journal.intent.State == "committed" && observed.observation.InputsChanged && journal.recoveryInputs == nil {
		return errors.New("configuration inputs changed before finalization; record retained")
	}
	if journal.recoveryInputs != nil {
		if err := journal.recoveryInputs(); err != nil {
			return err
		}
	}
	target, err := ordinaryTOMLTarget(journal.intent.Target)
	if err != nil {
		return err
	}
	directory, err := openConfigDirectory(target.directory(journal.state.root), false, 0)
	if err != nil {
		return err
	}
	defer func() { _ = directory.Close() }()
	if _, err := directory.Lstat(journal.intent.Stage); !errors.Is(err, fs.ErrNotExist) {
		return errors.New("configuration stage remains; record retained")
	}
	root, err := openConfigDirectory(journal.state.root, false, 0)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	if err := removeConfigReplacementFile(root, moduleEditIntentName, journal.identity, defaultConfigReplacementOps()); err != nil {
		return err
	}
	if err := syncRootDirectory(root); err != nil {
		return fmt.Errorf("configuration edit finalized but intent removal durability is unconfirmed: %w", err)
	}
	return nil
}

func publishReviewedModule(state *moduleProposalState, preCommit, guard, postCommit func() error) error {
	journal := newModuleEditJournal(state)
	ops := defaultConfigReplacementOps()
	ops.hooks = journal.hooks()
	return replaceSecureConfigFileUsing(state.target.directory(state.root), state.target.name, state.content,
		state.snapshot.identity(state.target), preCommit, guard, postCommit, ops)
}
