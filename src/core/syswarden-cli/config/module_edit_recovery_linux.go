//go:build linux

package config

import (
	"context"
	"errors"
	"io/fs"
	"path/filepath"
)

func applyModuleEditRecovery(state *moduleEditRecoveryState, guard func() error) error {
	journal := newModuleEditJournal(&moduleProposalState{root: state.root, target: state.target, snapshot: state.snapshot})
	journal.intent, journal.identity = state.observed.intent, state.observed.identity
	directory, err := openConfigDirectory(state.target.directory(state.root), false, 0)
	if err != nil {
		return err
	}
	defer func() { _ = directory.Close() }()
	// Compare every non-target input to the fresh recovery snapshot, not to
	// the historical proposal. Administrator changes present at review stay.
	recheck := func() error {
		if err := guard(); err != nil {
			return err
		}
		if err := journal.verify(); err != nil {
			return err
		}
		actual, _, err := captureModuleInputs(state.root, state.target, journal.identity)
		if err != nil {
			return err
		}
		if !sameRecoveryOtherInputs(state.snapshot, actual, state.target) {
			return errors.New("configuration inputs changed after recovery approval; evidence retained")
		}
		return nil
	}
	journal.recoveryInputs = recheck
	if err := recheck(); err != nil {
		return err
	}
	observed, err := observeModuleEdit(context.Background(), state.root)
	if err != nil {
		return err
	}
	if observed.observation != state.observed.observation || !sameUserModuleIdentity(observed.identity, journal.identity) {
		return errors.New("configuration edit pair changed before recovery")
	}
	if state.review.State == "published_pending" {
		// The source pair must still match the durable witnesses. Never
		// replace a later administrator inode or fabricate a missing original.
		live, err := readModuleEditWitness(directory, state.target.name)
		if err != nil {
			return err
		}
		stage, err := readModuleEditWitness(directory, journal.intent.Stage)
		if err != nil {
			return err
		}
		if !sameModuleEditFile(live, &journal.intent.Candidate) || !sameModuleEditFile(stage, journal.intent.Original) {
			return errors.New("configuration recovery pair is ambiguous")
		}
		if err := renameConfigFileAt(directory, state.target.name, journal.intent.Stage, journal.intent.Original != nil); err != nil {
			return err
		}
		if err := syncRootDirectory(directory); err != nil {
			return err
		}
	}
	if state.review.State == "prepared" || state.review.State == "published_pending" {
		if err := recheck(); err != nil {
			return err
		}
		if err := journal.transition("rolled_back"); err != nil {
			return err
		}
	}
	if err := recheck(); err != nil {
		return err
	}
	observed, err = observeModuleEdit(context.Background(), state.root)
	if err != nil {
		return err
	}
	expectedState := "rolled_back_cleanup"
	retained := &journal.intent.Candidate
	if journal.intent.State == "committed" {
		expectedState = "committed_cleanup"
		retained = journal.intent.Original
	}
	if observed.observation.State != expectedState || !sameUserModuleIdentity(observed.identity, journal.identity) {
		return errors.New("configuration recovery terminal pair changed")
	}
	if _, err := directory.Lstat(journal.intent.Stage); err == nil {
		raw, info, err := readSecureRegularFileSnapshotBounded(directory, journal.intent.Stage, journal.intent.Stage, maximumUserModuleSize)
		if err != nil {
			return err
		}
		identity := newSecureFileIdentity(raw, info)
		witness, err := moduleEditFileFrom(identity)
		if err != nil {
			return err
		}
		if !sameModuleEditFile(&witness, retained) {
			return errors.New("configuration recovery cleanup target changed")
		}
		if err := removeConfigReplacementFile(directory, journal.intent.Stage, identity, defaultConfigReplacementOps()); err != nil {
			return err
		}
		if err := syncRootDirectory(directory); err != nil {
			return err
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err := recheck(); err != nil {
		return err
	}
	return journal.finish()
}

func sameRecoveryOtherInputs(before, after *mergedConfigSnapshot, target tomlEditTarget) bool {
	if before == nil || after == nil || !sameFileAndMode(before.configRootInfo, after.configRootInfo) || !sameFileAndMode(before.modulesRootInfo, after.modulesRootInfo) || !sameUserModuleIdentity(before.marker, after.marker) {
		return false
	}
	if !target.master && !sameUserModuleIdentity(before.master, after.master) {
		return false
	}
	if target.name != userModuleName && !sameUserModuleIdentity(before.user, after.user) {
		return false
	}
	paths := func(snapshot *mergedConfigSnapshot) []string {
		result := make([]string, 0, len(snapshot.moduleNames))
		for _, name := range snapshot.moduleNames {
			if "modules/"+name != target.relative {
				result = append(result, name)
			}
		}
		return result
	}
	left, right := paths(before), paths(after)
	if len(left) != len(right) {
		return false
	}
	for i, name := range left {
		if name != right[i] {
			return false
		}
		if filepath.Base(name) != name {
			return false
		}
		if name != userModuleName && !sameUserModuleIdentity(before.modules[name], after.modules[name]) {
			return false
		}
	}
	return true
}
