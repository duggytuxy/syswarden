//go:build linux

package firewall

import (
	"context"
	"fmt"
	"os"
	"reflect"
	"sort"
)

// Replace only paths whose exact original inode is retained by the durable
// file plan. Everything outside that plan remains bound to the original
// process observation. Retired paths must also be absent in the service's
// mount namespace, not merely absent from the caller's configuration tree.
func legacyFail2banRetirementProcessPaths(host nftPersistenceFilesystem, record legacyFail2banPlanRecord, expected map[string]os.FileInfo) (map[string]os.FileInfo, []string, error) {
	_, digest, err := encodeLegacyFail2banPlan(record, host.expectedUID, host.expectedGID)
	if err != nil || len(expected) == 0 || len(expected) > 4096 {
		return nil, nil, fmt.Errorf("Fail2ban file-phase process view lacks a complete bound plan")
	}
	durable, err := readLegacyFail2banPlan(host, digest)
	if err != nil || !reflect.DeepEqual(durable, record) {
		return nil, nil, fmt.Errorf("Fail2ban file-phase process view differs from durable evidence")
	}
	state, err := inspectLegacyFail2banPlanState(host, record)
	if err != nil {
		return nil, nil, err
	}
	paths := make(map[string]os.FileInfo, len(expected)+len(state.retired))
	for path, identity := range expected {
		paths[path] = identity
	}
	sources := make(map[string]legacyRetirementFileRecord)
	for _, source := range record.Sources {
		sources[source.Source.Path] = source
	}
	var absent []string
	for _, source := range state.baseline.sources {
		original, present := expected[source.path]
		if !present && !state.retired[source.path] {
			return nil, nil, fmt.Errorf("Fail2ban retained source is absent from the inspected process view")
		}
		if present {
			observed := source.snapshot
			observed.identity = original
			if !matchesLegacyRetirementSource(sources[source.path], observed) {
				return nil, nil, fmt.Errorf("Fail2ban process source identity differs from the durable file plan")
			}
		}
		if state.retired[source.path] {
			file := sources[source.path]
			file.PlanSHA256 = digest
			delete(paths, source.path)
			paths[legacyRetirementBackupDirectory(file)+"/original"] = source.snapshot.identity
			absent = append(absent, source.path)
		} else {
			// Retained files never gain permission to change ctime or contents.
			if !sameNFTPersistenceIdentity(original, source.snapshot.identity) {
				return nil, nil, fmt.Errorf("Fail2ban retained process source changed during retirement")
			}
		}
	}
	for _, directory := range state.baseline.directories {
		original, present := expected[directory.path]
		if !present || !sameLegacyFail2banDirectory(original, directory.identity) {
			return nil, nil, fmt.Errorf("Fail2ban process configuration directory changed identity")
		}
		// The plan independently checks complete directory membership. Moving
		// its exact targets may change directory size, mtime and ctime only.
		paths[directory.path] = directory.identity
	}
	if len(paths) > 4352 || len(absent) > 256 {
		return nil, nil, fmt.Errorf("Fail2ban file-phase process view exceeds its bound")
	}
	sort.Strings(absent)
	return paths, absent, nil
}

func (binding *legacyFail2banProcessBinding) verifyFileRetirement(host nftPersistenceFilesystem, record legacyFail2banPlanRecord) error {
	if binding == nil {
		return fmt.Errorf("Fail2ban process binding is absent")
	}
	binding.mu.Lock()
	defer binding.mu.Unlock()
	paths, absent, err := legacyFail2banRetirementProcessPaths(host, record, binding.expected.paths)
	if err != nil {
		return err
	}
	return binding.observePaths(false, paths, absent)
}

func (inspection *legacyFail2banServiceInspection) verifyFileRetirement(ctx context.Context, record legacyFail2banPlanRecord) error {
	if inspection == nil || inspection.process == nil || inspection.parser.digest != record.ParserSHA256 {
		return fmt.Errorf("Fail2ban file retirement lacks its original service and parser evidence")
	}
	process := func() error { return inspection.process.verifyFileRetirement(inspection.host, record) }
	inventory := func() error {
		_, err := inspectLegacyFail2banPlanState(inspection.host, record)
		return err
	}
	return inspection.verifyEvidence(ctx, process, inventory)
}

func (inspection *legacyFail2banServiceInspection) readRuntimeFileRetirement(ctx context.Context, record legacyFail2banPlanRecord) (legacyFail2banRuntimeSnapshot, error) {
	verify := func(ctx context.Context) error { return inspection.verifyFileRetirement(ctx, record) }
	return inspection.readRuntimeUsing(ctx, verify)
}
