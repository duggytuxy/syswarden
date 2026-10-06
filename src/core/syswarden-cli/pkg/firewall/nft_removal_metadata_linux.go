//go:build linux

package firewall

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"reflect"
)

// The writer receipt stays active until persistent sources and all product
// tables are retired. Progress binds its original identity so an interrupted
// invocation can reopen that exact receipt in its private backup. Retire the
// progress selector last; the terminal guard no longer needs an active selector.
func (session *nftRemovalSession) retireMetadata(ctx context.Context, runner nftCommandRunner, ops legacyRetirementFileOps) error {
	if runner == nil || !validLegacyRetirementOperations(func() error { return nil }, ops) {
		return fmt.Errorf("firewall metadata retirement requires complete operations")
	}
	if err := session.check(ctx); err != nil {
		return err
	}
	plan, origin, present, err := readNFTRemovalProgress(session.host)
	if err != nil || !present || !reflect.DeepEqual(plan, session.plan) {
		return errors.Join(fmt.Errorf("firewall metadata retirement lacks exact durable progress"), err)
	}
	snapshot, attrs, err := snapshotNFTPersistenceMetadata(session.host, nftRemovalProgressPath)
	if err != nil {
		return err
	}
	canonical, err := encodeNFTRemovalProgress(plan, origin.record)
	if err != nil || !bytes.Equal(snapshot.content, canonical) {
		return fmt.Errorf("firewall progress changed during final retirement preparation")
	}
	progress, err := bindNFTPersistenceGraphSource(nftRemovalProgressPath, snapshot, attrs, canonical)
	if err != nil {
		return err
	}
	progressFile := nftPersistenceGraphFileRecord(progress, plan.sha256)
	check := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := session.producers.verify(ctx); err != nil {
			return err
		}
		if err := origin.verify(session.host); err != nil {
			return err
		}
		if _, err := currentNFTRetiredSource(session.host, plan); err != nil {
			return err
		}
		targets, err := observeNFTRemovalTargets(ctx, runner)
		if err != nil || len(targets) != 0 {
			return errors.Join(fmt.Errorf("firewall metadata cannot retire while product tables remain"), err)
		}
		retired, err := legacyRetirementSourceState(session.host, progressFile)
		if err != nil {
			return err
		}
		path := nftRemovalProgressPath
		if retired {
			backup := legacyRetirementBackupDirectory(progressFile)
			intent, err := readLegacyRetirementFileRecord(session.host, backup)
			if err != nil || intent != progressFile {
				return fmt.Errorf("retired progress lacks its exact durable intent")
			}
			path = backup + "/original"
		}
		actual, attrs, err := snapshotNFTPersistenceMetadata(session.host, path)
		if err != nil {
			return err
		}
		bound, err := bindNFTPersistenceGraphSource(nftRemovalProgressPath, actual, attrs, actual.content)
		if err != nil || bound != progress {
			return fmt.Errorf("firewall progress metadata changed during retirement")
		}
		return nil
	}
	if err := check(); err != nil {
		return err
	}
	for _, item := range []struct {
		name   string
		record nftPersistenceGraphSourceRecord
	}{{"writer", origin.record}, {"progress", progress}} {
		file := nftPersistenceGraphFileRecord(item.record, plan.sha256)
		if err := ensureLegacyRetirementPrivateDirectory(session.host, legacyRetirementBackupDirectory(file), ops); err != nil {
			return err
		}
		wrapped := ops
		wrapped.checkpoint = func(phase string) error { return ops.checkpoint("metadata-" + item.name + "-" + phase) }
		if err := retireLegacyConfigurationFileUsing(session.host, file, func(bool) error { return check() }, wrapped); err != nil {
			return err
		}
	}
	return check()
}
