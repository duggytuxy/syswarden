//go:build linux

package firewall

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"slices"
	"syscall"
)

func readNFTPersistenceGraphRecord(host nftPersistenceFilesystem, digest string) (nftPersistenceGraphRecord, error) {
	var empty nftPersistenceGraphRecord
	directory, err := openLegacyFail2banPlanDirectory(host, digest)
	if err != nil {
		return empty, err
	}
	_ = directory.Close()
	snapshot, err := host.snapshot(legacyFail2banPlanPath(digest) + "/plan.json")
	if err != nil {
		return empty, err
	}
	var record nftPersistenceGraphRecord
	if snapshot.identity.Mode().Perm() != 0600 || len(snapshot.content) > 2<<20 || json.Unmarshal(snapshot.content, &record) != nil {
		return empty, fmt.Errorf("nftables persistence graph journal is not a bounded private record")
	}
	canonical, actual, err := encodeNFTPersistenceGraphRecord(record, host)
	if err != nil || actual != digest || !bytes.Equal(canonical, snapshot.content) {
		return empty, fmt.Errorf("nftables persistence graph journal differs from its canonical reviewed digest")
	}
	return record, nil
}

func syncNFTPersistenceGraphRecord(host nftPersistenceFilesystem, digest string, ops legacyRetirementFileOps) error {
	if _, err := readNFTPersistenceGraphRecord(host, digest); err != nil {
		return err
	}
	path := legacyFail2banPlanPath(digest) + "/plan.json"
	before, err := host.snapshot(path)
	if err != nil {
		return err
	}
	directory, err := openLegacyFail2banPlanDirectory(host, digest)
	if err != nil {
		return err
	}
	defer func() { _ = directory.Close() }()
	file, err := directory.OpenFile("plan.json", os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	opened, statErr := file.Stat()
	if statErr != nil || !sameNFTPersistenceIdentity(before.identity, opened) {
		_ = file.Close()
		return fmt.Errorf("nftables persistence graph journal changed before synchronization")
	}
	syncErr := ops.sync(file)
	closeErr := file.Close()
	fd, err := directory.Open(".")
	if err != nil {
		return err
	}
	info, statErr := fd.Stat()
	directorySyncErr := ops.sync(fd)
	directoryCloseErr := fd.Close()
	if err := errors.Join(syncErr, closeErr, statErr, directorySyncErr, directoryCloseErr); err != nil {
		return err
	}
	after, err := host.snapshot(path)
	if err != nil || !sameLegacyFail2banSource(before, after) {
		return fmt.Errorf("nftables persistence graph journal changed during synchronization")
	}
	if _, err := readNFTPersistenceGraphRecord(host, digest); err != nil {
		return err
	}
	return attestLegacyRetirementDirectory(host, legacyFail2banPlanPath(digest), info)
}

func persistNFTPersistenceGraphRecord(host nftPersistenceFilesystem, record nftPersistenceGraphRecord, reviewed string, guard func() error, ops legacyRetirementFileOps) error {
	content, digest, err := encodeNFTPersistenceGraphRecord(record, host)
	if err != nil || digest != reviewed || !validLegacyRetirementOperations(guard, ops) {
		return fmt.Errorf("nftables persistence requires an exact reviewed graph and complete guards")
	}
	if err := guard(); err != nil {
		return err
	}
	if _, err := inspectNFTPersistenceGraphState(host, record); err != nil {
		return err
	}
	if err := ensureLegacyRetirementPrivateDirectory(host, legacyFail2banPlanPath(digest), ops); err != nil {
		return err
	}
	for _, source := range record.Sources {
		if !slices.Contains(record.Retiring, source.Artifact.Path) {
			continue
		}
		file := nftPersistenceGraphFileRecord(source, digest)
		if err := ensureLegacyRetirementPrivateDirectory(host, legacyRetirementBackupDirectory(file), ops); err != nil {
			return err
		}
		if err := verifyLegacyFail2banBackupFilesystem(host, file); err != nil {
			return err
		}
	}
	_, err = readNFTPersistenceGraphRecord(host, digest)
	if errors.Is(err, fs.ErrNotExist) {
		if err := guard(); err != nil {
			return err
		}
		state, err := inspectNFTPersistenceGraphState(host, record)
		if err != nil || len(state.edited) != 0 || len(state.retired) != 0 {
			return errors.Join(fmt.Errorf("cannot recreate a missing nftables graph journal after active configuration changes"), err)
		}
		directory, err := openLegacyFail2banPlanDirectory(host, digest)
		if err != nil {
			return err
		}
		defer func() { _ = directory.Close() }()
		fd, err := directory.Open(".")
		if err != nil {
			return err
		}
		defer func() { _ = fd.Close() }()
		if err := publishLegacyRetirementJSON(directory, fd, "plan", content, ops); err != nil {
			return err
		}
		if err := ops.checkpoint("graph-plan-published"); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	if err := syncNFTPersistenceGraphRecord(host, digest, ops); err != nil {
		return err
	}
	if err := guard(); err != nil {
		return err
	}
	if _, err := inspectNFTPersistenceGraphState(host, record); err != nil {
		return err
	}
	return ops.checkpoint("graph-plan-durable")
}

// The external guard must independently reattest the recorded ownership and
// producer evidence under removal locks. Passing graph inspection alone would
// not prove ownership or prevent a service from recreating retired rules.
// Shared includes are edited before any owned source is moved. Every retry
// requires the exact reviewed journal; no newest-file discovery is permitted.
func applyNFTPersistenceGraphRecord(host nftPersistenceFilesystem, record nftPersistenceGraphRecord, reviewed string, guard func(string, string) error, ops legacyRetirementFileOps) error {
	if guard == nil {
		return fmt.Errorf("nftables persistence retirement requires independent ownership and producer guards")
	}
	external := func() error { return guard(record.Ownership, record.Producers) }
	if err := persistNFTPersistenceGraphRecord(host, record, reviewed, external, ops); err != nil {
		return err
	}
	check := func() (nftPersistenceGraphState, error) {
		var empty nftPersistenceGraphState
		if _, err := readNFTPersistenceGraphRecord(host, reviewed); err != nil {
			return empty, err
		}
		if err := external(); err != nil {
			return empty, err
		}
		return inspectNFTPersistenceGraphState(host, record)
	}
	for _, source := range record.Sources {
		path := source.Artifact.Path
		if source.Artifact.SHA256 == source.EditedSHA256 || slices.Contains(record.Retiring, path) {
			continue
		}
		shared, err := prepareNFTPersistenceSharedEdit(host, path, reviewed, func() error { _, err := check(); return err }, ops)
		if err != nil {
			return err
		}
		if err := applyNFTPersistenceSharedEdit(host, shared, func(edited bool) error {
			state, err := check()
			if err != nil || state.edited[path] != edited {
				return errors.Join(fmt.Errorf("shared nftables edit differs from graph progress"), err)
			}
			return nil
		}, ops); err != nil {
			return err
		}
	}
	if err := ops.checkpoint("graph-shared-edits-durable"); err != nil {
		return err
	}
	for _, source := range record.Sources {
		path := source.Artifact.Path
		if !slices.Contains(record.Retiring, path) {
			continue
		}
		if err := retireLegacyConfigurationFileUsing(host, nftPersistenceGraphFileRecord(source, reviewed), func(retired bool) error {
			state, err := check()
			if err != nil || state.retired[path] != retired {
				return errors.Join(fmt.Errorf("nftables source retirement differs from graph progress"), err)
			}
			return nil
		}, ops); err != nil {
			return err
		}
	}
	if err := ops.checkpoint("graph-retirement-durable"); err != nil {
		return err
	}
	state, err := check()
	if err != nil || len(state.retired) != len(record.Retiring) {
		return errors.Join(fmt.Errorf("nftables persistence retirement is incomplete"), err)
	}
	for _, source := range record.Sources {
		if source.Artifact.SHA256 != source.EditedSHA256 && !slices.Contains(record.Retiring, source.Artifact.Path) && !state.edited[source.Artifact.Path] {
			return fmt.Errorf("nftables persistence shared edit is incomplete")
		}
	}
	return nil
}
