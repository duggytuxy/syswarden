//go:build linux

package integration

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	rsyslogProvenanceName   = ".syswarden-rsyslog-provenance-v1"
	rsyslogProvenanceSchema = "syswarden-rsyslog-provenance-v1"
)

type rsyslogArtifactProvenance struct {
	size   int64
	digest [sha256.Size]byte
}

type rsyslogProvenanceRegistry struct {
	exists  bool
	content []byte
	records map[string]rsyslogArtifactProvenance
}

type rsyslogProvenanceRecorder func(*os.File, string, []byte) error
type rsyslogMutationPreflight func() error

func validRsyslogProvenanceArtifactName(name string) bool {
	return name == wafRsyslogConfigName || name == rsyslogSIEMConfigName
}

func renderRsyslogProvenanceRegistry(records map[string]rsyslogArtifactProvenance) ([]byte, error) {
	names := make([]string, 0, len(records))
	for name, record := range records {
		if !validRsyslogProvenanceArtifactName(name) || record.size < 0 ||
			record.size > rsyslogArtifactContentLimit {
			return nil, fmt.Errorf("invalid rsyslog provenance record for %q", name)
		}
		names = append(names, name)
	}
	sort.Strings(names)
	var rendered strings.Builder
	rendered.WriteString(rsyslogProvenanceSchema)
	rendered.WriteByte('\n')
	for _, name := range names {
		record := records[name]
		fmt.Fprintf(&rendered, "%s\t%d\t%x\n", name, record.size, record.digest)
	}
	return []byte(rendered.String()), nil
}

func parseRsyslogProvenanceRegistry(content []byte) (map[string]rsyslogArtifactProvenance, error) {
	if len(content) == 0 || len(content) > rsyslogArtifactContentLimit ||
		content[len(content)-1] != '\n' {
		return nil, fmt.Errorf("rsyslog provenance registry is empty, oversized, or unterminated")
	}
	lines := strings.Split(strings.TrimSuffix(string(content), "\n"), "\n")
	if len(lines) == 0 || lines[0] != rsyslogProvenanceSchema {
		return nil, fmt.Errorf("unsupported rsyslog provenance registry schema")
	}
	records := make(map[string]rsyslogArtifactProvenance, len(lines)-1)
	for _, line := range lines[1:] {
		fields := strings.Split(line, "\t")
		if len(fields) != 3 || !validRsyslogProvenanceArtifactName(fields[0]) {
			return nil, fmt.Errorf("invalid rsyslog provenance registry record")
		}
		if _, duplicate := records[fields[0]]; duplicate {
			return nil, fmt.Errorf("duplicate rsyslog provenance record for %q", fields[0])
		}
		size, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil || size < 0 || size > rsyslogArtifactContentLimit {
			return nil, fmt.Errorf("invalid rsyslog provenance size for %q", fields[0])
		}
		rawDigest, err := hex.DecodeString(fields[2])
		if err != nil || len(rawDigest) != sha256.Size || fields[2] != strings.ToLower(fields[2]) {
			return nil, fmt.Errorf("invalid rsyslog provenance digest for %q", fields[0])
		}
		var digest [sha256.Size]byte
		copy(digest[:], rawDigest)
		records[fields[0]] = rsyslogArtifactProvenance{size: size, digest: digest}
	}
	canonical, err := renderRsyslogProvenanceRegistry(records)
	if err != nil || !bytes.Equal(canonical, content) {
		return nil, errors.Join(fmt.Errorf("rsyslog provenance registry is not canonical"), err)
	}
	return records, nil
}

func readRsyslogProvenanceRegistryAtUsing(
	parentPath string,
	uid, gid uint32,
) (rsyslogProvenanceRegistry, error) {
	directory, exists, err := openExistingOwnedArtifactDirectoryAt(
		parentPath, wafRsyslogDirectoryName, uid, gid,
	)
	if err != nil || !exists {
		return rsyslogProvenanceRegistry{}, err
	}
	defer directory.Close()
	return readRsyslogProvenanceRegistryInDirectory(directory, uid, gid)
}

func readRsyslogProvenanceRegistryInDirectory(
	directory *os.File,
	uid, gid uint32,
) (rsyslogProvenanceRegistry, error) {
	if directory == nil {
		return rsyslogProvenanceRegistry{}, fmt.Errorf("rsyslog provenance directory is unavailable")
	}
	state, content, err := inspectRsyslogArtifact(directory, rsyslogProvenanceName, uid, gid)
	if err != nil || !state.exists {
		return rsyslogProvenanceRegistry{}, err
	}
	records, err := parseRsyslogProvenanceRegistry(content)
	if err != nil {
		return rsyslogProvenanceRegistry{}, err
	}
	return rsyslogProvenanceRegistry{
		exists:  true,
		content: append([]byte(nil), content...),
		records: records,
	}, nil
}

func recordRsyslogArtifactProvenance(
	directory *os.File,
	name string,
	expected []byte,
) error {
	return recordRsyslogArtifactProvenanceInDirectoryUsing(
		directory, 0, 0, name, expected,
		func(directory *os.File) error { return directory.Sync() },
	)
}

func snapshotRsyslogArtifactInDirectory(
	directory *os.File,
	uid, gid uint32,
	name string,
) (wafRsyslogConfigState, []byte, error) {
	if directory == nil {
		return wafRsyslogConfigState{}, nil, fmt.Errorf("rsyslog artifact directory is unavailable")
	}
	return inspectRsyslogArtifact(directory, name, uid, gid)
}

func rollbackUnactivatedRsyslogArtifactInDirectoryUsing(
	directory *os.File,
	uid, gid uint32,
	name, label string,
	desired []byte,
	previous wafRsyslogConfigState,
	previousContent []byte,
) error {
	if directory == nil {
		return fmt.Errorf("rsyslog rollback directory is unavailable")
	}
	if previous.exists {
		_, err := reconcileRsyslogArtifactInDirectoryUsing(
			directory,
			name,
			uid,
			gid,
			previousContent,
			nil,
			func(directory *os.File) error { return directory.Sync() },
		)
		return err
	}
	removed, err := removeExactOwnedArtifactInDirectoryUsing(
		directory,
		uid,
		gid,
		exactContentExpectation(label, name, desired, 0600),
		defaultExactOwnedArtifactRemovalOptions(),
	)
	if err != nil {
		return err
	}
	if removed {
		return nil
	}
	state, _, inspectErr := snapshotRsyslogArtifactInDirectory(directory, uid, gid, name)
	if inspectErr != nil || state.exists {
		return errors.Join(fmt.Errorf("unactivated %s was not rolled back", label), inspectErr)
	}
	return nil
}

func reconcileRsyslogArtifactWithProvenanceAtUsing(
	parentPath string,
	uid, gid uint32,
	name, label string,
	desired []byte,
	activate func(bool) error,
	record rsyslogProvenanceRecorder,
	preflight rsyslogMutationPreflight,
) error {
	if activate == nil || record == nil || preflight == nil {
		return fmt.Errorf("rsyslog activation, provenance recorder, or mutation preflight is unavailable")
	}
	directory, err := openWAFRsyslogDirectoryAt(parentPath, uid, gid)
	if err != nil {
		return err
	}
	defer directory.Close()
	if err := unix.Flock(int(directory.Fd()), unix.LOCK_EX); err != nil {
		return fmt.Errorf("lock rsyslog producer transaction: %w", err)
	}
	defer func() { _ = unix.Flock(int(directory.Fd()), unix.LOCK_UN) }()
	if err := preflight(); err != nil {
		return fmt.Errorf("refuse stale rsyslog producer transaction: %w", err)
	}

	previous, previousContent, err := snapshotRsyslogArtifactInDirectory(
		directory, uid, gid, name,
	)
	if err != nil {
		return fmt.Errorf("snapshot %s before publication: %w", label, err)
	}
	changed, publicationErr := reconcileRsyslogArtifactInDirectoryUsing(
		directory,
		name,
		uid,
		gid,
		desired,
		nil,
		func(directory *os.File) error { return directory.Sync() },
	)
	var publicationDurability *wafRsyslogPublicationDurabilityError
	if publicationErr != nil && !errors.As(publicationErr, &publicationDurability) {
		return fmt.Errorf("publish %s rsyslog configuration: %w", label, publicationErr)
	}
	provenanceErr := record(directory, name, desired)
	var provenanceDurability *wafRsyslogPublicationDurabilityError
	if provenanceErr != nil && !errors.As(provenanceErr, &provenanceDurability) {
		var rollbackErr error
		if changed {
			rollbackErr = rollbackUnactivatedRsyslogArtifactInDirectoryUsing(
				directory, uid, gid, name, label, desired, previous, previousContent,
			)
		}
		return errors.Join(
			fmt.Errorf("record %s rsyslog provenance before activation: %w", label, provenanceErr),
			rollbackErr,
		)
	}
	return finishRsyslogArtifactSetup(
		label,
		changed,
		errors.Join(publicationErr, provenanceErr),
		activate,
	)
}

func recordRsyslogArtifactProvenanceAtUsing(
	parentPath string,
	uid, gid uint32,
	name string,
	expected []byte,
	syncDirectory func(*os.File) error,
) error {
	if !validRsyslogProvenanceArtifactName(name) || len(expected) > rsyslogArtifactContentLimit {
		return fmt.Errorf("invalid rsyslog artifact provenance input")
	}
	directory, err := openWAFRsyslogDirectoryAt(parentPath, uid, gid)
	if err != nil {
		return err
	}
	defer directory.Close()
	if err := unix.Flock(int(directory.Fd()), unix.LOCK_EX); err != nil {
		return fmt.Errorf("lock rsyslog provenance registry: %w", err)
	}
	defer func() { _ = unix.Flock(int(directory.Fd()), unix.LOCK_UN) }()
	return recordRsyslogArtifactProvenanceInDirectoryUsing(
		directory, uid, gid, name, expected, syncDirectory,
	)
}

func recordRsyslogArtifactProvenanceInDirectoryUsing(
	directory *os.File,
	uid, gid uint32,
	name string,
	expected []byte,
	syncDirectory func(*os.File) error,
) error {
	if directory == nil || syncDirectory == nil ||
		!validRsyslogProvenanceArtifactName(name) || len(expected) > rsyslogArtifactContentLimit {
		return fmt.Errorf("invalid rsyslog artifact provenance input")
	}
	artifact, actual, err := inspectRsyslogArtifact(directory, name, uid, gid)
	if err != nil || !artifact.exists || !bytes.Equal(actual, expected) {
		return errors.Join(fmt.Errorf("refusing provenance for unattested rsyslog artifact %s", name), err)
	}
	registryState, registryContent, err := inspectRsyslogArtifact(
		directory, rsyslogProvenanceName, uid, gid,
	)
	if err != nil {
		return err
	}
	records := make(map[string]rsyslogArtifactProvenance, 2)
	if registryState.exists {
		records, err = parseRsyslogProvenanceRegistry(registryContent)
		if err != nil {
			return err
		}
	}
	records[name] = rsyslogArtifactProvenance{
		size:   artifact.size,
		digest: artifact.digest,
	}
	desired, err := renderRsyslogProvenanceRegistry(records)
	if err != nil {
		return err
	}
	_, err = reconcileRsyslogArtifactInDirectoryUsing(
		directory,
		rsyslogProvenanceName,
		uid,
		gid,
		desired,
		nil,
		syncDirectory,
	)
	return err
}

func removeRsyslogArtifactProvenanceInDirectoryUsing(
	directory *os.File,
	uid, gid uint32,
	name string,
	expected rsyslogArtifactProvenance,
	options exactOwnedArtifactRemovalOptions,
) error {
	if directory == nil || !validRsyslogProvenanceArtifactName(name) {
		return fmt.Errorf("invalid rsyslog provenance removal input")
	}
	options = normalizeExactOwnedArtifactRemovalOptions(options)
	state, content, err := inspectRsyslogArtifact(directory, rsyslogProvenanceName, uid, gid)
	if err != nil || !state.exists {
		return errors.Join(fmt.Errorf("rsyslog provenance registry disappeared"), err)
	}
	records, err := parseRsyslogProvenanceRegistry(content)
	if err != nil {
		return err
	}
	record, exists := records[name]
	if !exists || record != expected {
		return fmt.Errorf("rsyslog provenance for %s changed concurrently", name)
	}
	delete(records, name)
	if len(records) == 0 {
		removed, err := removeExactOwnedArtifactDirectInDirectoryUsing(
			directory,
			uid,
			gid,
			exactContentExpectation(
				"SysWarden rsyslog provenance registry",
				rsyslogProvenanceName,
				content,
				0600,
			),
			options,
		)
		if err != nil || !removed {
			return errors.Join(fmt.Errorf("remove empty rsyslog provenance registry"), err)
		}
		return nil
	}
	desired, err := renderRsyslogProvenanceRegistry(records)
	if err != nil {
		return err
	}
	_, err = reconcileRsyslogArtifactInDirectoryUsing(
		directory,
		rsyslogProvenanceName,
		uid,
		gid,
		desired,
		nil,
		options.syncDirectory,
	)
	return err
}

func provenanceExpectation(
	label, name string,
	record rsyslogArtifactProvenance,
) exactOwnedArtifactExpectation {
	return exactOwnedArtifactExpectation{
		label:          label,
		name:           name,
		digest:         record.digest,
		size:           record.size,
		permittedModes: map[uint32]struct{}{0600: {}},
	}
}
