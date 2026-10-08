//go:build linux

package firewall

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"syswarden-cli/pkg/wireguardstate"
)

type nftPersistenceGraphState struct {
	original nftPersistenceGraph
	shared   map[string]nftPersistenceSharedRecord
	edited   map[string]bool
	retired  map[string]bool
}

func nftPersistenceGraphFileRecord(source nftPersistenceGraphSourceRecord, digest string) legacyRetirementFileRecord {
	return legacyRetirementFileRecord{Schema: legacyRetirementSchema, PlanSHA256: digest, Source: source.Artifact, Size: source.Size, ModifiedNS: source.ModifiedNS}
}

func matchesNFTPersistenceGraphSource(source nftPersistenceGraphSourceRecord, snapshot nftPersistenceRead, attrs []nftPersistenceXattr) bool {
	edit, err := planLegacyNFTIncludeRetirement(snapshot.content)
	if err != nil {
		return false
	}
	actual, err := bindNFTPersistenceGraphSource(source.Artifact.Path, snapshot, attrs, edit.content)
	return err == nil && actual.Size == source.Size && actual.ModifiedNS == source.ModifiedNS &&
		actual.Xattrs == source.Xattrs && actual.EditedSHA256 == source.EditedSHA256 &&
		wireguardstate.MatchesRecordedArtifact(actual.Artifact, source.Artifact)
}

// A directory's link count tracks its immediate subdirectories, not its
// identity. Other verified removal phases can retire a sibling directory
// between retries. Keep the recorded inode, filesystem, ownership and mode
// exact, while rechecking every source, include and wildcard independently.
// This exception is confined to durable graph recovery. Initial preparation,
// open-file race checks and regular-file single-link checks remain strict.
func sameNFTPersistenceRecoveryDirectory(actual, expected legacyFail2banPlanDirectory) bool {
	if actual.NLink == 0 || expected.NLink == 0 {
		return false
	}
	actual.NLink = expected.NLink
	return sameLegacyFail2banPlanDirectory(actual, expected)
}

func verifyNFTPersistenceGraphDirectories(host nftPersistenceFilesystem, record nftPersistenceGraphRecord) error {
	for _, expected := range record.Directories {
		directory, err := host.openDirectory(expected.Path)
		if err != nil {
			return err
		}
		info, err := directory.Stat(".")
		_ = directory.Close()
		if err != nil {
			return err
		}
		actual, err := bindLegacyFail2banPlanDirectory(host, expected.Path, info)
		if err != nil || !sameNFTPersistenceRecoveryDirectory(actual, expected) {
			return fmt.Errorf("nftables persistence source directory differs from reviewed evidence: %q", expected.Path)
		}
	}
	return nil
}

// Reconstruct the original graph only from exact original inodes. Retained
// administrator sources must remain active. Private originals cannot replace
// a missing retained source, and every moved source requires its exact intent.
// This checks dependencies and progress, not ownership or producer quiescence.
func inspectNFTPersistenceGraphState(host nftPersistenceFilesystem, record nftPersistenceGraphRecord) (nftPersistenceGraphState, error) {
	var empty nftPersistenceGraphState
	_, digest, err := encodeNFTPersistenceGraphRecord(record, host)
	if err != nil {
		return empty, err
	}
	if err := verifyNFTPersistenceGraphDirectories(host, record); err != nil {
		return empty, err
	}
	state := nftPersistenceGraphState{shared: make(map[string]nftPersistenceSharedRecord), edited: make(map[string]bool), retired: make(map[string]bool)}
	originals := make(map[string]nftPersistenceRead)
	active := make(map[string]nftPersistenceRead)
	var retiring []nftPersistenceRetiredSource
	for _, source := range record.Sources {
		path := source.Artifact.Path
		location := path
		if slices.Contains(record.Retiring, path) {
			file := nftPersistenceGraphFileRecord(source, digest)
			retired, err := legacyRetirementSourceState(host, file)
			if err != nil {
				return empty, err
			}
			intent, err := readLegacyRetirementFileRecord(host, legacyRetirementBackupDirectory(file))
			if err != nil && !(errors.Is(err, fs.ErrNotExist) && !retired) || err == nil && intent != file {
				return empty, fmt.Errorf("nftables persistence source lacks its exact retirement intent: %q", path)
			}
			if retired {
				location = legacyRetirementBackupDirectory(file) + "/original"
				state.retired[path] = true
			}
		} else if source.Artifact.SHA256 != source.EditedSHA256 {
			intent, err := readNFTPersistenceSharedRecord(host, path, digest)
			if err == nil {
				if intent.Original != nftPersistenceGraphFileRecord(source, digest) || intent.Xattrs != source.Xattrs || intent.Replacement.Source.SHA256 != source.EditedSHA256 {
					return empty, fmt.Errorf("shared nftables intent differs from the reviewed graph: %q", path)
				}
				shared, err := inspectNFTPersistenceSharedState(host, intent)
				if err != nil {
					return empty, err
				}
				state.shared[path] = intent
				if shared.phase != 0 {
					state.edited[path] = true
					active[path] = shared.replacement
					location = nftPersistenceSharedDirectory(intent) + "/" + intent.Stage
					if shared.phase == 2 {
						location = nftPersistenceSharedDirectory(intent) + "/original"
					}
				}
			} else if !errors.Is(err, fs.ErrNotExist) {
				return empty, err
			}
		}
		snapshot, attrs, err := snapshotNFTPersistenceMetadata(host, location)
		if err != nil || !matchesNFTPersistenceGraphSource(source, snapshot, attrs) {
			return empty, fmt.Errorf("nftables persistence original changed or is unavailable: %q", path)
		}
		originals[path] = snapshot
		if !state.edited[path] && !state.retired[path] {
			active[path] = snapshot
		}
		if slices.Contains(record.Retiring, path) {
			retiring = append(retiring, nftPersistenceRetiredSource{path, sha256.Sum256(snapshot.content)})
		}
	}
	expansions := make(map[string][]string)
	for _, expansion := range record.Expansions {
		expansions[expansion.Pattern] = expansion.Paths
		var expected []string
		for _, path := range expansion.Paths {
			if !state.retired[path] {
				expected = append(expected, path)
			}
		}
		actual, err := host.expand(expansion.Pattern)
		if err != nil || !slices.Equal(actual, expected) {
			return empty, fmt.Errorf("nftables persistence wildcard changed outside the reviewed retirement: %q", expansion.Pattern)
		}
	}
	state.original, err = inspectNFTPersistenceGraph(record.Entries, nftPersistenceGraphReader{
		read: func(path string) (nftPersistenceRead, error) {
			value, exists := originals[path]
			if !exists {
				return nftPersistenceRead{}, fmt.Errorf("original include refers to an unreviewed source")
			}
			return value, nil
		},
		expand: func(pattern string) ([]string, error) {
			value, exists := expansions[pattern]
			if !exists {
				return nil, fmt.Errorf("original include refers to an unreviewed expansion")
			}
			return value, nil
		},
	})
	if err != nil || len(state.original.sources) != len(record.Sources) || len(state.original.expansions) != len(record.Expansions) {
		return empty, errors.Join(fmt.Errorf("nftables original graph does not cover exactly the reviewed sources and expansions"), err)
	}
	if err := verifyNFTPersistenceRetirementCoverageWithProductEntry(state.original, retiring, record.ProductEntry); err != nil {
		return empty, err
	}
	currentEntries := append([]string(nil), record.Entries...)
	if record.ProductEntry && state.retired[legacyNFTIncludePath] {
		currentEntries = slices.DeleteFunc(currentEntries, func(path string) bool { return path == legacyNFTIncludePath })
	}
	var current nftPersistenceGraph
	if len(currentEntries) > 0 {
		current, err = inspectNFTPersistenceGraph(currentEntries, host.reader())
		if err != nil {
			return empty, err
		}
	}
	reachable := make(map[string]bool)
	for _, source := range current.sources {
		expected, exists := active[source.path]
		if !exists || sha256.Sum256(expected.content) != source.sha256 || !sameNFTPersistenceIdentity(expected.identity, source.identity) {
			return empty, fmt.Errorf("active nftables include graph changed during recovery inspection")
		}
		reachable[source.path] = true
	}
	for _, source := range record.Sources {
		if !slices.Contains(record.Retiring, source.Artifact.Path) && !reachable[source.Artifact.Path] {
			return empty, fmt.Errorf("nftables persistence recovery detached a retained administrator source: %q", source.Artifact.Path)
		}
	}
	if err := verifyNFTPersistenceGraphDirectories(host, record); err != nil {
		return empty, err
	}
	return state, nil
}
