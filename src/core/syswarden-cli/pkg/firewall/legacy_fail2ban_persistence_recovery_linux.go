//go:build linux

package firewall

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"syscall"
	"syswarden-cli/pkg/wireguardstate"
)

const legacyFail2banPersistenceSchema = "syswarden-legacy-fail2ban-persistence-v1"

type legacyFail2banPersistenceRecord struct {
	Schema      string                               `json:"schema"`
	FilePlan    string                               `json:"file_plan_sha256"`
	Kernel      legacyFail2banNFTJournalRecord       `json:"kernel"`
	Loader      string                               `json:"loader_sha256"`
	Entries     []string                             `json:"entries"`
	Absent      []string                             `json:"absent"`
	Sources     []nftPersistenceGraphSourceRecord    `json:"sources"`
	Directories []legacyFail2banPlanDirectory        `json:"directories"`
	Expansions  []nftPersistenceGraphExpansionRecord `json:"expansions"`
}

// The public plan contains metadata only. Complete source and runtime evidence
// stays in the private local journal and is never printed by this coordinator.
type LegacyFail2banPersistenceSummary struct {
	Schema                 string   `json:"schema"`
	FilePlanSHA256         string   `json:"file_plan_sha256"`
	PlanSHA256             string   `json:"plan_sha256"`
	SharedFiles            []string `json:"shared_files"`
	StopsProductServices   bool     `json:"stops_product_services"`
	PreservesSharedService bool     `json:"preserves_shared_fail2ban_service"`
	ChangesKernelRules     bool     `json:"changes_kernel_rules"`
	BackupDirectory        string   `json:"backup_directory"`
}

func legacyFail2banPersistencePath(filePlan, review string) string {
	return legacyFail2banPlanPath(filePlan) + "/persistence/" + review
}

func encodeLegacyFail2banPersistence(record legacyFail2banPersistenceRecord, host nftPersistenceFilesystem) ([]byte, string, error) {
	invalid := func() ([]byte, string, error) {
		return nil, "", fmt.Errorf("invalid bounded Fail2ban persistence review")
	}
	if record.Schema != legacyFail2banPersistenceSchema || !validLegacyRetirementDigest(record.FilePlan) || !validLegacyRetirementDigest(record.Loader) || record.Kernel.Quiescence.FilePlan != record.FilePlan || len(record.Entries) == 0 || len(record.Entries) > maximumNFTPersistenceFiles || len(record.Sources) == 0 || len(record.Sources) > maximumNFTPersistenceFiles || len(record.Directories) == 0 || len(record.Directories) > maximumNFTPersistenceFiles || len(record.Expansions) > maximumNFTPersistenceIncludes || len(record.Absent) > len(knownNFTPersistenceEntryPoints) {
		return invalid()
	}
	if _, _, _, err := encodeLegacyFail2banNFTJournalRecord(record.Kernel); err != nil {
		return invalid()
	}
	sources := make(map[string]bool)
	changed := false
	for index, source := range record.Sources {
		path := source.Artifact.Path
		if index > 0 && record.Sources[index-1].Artifact.Path >= path || !canonicalNFTPersistencePath(path, false) || !validLegacyRetirementDigest(source.EditedSHA256) || !validLegacyRetirementDigest(source.Xattrs) || validateLegacyRetirementFileRecord(nftPersistenceGraphFileRecord(source, record.FilePlan), host.expectedUID, host.expectedGID) != nil {
			return invalid()
		}
		sources[path] = true
		changed = changed || source.Artifact.SHA256 != source.EditedSHA256
	}
	if !changed {
		return invalid()
	}
	for index, path := range record.Entries {
		if !sources[path] || index > 0 && record.Entries[index-1] >= path {
			return invalid()
		}
	}
	for index, path := range record.Absent {
		if !slices.Contains(knownNFTPersistenceEntryPoints, path) || sources[path] || index > 0 && record.Absent[index-1] >= path {
			return invalid()
		}
	}
	parents := make(map[string]bool)
	for index, directory := range record.Directories {
		if directory.Path != "/" && !canonicalNFTPersistencePath(directory.Path, false) || index > 0 && record.Directories[index-1].Path >= directory.Path || directory.Inode == 0 || directory.NLink == 0 || directory.Mode&syscall.S_IFMT != syscall.S_IFDIR || directory.Mode & ^uint32(syscall.S_IFDIR|0777) != 0 || directory.Mode&0022 != 0 || directory.UID != host.expectedUID || directory.GID != host.expectedGID || !wireguardstate.ValidFilesystemUUID(directory.FilesystemUUID) {
			return invalid()
		}
		parents[directory.Path] = true
	}
	for path := range sources {
		if !parents[filepath.Dir(path)] {
			return invalid()
		}
	}
	for index, expansion := range record.Expansions {
		if !canonicalNFTPersistencePath(expansion.Pattern, true) || index > 0 && record.Expansions[index-1].Pattern >= expansion.Pattern || len(expansion.Paths) > maximumNFTPersistenceFiles {
			return invalid()
		}
		for index, path := range expansion.Paths {
			match, err := matchNFTPersistenceWildcard(expansion.Pattern, path)
			if err != nil || !match || !sources[path] || index > 0 && expansion.Paths[index-1] >= path {
				return invalid()
			}
		}
	}
	content, err := json.Marshal(record)
	if err != nil || len(content) > 2<<20 {
		return invalid()
	}
	return content, fmt.Sprintf("%x", sha256.Sum256(content)), nil
}

func prepareLegacyFail2banPersistence(host nftPersistenceFilesystem, loader *nftPersistenceLoaderInspection, filePlan string, kernel legacyFail2banNFTJournalRecord) (legacyFail2banPersistenceRecord, string, error) {
	record := legacyFail2banPersistenceRecord{Schema: legacyFail2banPersistenceSchema, FilePlan: filePlan, Kernel: kernel, Loader: loader.digest, Entries: slices.Clone(loader.status.entries)}
	for _, path := range knownNFTPersistenceEntryPoints {
		_, err := host.snapshot(path)
		if errors.Is(err, fs.ErrNotExist) {
			record.Absent = append(record.Absent, path)
		} else if err != nil {
			return record, "", err
		} else if !slices.Contains(record.Entries, path) {
			record.Entries = append(record.Entries, path)
		}
	}
	sort.Strings(record.Entries)
	sort.Strings(record.Absent)
	graph, err := inspectNFTPersistenceGraph(record.Entries, host.reader())
	if err != nil {
		return record, "", err
	}
	parents := make(map[string]bool)
	for _, source := range graph.sources {
		snapshot, attrs, err := snapshotNFTPersistenceMetadata(host, source.path)
		if err != nil || !sameNFTPersistenceIdentity(snapshot.identity, source.identity) || sha256.Sum256(snapshot.content) != source.sha256 {
			return record, "", fmt.Errorf("persistence source changed during Fail2ban review")
		}
		edit, err := planLegacyFail2banPersistence(snapshot.content, kernel)
		if err != nil {
			return record, "", err
		}
		bound, err := bindNFTPersistenceGraphSource(source.path, snapshot, attrs, edit.content)
		if err != nil {
			return record, "", err
		}
		record.Sources = append(record.Sources, bound)
		parents[filepath.Dir(source.path)] = true
	}
	for path := range parents {
		parent, err := host.openDirectory(path)
		if err != nil {
			return record, "", err
		}
		info, err := parent.Stat(".")
		_ = parent.Close()
		if err != nil {
			return record, "", err
		}
		bound, err := bindLegacyFail2banPlanDirectory(host, path, info)
		if err != nil {
			return record, "", err
		}
		record.Directories = append(record.Directories, bound)
	}
	sort.Slice(record.Directories, func(i, j int) bool { return record.Directories[i].Path < record.Directories[j].Path })
	for _, expansion := range graph.expansions {
		record.Expansions = append(record.Expansions, nftPersistenceGraphExpansionRecord{expansion.pattern, slices.Clone(expansion.paths)})
	}
	_, digest, err := encodeLegacyFail2banPersistence(record, host)
	if err == nil {
		_, err = inspectLegacyFail2banPersistenceState(host, record, digest)
	}
	return record, digest, err
}

// Reconstruct original bytes only from the active original inode or its exact
// exchange journal. No absent path, duplicate backup or unrecorded replacement
// establishes completion. Shared include dependencies never change here.
func inspectLegacyFail2banPersistenceState(host nftPersistenceFilesystem, record legacyFail2banPersistenceRecord, review string) (map[string]bool, error) {
	_, digest, err := encodeLegacyFail2banPersistence(record, host)
	if err != nil || digest != review {
		return nil, fmt.Errorf("Fail2ban persistence differs from the exact reviewed plan")
	}
	if err := verifyNFTPersistenceGraphDirectories(host, nftPersistenceGraphRecord{Directories: record.Directories}); err != nil {
		return nil, err
	}
	planner := func(content []byte) (nftPersistenceEdit, error) {
		return planLegacyFail2banPersistence(content, record.Kernel)
	}
	originals := make(map[string]nftPersistenceRead)
	active := make(map[string]nftPersistenceRead)
	edited := make(map[string]bool)
	for _, source := range record.Sources {
		path, location := source.Artifact.Path, source.Artifact.Path
		if source.Artifact.SHA256 != source.EditedSHA256 {
			shared, err := readNFTPersistenceSharedRecord(host, path, review)
			if err == nil {
				if shared.Original != nftPersistenceGraphFileRecord(source, review) || shared.Xattrs != source.Xattrs || shared.Replacement.Source.SHA256 != source.EditedSHA256 {
					return nil, fmt.Errorf("shared Fail2ban source intent differs from review")
				}
				state, err := inspectNFTPersistenceSharedStateUsing(host, shared, planner)
				if err != nil {
					return nil, err
				}
				if state.phase != 0 {
					active[path], edited[path] = state.replacement, state.phase == 2
					location = nftPersistenceSharedDirectory(shared) + "/" + shared.Stage
					if state.phase == 2 {
						location = nftPersistenceSharedDirectory(shared) + "/original"
					}
				}
			} else if !errors.Is(err, fs.ErrNotExist) {
				return nil, err
			}
		}
		snapshot, attrs, err := snapshotNFTPersistenceMetadata(host, location)
		if err != nil {
			return nil, err
		}
		edit, err := planner(snapshot.content)
		if err != nil {
			return nil, err
		}
		bound, err := bindNFTPersistenceGraphSource(path, snapshot, attrs, edit.content)
		if err != nil || !wireguardstate.MatchesRecordedArtifact(bound.Artifact, source.Artifact) || bound.Size != source.Size || bound.ModifiedNS != source.ModifiedNS || bound.Xattrs != source.Xattrs || bound.EditedSHA256 != source.EditedSHA256 {
			return nil, fmt.Errorf("shared Fail2ban original bytes or metadata changed")
		}
		originals[path] = snapshot
		if _, present := active[path]; !present {
			active[path] = snapshot
		}
	}
	for _, absent := range record.Absent {
		if _, err := host.snapshot(absent); !errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("a previously absent persistence entry appeared")
		}
	}
	for _, expansion := range record.Expansions {
		current, err := host.expand(expansion.Pattern)
		if err != nil || !slices.Equal(current, expansion.Paths) {
			return nil, fmt.Errorf("shared persistence wildcard expansion changed")
		}
	}
	for _, expected := range []map[string]nftPersistenceRead{originals, active} {
		reader := nftPersistenceGraphReader{read: func(path string) (nftPersistenceRead, error) {
			value, found := expected[path]
			if !found {
				return nftPersistenceRead{}, fmt.Errorf("unreviewed shared persistence dependency")
			}
			return value, nil
		}, expand: host.expand}
		graph, err := inspectNFTPersistenceGraph(record.Entries, reader)
		if err != nil || len(graph.sources) != len(expected) || len(graph.expansions) != len(record.Expansions) {
			return nil, fmt.Errorf("shared persistence graph differs from its complete reviewed inventory")
		}
		for index, expansion := range graph.expansions {
			if expansion.pattern != record.Expansions[index].Pattern || !slices.Equal(expansion.paths, record.Expansions[index].Paths) {
				return nil, fmt.Errorf("shared persistence include expressions changed")
			}
		}
	}
	graph, err := inspectNFTPersistenceGraph(record.Entries, host.reader())
	if err != nil || len(graph.sources) != len(active) {
		return nil, fmt.Errorf("active shared persistence graph changed during verification")
	}
	for _, source := range graph.sources {
		expected, found := active[source.path]
		if !found || sha256.Sum256(expected.content) != source.sha256 || !sameNFTPersistenceIdentity(expected.identity, source.identity) {
			return nil, fmt.Errorf("active shared persistence source changed during verification")
		}
	}
	return edited, verifyNFTPersistenceGraphDirectories(host, nftPersistenceGraphRecord{Directories: record.Directories})
}

func readLegacyFail2banPersistence(host nftPersistenceFilesystem, filePlan, review string) (legacyFail2banPersistenceRecord, error) {
	var record legacyFail2banPersistenceRecord
	if !validLegacyRetirementDigest(filePlan) || !validLegacyRetirementDigest(review) {
		return record, fmt.Errorf("shared persistence resumption requires both exact digests")
	}
	snapshot, err := host.snapshot(legacyFail2banPersistencePath(filePlan, review) + "/intent.json")
	if err != nil {
		return record, err
	}
	if len(snapshot.content) > 2<<20 || snapshot.identity.Mode().Perm() != 0600 || json.Unmarshal(snapshot.content, &record) != nil {
		return record, fmt.Errorf("shared persistence intent is not private and bounded")
	}
	content, digest, err := encodeLegacyFail2banPersistence(record, host)
	if err != nil || digest != review || record.FilePlan != filePlan || !bytes.Equal(content, snapshot.content) {
		return record, fmt.Errorf("shared persistence intent differs from its original exact review")
	}
	return record, nil
}

func legacyFail2banPersistenceSummary(record legacyFail2banPersistenceRecord, digest string) LegacyFail2banPersistenceSummary {
	summary := LegacyFail2banPersistenceSummary{Schema: record.Schema, FilePlanSHA256: record.FilePlan, PlanSHA256: digest, StopsProductServices: true, PreservesSharedService: true, BackupDirectory: legacyFail2banPlanPath(digest) + "/nft-persistence"}
	for _, source := range record.Sources {
		if source.Artifact.SHA256 != source.EditedSHA256 {
			summary.SharedFiles = append(summary.SharedFiles, source.Artifact.Path)
		}
	}
	return summary
}

func InspectLegacyFail2banPersistence(ctx context.Context) (LegacyFail2banPersistenceSummary, error) {
	var empty LegacyFail2banPersistenceSummary
	session, err := inspectLegacyFail2banRecoverySession(ctx, "", "", false, true)
	if err != nil {
		return empty, err
	}
	defer session.close()
	loader, err := inspectNFTPersistenceLoader(ctx, session.host)
	if err != nil {
		return empty, err
	}
	record, digest, err := prepareLegacyFail2banPersistence(session.host, loader, session.plan.sha256, session.kernel)
	if err != nil {
		return empty, err
	}
	if err := loader.verify(ctx); err != nil {
		return empty, err
	}
	return legacyFail2banPersistenceSummary(record, digest), nil
}

func ApplyLegacyFail2banPersistence(ctx context.Context, filePlan, review string, prepare func() error) (LegacyFail2banPersistenceSummary, error) {
	var empty LegacyFail2banPersistenceSummary
	if !validLegacyRetirementDigest(filePlan) || !validLegacyRetirementDigest(review) || prepare == nil {
		return empty, fmt.Errorf("shared Fail2ban persistence requires both reviewed digests and removal preparation")
	}
	session, err := inspectLegacyFail2banRecoverySession(ctx, filePlan, "", false, true)
	if err != nil {
		return empty, err
	}
	defer session.close()
	loader, err := inspectNFTPersistenceLoader(ctx, session.host)
	if err != nil {
		return empty, err
	}
	record, err := readLegacyFail2banPersistence(session.host, filePlan, review)
	if errors.Is(err, fs.ErrNotExist) {
		var digest string
		record, digest, err = prepareLegacyFail2banPersistence(session.host, loader, filePlan, session.kernel)
		if err == nil && digest != review {
			err = fmt.Errorf("shared Fail2ban persistence changed since review")
		}
	}
	if err != nil {
		return empty, err
	}
	if err := prepare(); err != nil {
		return empty, err
	}
	lock, err := acquireNFTReloadGuard()
	if err != nil {
		return empty, err
	}
	defer releaseNFTReloadGuard(lock)
	adapter, err := newLegacyFail2banRuntimeRetirementAdapter(session.host, session.plan, session.inspection, func(ctx context.Context) error { return ctx.Err() })
	if err != nil {
		return empty, err
	}
	guard := func() error {
		if err := attestLegacyFail2banRecoveryProduct(); err != nil {
			return err
		}
		if loader.digest != record.Loader {
			return fmt.Errorf("shared nftables loader changed since persistence review")
		}
		if err := loader.verify(ctx); err != nil {
			return err
		}
		current, _, err := prepareLegacyFail2banRuntimeRetirementSchema(ctx, adapter, record.Kernel.Schema)
		if err != nil {
			return err
		}
		expected, _, _, err := encodeLegacyFail2banNFTJournalRecord(record.Kernel)
		if err != nil {
			return err
		}
		actual, _, _, err := encodeLegacyFail2banNFTJournalRecord(current)
		if err != nil || !bytes.Equal(actual, expected) {
			return fmt.Errorf("live Fail2ban state changed since persistent source review")
		}
		_, err = inspectLegacyFail2banPersistenceState(session.host, record, review)
		return err
	}
	ops := defaultLegacyRetirementFileOps()
	if err := persistLegacyFail2banPlanUsing(session.host, session.plan, guard, ops); err != nil {
		return empty, err
	}
	content, err := persistLegacyFail2banPersistenceReview(session.host, record, review, guard, ops)
	if err != nil {
		return empty, err
	}
	boundGuard := func() error {
		stored, err := readLegacyFail2banPersistence(session.host, filePlan, review)
		if err != nil {
			return err
		}
		wire, _, err := encodeLegacyFail2banPersistence(stored, session.host)
		if err != nil || !bytes.Equal(wire, content) {
			return fmt.Errorf("shared persistence intent changed at a mutation boundary")
		}
		return guard()
	}
	planner := func(content []byte) (nftPersistenceEdit, error) {
		return planLegacyFail2banPersistence(content, record.Kernel)
	}
	for _, source := range record.Sources {
		if source.Artifact.SHA256 == source.EditedSHA256 {
			continue
		}
		shared, err := prepareNFTPersistenceSharedEditUsing(session.host, source.Artifact.Path, review, boundGuard, ops, planner)
		if err != nil {
			return empty, err
		}
		if err := applyNFTPersistenceSharedEditUsing(session.host, shared, func(bool) error { return boundGuard() }, ops, planner); err != nil {
			return empty, err
		}
	}
	if err := boundGuard(); err != nil {
		return empty, err
	}
	edited, err := inspectLegacyFail2banPersistenceState(session.host, record, review)
	if err != nil {
		return empty, err
	}
	for _, source := range record.Sources {
		if source.Artifact.SHA256 != source.EditedSHA256 && !edited[source.Artifact.Path] {
			return empty, fmt.Errorf("shared persistent source retirement is incomplete")
		}
	}
	return legacyFail2banPersistenceSummary(record, review), nil
}

// Reuse an exact immutable review after interruption. Existing evidence must
// never be overwritten, even when a command is being applied again.
func persistLegacyFail2banPersistenceReview(host nftPersistenceFilesystem, record legacyFail2banPersistenceRecord, review string, guard func() error, ops legacyRetirementFileOps) ([]byte, error) {
	if !validLegacyRetirementOperations(guard, ops) {
		return nil, fmt.Errorf("persistent review requires complete mutation guards")
	}
	content, digest, err := encodeLegacyFail2banPersistence(record, host)
	if err != nil || digest != review {
		return nil, fmt.Errorf("persistent review differs from its exact authorization")
	}
	if err := guard(); err != nil {
		return nil, err
	}
	path := legacyFail2banPersistencePath(record.FilePlan, review)
	if err := ensureLegacyRetirementPrivateDirectory(host, path, ops); err != nil {
		return nil, err
	}
	root, err := host.openDirectory(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	fd, err := root.Open(".")
	if err != nil {
		return nil, err
	}
	defer func() { _ = fd.Close() }()
	identity, err := fd.Stat()
	if err != nil {
		return nil, err
	}
	retained, err := host.snapshot(path + "/intent.json")
	if errors.Is(err, fs.ErrNotExist) {
		if err := guard(); err != nil {
			return nil, err
		}
		if err := attestLegacyRetirementDirectory(host, path, identity); err != nil {
			return nil, err
		}
		if err := publishLegacyRetirementJSON(root, fd, "intent", content, ops); err != nil {
			return nil, err
		}
		retained, err = host.snapshot(path + "/intent.json")
	}
	if err != nil || retained.identity.Mode().Perm() != 0600 || !bytes.Equal(retained.content, content) {
		return nil, fmt.Errorf("persistent review differs from its immutable private record")
	}
	file, err := root.OpenFile("intent.json", os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	actual, err := file.Stat()
	if err != nil || !sameNFTPersistenceIdentity(retained.identity, actual) {
		return nil, fmt.Errorf("persistent review changed before synchronization")
	}
	if err := errors.Join(ops.sync(file), ops.sync(fd)); err != nil {
		return nil, err
	}
	if err := attestLegacyRetirementDirectory(host, path, identity); err != nil {
		return nil, err
	}
	if _, err := readLegacyFail2banPersistence(host, record.FilePlan, review); err != nil {
		return nil, err
	}
	return content, guard()
}
