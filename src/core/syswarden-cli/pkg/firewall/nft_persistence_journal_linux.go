//go:build linux

package firewall

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"syswarden-cli/pkg/wireguardstate"
)

const nftPersistenceGraphSchema = "syswarden-nftables-retirement-graph-v1"

type nftPersistenceGraphSourceRecord struct {
	Artifact     wireguardstate.Artifact `json:"artifact"`
	Size         int64                   `json:"size"`
	ModifiedNS   int64                   `json:"modified_ns"`
	Xattrs       string                  `json:"xattrs_sha256"`
	EditedSHA256 string                  `json:"edited_sha256"`
}

type nftPersistenceGraphExpansionRecord struct {
	Pattern string   `json:"pattern"`
	Paths   []string `json:"paths"`
}

type nftPersistenceGraphRecord struct {
	Schema       string                               `json:"schema"`
	Ownership    string                               `json:"ownership_evidence_sha256"`
	Producers    string                               `json:"producer_evidence_sha256"`
	Entries      []string                             `json:"entries"`
	Sources      []nftPersistenceGraphSourceRecord    `json:"sources"`
	Directories  []legacyFail2banPlanDirectory        `json:"directories"`
	Expansions   []nftPersistenceGraphExpansionRecord `json:"expansions"`
	Retiring     []string                             `json:"retiring"`
	ProductEntry bool                                 `json:"dedicated_product_entry,omitempty"`
}

func bindNFTPersistenceGraphSource(path string, snapshot nftPersistenceRead, attrs []nftPersistenceXattr, edited []byte) (nftPersistenceGraphSourceRecord, error) {
	var empty nftPersistenceGraphSourceRecord
	if snapshot.identity == nil || !snapshot.identity.Mode().IsRegular() || !canonicalNFTPersistencePath(path, false) || len(path) > 4096 {
		return empty, fmt.Errorf("nftables graph source lacks an exact regular-file identity")
	}
	stat, valid := snapshot.identity.Sys().(*syscall.Stat_t)
	if !valid || int64(len(snapshot.content)) != snapshot.identity.Size() || !wireguardstate.ValidFilesystemUUID(snapshot.filesystemUUID) {
		return empty, fmt.Errorf("nftables graph source lacks exact bounded content and filesystem evidence")
	}
	return nftPersistenceGraphSourceRecord{
		Artifact: wireguardstate.Artifact{Path: path, SHA256: fmt.Sprintf("%x", sha256.Sum256(snapshot.content)), Mode: uint32(snapshot.identity.Mode().Perm()), UID: stat.Uid, GID: stat.Gid, NLink: uint64(stat.Nlink), Device: uint64(stat.Dev), Inode: stat.Ino, FilesystemUUID: snapshot.filesystemUUID},
		Size:     snapshot.identity.Size(), ModifiedNS: snapshot.identity.ModTime().UnixNano(), Xattrs: nftPersistenceXattrDigest(attrs), EditedSHA256: fmt.Sprintf("%x", sha256.Sum256(edited)),
	}, nil
}

func encodeNFTPersistenceGraphRecord(record nftPersistenceGraphRecord, host nftPersistenceFilesystem) ([]byte, string, error) {
	invalid := func() ([]byte, string, error) {
		return nil, "", fmt.Errorf("invalid or unbounded nftables retirement graph evidence")
	}
	if record.Schema != nftPersistenceGraphSchema || !validLegacyRetirementDigest(record.Ownership) || !validLegacyRetirementDigest(record.Producers) ||
		record.Ownership == strings.Repeat("0", 64) || record.Producers == strings.Repeat("0", 64) ||
		len(record.Entries) == 0 || len(record.Entries) > maximumNFTPersistenceFiles || len(record.Sources) == 0 || len(record.Sources) > maximumNFTPersistenceFiles ||
		len(record.Directories) == 0 || len(record.Directories) > maximumNFTPersistenceFiles || len(record.Expansions) > maximumNFTPersistenceIncludes ||
		len(record.Retiring) == 0 || len(record.Retiring) > maximumNFTPersistenceFiles {
		return invalid()
	}
	directories := make(map[string]bool)
	for index, directory := range record.Directories {
		if directory.Path != "/" && !canonicalNFTPersistencePath(directory.Path, false) || len(directory.Path) > 4096 ||
			index > 0 && record.Directories[index-1].Path >= directory.Path || directory.Inode == 0 || directory.NLink == 0 ||
			directory.Mode&syscall.S_IFMT != syscall.S_IFDIR || directory.Mode & ^uint32(syscall.S_IFDIR|0777) != 0 || directory.Mode&0022 != 0 ||
			directory.UID != host.expectedUID || directory.GID != host.expectedGID || !wireguardstate.ValidFilesystemUUID(directory.FilesystemUUID) {
			return invalid()
		}
		directories[directory.Path] = true
	}
	sources := make(map[string]bool)
	var total int64
	for index, source := range record.Sources {
		file := source.Artifact
		if !canonicalNFTPersistencePath(file.Path, false) || len(file.Path) > 4096 || index > 0 && record.Sources[index-1].Artifact.Path >= file.Path ||
			!directories[filepath.Dir(file.Path)] || directories[file.Path] || !validLegacyRetirementDigest(file.SHA256) || !validLegacyRetirementDigest(source.EditedSHA256) ||
			!validLegacyRetirementDigest(source.Xattrs) || file.Mode > 0777 || file.Mode&0022 != 0 || file.UID != host.expectedUID || file.GID != host.expectedGID ||
			file.SHA256 != source.EditedSHA256 && !strings.HasPrefix(file.Path, "/etc/") ||
			file.NLink != 1 || file.Inode == 0 || !wireguardstate.ValidFilesystemUUID(file.FilesystemUUID) || source.Size < 0 || source.Size > maximumNFTPersistenceBytes || total > maximumNFTPersistenceGraphBytes-source.Size {
			return invalid()
		}
		total += source.Size
		sources[file.Path] = true
	}
	entries := make(map[string]bool)
	for index, path := range record.Entries {
		if !sources[path] || index > 0 && record.Entries[index-1] >= path {
			return invalid()
		}
		entries[path] = true
	}
	for index, path := range record.Retiring {
		if !sources[path] || entries[path] && !(record.ProductEntry && path == legacyNFTIncludePath) || !strings.HasPrefix(path, "/etc/") || index > 0 && record.Retiring[index-1] >= path {
			return invalid()
		}
	}
	if record.ProductEntry && (len(record.Retiring) != 1 || record.Retiring[0] != legacyNFTIncludePath || !entries[legacyNFTIncludePath]) {
		return invalid()
	}
	var edges int
	for index, expansion := range record.Expansions {
		if !canonicalNFTPersistencePath(expansion.Pattern, true) || len(expansion.Pattern) > 4096 || !strings.Contains(expansion.Pattern, "*") ||
			index > 0 && record.Expansions[index-1].Pattern >= expansion.Pattern || len(expansion.Paths) > maximumNFTPersistenceFiles {
			return invalid()
		}
		if _, err := matchNFTPersistenceWildcard(expansion.Pattern, ""); err != nil {
			return invalid()
		}
		for i, path := range expansion.Paths {
			match, err := matchNFTPersistenceWildcard(expansion.Pattern, path)
			if err != nil || !match || !sources[path] || i > 0 && expansion.Paths[i-1] >= path {
				return invalid()
			}
		}
		edges += len(expansion.Paths)
		if edges > maximumNFTPersistenceIncludes {
			return invalid()
		}
	}
	content, err := json.Marshal(record)
	if err != nil || len(content) > 2<<20 {
		return invalid()
	}
	return content, fmt.Sprintf("%x", sha256.Sum256(content)), nil
}

// Ownership and external-producer evidence must come from independent
// attestations. This binding records their digests; it cannot create them from
// a filename, a generated marker or the include graph itself. Preparation is
// read-only and does not authorize editing until those attestations are checked
// again by the applying coordinator under its removal locks.
func prepareNFTPersistenceGraphRecord(host nftPersistenceFilesystem, entries []string, retiring []nftPersistenceRetiredSource, ownership, producers string) (nftPersistenceGraphRecord, string, error) {
	return prepareNFTPersistenceGraphRecordWithProductEntry(host, entries, retiring, ownership, producers, false)
}

func prepareNFTPersistenceGraphRecordWithProductEntry(host nftPersistenceFilesystem, entries []string, retiring []nftPersistenceRetiredSource, ownership, producers string, productEntry bool) (nftPersistenceGraphRecord, string, error) {
	var empty nftPersistenceGraphRecord
	graph, err := inspectNFTPersistenceGraph(entries, host.reader())
	if err != nil {
		return empty, "", err
	}
	if err := verifyNFTPersistenceRetirementCoverageWithProductEntry(graph, retiring, productEntry); err != nil {
		return empty, "", err
	}
	record := nftPersistenceGraphRecord{Schema: nftPersistenceGraphSchema, Ownership: ownership, Producers: producers, Entries: append([]string(nil), graph.entries...), ProductEntry: productEntry}
	parents := make(map[string]bool)
	for _, source := range graph.sources {
		snapshot, attrs, err := snapshotNFTPersistenceMetadata(host, source.path)
		if err != nil || !sameNFTPersistenceIdentity(snapshot.identity, source.identity) || sha256.Sum256(snapshot.content) != source.sha256 {
			return empty, "", fmt.Errorf("nftables graph source changed during metadata binding")
		}
		bound, err := bindNFTPersistenceGraphSource(source.path, snapshot, attrs, source.edit.content)
		if err != nil {
			return empty, "", err
		}
		record.Sources = append(record.Sources, bound)
		parents[filepath.Dir(source.path)] = true
	}
	for path := range parents {
		parent, err := host.openDirectory(path)
		if err != nil {
			return empty, "", err
		}
		info, err := parent.Stat(".")
		_ = parent.Close()
		if err != nil {
			return empty, "", err
		}
		bound, err := bindLegacyFail2banPlanDirectory(host, path, info)
		if err != nil {
			return empty, "", err
		}
		record.Directories = append(record.Directories, bound)
	}
	sort.Slice(record.Directories, func(i, j int) bool { return record.Directories[i].Path < record.Directories[j].Path })
	for _, expansion := range graph.expansions {
		record.Expansions = append(record.Expansions, nftPersistenceGraphExpansionRecord{expansion.pattern, append([]string(nil), expansion.paths...)})
	}
	for _, source := range retiring {
		record.Retiring = append(record.Retiring, source.path)
	}
	sort.Strings(record.Retiring)
	if err := verifyNFTPersistenceGraph(graph, host.reader()); err != nil {
		return empty, "", err
	}
	// Recheck xattrs as well as source bytes at the end of the read-only pass.
	for _, source := range record.Sources {
		current, attrs, err := snapshotNFTPersistenceMetadata(host, source.Artifact.Path)
		if err != nil {
			return empty, "", err
		}
		edit, err := planLegacyNFTIncludeRetirement(current.content)
		if err != nil {
			return empty, "", err
		}
		bound, err := bindNFTPersistenceGraphSource(source.Artifact.Path, current, attrs, edit.content)
		if err != nil || bound != source {
			return empty, "", fmt.Errorf("nftables graph metadata changed during preparation")
		}
	}
	for _, expected := range record.Directories {
		parent, err := host.openDirectory(expected.Path)
		if err != nil {
			return empty, "", err
		}
		identity, err := parent.Stat(".")
		_ = parent.Close()
		if err != nil {
			return empty, "", err
		}
		current, err := bindLegacyFail2banPlanDirectory(host, expected.Path, identity)
		if err != nil || !sameLegacyFail2banPlanDirectory(current, expected) {
			return empty, "", fmt.Errorf("nftables graph parent directory changed during preparation")
		}
	}
	_, digest, err := encodeNFTPersistenceGraphRecord(record, host)
	if err != nil {
		return empty, "", err
	}
	return record, digest, nil
}
