//go:build linux

package firewall

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
)

const nftHistoricalInputSchema = "syswarden-historical-firewall-inputs-v1"

// This is an operator-supplied description of separately retained generation
// inputs, not a receipt emitted by a historical writer. Applying a review must
// explicitly confirm their origin. Never reconstruct this document from the
// candidate firewall source or from an agreeing live ruleset.
type nftHistoricalInputDocument struct {
	Schema     string                       `json:"schema"`
	Generation string                       `json:"generation"`
	Inputs     nftV4028PersistenceInputs    `json:"inputs"`
	Evidence   []nftHistoricalInputEvidence `json:"evidence"`
}

type nftHistoricalInputEvidence struct {
	Kind   string `json:"kind"`
	File   string `json:"file"`
	SHA256 string `json:"sha256"`
}

type nftHistoricalInputInspection struct {
	path     string
	document nftHistoricalInputDocument
	files    []nftPersistenceGraphSourceRecord
	digest   string
}

func inspectNFTHistoricalInputs(host nftPersistenceFilesystem, path string) (nftHistoricalInputInspection, error) {
	var empty nftHistoricalInputInspection
	if !canonicalNFTPersistencePath(path, false) || !strings.HasPrefix(path, "/root/") {
		return empty, fmt.Errorf("historical inputs require an absolute private capture path under /root")
	}
	parent, err := host.openDirectory(filepath.Dir(path))
	if err != nil {
		return empty, err
	}
	info, statErr := parent.Stat(".")
	closeErr := parent.Close()
	if statErr != nil || closeErr != nil || info.Mode().Perm() != 0700 {
		return empty, fmt.Errorf("historical input capture directory must be private")
	}
	snapshot, attrs, err := snapshotNFTPersistenceMetadata(host, path)
	if err != nil || snapshot.identity == nil || snapshot.identity.Mode().Perm() != 0600 || len(snapshot.content) > 256<<10 {
		return empty, fmt.Errorf("historical input description must be a bounded private regular file")
	}
	var document nftHistoricalInputDocument
	decoder := json.NewDecoder(bytes.NewReader(snapshot.content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return empty, fmt.Errorf("historical input description has an unsupported schema")
	}
	canonical, err := json.Marshal(document)
	var compact bytes.Buffer
	if err != nil || json.Compact(&compact, snapshot.content) != nil || !bytes.Equal(compact.Bytes(), canonical) || document.Schema != nftHistoricalInputSchema || document.Generation != "v4.02.8" || len(document.Evidence) != 2 {
		return empty, fmt.Errorf("historical input description must have canonical fields, one supported generation and both independent evidence sources")
	}
	bound, err := bindNFTPersistenceGraphSource(path, snapshot, attrs, snapshot.content)
	if err != nil {
		return empty, err
	}
	inspection := nftHistoricalInputInspection{path: path, document: document, files: []nftPersistenceGraphSourceRecord{bound}}
	for index, evidence := range document.Evidence {
		if evidence.Kind != []string{"configuration", "host-inputs"}[index] || !nftHistoricalEvidenceName(evidence.File) || evidence.File == filepath.Base(path) || !validLegacyRetirementDigest(evidence.SHA256) {
			return empty, fmt.Errorf("historical evidence requires distinct bounded configuration and host-input files")
		}
		if index > 0 && evidence.File == document.Evidence[0].File {
			return empty, fmt.Errorf("historical evidence files must be distinct")
		}
		evidencePath := filepath.Join(filepath.Dir(path), evidence.File)
		original, attributes, err := snapshotNFTPersistenceMetadata(host, evidencePath)
		if err != nil || original.identity == nil || original.identity.Mode().Perm() != 0600 || len(original.content) == 0 || len(original.content) > 1<<20 || nftSHA256Hex(original.content) != evidence.SHA256 {
			return empty, fmt.Errorf("historical evidence is missing, unsafe or differs from its supplied fingerprint: %s", evidence.Kind)
		}
		record, err := bindNFTPersistenceGraphSource(evidencePath, original, attributes, original.content)
		if err != nil {
			return empty, err
		}
		inspection.files = append(inspection.files, record)
	}
	content, err := json.Marshal(inspection.files)
	if err != nil {
		return empty, err
	}
	inspection.digest = nftSHA256Hex(content)
	return inspection, inspection.verify(host)
}

func nftHistoricalEvidenceName(name string) bool {
	if len(name) == 0 || len(name) > 128 || name[0] == '.' || name[0] == '-' {
		return false
	}
	for _, char := range name {
		if !(char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || char == '.' || char == '-' || char == '_') {
			return false
		}
	}
	return true
}

func (inspection nftHistoricalInputInspection) verify(host nftPersistenceFilesystem) error {
	parent, err := host.openDirectory(filepath.Dir(inspection.path))
	if err != nil {
		return err
	}
	info, statErr := parent.Stat(".")
	closeErr := parent.Close()
	if statErr != nil || closeErr != nil || info.Mode().Perm() != 0700 {
		return fmt.Errorf("historical input capture directory changed its private boundary")
	}
	if inspection.path == "" || len(inspection.files) != 3 || inspection.files[0].Artifact.Path != inspection.path {
		return fmt.Errorf("historical inputs lack their independent capture identity")
	}
	for _, expected := range inspection.files {
		current, attrs, err := snapshotNFTPersistenceMetadata(host, expected.Artifact.Path)
		if err != nil || current.identity == nil || current.identity.Mode().Perm() != 0600 || !matchesNFTPersistenceGraphSource(expected, current, attrs) {
			return fmt.Errorf("historical input evidence changed after inspection")
		}
	}
	encoded, err := json.Marshal(inspection.files)
	if err != nil || nftSHA256Hex(encoded) != inspection.digest {
		return fmt.Errorf("historical input identities differ from the reviewed authority")
	}
	return nil
}

// A capture must remain outside every file inspected by the persistence graph.
// It is retained verbatim at its private original paths across recovery.
func (inspection nftHistoricalInputInspection) independentOf(plan nftHistoricalPersistencePlan) error {
	if plan.binding.Origins != inspection.digest || plan.binding.V4028 == nil || plan.binding.Current != nil {
		return fmt.Errorf("historical source plan differs from the selected input capture")
	}
	for _, source := range plan.graph.Sources {
		for _, input := range inspection.files {
			if source.Artifact.Path == input.Artifact.Path || (source.Artifact.Device == input.Artifact.Device && source.Artifact.Inode == input.Artifact.Inode && source.Artifact.FilesystemUUID == input.Artifact.FilesystemUUID) {
				return fmt.Errorf("historical inputs overlap a candidate persistence source")
			}
		}
	}
	left, err := json.Marshal(plan.binding.V4028)
	right, otherErr := json.Marshal(inspection.document.Inputs)
	if err != nil || otherErr != nil || !bytes.Equal(left, right) {
		return fmt.Errorf("historical generator inputs differ from their independently reviewed capture")
	}
	return nil
}

func nftHistoricalInputFilePaths(inspection nftHistoricalInputInspection) []string {
	paths := make([]string, 0, len(inspection.files))
	for _, file := range inspection.files {
		paths = append(paths, file.Artifact.Path)
	}
	slices.Sort(paths)
	return paths
}
