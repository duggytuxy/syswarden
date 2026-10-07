//go:build linux

package firewall

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
)

const legacyIPTablesInputSchema = "syswarden-historical-iptables-inputs-v1"

type legacyIPTablesInputDocument struct {
	Schema     string                       `json:"schema"`
	Generation string                       `json:"generation"`
	Epoch      nftRemovalEpoch              `json:"epoch"`
	Inputs     legacyIPTablesInputs         `json:"inputs"`
	Evidence   []nftHistoricalInputEvidence `json:"evidence"`
}

type legacyIPTablesInputInspection struct {
	path      string
	document  legacyIPTablesInputDocument
	files     []nftPersistenceGraphSourceRecord
	before    legacyIPTablesObservation
	generated legacyIPTablesObservation
	digest    string
}

func inspectLegacyIPTablesInputs(host nftPersistenceFilesystem, path string, epoch nftRemovalEpoch) (legacyIPTablesInputInspection, error) {
	var empty legacyIPTablesInputInspection
	if !canonicalNFTPersistencePath(path, false) || !strings.HasPrefix(path, "/root/") || epoch.BootID == "" || epoch.Inode == 0 {
		return empty, fmt.Errorf("historical iptables inputs require a private original capture and a current boot/namespace identity")
	}
	parent, err := host.openDirectory(filepath.Dir(path))
	if err != nil {
		return empty, err
	}
	info, statErr := parent.Stat(".")
	closeErr := parent.Close()
	if statErr != nil || closeErr != nil || info.Mode().Perm() != 0700 {
		return empty, fmt.Errorf("historical iptables capture directory must be private")
	}
	snapshot, attrs, err := snapshotNFTPersistenceMetadata(host, path)
	if err != nil || snapshot.identity == nil || snapshot.identity.Mode().Perm() != 0600 || len(snapshot.content) > 256<<10 {
		return empty, fmt.Errorf("historical iptables description must be a bounded private regular file")
	}
	var document legacyIPTablesInputDocument
	decoder := json.NewDecoder(bytes.NewReader(snapshot.content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return empty, fmt.Errorf("unsupported historical iptables capture schema")
	}
	canonical, err := json.Marshal(document)
	var compact bytes.Buffer
	if err != nil || json.Compact(&compact, snapshot.content) != nil || !bytes.Equal(compact.Bytes(), canonical) || document.Schema != legacyIPTablesInputSchema || document.Generation != "v4.02.8" || document.Epoch != epoch || len(document.Evidence) < 4 || len(document.Evidence) > 5 {
		return empty, fmt.Errorf("historical iptables capture is noncanonical, incomplete or belongs to another boot/namespace")
	}
	if _, err := legacyIPTablesExpectedBlock(document.Inputs); err != nil {
		return empty, err
	}
	bound, err := bindNFTPersistenceGraphSource(path, snapshot, attrs, snapshot.content)
	if err != nil {
		return empty, err
	}
	result := legacyIPTablesInputInspection{path: path, document: document, files: []nftPersistenceGraphSourceRecord{bound}}
	kinds := []string{"configuration", "nft-before", "nft-generated", "iptables-generated", "iptables-before"}
	seen := map[string]bool{filepath.Base(path): true}
	captures := make(map[string][]byte)
	for index, evidence := range document.Evidence {
		if evidence.Kind != kinds[index] || !nftHistoricalEvidenceName(evidence.File) || seen[evidence.File] || !validLegacyRetirementDigest(evidence.SHA256) {
			return empty, fmt.Errorf("historical iptables capture requires distinct original evidence files in canonical order")
		}
		seen[evidence.File] = true
		original, attrs, err := snapshotNFTPersistenceMetadata(host, filepath.Join(filepath.Dir(path), evidence.File))
		if err != nil || original.identity == nil || original.identity.Mode().Perm() != 0600 || len(original.content) == 0 || len(original.content) > 8<<20 || nftSHA256Hex(original.content) != evidence.SHA256 {
			return empty, fmt.Errorf("historical iptables evidence is unsafe, unavailable or differs from its fingerprint: %s", evidence.Kind)
		}
		record, err := bindNFTPersistenceGraphSource(filepath.Join(filepath.Dir(path), evidence.File), original, attrs, original.content)
		if err != nil {
			return empty, err
		}
		result.files = append(result.files, record)
		captures[evidence.Kind] = original.content
	}
	priorText := captures["iptables-before"]
	if priorText == nil {
		// A successful original nft ruleset capture can prove there were no
		// IPv4 compatibility rules. Do not manufacture a missing text capture
		// when any original rule exists; observeLegacyIPTables refuses it.
		priorText = []byte("*filter\nCOMMIT\n")
	}
	result.before, err = observeLegacyIPTables(captures["nft-before"], priorText)
	if err != nil {
		return empty, err
	}
	result.generated, err = observeLegacyIPTables(captures["nft-generated"], captures["iptables-generated"])
	if err != nil {
		return empty, err
	}
	if _, err := historicalIPTablesAddedRules(result.before, result.generated, document.Inputs); err != nil {
		return empty, err
	}
	binding, err := json.Marshal(result.files)
	if err != nil {
		return empty, err
	}
	result.digest = nftSHA256Hex(binding)
	return result, result.verify(host, epoch)
}

func (inspection legacyIPTablesInputInspection) verify(host nftPersistenceFilesystem, epoch nftRemovalEpoch) error {
	if inspection.document.Epoch != epoch || len(inspection.files) < 5 || len(inspection.files) > 6 || inspection.files[0].Artifact.Path != inspection.path {
		return fmt.Errorf("historical iptables origin identities are incomplete or changed")
	}
	parent, err := host.openDirectory(filepath.Dir(inspection.path))
	if err != nil {
		return err
	}
	info, statErr := parent.Stat(".")
	closeErr := parent.Close()
	if statErr != nil || closeErr != nil || info.Mode().Perm() != 0700 {
		return fmt.Errorf("historical iptables private capture boundary changed")
	}
	for _, expected := range inspection.files {
		current, attrs, err := snapshotNFTPersistenceMetadata(host, expected.Artifact.Path)
		if err != nil || current.identity == nil || current.identity.Mode().Perm() != 0600 || !matchesNFTHistoricalInput(expected, current, attrs) {
			return fmt.Errorf("historical iptables origin evidence changed after review")
		}
	}
	binding, err := json.Marshal(inspection.files)
	if err != nil || nftSHA256Hex(binding) != inspection.digest {
		return fmt.Errorf("historical iptables capture identities differ from their reviewed binding")
	}
	return nil
}
