//go:build linux

package firewall

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"reflect"
	"strings"
	"syscall"
)

const nftHistoricalPersistenceSchema = "syswarden-historical-persistence-binding-v1"

// Origins binds independent input provenance. It must never be derived just
// from the candidate file, a product-like name or agreeing runtime snapshots.
// The applying adapter must verify it and all producer evidence under its locks.
type nftHistoricalPersistenceBinding struct {
	Schema       string                          `json:"schema"`
	Origins      string                          `json:"input_origins_sha256"`
	Producers    string                          `json:"producer_evidence_sha256"`
	Inet         nftShellInputs                  `json:"inet_inputs"`
	Ingress      *nftHistoricalIngressInputs     `json:"ingress_inputs"`
	Source       nftPersistenceGraphSourceRecord `json:"source"`
	V4028        *nftV4028PersistenceInputs      `json:"v4028_inputs,omitempty"`
	Current      *nftCurrentPersistenceInputs    `json:"current_inputs,omitempty"`
	ProductEntry bool                            `json:"dedicated_product_entry,omitempty"`
}

type nftHistoricalPersistencePlan struct {
	binding nftHistoricalPersistenceBinding
	graph   nftPersistenceGraphRecord
	sha256  string
}

func encodeNFTHistoricalPersistenceBinding(binding nftHistoricalPersistenceBinding) ([]byte, string, error) {
	if binding.Schema != nftHistoricalPersistenceSchema || binding.Source.Artifact.Path != legacyNFTIncludePath ||
		binding.Source.EditedSHA256 != binding.Source.Artifact.SHA256 ||
		!validLegacyRetirementDigest(binding.Origins) || binding.Origins == strings.Repeat("0", 64) ||
		!validLegacyRetirementDigest(binding.Producers) || binding.Producers == strings.Repeat("0", 64) {
		return nil, "", fmt.Errorf("historical persistence lacks exact source and independent authority bindings")
	}
	if binding.V4028 != nil && binding.Current != nil || (binding.V4028 != nil || binding.Current != nil) && (binding.Ingress != nil || !reflect.DeepEqual(binding.Inet, nftShellInputs{})) {
		return nil, "", fmt.Errorf("historical persistence has ambiguous renderer-generation inputs")
	}
	if binding.ProductEntry && binding.Current == nil {
		return nil, "", fmt.Errorf("dedicated product entry retirement requires current writer ownership")
	}
	content, err := json.Marshal(binding)
	if err != nil || len(content) > maximumNFTPersistenceBytes {
		return nil, "", fmt.Errorf("historical persistence binding exceeds its byte bound")
	}
	return content, fmt.Sprintf("%x", sha256.Sum256(content)), nil
}

// Join the complete historical source recognizer to the include graph, exact
// filesystem identity and immutable input evidence. This performs no writes.
// The authority digests must be obtained by the independent production adapter.
func prepareNFTHistoricalPersistencePlan(host nftPersistenceFilesystem, entries []string, inet nftShellInputs, ingress *nftHistoricalIngressInputs, origins, producers string) (nftHistoricalPersistencePlan, error) {
	return prepareNFTRecognizedPersistencePlan(host, entries, nftHistoricalPersistenceBinding{Schema: nftHistoricalPersistenceSchema, Origins: origins, Producers: producers, Inet: inet, Ingress: ingress})
}

func prepareNFTV4028PersistencePlan(host nftPersistenceFilesystem, entries []string, input nftV4028PersistenceInputs, origins, producers string) (nftHistoricalPersistencePlan, error) {
	return prepareNFTRecognizedPersistencePlan(host, entries, nftHistoricalPersistenceBinding{Schema: nftHistoricalPersistenceSchema, Origins: origins, Producers: producers, V4028: &input})
}

func prepareNFTCurrentPersistencePlan(host nftPersistenceFilesystem, entries []string, input nftCurrentPersistenceInputs, origins, producers string) (nftHistoricalPersistencePlan, error) {
	return prepareNFTRecognizedPersistencePlan(host, entries, nftHistoricalPersistenceBinding{Schema: nftHistoricalPersistenceSchema, Origins: origins, Producers: producers, Current: &input})
}

func inspectNFTBoundPersistentSource(source []byte, binding nftHistoricalPersistenceBinding) error {
	if binding.Current != nil {
		if binding.V4028 != nil || binding.Ingress != nil || !reflect.DeepEqual(binding.Inet, nftShellInputs{}) {
			return fmt.Errorf("persistent source inputs mix renderer generations")
		}
		_, err := inspectNFTCurrentPersistentFile(source, *binding.Current)
		return err
	}
	if binding.V4028 != nil {
		if binding.Ingress != nil || !reflect.DeepEqual(binding.Inet, nftShellInputs{}) {
			return fmt.Errorf("persistent source inputs mix renderer generations")
		}
		_, err := inspectNFTV4028PersistentFile(source, *binding.V4028)
		return err
	}
	_, err := inspectNFTHistoricalPersistentFile(source, binding.Inet, binding.Ingress)
	return err
}

func prepareNFTRecognizedPersistencePlan(host nftPersistenceFilesystem, entries []string, binding nftHistoricalPersistenceBinding) (nftHistoricalPersistencePlan, error) {
	var empty nftHistoricalPersistencePlan
	snapshot, attrs, err := snapshotNFTPersistenceMetadata(host, legacyNFTIncludePath)
	if err != nil {
		return empty, err
	}
	if err := inspectNFTBoundPersistentSource(snapshot.content, binding); err != nil {
		return empty, err
	}
	source, err := bindNFTPersistenceGraphSource(legacyNFTIncludePath, snapshot, attrs, snapshot.content)
	if err != nil {
		return empty, err
	}
	binding.Source = source
	content, ownership, err := encodeNFTHistoricalPersistenceBinding(binding)
	if err != nil {
		return empty, err
	}
	// Freeze slices and maps supplied by the caller before returning a plan.
	var frozen nftHistoricalPersistenceBinding
	if err := json.Unmarshal(content, &frozen); err != nil {
		return empty, err
	}
	binding = frozen
	retiring := []nftPersistenceRetiredSource{{legacyNFTIncludePath, sha256.Sum256(snapshot.content)}}
	graph, digest, err := prepareNFTPersistenceGraphRecordWithProductEntry(host, entries, retiring, ownership, binding.Producers, binding.ProductEntry)
	if err != nil {
		return empty, err
	}
	plan := nftHistoricalPersistencePlan{binding: binding, graph: graph, sha256: digest}
	if err := verifyNFTHistoricalPersistencePlan(host, plan); err != nil {
		return empty, err
	}
	return plan, nil
}

// After a partial retirement, validate the exact retained original inode.
// A recreated active source or altered private original is never accepted.
func verifyNFTHistoricalPersistencePlan(host nftPersistenceFilesystem, plan nftHistoricalPersistencePlan) error {
	_, ownership, err := encodeNFTHistoricalPersistenceBinding(plan.binding)
	if err != nil {
		return err
	}
	_, digest, err := encodeNFTPersistenceGraphRecord(plan.graph, host)
	if err != nil || digest != plan.sha256 || plan.graph.Ownership != ownership || plan.graph.Producers != plan.binding.Producers || plan.graph.ProductEntry != plan.binding.ProductEntry ||
		len(plan.graph.Retiring) != 1 || plan.graph.Retiring[0] != legacyNFTIncludePath {
		return fmt.Errorf("historical source binding differs from the reviewed persistence graph")
	}
	found := false
	for _, source := range plan.graph.Sources {
		if source.Artifact.Path == legacyNFTIncludePath {
			found = source == plan.binding.Source
		}
	}
	if !found {
		return fmt.Errorf("historical source identity is absent from the reviewed graph")
	}
	state, err := inspectNFTPersistenceGraphState(host, plan.graph)
	if err != nil {
		return err
	}
	path := legacyNFTIncludePath
	if state.retired[path] {
		path = legacyRetirementBackupDirectory(nftPersistenceGraphFileRecord(plan.binding.Source, digest)) + "/original"
	}
	snapshot, attrs, err := snapshotNFTPersistenceMetadata(host, path)
	if err != nil || !matchesNFTPersistenceGraphSource(plan.binding.Source, snapshot, attrs) {
		return fmt.Errorf("historical source or its retained private original changed")
	}
	return inspectNFTBoundPersistentSource(snapshot.content, plan.binding)
}

func readNFTHistoricalPersistencePlan(host nftPersistenceFilesystem, digest string) (nftHistoricalPersistencePlan, error) {
	var empty nftHistoricalPersistencePlan
	graph, err := readNFTPersistenceGraphRecord(host, digest)
	if err != nil {
		return empty, err
	}
	snapshot, err := host.snapshot(legacyFail2banPlanPath(digest) + "/historical-source.json")
	if err != nil || snapshot.identity == nil || snapshot.identity.Mode().Perm() != 0600 {
		return empty, fmt.Errorf("historical persistence recovery lacks its private source binding")
	}
	var binding nftHistoricalPersistenceBinding
	if err := json.Unmarshal(snapshot.content, &binding); err != nil {
		return empty, err
	}
	canonical, _, err := encodeNFTHistoricalPersistenceBinding(binding)
	if err != nil || !bytes.Equal(canonical, snapshot.content) {
		return empty, fmt.Errorf("historical persistence source journal is not canonical")
	}
	plan := nftHistoricalPersistencePlan{binding, graph, digest}
	return plan, verifyNFTHistoricalPersistencePlan(host, plan)
}

func syncNFTHistoricalSourceBinding(host nftPersistenceFilesystem, digest string, ops legacyRetirementFileOps) error {
	if _, err := readNFTHistoricalPersistencePlan(host, digest); err != nil {
		return err
	}
	path := legacyFail2banPlanPath(digest) + "/historical-source.json"
	before, err := host.snapshot(path)
	if err != nil {
		return err
	}
	directory, err := openLegacyFail2banPlanDirectory(host, digest)
	if err != nil {
		return err
	}
	defer func() { _ = directory.Close() }()
	file, err := directory.OpenFile("historical-source.json", os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	identity, statErr := file.Stat()
	if statErr != nil || !sameNFTPersistenceIdentity(before.identity, identity) {
		_ = file.Close()
		return fmt.Errorf("historical source journal changed before synchronization")
	}
	fileErr := errors.Join(ops.sync(file), file.Close())
	fd, err := directory.Open(".")
	if err != nil {
		return errors.Join(fileErr, err)
	}
	directoryIdentity, statErr := fd.Stat()
	if err := errors.Join(fileErr, statErr, ops.sync(fd), fd.Close()); err != nil {
		return err
	}
	after, err := host.snapshot(path)
	if err != nil || !sameLegacyFail2banSource(before, after) {
		return fmt.Errorf("historical source journal changed during synchronization")
	}
	if err := attestLegacyRetirementDirectory(host, legacyFail2banPlanPath(digest), directoryIdentity); err != nil {
		return err
	}
	_, err = readNFTHistoricalPersistencePlan(host, digest)
	return err
}

// The graph and source binding are durable before the first active file edit.
// The independent guard is mandatory at every existing graph mutation boundary.
// This coordinator never stops a shared service or changes the live ruleset.
func applyNFTHistoricalPersistencePlan(host nftPersistenceFilesystem, plan nftHistoricalPersistencePlan, reviewed string, guard func(string, string) error, ops legacyRetirementFileOps) error {
	if guard == nil || reviewed != plan.sha256 {
		return fmt.Errorf("historical persistence requires the exact reviewed plan and independent authority guard")
	}
	check := func() error {
		if err := guard(plan.binding.Origins, plan.binding.Producers); err != nil {
			return err
		}
		return verifyNFTHistoricalPersistencePlan(host, plan)
	}
	if err := check(); err != nil {
		return err
	}
	if err := persistNFTPersistenceGraphRecord(host, plan.graph, reviewed, check, ops); err != nil {
		return err
	}
	content, ownership, err := encodeNFTHistoricalPersistenceBinding(plan.binding)
	if err != nil {
		return err
	}
	path := legacyFail2banPlanPath(reviewed) + "/historical-source.json"
	snapshot, err := host.snapshot(path)
	if errors.Is(err, fs.ErrNotExist) {
		state, stateErr := inspectNFTPersistenceGraphState(host, plan.graph)
		if stateErr != nil || len(state.edited) != 0 || len(state.retired) != 0 {
			return fmt.Errorf("historical source binding cannot be recreated after active file changes")
		}
		if err := check(); err != nil {
			return err
		}
		directory, err := openLegacyFail2banPlanDirectory(host, reviewed)
		if err != nil {
			return err
		}
		defer func() { _ = directory.Close() }()
		fd, err := directory.Open(".")
		if err != nil {
			return err
		}
		defer func() { _ = fd.Close() }()
		if err := publishLegacyRetirementJSON(directory, fd, "historical-source", content, ops); err != nil {
			return err
		}
	} else if err != nil || snapshot.identity == nil || snapshot.identity.Mode().Perm() != 0600 || !bytes.Equal(snapshot.content, content) {
		return fmt.Errorf("historical persistence source journal differs from reviewed evidence")
	}
	if err := syncNFTHistoricalSourceBinding(host, reviewed, ops); err != nil {
		return err
	}
	if err := ops.checkpoint("historical-source-binding-durable"); err != nil {
		return err
	}
	return applyNFTPersistenceGraphRecord(host, plan.graph, reviewed, func(actualOwnership, actualProducers string) error {
		if actualOwnership != ownership || actualProducers != plan.binding.Producers {
			return fmt.Errorf("historical persistence authority changed")
		}
		if _, err := readNFTHistoricalPersistencePlan(host, reviewed); err != nil {
			return err
		}
		return check()
	}, ops)
}
