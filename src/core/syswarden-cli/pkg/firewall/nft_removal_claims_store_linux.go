//go:build linux

package firewall

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"slices"
	"syscall"
	"syswarden-cli/pkg/runtimehistory"
	"syswarden-cli/pkg/wireguardstate"
)

const nftRuntimeHistoryPath = "/var/lib/syswarden/runtime-lifecycle"

type nftRuntimeHistoryEvidence struct {
	digest    string
	strict    string
	model     runtimehistory.Model
	directory os.FileInfo
}

// Keep the core's own directory lease until the complete source and kernel
// retirement has finished. An absent store authorizes no dynamic population.
type nftRuntimeHistoryLease struct {
	host     nftPersistenceFilesystem
	file     *os.File
	evidence nftRuntimeHistoryEvidence
}

func inspectNFTRuntimeHistory(host nftPersistenceFilesystem) (nftRuntimeHistoryEvidence, error) {
	var empty nftRuntimeHistoryEvidence
	root, err := host.openDirectory(nftRuntimeHistoryPath)
	if errors.Is(err, fs.ErrNotExist) {
		return empty, nil
	}
	if err != nil {
		return empty, err
	}
	defer func() { _ = root.Close() }()
	before, err := root.Stat(".")
	if err != nil || before.Mode().Perm() != 0700 {
		return empty, fmt.Errorf("native runtime history directory is not private")
	}
	file, err := root.Open(".")
	if err != nil {
		return empty, err
	}
	names, readErr := file.Readdirnames(4)
	closeErr := file.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) || closeErr != nil {
		return empty, fmt.Errorf("cannot inspect native runtime history inventory")
	}
	slices.Sort(names)
	if !slices.Equal(names, []string{"anchor.json", "intent.slot", "state.json"}) {
		return empty, fmt.Errorf("native runtime history contains missing, additional or pending artifacts")
	}
	content := make(map[string][]byte, 3)
	var records []nftPersistenceGraphSourceRecord
	for _, name := range names {
		path := nftRuntimeHistoryPath + "/" + name
		snapshot, attrs, err := snapshotNFTPersistenceMetadata(host, path)
		if err != nil {
			return empty, err
		}
		if snapshot.identity.Mode().Perm() != 0600 {
			return empty, fmt.Errorf("native runtime history file is not private")
		}
		record, err := bindNFTPersistenceGraphSource(path, snapshot, attrs, snapshot.content)
		if err != nil {
			return empty, err
		}
		records = append(records, record)
		content[name] = snapshot.content
	}
	decoded, err := runtimehistory.DecodeQuiescent(content["state.json"], content["anchor.json"], content["intent.slot"])
	if err != nil {
		return empty, err
	}
	after, err := root.Stat(".")
	if err != nil || !sameNFTPersistenceIdentity(before, after) {
		return empty, fmt.Errorf("native runtime history inventory changed")
	}
	current, err := host.openDirectory(nftRuntimeHistoryPath)
	if err != nil {
		return empty, err
	}
	named, statErr := current.Stat(".")
	_ = current.Close()
	if statErr != nil || !sameNFTPersistenceIdentity(before, named) {
		return empty, fmt.Errorf("native runtime history path changed")
	}
	directory, err := bindLegacyFail2banPlanDirectory(host, nftRuntimeHistoryPath, before)
	if err != nil {
		return empty, err
	}
	durable, strict, err := nftRuntimeHistoryDigests(directory, records)
	if err != nil {
		return empty, err
	}
	return nftRuntimeHistoryEvidence{digest: durable, strict: strict, model: decoded.Model, directory: before}, nil
}

// Device numbers may change across boots. Only an independently captured
// persistent filesystem identity permits that difference in a durable intent.
// The operation-local digest still binds every device number under the lease.
func nftRuntimeHistoryDigests(directory legacyFail2banPlanDirectory, records []nftPersistenceGraphSourceRecord) (string, string, error) {
	if !wireguardstate.ValidFilesystemUUID(directory.FilesystemUUID) {
		return "", "", fmt.Errorf("native runtime history has an invalid filesystem identity")
	}
	bound := struct {
		Directory legacyFail2banPlanDirectory       `json:"directory"`
		Files     []nftPersistenceGraphSourceRecord `json:"files"`
	}{directory, slices.Clone(records)}
	for _, record := range bound.Files {
		if !wireguardstate.ValidFilesystemUUID(record.Artifact.FilesystemUUID) {
			return "", "", fmt.Errorf("native runtime history file has an invalid filesystem identity")
		}
	}
	wire, err := json.Marshal(bound)
	if err != nil {
		return "", "", err
	}
	strict := fmt.Sprintf("%x", sha256.Sum256(wire))
	if bound.Directory.FilesystemUUID != "" {
		bound.Directory.Device = 0
	}
	for index := range bound.Files {
		if bound.Files[index].Artifact.FilesystemUUID != "" {
			bound.Files[index].Artifact.Device = 0
		}
	}
	wire, err = json.Marshal(bound)
	if err != nil {
		return "", "", err
	}
	return fmt.Sprintf("%x", sha256.Sum256(wire)), strict, nil
}

func acquireNFTRuntimeHistory(host nftPersistenceFilesystem) (*nftRuntimeHistoryLease, error) {
	lease := &nftRuntimeHistoryLease{host: host}
	root, err := host.openDirectory(nftRuntimeHistoryPath)
	if err == nil {
		lease.file, err = root.Open(".")
		_ = root.Close()
		if err != nil {
			return nil, err
		}
		if err := syscall.Flock(int(lease.file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
			lease.close()
			return nil, fmt.Errorf("native runtime history still has an active owner: %w", err)
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	lease.evidence, err = inspectNFTRuntimeHistory(host)
	if err == nil {
		err = lease.verify()
	}
	if err != nil {
		lease.close()
		return nil, err
	}
	return lease, nil
}

func (lease *nftRuntimeHistoryLease) close() {
	if lease != nil && lease.file != nil {
		_ = lease.file.Close()
		lease.file = nil
	}
}

func (lease *nftRuntimeHistoryLease) verify() error {
	if lease == nil {
		return nil
	} // No proof means static-only retirement.
	current, err := inspectNFTRuntimeHistory(lease.host)
	if err != nil {
		return err
	}
	if current.digest != lease.evidence.digest || current.strict != lease.evidence.strict {
		return fmt.Errorf("native runtime history changed during retirement")
	}
	if lease.file == nil {
		if current.digest != "" {
			return fmt.Errorf("native runtime history appeared without a lease")
		}
		return nil
	}
	opened, err := lease.file.Stat()
	if err != nil || !sameNFTPersistenceIdentity(opened, current.directory) || !sameNFTPersistenceIdentity(lease.evidence.directory, current.directory) {
		return fmt.Errorf("native runtime history lease or directory changed")
	}
	return nil
}

func (lease *nftRuntimeHistoryLease) digest() string {
	if lease == nil {
		return ""
	}
	return lease.evidence.digest
}
