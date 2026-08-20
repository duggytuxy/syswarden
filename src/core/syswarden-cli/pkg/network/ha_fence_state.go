package network

import (
	"bytes"
	cryptorand "crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const (
	cliHAFenceVersion                  = 1
	cliHAFenceStateName                = "native-sync-fence.json"
	cliHAFenceTombstonesName           = "native-sync-fence-epochs.json"
	cliHAFenceLockName                 = "native-sync-fence.lock"
	cliHAFenceStateInactive            = "inactive"
	cliHAFenceStateEngaging            = "engaging"
	cliHAFenceStateActiveDrained       = "active_drained"
	cliHAFenceStateRecovering          = "recovering"
	cliHAFenceStateError               = "error"
	cliHAFenceMembershipScope          = "one_receiving_api_endpoint_per_syswarden_node"
	maxCLIHAFenceStateBytes      int64 = 64 * 1024
)

type cliHAFenceDiskState struct {
	Version                     int     `json:"version"`
	State                       string  `json:"state"`
	Epoch                       string  `json:"epoch"`
	MembershipSHA256            string  `json:"membership_sha256"`
	LegacyWriterInventorySHA256 string  `json:"legacy_writer_inventory_sha256"`
	Generation                  uint64  `json:"generation"`
	Condition                   string  `json:"condition"`
	DrainedAt                   *string `json:"drained_at"`
}

type haLegacyWriterFence struct {
	directory        string
	expectedOwnerUID int
	now              func() time.Time
	random           io.Reader
}

func newHALegacyWriterFence(directory string, expectedOwnerUID int) *haLegacyWriterFence {
	return &haLegacyWriterFence{
		directory: filepath.Clean(directory), expectedOwnerUID: expectedOwnerUID,
		now: time.Now, random: cryptorand.Reader,
	}
}

func openCLIHAFenceDirectory(fence *haLegacyWriterFence) (*os.Root, error) {
	if fence == nil || fence.expectedOwnerUID < 0 || !filepath.IsAbs(fence.directory) || fence.directory == string(filepath.Separator) {
		return nil, fmt.Errorf("invalid HA native-sync fence configuration")
	}
	root, _, err := openSafeHAStatusDirectory(filepath.Join(fence.directory, cliHAFenceStateName), fence.expectedOwnerUID)
	return root, err
}

func openCLIHAFenceLock(root *os.Root, expectedOwnerUID int, exclusive bool) (*os.File, error) {
	return openCLIHAFenceLockMode(root, expectedOwnerUID, exclusive, false)
}

func openCLIHAFenceLockMode(root *os.Root, expectedOwnerUID int, exclusive, nonblocking bool) (*os.File, error) {
	info, err := root.Lstat(cliHAFenceLockName)
	if errors.Is(err, fs.ErrNotExist) {
		created, createErr := root.OpenFile(cliHAFenceLockName, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
		if createErr != nil {
			return nil, createErr
		}
		if syncErr := created.Sync(); syncErr != nil {
			_ = created.Close()
			return nil, syncErr
		}
		info, err = created.Stat()
		_ = created.Close()
	}
	if err != nil {
		return nil, err
	}
	owner, ownerErr := haFileOwnerUID(info)
	if ownerErr != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || owner != expectedOwnerUID {
		return nil, fmt.Errorf("HA native-sync fence lock must be a regular 0600 file owned by UID %d", expectedOwnerUID)
	}
	file, err := root.OpenFile(cliHAFenceLockName, os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		_ = file.Close()
		return nil, fmt.Errorf("HA native-sync fence lock changed while opening")
	}
	operation := syscall.LOCK_SH
	if exclusive {
		operation = syscall.LOCK_EX
	}
	if nonblocking {
		operation |= syscall.LOCK_NB
	}
	if err := syscall.Flock(int(file.Fd()), operation); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}

func closeCLIHAFenceLock(file *os.File) {
	if file == nil {
		return
	}
	_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
	_ = file.Close()
}

func readCLIHAFenceState(root *os.Root, expectedOwnerUID int) (cliHAFenceDiskState, error) {
	info, err := root.Lstat(cliHAFenceStateName)
	if err != nil {
		return cliHAFenceDiskState{}, err
	}
	owner, ownerErr := haFileOwnerUID(info)
	if ownerErr != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || owner != expectedOwnerUID {
		return cliHAFenceDiskState{}, fmt.Errorf("HA native-sync fence state must be a regular 0600 file owned by UID %d", expectedOwnerUID)
	}
	file, err := root.Open(cliHAFenceStateName)
	if err != nil {
		return cliHAFenceDiskState{}, err
	}
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		_ = file.Close()
		return cliHAFenceDiskState{}, fmt.Errorf("HA native-sync fence state changed while opening")
	}
	wire, readErr := io.ReadAll(io.LimitReader(file, maxCLIHAFenceStateBytes+1))
	closeErr := file.Close()
	if readErr != nil {
		return cliHAFenceDiskState{}, readErr
	}
	if closeErr != nil {
		return cliHAFenceDiskState{}, closeErr
	}
	if len(wire) > int(maxCLIHAFenceStateBytes) {
		return cliHAFenceDiskState{}, fmt.Errorf("HA native-sync fence state is too large")
	}
	if err := rejectCLIHALedgerDuplicateKeys(wire); err != nil {
		return cliHAFenceDiskState{}, fmt.Errorf("decode HA native-sync fence state: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.DisallowUnknownFields()
	var state cliHAFenceDiskState
	if err := decoder.Decode(&state); err != nil {
		return cliHAFenceDiskState{}, fmt.Errorf("decode HA native-sync fence state: %w", err)
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); err != io.EOF {
		return cliHAFenceDiskState{}, fmt.Errorf("decode HA native-sync fence state: trailing JSON")
	}
	if err := validateCLIHAFenceState(state); err != nil {
		return cliHAFenceDiskState{}, err
	}
	canonical, err := json.Marshal(state)
	if err != nil {
		return cliHAFenceDiskState{}, err
	}
	canonical = append(canonical, '\n')
	if !bytes.Equal(wire, canonical) {
		return cliHAFenceDiskState{}, fmt.Errorf("HA native-sync fence state bytes are not canonical")
	}
	return state, nil
}

func validateCLIHAFenceState(state cliHAFenceDiskState) error {
	if state.Version != cliHAFenceVersion || state.Generation == 0 {
		return fmt.Errorf("invalid HA native-sync fence version or generation")
	}
	switch state.State {
	case cliHAFenceStateInactive:
		if state.Epoch != "" || state.MembershipSHA256 != "" || state.LegacyWriterInventorySHA256 != "" || state.Condition != "" || state.DrainedAt != nil {
			return fmt.Errorf("inactive HA native-sync fence contains campaign data")
		}
	case cliHAFenceStateEngaging, cliHAFenceStateRecovering:
		if !validCLIHAFenceCampaign(state) || state.Condition != "" || state.DrainedAt != nil {
			return fmt.Errorf("invalid transitional HA native-sync fence")
		}
	case cliHAFenceStateActiveDrained:
		if !validCLIHAFenceCampaign(state) || !validCLIHAFenceCondition(state.Condition) || state.DrainedAt == nil {
			return fmt.Errorf("invalid active HA native-sync fence")
		}
		parsed, err := time.Parse(time.RFC3339, *state.DrainedAt)
		if err != nil || parsed.UTC().Format(time.RFC3339) != *state.DrainedAt {
			return fmt.Errorf("HA native-sync fence drain timestamp is not canonical")
		}
	case cliHAFenceStateError:
		if state.Condition != "" || state.DrainedAt != nil {
			return fmt.Errorf("error HA native-sync fence cannot attest a drain")
		}
	default:
		return fmt.Errorf("invalid HA native-sync fence state %q", state.State)
	}
	return nil
}

func validCLIHAFenceCampaign(state cliHAFenceDiskState) bool {
	return state.Epoch != "" && validLowerSHA256(state.MembershipSHA256) && validLowerSHA256(state.LegacyWriterInventorySHA256)
}

func validLowerSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func validCLIHAFenceCondition(value string) bool {
	if !strings.HasPrefix(value, "sw-fence-v1-") {
		return false
	}
	encoded := strings.TrimPrefix(value, "sw-fence-v1-")
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	return err == nil && len(decoded) == 32 && base64.RawURLEncoding.EncodeToString(decoded) == encoded
}

func publishCLIHAFenceState(root *os.Root, expectedOwnerUID int, state cliHAFenceDiskState) error {
	if err := validateCLIHAFenceState(state); err != nil {
		return err
	}
	wire, err := json.Marshal(state)
	if err != nil {
		return err
	}
	wire = append(wire, '\n')
	return publishHAStatusAtomically(root, cliHAFenceStateName, expectedOwnerUID, wire)
}

func acquireHALegacyWriterLease(fence *haLegacyWriterFence) (func(), error) {
	if fence == nil {
		return func() {}, nil
	}
	root, err := openCLIHAFenceDirectory(fence)
	if err != nil {
		return nil, fmt.Errorf("open HA native-sync fence: %w", err)
	}
	lock, err := openCLIHAFenceLockMode(root, fence.expectedOwnerUID, true, true)
	if err != nil {
		_ = root.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, fmt.Errorf("HA native-sync fence is transitioning; legacy writer attempt was not queued")
		}
		return nil, fmt.Errorf("lock HA native-sync fence: %w", err)
	}
	state, err := readCLIHAFenceState(root, fence.expectedOwnerUID)
	if err != nil {
		closeCLIHAFenceLock(lock)
		_ = root.Close()
		return nil, fmt.Errorf("HA native-sync fence is unavailable: %w", err)
	}
	if state.State != cliHAFenceStateInactive {
		closeCLIHAFenceLock(lock)
		_ = root.Close()
		return nil, fmt.Errorf("legacy HA writer is blocked by native-sync fence state %s", state.State)
	}
	return func() {
		closeCLIHAFenceLock(lock)
		_ = root.Close()
	}, nil
}

func randomCLIHAFenceCondition(source io.Reader) (string, error) {
	var raw [32]byte
	if _, err := io.ReadFull(source, raw[:]); err != nil {
		return "", err
	}
	return "sw-fence-v1-" + base64.RawURLEncoding.EncodeToString(raw[:]), nil
}
