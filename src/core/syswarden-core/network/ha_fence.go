package network

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
)

const (
	haFenceVersion                  = 1
	haFenceScope                    = "legacy_ips_mutations"
	haFenceCapability               = "native_sync_fence_v1"
	haFenceConditionHeader          = "X-SysWarden-HA-Fence-Condition"
	haFenceChallengeHeader          = "X-SysWarden-HA-Challenge"
	haFenceStateName                = "native-sync-fence.json"
	haFenceTombstonesName           = "native-sync-fence-epochs.json"
	haFenceLockName                 = "native-sync-fence.lock"
	haFenceStateInactive            = "inactive"
	haFenceStateEngaging            = "engaging"
	haFenceStateActiveDrained       = "active_drained"
	haFenceStateRecovering          = "recovering"
	haFenceStateError               = "error"
	maxHAFenceStateBytes      int64 = 64 * 1024
)

var haFenceTokenRE = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

type haFenceDiskState struct {
	Version                     int     `json:"version"`
	State                       string  `json:"state"`
	Epoch                       string  `json:"epoch"`
	MembershipSHA256            string  `json:"membership_sha256"`
	LegacyWriterInventorySHA256 string  `json:"legacy_writer_inventory_sha256"`
	Generation                  uint64  `json:"generation"`
	Condition                   string  `json:"condition"`
	DrainedAt                   *string `json:"drained_at"`
}

type haNativeSyncFenceStatus struct {
	Version                     int     `json:"version"`
	Scope                       string  `json:"scope"`
	State                       string  `json:"state"`
	Epoch                       string  `json:"epoch"`
	MembershipSHA256            string  `json:"membership_sha256"`
	LegacyWriterInventorySHA256 string  `json:"legacy_writer_inventory_sha256"`
	Generation                  uint64  `json:"generation"`
	ServerInstanceID            string  `json:"server_instance_id"`
	ActiveOutboundWriters       int     `json:"active_outbound_writers"`
	ActiveInboundLegacy         int     `json:"active_inbound_legacy_mutations"`
	Condition                   string  `json:"condition"`
	DrainedAt                   *string `json:"drained_at"`
	ExpiresAt                   *string `json:"expires_at"`
	Challenge                   *string `json:"challenge"`
}

type haFenceController struct {
	directory        string
	expectedOwnerUID int
	serverInstanceID string
	now              func() time.Time
	random           io.Reader
}

type haFenceHTTPError struct {
	Status int
	Text   string
}

func (err *haFenceHTTPError) Error() string {
	return err.Text
}

func newHAFenceController(directory string, expectedOwnerUID int) (*haFenceController, error) {
	if expectedOwnerUID < 0 {
		return nil, fmt.Errorf("invalid HA fence owner UID")
	}
	directory = filepath.Clean(directory)
	if !filepath.IsAbs(directory) || directory == string(filepath.Separator) {
		return nil, fmt.Errorf("HA fence directory must be an absolute non-root path")
	}
	instanceID, err := randomHAFenceToken(rand.Reader, "")
	if err != nil {
		return nil, fmt.Errorf("generate HA server instance identifier: %w", err)
	}
	return &haFenceController{
		directory:        directory,
		expectedOwnerUID: expectedOwnerUID,
		serverInstanceID: instanceID,
		now:              time.Now,
		random:           rand.Reader,
	}, nil
}

func randomHAFenceToken(source io.Reader, prefix string) (string, error) {
	var raw [32]byte
	if _, err := io.ReadFull(source, raw[:]); err != nil {
		return "", err
	}
	return prefix + base64.RawURLEncoding.EncodeToString(raw[:]), nil
}

func haFenceOwnerUID(info fs.FileInfo) (int, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return -1, fmt.Errorf("HA fence owner UID is unavailable")
	}
	return int(stat.Uid), nil
}

func (fence *haFenceController) openDirectory(create bool) (*os.Root, error) {
	if create {
		if err := os.MkdirAll(fence.directory, 0700); err != nil {
			return nil, fmt.Errorf("create HA fence directory: %w", err)
		}
	}
	info, err := os.Lstat(fence.directory)
	if err != nil {
		return nil, err
	}
	owner, ownerErr := haFenceOwnerUID(info)
	if ownerErr != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
		owner != fence.expectedOwnerUID || info.Mode().Perm()&0077 != 0 {
		return nil, fmt.Errorf("HA fence directory must be a real owner-only directory owned by UID %d", fence.expectedOwnerUID)
	}
	root, err := os.OpenRoot(fence.directory)
	if err != nil {
		return nil, err
	}
	opened, err := root.Stat(".")
	if err != nil || !os.SameFile(info, opened) {
		_ = root.Close()
		return nil, fmt.Errorf("HA fence directory changed while opening")
	}
	return root, nil
}

func openHAFenceLock(root *os.Root, expectedOwnerUID int, exclusive bool) (*os.File, error) {
	return openHAFenceLockMode(root, expectedOwnerUID, exclusive, false)
}

func openHAFenceLockMode(root *os.Root, expectedOwnerUID int, exclusive, nonblocking bool) (*os.File, error) {
	info, err := root.Lstat(haFenceLockName)
	if errors.Is(err, fs.ErrNotExist) {
		file, createErr := root.OpenFile(haFenceLockName, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
		if createErr != nil {
			return nil, createErr
		}
		if syncErr := file.Sync(); syncErr != nil {
			_ = file.Close()
			return nil, syncErr
		}
		info, err = file.Stat()
		_ = file.Close()
	}
	if err != nil {
		return nil, err
	}
	owner, ownerErr := haFenceOwnerUID(info)
	if ownerErr != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || owner != expectedOwnerUID {
		return nil, fmt.Errorf("HA fence lock must be a regular 0600 file owned by UID %d", expectedOwnerUID)
	}
	file, err := root.OpenFile(haFenceLockName, os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		_ = file.Close()
		return nil, fmt.Errorf("HA fence lock changed while opening")
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

func closeHAFenceLock(file *os.File) {
	if file == nil {
		return
	}
	_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
	_ = file.Close()
}

func (fence *haFenceController) withLock(exclusive, create bool, action func(*os.Root) error) error {
	root, err := fence.openDirectory(create)
	if err != nil {
		return err
	}
	defer root.Close()
	lock, err := openHAFenceLock(root, fence.expectedOwnerUID, exclusive)
	if err != nil {
		return err
	}
	defer closeHAFenceLock(lock)
	return action(root)
}

func readHAFenceState(root *os.Root, expectedOwnerUID int) (haFenceDiskState, error) {
	info, err := root.Lstat(haFenceStateName)
	if err != nil {
		return haFenceDiskState{}, err
	}
	owner, ownerErr := haFenceOwnerUID(info)
	if ownerErr != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || owner != expectedOwnerUID {
		return haFenceDiskState{}, fmt.Errorf("HA fence state must be a regular 0600 file owned by UID %d", expectedOwnerUID)
	}
	wire, err := readHARegularFileBounded(root, haFenceStateName, maxHAFenceStateBytes)
	if err != nil {
		return haFenceDiskState{}, err
	}
	if err := rejectHADuplicateJSONKeys(wire); err != nil {
		return haFenceDiskState{}, fmt.Errorf("decode HA fence state: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.DisallowUnknownFields()
	var state haFenceDiskState
	if err := decoder.Decode(&state); err != nil {
		return haFenceDiskState{}, fmt.Errorf("decode HA fence state: %w", err)
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); err != io.EOF {
		return haFenceDiskState{}, fmt.Errorf("decode HA fence state: trailing JSON")
	}
	if err := validateHAFenceState(state); err != nil {
		return haFenceDiskState{}, err
	}
	canonical, err := json.Marshal(state)
	if err != nil {
		return haFenceDiskState{}, err
	}
	canonical = append(canonical, '\n')
	if !bytes.Equal(wire, canonical) {
		return haFenceDiskState{}, fmt.Errorf("HA fence state bytes are not canonical")
	}
	return state, nil
}

func validateHAFenceState(state haFenceDiskState) error {
	if state.Version != haFenceVersion || state.Generation == 0 {
		return fmt.Errorf("invalid HA fence state version or generation")
	}
	switch state.State {
	case haFenceStateInactive:
		if state.Epoch != "" || state.MembershipSHA256 != "" || state.LegacyWriterInventorySHA256 != "" ||
			state.Condition != "" || state.DrainedAt != nil {
			return fmt.Errorf("inactive HA fence state contains campaign data")
		}
	case haFenceStateEngaging, haFenceStateRecovering:
		if !validHAFenceCampaignIdentity(state) || state.Condition != "" || state.DrainedAt != nil {
			return fmt.Errorf("transitional HA fence state is invalid")
		}
	case haFenceStateActiveDrained:
		if !validHAFenceCampaignIdentity(state) || !validHAFenceCondition(state.Condition) || state.DrainedAt == nil {
			return fmt.Errorf("active HA fence state is invalid")
		}
		parsed, err := time.Parse(time.RFC3339, *state.DrainedAt)
		if err != nil || parsed.UTC().Format(time.RFC3339) != *state.DrainedAt {
			return fmt.Errorf("active HA fence drain timestamp is not canonical")
		}
	case haFenceStateError:
		if state.Condition != "" || state.DrainedAt != nil {
			return fmt.Errorf("error HA fence state cannot attest a drain")
		}
	default:
		return fmt.Errorf("invalid HA fence state %q", state.State)
	}
	return nil
}

func validHAFenceCampaignIdentity(state haFenceDiskState) bool {
	return state.Epoch != "" && isLowerHexSHA256(state.MembershipSHA256) && isLowerHexSHA256(state.LegacyWriterInventorySHA256)
}

func isLowerHexSHA256(value string) bool {
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

func validHAFenceCondition(value string) bool {
	if !strings.HasPrefix(value, "sw-fence-v1-") {
		return false
	}
	token := strings.TrimPrefix(value, "sw-fence-v1-")
	decoded, err := base64.RawURLEncoding.DecodeString(token)
	return err == nil && len(decoded) == 32 && base64.RawURLEncoding.EncodeToString(decoded) == token
}

func publishHAFenceState(root *os.Root, state haFenceDiskState) error {
	if err := validateHAFenceState(state); err != nil {
		return err
	}
	wire, err := json.Marshal(state)
	if err != nil {
		return err
	}
	wire = append(wire, '\n')
	return publishHAFileAtomically(root, haFenceStateName, wire)
}

func (fence *haFenceController) prepareForServer() error {
	return fence.withLock(true, true, func(root *os.Root) error {
		state, err := readHAFenceState(root, fence.expectedOwnerUID)
		stateMissing := errors.Is(err, fs.ErrNotExist)
		if err != nil && !stateMissing {
			return err
		}
		tombstones, tombstonesExist, err := readHAFenceEpochTombstones(root, fence.expectedOwnerUID)
		if err != nil {
			return err
		}
		openEpoch, retiredEpochs, err := analyzeHAFenceEpochTombstones(tombstones)
		if err != nil {
			return err
		}
		if stateMissing {
			state = haFenceDiskState{Version: haFenceVersion, State: haFenceStateInactive, Generation: 1}
			if openEpoch == nil {
				return publishHAFenceState(root, state)
			}
		}
		stateLacksCampaign := state.Epoch == "" && state.MembershipSHA256 == "" && state.LegacyWriterInventorySHA256 == ""
		if !tombstonesExist {
			if (state.State == haFenceStateInactive && state.Generation == 1) ||
				(state.State == haFenceStateError && stateLacksCampaign) {
				return nil
			}
			return fmt.Errorf("HA fence campaign state has no durable epoch tombstones")
		}
		if openEpoch == nil {
			if state.State == haFenceStateInactive || (state.State == haFenceStateError && stateLacksCampaign) {
				return nil
			}
			retiredEpoch, retired := retiredEpochs[state.Epoch]
			if !retired || !haFenceStateMatchesEpoch(state, retiredEpoch) {
				return fmt.Errorf("HA fence state has no matching open or retired epoch tombstone")
			}
			if err := incrementHAFenceGeneration(&state); err != nil {
				return err
			}
			return publishHAFenceState(root, haFenceDiskState{
				Version: haFenceVersion, State: haFenceStateInactive, Generation: state.Generation,
			})
		}
		if (state.State == haFenceStateInactive || state.State == haFenceStateError) && stateLacksCampaign {
			state.Epoch = openEpoch.Epoch
			state.MembershipSHA256 = openEpoch.MembershipSHA256
			state.LegacyWriterInventorySHA256 = openEpoch.LegacyWriterInventorySHA256
		} else if !haFenceStateMatchesEpoch(state, *openEpoch) {
			return fmt.Errorf("HA fence state conflicts with the open epoch tombstone")
		}
		state.State = haFenceStateRecovering
		if err := incrementHAFenceGeneration(&state); err != nil {
			return err
		}
		state.Condition = ""
		state.DrainedAt = nil
		if err := publishHAFenceState(root, state); err != nil {
			return err
		}
		condition, err := randomHAFenceToken(fence.random, "sw-fence-v1-")
		if err != nil {
			return err
		}
		drainedAt := fence.now().UTC().Truncate(time.Second).Format(time.RFC3339)
		state.State = haFenceStateActiveDrained
		if err := incrementHAFenceGeneration(&state); err != nil {
			return err
		}
		state.Condition = condition
		state.DrainedAt = &drainedAt
		return publishHAFenceState(root, state)
	})
}

func parseHAFenceChallenge(header http.Header) (*string, error) {
	values := header.Values(haFenceChallengeHeader)
	if len(values) == 0 {
		return nil, nil
	}
	if len(values) != 1 || !haFenceTokenRE.MatchString(values[0]) {
		return nil, fmt.Errorf("invalid HA fence challenge header")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(values[0])
	if err != nil || len(decoded) != 32 || base64.RawURLEncoding.EncodeToString(decoded) != values[0] {
		return nil, fmt.Errorf("invalid HA fence challenge header")
	}
	value := values[0]
	return &value, nil
}

func (fence *haFenceController) status(challenge *string) (haNativeSyncFenceStatus, error) {
	status := haNativeSyncFenceStatus{
		Version: haFenceVersion, Scope: haFenceScope, State: haFenceStateError,
		ServerInstanceID: fence.serverInstanceID, Challenge: challenge,
	}
	err := fence.withLock(false, false, func(root *os.Root) error {
		state, err := readHAFenceState(root, fence.expectedOwnerUID)
		if err != nil {
			return err
		}
		status.State = state.State
		status.Epoch = state.Epoch
		status.MembershipSHA256 = state.MembershipSHA256
		status.LegacyWriterInventorySHA256 = state.LegacyWriterInventorySHA256
		status.Generation = state.Generation
		status.Condition = state.Condition
		status.DrainedAt = state.DrainedAt
		return nil
	})
	return status, err
}

func parseHAFenceConditionHeader(header http.Header) (string, bool, error) {
	values := header.Values(haFenceConditionHeader)
	if len(values) == 0 {
		return "", false, nil
	}
	if len(values) != 1 || !validHAFenceCondition(values[0]) {
		return "", true, fmt.Errorf("invalid HA fence condition header")
	}
	return values[0], true, nil
}

func (fence *haFenceController) withLegacyMutation(method string, header http.Header, mutation func()) error {
	root, err := fence.openDirectory(false)
	if err != nil {
		return &haFenceHTTPError{Status: http.StatusServiceUnavailable, Text: "HA native-sync fence is unavailable"}
	}
	defer root.Close()
	lock, err := openHAFenceLockMode(root, fence.expectedOwnerUID, true, true)
	if err != nil {
		return &haFenceHTTPError{Status: http.StatusServiceUnavailable, Text: "HA native-sync fence is transitioning; mutation was not queued"}
	}
	defer closeHAFenceLock(lock)
	return func() error {
		state, err := readHAFenceState(root, fence.expectedOwnerUID)
		if err != nil {
			return &haFenceHTTPError{Status: http.StatusServiceUnavailable, Text: "HA native-sync fence is unavailable"}
		}
		condition, present, headerErr := parseHAFenceConditionHeader(header)
		if headerErr != nil {
			return &haFenceHTTPError{Status: http.StatusBadRequest, Text: "Invalid HA fence condition"}
		}
		switch state.State {
		case haFenceStateInactive:
			if present {
				return &haFenceHTTPError{Status: http.StatusPreconditionFailed, Text: "HA fence condition no longer matches"}
			}
		case haFenceStateActiveDrained:
			if method == http.MethodPost {
				return &haFenceHTTPError{Status: http.StatusLocked, Text: "Legacy HA writes are fenced"}
			}
			if !present {
				return &haFenceHTTPError{Status: http.StatusPreconditionRequired, Text: "HA fence condition is required"}
			}
			if condition != state.Condition {
				return &haFenceHTTPError{Status: http.StatusPreconditionFailed, Text: "HA fence condition no longer matches"}
			}
		case haFenceStateEngaging, haFenceStateRecovering, haFenceStateError:
			return &haFenceHTTPError{Status: http.StatusServiceUnavailable, Text: "Legacy HA mutations are unavailable while the fence is transitioning"}
		default:
			return &haFenceHTTPError{Status: http.StatusServiceUnavailable, Text: "HA native-sync fence is unavailable"}
		}
		mutation()
		return nil
	}()
}
