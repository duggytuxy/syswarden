package network

import (
	"bytes"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"
	"time"
)

const (
	haFenceTombstonesVersion    = 1
	haFenceWriterClosureVersion = 1
	defaultHAFenceTLSLeafPath   = "/var/lib/syswarden/ha/server.crt"
	maxHAFenceClosureBytes      = 1024 * 1024
	maxHAFenceTombstonesBytes   = 16 * 1024 * 1024
)

type HAFenceWriterClosureEntry struct {
	ID                string `json:"id"`
	Disposition       string `json:"disposition"`
	ClosureGeneration string `json:"closure_generation"`
	ClosedAt          string `json:"closed_at"`
	EvidenceSHA256    string `json:"evidence_sha256"`
}

type HAFenceWriterClosure struct {
	SchemaVersion               int                         `json:"schema_version"`
	Epoch                       string                      `json:"epoch"`
	MembershipSHA256            string                      `json:"membership_sha256"`
	LegacyWriterInventorySHA256 string                      `json:"legacy_writer_inventory_sha256"`
	LegacyRetryQueueDrained     bool                        `json:"legacy_retry_queue_drained"`
	Writers                     []HAFenceWriterClosureEntry `json:"writers"`
}

type HAFenceLocalStatus struct {
	Version                     int     `json:"version"`
	State                       string  `json:"state"`
	Epoch                       string  `json:"epoch"`
	MembershipSHA256            string  `json:"membership_sha256"`
	LegacyWriterInventorySHA256 string  `json:"legacy_writer_inventory_sha256"`
	Generation                  uint64  `json:"generation"`
	Condition                   string  `json:"condition"`
	DrainedAt                   *string `json:"drained_at"`
}

type haFenceEpochEvent struct {
	Event                       string                `json:"event"`
	Epoch                       string                `json:"epoch"`
	MembershipSHA256            string                `json:"membership_sha256"`
	LegacyWriterInventorySHA256 string                `json:"legacy_writer_inventory_sha256"`
	RecordedAt                  string                `json:"recorded_at"`
	WriterClosureSHA256         string                `json:"writer_closure_sha256,omitempty"`
	WriterClosure               *HAFenceWriterClosure `json:"writer_closure,omitempty"`
}

type haFenceEpochTombstones struct {
	Version int                 `json:"version"`
	Events  []haFenceEpochEvent `json:"events"`
}

type haFenceAdminOptions struct {
	fence            *haLegacyWriterFence
	tlsLeafPath      string
	expectedOwnerUID int
	now              func() time.Time
	random           io.Reader
}

func defaultHAFenceAdminOptions() haFenceAdminOptions {
	return haFenceAdminOptions{
		fence:            newHALegacyWriterFence(defaultHAFenceDirectory, 0),
		tlsLeafPath:      defaultHAFenceTLSLeafPath,
		expectedOwnerUID: 0,
		now:              time.Now,
		random:           cryptorand.Reader,
	}
}

func requireHAFenceRoot() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("HA native-sync fence administration requires root")
	}
	return nil
}

func canonicalHAFenceTime(value string) bool {
	parsed, err := time.Parse(time.RFC3339, value)
	return err == nil && parsed.UTC().Format(time.RFC3339) == value
}

func currentHAFenceTime(now func() time.Time) (string, error) {
	if now == nil {
		return "", fmt.Errorf("HA fence clock is unavailable")
	}
	return now().UTC().Truncate(time.Second).Format(time.RFC3339), nil
}

func validHAFenceClosureGeneration(value string) bool {
	if value == "" || len(value) > 256 || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if character < 0x21 || character > 0x7e {
			return false
		}
	}
	return true
}

func terminalHAFenceWriterDisposition(value string) bool {
	switch value {
	case "migrated_enriched_only", "disabled", "credential_revoked", "network_quarantined":
		return true
	default:
		return false
	}
}

func canonicalHAFenceWriterClosureBytes(closure HAFenceWriterClosure) ([]byte, error) {
	wire, err := json.MarshalIndent(closure, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(wire, '\n'), nil
}

func validateHAFenceWriterClosure(closure *HAFenceWriterClosure, manifest *HAFenceManifest) error {
	if closure == nil || manifest == nil || closure.SchemaVersion != haFenceWriterClosureVersion ||
		closure.Epoch != manifest.Epoch || closure.MembershipSHA256 != manifest.MembershipSHA256 ||
		closure.LegacyWriterInventorySHA256 != manifest.LegacyWriterInventorySHA256 ||
		!closure.LegacyRetryQueueDrained || closure.Writers == nil || len(closure.Writers) != len(manifest.LegacyWriterIDs) {
		return fmt.Errorf("writer closure does not match the HA fence manifest")
	}
	for index, writer := range closure.Writers {
		if writer.ID != manifest.LegacyWriterIDs[index] || !terminalHAFenceWriterDisposition(writer.Disposition) ||
			!validHAFenceClosureGeneration(writer.ClosureGeneration) || !canonicalHAFenceTime(writer.ClosedAt) ||
			!validLowerSHA256(writer.EvidenceSHA256) {
			return fmt.Errorf("writer closure entry %d is incomplete or noncanonical", index)
		}
	}
	return nil
}

func readHAFenceWriterClosure(path string, expectedOwnerUID int, manifest *HAFenceManifest) (*HAFenceWriterClosure, []byte, error) {
	wire, err := readProtectedHAFile(path, expectedOwnerUID, maxHAFenceClosureBytes)
	if err != nil {
		return nil, nil, err
	}
	var closure HAFenceWriterClosure
	if err := decodeStrictHAJSON(wire, &closure); err != nil {
		return nil, nil, fmt.Errorf("decode HA writer closure: %w", err)
	}
	if err := validateHAFenceWriterClosure(&closure, manifest); err != nil {
		return nil, nil, err
	}
	canonical, err := canonicalHAFenceWriterClosureBytes(closure)
	if err != nil || !bytes.Equal(wire, canonical) {
		return nil, nil, fmt.Errorf("HA writer closure bytes are not canonical")
	}
	return &closure, wire, nil
}

func validateHAFenceEpochEvent(event haFenceEpochEvent) error {
	if event.Event != "engaged" && event.Event != "retired" {
		return fmt.Errorf("invalid HA fence epoch event")
	}
	if !haFenceUUIDv4RE.MatchString(event.Epoch) || !validLowerSHA256(event.MembershipSHA256) ||
		!validLowerSHA256(event.LegacyWriterInventorySHA256) || !canonicalHAFenceTime(event.RecordedAt) {
		return fmt.Errorf("invalid HA fence epoch event identity")
	}
	if event.Event == "engaged" {
		if event.WriterClosureSHA256 != "" || event.WriterClosure != nil {
			return fmt.Errorf("engagement event contains release evidence")
		}
		return nil
	}
	if !validLowerSHA256(event.WriterClosureSHA256) || event.WriterClosure == nil {
		return fmt.Errorf("retirement event lacks writer closure evidence")
	}
	wire, err := canonicalHAFenceWriterClosureBytes(*event.WriterClosure)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(wire)
	if hex.EncodeToString(digest[:]) != event.WriterClosureSHA256 {
		return fmt.Errorf("retirement event writer closure digest mismatch")
	}
	closure := event.WriterClosure
	if closure.SchemaVersion != haFenceWriterClosureVersion || closure.Epoch != event.Epoch ||
		closure.MembershipSHA256 != event.MembershipSHA256 ||
		closure.LegacyWriterInventorySHA256 != event.LegacyWriterInventorySHA256 ||
		!closure.LegacyRetryQueueDrained || closure.Writers == nil {
		return fmt.Errorf("retirement event writer closure identity mismatch")
	}
	previousWriter := ""
	var writerPreimage strings.Builder
	writerPreimage.WriteString(haFenceLegacyWriterDigestHeader)
	for _, writer := range closure.Writers {
		if !haFenceWriterIDRE.MatchString(writer.ID) || writer.ID <= previousWriter ||
			!terminalHAFenceWriterDisposition(writer.Disposition) || !validHAFenceClosureGeneration(writer.ClosureGeneration) ||
			!canonicalHAFenceTime(writer.ClosedAt) || !validLowerSHA256(writer.EvidenceSHA256) {
			return fmt.Errorf("retirement event contains an invalid writer closure")
		}
		previousWriter = writer.ID
		writerPreimage.WriteString(writer.ID)
		writerPreimage.WriteByte('\n')
	}
	writerDigest := sha256.Sum256([]byte(writerPreimage.String()))
	if hex.EncodeToString(writerDigest[:]) != closure.LegacyWriterInventorySHA256 {
		return fmt.Errorf("retirement event writer inventory digest mismatch")
	}
	return nil
}

func readHAFenceEpochTombstones(root *os.Root, expectedOwnerUID int) (haFenceEpochTombstones, error) {
	info, err := root.Lstat(cliHAFenceTombstonesName)
	if errors.Is(err, fs.ErrNotExist) {
		return haFenceEpochTombstones{Version: haFenceTombstonesVersion, Events: []haFenceEpochEvent{}}, nil
	}
	if err != nil {
		return haFenceEpochTombstones{}, err
	}
	owner, ownerErr := haFileOwnerUID(info)
	if ownerErr != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || owner != expectedOwnerUID {
		return haFenceEpochTombstones{}, fmt.Errorf("HA fence epoch tombstones must be a regular 0600 file owned by UID %d", expectedOwnerUID)
	}
	file, err := root.Open(cliHAFenceTombstonesName)
	if err != nil {
		return haFenceEpochTombstones{}, err
	}
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		_ = file.Close()
		return haFenceEpochTombstones{}, fmt.Errorf("HA fence epoch tombstones changed while opening")
	}
	wire, readErr := io.ReadAll(io.LimitReader(file, maxHAFenceTombstonesBytes+1))
	closeErr := file.Close()
	if readErr != nil {
		return haFenceEpochTombstones{}, readErr
	}
	if closeErr != nil {
		return haFenceEpochTombstones{}, closeErr
	}
	if len(wire) > maxHAFenceTombstonesBytes {
		return haFenceEpochTombstones{}, fmt.Errorf("HA fence epoch tombstones are too large")
	}
	var tombstones haFenceEpochTombstones
	if err := decodeStrictHAJSON(wire, &tombstones); err != nil {
		return haFenceEpochTombstones{}, fmt.Errorf("decode HA fence epoch tombstones: %w", err)
	}
	if tombstones.Version != haFenceTombstonesVersion || tombstones.Events == nil {
		return haFenceEpochTombstones{}, fmt.Errorf("invalid HA fence epoch tombstone envelope")
	}
	seenEngaged := make(map[string]haFenceEpochEvent)
	seenRetired := make(map[string]bool)
	for _, event := range tombstones.Events {
		if err := validateHAFenceEpochEvent(event); err != nil {
			return haFenceEpochTombstones{}, err
		}
		if event.Event == "engaged" {
			if _, duplicate := seenEngaged[event.Epoch]; duplicate || seenRetired[event.Epoch] {
				return haFenceEpochTombstones{}, fmt.Errorf("duplicate HA fence engagement epoch")
			}
			seenEngaged[event.Epoch] = event
			continue
		}
		engagement, found := seenEngaged[event.Epoch]
		if !found || seenRetired[event.Epoch] || engagement.MembershipSHA256 != event.MembershipSHA256 ||
			engagement.LegacyWriterInventorySHA256 != event.LegacyWriterInventorySHA256 {
			return haFenceEpochTombstones{}, fmt.Errorf("invalid HA fence retirement event order")
		}
		seenRetired[event.Epoch] = true
	}
	openEpochs := 0
	for epoch := range seenEngaged {
		if !seenRetired[epoch] {
			openEpochs++
		}
	}
	if openEpochs > 1 {
		return haFenceEpochTombstones{}, fmt.Errorf("HA fence epoch tombstones contain multiple open campaigns")
	}
	canonical, err := json.Marshal(tombstones)
	if err != nil {
		return haFenceEpochTombstones{}, err
	}
	canonical = append(canonical, '\n')
	if !bytes.Equal(wire, canonical) {
		return haFenceEpochTombstones{}, fmt.Errorf("HA fence epoch tombstone bytes are not canonical")
	}
	return tombstones, nil
}

func publishHAFenceEpochTombstones(root *os.Root, expectedOwnerUID int, tombstones haFenceEpochTombstones) error {
	wire, err := json.Marshal(tombstones)
	if err != nil {
		return err
	}
	wire = append(wire, '\n')
	return publishHAStatusAtomically(root, cliHAFenceTombstonesName, expectedOwnerUID, wire)
}

func findHAFenceEpochEvents(tombstones haFenceEpochTombstones, epoch string) (engaged, retired *haFenceEpochEvent) {
	for index := range tombstones.Events {
		event := &tombstones.Events[index]
		if event.Epoch != epoch {
			continue
		}
		if event.Event == "engaged" {
			engaged = event
		} else if event.Event == "retired" {
			retired = event
		}
	}
	return engaged, retired
}

func findOpenHAFenceEpoch(tombstones haFenceEpochTombstones) *haFenceEpochEvent {
	retired := make(map[string]bool)
	for _, event := range tombstones.Events {
		if event.Event == "retired" {
			retired[event.Epoch] = true
		}
	}
	for index := range tombstones.Events {
		event := &tombstones.Events[index]
		if event.Event == "engaged" && !retired[event.Epoch] {
			return event
		}
	}
	return nil
}

func verifyLocalHAFenceIdentity(manifest *HAFenceManifest, tlsLeafPath string, expectedOwnerUID int) error {
	fingerprint, err := tlsLeafFingerprintFromPEM(tlsLeafPath, expectedOwnerUID)
	if err != nil {
		return fmt.Errorf("verify local HA TLS identity: %w", err)
	}
	matches := 0
	for _, member := range manifest.Members {
		if member.TLSLeafCertificateSHA256 == fingerprint {
			matches++
		}
	}
	if matches != 1 {
		return fmt.Errorf("local HA TLS leaf identity must appear exactly once in the manifest")
	}
	return nil
}

func sameHAFenceCampaign(state cliHAFenceDiskState, manifest *HAFenceManifest) bool {
	return state.Epoch == manifest.Epoch && state.MembershipSHA256 == manifest.MembershipSHA256 &&
		state.LegacyWriterInventorySHA256 == manifest.LegacyWriterInventorySHA256
}

func nextHAFenceGeneration(current uint64) (uint64, error) {
	if current == ^uint64(0) {
		return 0, fmt.Errorf("HA fence generation is exhausted")
	}
	return current + 1, nil
}

func transitionHAFenceState(root *os.Root, options haFenceAdminOptions, state cliHAFenceDiskState, manifest *HAFenceManifest, transition string) (cliHAFenceDiskState, error) {
	generation, err := nextHAFenceGeneration(state.Generation)
	if err != nil {
		return cliHAFenceDiskState{}, err
	}
	state = cliHAFenceDiskState{
		Version: cliHAFenceVersion, State: transition, Epoch: manifest.Epoch,
		MembershipSHA256:            manifest.MembershipSHA256,
		LegacyWriterInventorySHA256: manifest.LegacyWriterInventorySHA256,
		Generation:                  generation,
	}
	if err := publishCLIHAFenceState(root, options.expectedOwnerUID, state); err != nil {
		return cliHAFenceDiskState{}, err
	}
	condition, err := randomCLIHAFenceCondition(options.random)
	if err != nil {
		return cliHAFenceDiskState{}, err
	}
	drainedAt, err := currentHAFenceTime(options.now)
	if err != nil {
		return cliHAFenceDiskState{}, err
	}
	state.State = cliHAFenceStateActiveDrained
	state.Generation, err = nextHAFenceGeneration(state.Generation)
	if err != nil {
		return cliHAFenceDiskState{}, err
	}
	state.Condition = condition
	state.DrainedAt = &drainedAt
	if err := publishCLIHAFenceState(root, options.expectedOwnerUID, state); err != nil {
		return cliHAFenceDiskState{}, err
	}
	return state, nil
}

func engageHAFence(manifestPath string, options haFenceAdminOptions) error {
	manifest, _, err := readHAFenceManifest(manifestPath, options.expectedOwnerUID)
	if err != nil {
		return err
	}
	if err := verifyLocalHAFenceIdentity(manifest, options.tlsLeafPath, options.expectedOwnerUID); err != nil {
		return err
	}
	root, err := openCLIHAFenceDirectory(options.fence)
	if err != nil {
		return err
	}
	defer root.Close()
	lock, err := openCLIHAFenceLock(root, options.expectedOwnerUID, true)
	if err != nil {
		return err
	}
	defer closeCLIHAFenceLock(lock)
	state, err := readCLIHAFenceState(root, options.expectedOwnerUID)
	if err != nil {
		return err
	}
	if state.State != cliHAFenceStateInactive {
		return fmt.Errorf("HA fence engagement requires inactive state, got %s", state.State)
	}
	tombstones, err := readHAFenceEpochTombstones(root, options.expectedOwnerUID)
	if err != nil {
		return err
	}
	if openEpoch := findOpenHAFenceEpoch(tombstones); openEpoch != nil {
		return fmt.Errorf("HA fence epoch %s is already open; recover it before starting another campaign", openEpoch.Epoch)
	}
	engaged, retired := findHAFenceEpochEvents(tombstones, manifest.Epoch)
	if engaged != nil || retired != nil {
		return fmt.Errorf("HA fence epoch was already used; use recovery only for an interrupted open epoch")
	}
	recordedAt, err := currentHAFenceTime(options.now)
	if err != nil {
		return err
	}
	tombstones.Events = append(tombstones.Events, haFenceEpochEvent{
		Event: "engaged", Epoch: manifest.Epoch, MembershipSHA256: manifest.MembershipSHA256,
		LegacyWriterInventorySHA256: manifest.LegacyWriterInventorySHA256, RecordedAt: recordedAt,
	})
	if err := publishHAFenceEpochTombstones(root, options.expectedOwnerUID, tombstones); err != nil {
		return err
	}
	_, err = transitionHAFenceState(root, options, state, manifest, cliHAFenceStateEngaging)
	return err
}

func recoverHAFence(manifestPath string, options haFenceAdminOptions) error {
	manifest, _, err := readHAFenceManifest(manifestPath, options.expectedOwnerUID)
	if err != nil {
		return err
	}
	if err := verifyLocalHAFenceIdentity(manifest, options.tlsLeafPath, options.expectedOwnerUID); err != nil {
		return err
	}
	root, err := openCLIHAFenceDirectory(options.fence)
	if err != nil {
		return err
	}
	defer root.Close()
	lock, err := openCLIHAFenceLock(root, options.expectedOwnerUID, true)
	if err != nil {
		return err
	}
	defer closeCLIHAFenceLock(lock)
	state, err := readCLIHAFenceState(root, options.expectedOwnerUID)
	if err != nil {
		return err
	}
	tombstones, err := readHAFenceEpochTombstones(root, options.expectedOwnerUID)
	if err != nil {
		return err
	}
	engaged, retired := findHAFenceEpochEvents(tombstones, manifest.Epoch)
	if engaged == nil || retired != nil || engaged.MembershipSHA256 != manifest.MembershipSHA256 ||
		engaged.LegacyWriterInventorySHA256 != manifest.LegacyWriterInventorySHA256 {
		return fmt.Errorf("HA fence epoch is not an open recoverable campaign")
	}
	stateMayLackIdentity := state.State == cliHAFenceStateInactive ||
		(state.State == cliHAFenceStateError && state.Epoch == "" && state.MembershipSHA256 == "" && state.LegacyWriterInventorySHA256 == "")
	if !stateMayLackIdentity && !sameHAFenceCampaign(state, manifest) {
		return fmt.Errorf("local HA fence state belongs to another campaign")
	}
	_, err = transitionHAFenceState(root, options, state, manifest, cliHAFenceStateRecovering)
	return err
}

func releaseHAFence(manifestPath, closurePath string, options haFenceAdminOptions) error {
	manifest, _, err := readHAFenceManifest(manifestPath, options.expectedOwnerUID)
	if err != nil {
		return err
	}
	if err := verifyLocalHAFenceIdentity(manifest, options.tlsLeafPath, options.expectedOwnerUID); err != nil {
		return err
	}
	closure, closureWire, err := readHAFenceWriterClosure(closurePath, options.expectedOwnerUID, manifest)
	if err != nil {
		return err
	}
	closureDigestRaw := sha256.Sum256(closureWire)
	closureDigest := hex.EncodeToString(closureDigestRaw[:])
	root, err := openCLIHAFenceDirectory(options.fence)
	if err != nil {
		return err
	}
	defer root.Close()
	lock, err := openCLIHAFenceLock(root, options.expectedOwnerUID, true)
	if err != nil {
		return err
	}
	defer closeCLIHAFenceLock(lock)
	state, err := readCLIHAFenceState(root, options.expectedOwnerUID)
	if err != nil {
		return err
	}
	tombstones, err := readHAFenceEpochTombstones(root, options.expectedOwnerUID)
	if err != nil {
		return err
	}
	engaged, retired := findHAFenceEpochEvents(tombstones, manifest.Epoch)
	if engaged == nil || engaged.MembershipSHA256 != manifest.MembershipSHA256 ||
		engaged.LegacyWriterInventorySHA256 != manifest.LegacyWriterInventorySHA256 {
		return fmt.Errorf("HA fence epoch has no matching engagement tombstone")
	}
	if retired != nil {
		if retired.WriterClosureSHA256 != closureDigest {
			return fmt.Errorf("HA fence epoch was retired with different closure evidence")
		}
		if state.State == cliHAFenceStateInactive {
			return nil
		}
		if state.State != cliHAFenceStateActiveDrained || !sameHAFenceCampaign(state, manifest) {
			return fmt.Errorf("retired HA fence epoch conflicts with local state")
		}
	} else {
		if state.State != cliHAFenceStateActiveDrained || !sameHAFenceCampaign(state, manifest) {
			return fmt.Errorf("HA fence release requires the matching active_drained state")
		}
		recordedAt, timeErr := currentHAFenceTime(options.now)
		if timeErr != nil {
			return timeErr
		}
		tombstones.Events = append(tombstones.Events, haFenceEpochEvent{
			Event: "retired", Epoch: manifest.Epoch, MembershipSHA256: manifest.MembershipSHA256,
			LegacyWriterInventorySHA256: manifest.LegacyWriterInventorySHA256, RecordedAt: recordedAt,
			WriterClosureSHA256: closureDigest, WriterClosure: closure,
		})
		if err := publishHAFenceEpochTombstones(root, options.expectedOwnerUID, tombstones); err != nil {
			return err
		}
	}
	generation, err := nextHAFenceGeneration(state.Generation)
	if err != nil {
		return err
	}
	return publishCLIHAFenceState(root, options.expectedOwnerUID, cliHAFenceDiskState{
		Version: cliHAFenceVersion, State: cliHAFenceStateInactive, Generation: generation,
	})
}

func readLocalHAFenceStatus(options haFenceAdminOptions) (HAFenceLocalStatus, error) {
	root, err := openCLIHAFenceDirectory(options.fence)
	if err != nil {
		return HAFenceLocalStatus{}, err
	}
	defer root.Close()
	lock, err := openCLIHAFenceLock(root, options.expectedOwnerUID, false)
	if err != nil {
		return HAFenceLocalStatus{}, err
	}
	defer closeCLIHAFenceLock(lock)
	state, err := readCLIHAFenceState(root, options.expectedOwnerUID)
	if err != nil {
		return HAFenceLocalStatus{}, err
	}
	return HAFenceLocalStatus(state), nil
}

func EngageHAFence(manifestPath string) error {
	if err := requireHAFenceRoot(); err != nil {
		return err
	}
	return engageHAFence(manifestPath, defaultHAFenceAdminOptions())
}

func RecoverHAFence(manifestPath string) error {
	if err := requireHAFenceRoot(); err != nil {
		return err
	}
	return recoverHAFence(manifestPath, defaultHAFenceAdminOptions())
}

func ReleaseHAFence(manifestPath, closurePath string) error {
	if err := requireHAFenceRoot(); err != nil {
		return err
	}
	return releaseHAFence(manifestPath, closurePath, defaultHAFenceAdminOptions())
}

func ReadLocalHAFenceStatus() (HAFenceLocalStatus, error) {
	if err := requireHAFenceRoot(); err != nil {
		return HAFenceLocalStatus{}, err
	}
	return readLocalHAFenceStatus(defaultHAFenceAdminOptions())
}
