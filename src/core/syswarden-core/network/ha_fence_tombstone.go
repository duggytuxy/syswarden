package network

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"regexp"
	"strings"
	"time"
)

const (
	haFenceTombstonesVersion          = 1
	haFenceWriterClosureVersion       = 1
	maxHAFenceTombstonesBytes   int64 = 16 * 1024 * 1024
)

var (
	haFenceEpochUUIDv4RE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	haFenceWriterIDRE    = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
)

type haFenceWriterClosureEntry struct {
	ID                string `json:"id"`
	Disposition       string `json:"disposition"`
	ClosureGeneration string `json:"closure_generation"`
	ClosedAt          string `json:"closed_at"`
	EvidenceSHA256    string `json:"evidence_sha256"`
}

type haFenceWriterClosure struct {
	SchemaVersion               int                         `json:"schema_version"`
	Epoch                       string                      `json:"epoch"`
	MembershipSHA256            string                      `json:"membership_sha256"`
	LegacyWriterInventorySHA256 string                      `json:"legacy_writer_inventory_sha256"`
	LegacyRetryQueueDrained     bool                        `json:"legacy_retry_queue_drained"`
	Writers                     []haFenceWriterClosureEntry `json:"writers"`
}

type haFenceEpochEvent struct {
	Event                       string                `json:"event"`
	Epoch                       string                `json:"epoch"`
	MembershipSHA256            string                `json:"membership_sha256"`
	LegacyWriterInventorySHA256 string                `json:"legacy_writer_inventory_sha256"`
	RecordedAt                  string                `json:"recorded_at"`
	WriterClosureSHA256         string                `json:"writer_closure_sha256,omitempty"`
	WriterClosure               *haFenceWriterClosure `json:"writer_closure,omitempty"`
}

type haFenceEpochTombstones struct {
	Version int                 `json:"version"`
	Events  []haFenceEpochEvent `json:"events"`
}

func canonicalHAFenceTimestamp(value string) bool {
	parsed, err := time.Parse(time.RFC3339, value)
	return err == nil && parsed.UTC().Format(time.RFC3339) == value
}

func validHAFenceClosureGeneration(value string) bool {
	if value == "" || len(value) > 256 {
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

func canonicalHAFenceWriterClosureBytes(closure haFenceWriterClosure) ([]byte, error) {
	wire, err := json.MarshalIndent(closure, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(wire, '\n'), nil
}

func validateHAFenceEpochEvent(event haFenceEpochEvent) error {
	if !haFenceEpochUUIDv4RE.MatchString(event.Epoch) || !isLowerHexSHA256(event.MembershipSHA256) ||
		!isLowerHexSHA256(event.LegacyWriterInventorySHA256) || !canonicalHAFenceTimestamp(event.RecordedAt) {
		return fmt.Errorf("invalid HA fence epoch tombstone identity")
	}
	if event.Event == "engaged" {
		if event.WriterClosureSHA256 != "" || event.WriterClosure != nil {
			return fmt.Errorf("HA fence engagement tombstone contains release evidence")
		}
		return nil
	}
	if event.Event != "retired" || !isLowerHexSHA256(event.WriterClosureSHA256) || event.WriterClosure == nil {
		return fmt.Errorf("invalid HA fence retirement tombstone")
	}
	closure := event.WriterClosure
	if closure.SchemaVersion != haFenceWriterClosureVersion || closure.Epoch != event.Epoch ||
		closure.MembershipSHA256 != event.MembershipSHA256 ||
		closure.LegacyWriterInventorySHA256 != event.LegacyWriterInventorySHA256 ||
		!closure.LegacyRetryQueueDrained || closure.Writers == nil {
		return fmt.Errorf("HA fence retirement tombstone closure identity mismatch")
	}
	previousWriter := ""
	var writerPreimage strings.Builder
	writerPreimage.WriteString("syswarden-ha-legacy-writers-v1\n")
	for _, writer := range closure.Writers {
		if !haFenceWriterIDRE.MatchString(writer.ID) || writer.ID <= previousWriter ||
			!terminalHAFenceWriterDisposition(writer.Disposition) ||
			!validHAFenceClosureGeneration(writer.ClosureGeneration) ||
			!canonicalHAFenceTimestamp(writer.ClosedAt) || !isLowerHexSHA256(writer.EvidenceSHA256) {
			return fmt.Errorf("HA fence retirement tombstone contains invalid writer closure evidence")
		}
		previousWriter = writer.ID
		writerPreimage.WriteString(writer.ID)
		writerPreimage.WriteByte('\n')
	}
	writerDigest := sha256.Sum256([]byte(writerPreimage.String()))
	if hex.EncodeToString(writerDigest[:]) != closure.LegacyWriterInventorySHA256 {
		return fmt.Errorf("HA fence retirement tombstone writer inventory digest mismatch")
	}
	closureWire, err := canonicalHAFenceWriterClosureBytes(*closure)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(closureWire)
	if hex.EncodeToString(digest[:]) != event.WriterClosureSHA256 {
		return fmt.Errorf("HA fence retirement tombstone closure digest mismatch")
	}
	return nil
}

func readHAFenceEpochTombstones(root *os.Root, expectedOwnerUID int) (haFenceEpochTombstones, bool, error) {
	info, err := root.Lstat(haFenceTombstonesName)
	if errors.Is(err, fs.ErrNotExist) {
		return haFenceEpochTombstones{Version: haFenceTombstonesVersion, Events: []haFenceEpochEvent{}}, false, nil
	}
	if err != nil {
		return haFenceEpochTombstones{}, false, err
	}
	owner, ownerErr := haFenceOwnerUID(info)
	if ownerErr != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || owner != expectedOwnerUID {
		return haFenceEpochTombstones{}, true, fmt.Errorf("HA fence epoch tombstones must be a regular 0600 file owned by UID %d", expectedOwnerUID)
	}
	wire, err := readHARegularFileBounded(root, haFenceTombstonesName, maxHAFenceTombstonesBytes)
	if err != nil {
		return haFenceEpochTombstones{}, true, err
	}
	if err := rejectHADuplicateJSONKeys(wire); err != nil {
		return haFenceEpochTombstones{}, true, fmt.Errorf("decode HA fence epoch tombstones: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.DisallowUnknownFields()
	var tombstones haFenceEpochTombstones
	if err := decoder.Decode(&tombstones); err != nil {
		return haFenceEpochTombstones{}, true, fmt.Errorf("decode HA fence epoch tombstones: %w", err)
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); err != io.EOF {
		return haFenceEpochTombstones{}, true, fmt.Errorf("decode HA fence epoch tombstones: trailing JSON")
	}
	if tombstones.Version != haFenceTombstonesVersion || tombstones.Events == nil {
		return haFenceEpochTombstones{}, true, fmt.Errorf("invalid HA fence epoch tombstone envelope")
	}
	canonical, err := json.Marshal(tombstones)
	if err != nil {
		return haFenceEpochTombstones{}, true, err
	}
	canonical = append(canonical, '\n')
	if !bytes.Equal(wire, canonical) {
		return haFenceEpochTombstones{}, true, fmt.Errorf("HA fence epoch tombstone bytes are not canonical")
	}
	return tombstones, true, nil
}

func analyzeHAFenceEpochTombstones(tombstones haFenceEpochTombstones) (*haFenceEpochEvent, map[string]haFenceEpochEvent, error) {
	engaged := make(map[string]haFenceEpochEvent)
	retired := make(map[string]haFenceEpochEvent)
	for _, event := range tombstones.Events {
		if err := validateHAFenceEpochEvent(event); err != nil {
			return nil, nil, err
		}
		if event.Event == "engaged" {
			if _, duplicate := engaged[event.Epoch]; duplicate {
				return nil, nil, fmt.Errorf("duplicate HA fence engagement tombstone")
			}
			engaged[event.Epoch] = event
			continue
		}
		engagement, found := engaged[event.Epoch]
		if !found || engagement.MembershipSHA256 != event.MembershipSHA256 ||
			engagement.LegacyWriterInventorySHA256 != event.LegacyWriterInventorySHA256 {
			return nil, nil, fmt.Errorf("HA fence retirement tombstone has no matching engagement")
		}
		if _, duplicate := retired[event.Epoch]; duplicate {
			return nil, nil, fmt.Errorf("duplicate HA fence retirement tombstone")
		}
		retired[event.Epoch] = event
	}
	var openEpoch *haFenceEpochEvent
	for epoch, event := range engaged {
		if _, completed := retired[epoch]; completed {
			continue
		}
		if openEpoch != nil {
			return nil, nil, fmt.Errorf("HA fence epoch tombstones contain multiple open campaigns")
		}
		copy := event
		openEpoch = &copy
	}
	return openEpoch, retired, nil
}

func haFenceStateMatchesEpoch(state haFenceDiskState, event haFenceEpochEvent) bool {
	return state.Epoch == event.Epoch && state.MembershipSHA256 == event.MembershipSHA256 &&
		state.LegacyWriterInventorySHA256 == event.LegacyWriterInventorySHA256
}

func incrementHAFenceGeneration(state *haFenceDiskState) error {
	if state.Generation == ^uint64(0) {
		return fmt.Errorf("HA fence generation is exhausted")
	}
	state.Generation++
	return nil
}
