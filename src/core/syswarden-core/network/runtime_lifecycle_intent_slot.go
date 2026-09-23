package network

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"syscall"
)

const (
	runtimeIntentSlotName = "intent.slot"
	runtimeIntentSlotSize = 4096
	runtimeIntentHeader   = 44
)

// The hashed model requires this slot for new stores. Legacy histories retain
// their atomic intent journal; absence must never silently downgrade a store.
type runtimeIntentFrame struct {
	Version int                     `json:"version"`
	Anchor  runtimeLifecycleAnchor  `json:"anchor"`
	Intent  *runtimeLifecycleIntent `json:"intent,omitempty"`
}

func encodeRuntimeIntentFrame(frame runtimeIntentFrame) ([]byte, error) {
	if frame.Version != 1 || frame.Anchor.Version != 1 {
		return nil, fmt.Errorf("unsupported runtime intent frame")
	}
	payload, err := json.Marshal(frame)
	if err != nil || len(payload) > runtimeIntentSlotSize-runtimeIntentHeader {
		return nil, fmt.Errorf("runtime intent frame exceeds its fixed bound")
	}
	wire := make([]byte, runtimeIntentSlotSize)
	copy(wire, "SWINT001")
	binary.BigEndian.PutUint32(wire[8:12], uint32(len(payload)))
	copy(wire[runtimeIntentHeader:], payload)
	digest := sha256.Sum256(wire)
	copy(wire[12:runtimeIntentHeader], digest[:])
	return wire, nil
}

func decodeRuntimeIntentFrame(wire []byte) (runtimeIntentFrame, error) {
	var frame runtimeIntentFrame
	if len(wire) != runtimeIntentSlotSize || string(wire[:8]) != "SWINT001" {
		return frame, fmt.Errorf("runtime intent frame has invalid framing")
	}
	size := int(binary.BigEndian.Uint32(wire[8:12]))
	if size < 1 || size > runtimeIntentSlotSize-runtimeIntentHeader {
		return frame, fmt.Errorf("runtime intent frame has invalid payload length")
	}
	var checked [runtimeIntentSlotSize]byte
	copy(checked[:], wire)
	clear(checked[12:runtimeIntentHeader])
	digest := sha256.Sum256(checked[:])
	if !bytes.Equal(wire[12:runtimeIntentHeader], digest[:]) {
		return frame, fmt.Errorf("runtime intent frame integrity check failed")
	}
	for _, value := range wire[runtimeIntentHeader+size:] {
		if value != 0 {
			return frame, fmt.Errorf("runtime intent frame padding is not canonical")
		}
	}
	payload := wire[runtimeIntentHeader : runtimeIntentHeader+size]
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&frame); err != nil {
		return frame, err
	}
	canonical, err := json.Marshal(frame)
	if err != nil || frame.Version != 1 || frame.Anchor.Version != 1 || !bytes.Equal(canonical, payload) {
		return frame, fmt.Errorf("runtime intent frame is not canonical")
	}
	return frame, nil
}

func runtimeIntentWireDigest(wire []byte) string {
	digest := sha256.Sum256(wire)
	return hex.EncodeToString(digest[:])
}

func (store *runtimeLifecycleStore) attestIntentSlot() error {
	if err := store.attestDirectory(); err != nil {
		return err
	}
	if store.intentSlot == nil {
		return fmt.Errorf("runtime intent slot is not open")
	}
	current, err := store.root.Lstat(runtimeIntentSlotName)
	opened, openErr := store.intentSlot.Stat()
	if err != nil || openErr != nil || !os.SameFile(current, opened) {
		return fmt.Errorf("runtime intent slot changed identity")
	}
	owner, ownerErr := haFenceOwnerUID(opened)
	stat, statOK := opened.Sys().(*syscall.Stat_t)
	if ownerErr != nil || owner != store.ownerUID || !statOK || stat.Nlink != 1 ||
		!opened.Mode().IsRegular() || opened.Mode().Perm() != 0600 || opened.Size() != runtimeIntentSlotSize {
		return fmt.Errorf("runtime intent slot must remain private, single-link and fixed-size")
	}
	return nil
}

func (store *runtimeLifecycleStore) openIntentSlot() error {
	if err := store.attestDirectory(); err != nil {
		return err
	}
	if store.intentSlot == nil {
		info, err := store.root.Lstat(runtimeIntentSlotName)
		if err != nil || !info.Mode().IsRegular() {
			return fmt.Errorf("runtime intent slot is absent or not a regular file")
		}
		file, err := store.root.OpenFile(runtimeIntentSlotName, os.O_RDWR, 0)
		if err != nil {
			return err
		}
		opened, err := file.Stat()
		if err != nil || !os.SameFile(info, opened) {
			_ = file.Close()
			return fmt.Errorf("runtime intent slot changed while opening")
		}
		store.intentSlot = file
	}
	return store.attestIntentSlot()
}

func (store *runtimeLifecycleStore) readIntentSlot() (runtimeIntentFrame, error) {
	if err := store.openIntentSlot(); err != nil {
		return runtimeIntentFrame{}, err
	}
	wire := make([]byte, runtimeIntentSlotSize)
	if _, err := store.intentSlot.ReadAt(wire, 0); err != nil {
		return runtimeIntentFrame{}, err
	}
	if err := store.attestIntentSlot(); err != nil {
		return runtimeIntentFrame{}, err
	}
	frame, err := decodeRuntimeIntentFrame(wire)
	if err == nil {
		store.observedIntent = runtimeIntentWireDigest(wire)
	}
	return frame, err
}

// No in-place write is assumed atomic. Prepare returns only after a complete
// frame is synced and read back. Partial frames fence recovery; a valid intent
// still requires fresh native witnesses and never proves a completed mutation.
func (store *runtimeLifecycleStore) writeIntentSlot(frame runtimeIntentFrame) error {
	if err := store.openIntentSlot(); err != nil {
		return err
	}
	wire, err := encodeRuntimeIntentFrame(frame)
	if err != nil {
		return err
	}
	write := store.writeSlot
	if write == nil {
		write = func(file *os.File, value []byte) (int, error) { return file.WriteAt(value, 0) }
	}
	written, err := write(store.intentSlot, wire)
	if err != nil {
		return err
	}
	if written != len(wire) {
		return io.ErrShortWrite
	}
	sync := store.syncSlot
	if sync == nil {
		sync = (*os.File).Sync
	}
	if err := sync(store.intentSlot); err != nil {
		return err
	}
	readback := make([]byte, runtimeIntentSlotSize)
	if _, err := store.intentSlot.ReadAt(readback, 0); err != nil {
		return err
	}
	if !bytes.Equal(wire, readback) {
		return fmt.Errorf("runtime intent slot readback differs from the synced frame")
	}
	if err := store.attestIntentSlot(); err != nil {
		return err
	}
	if store.afterPublish != nil {
		return store.afterPublish(runtimeIntentSlotName)
	}
	return nil
}

// Only a fully journaled genesis may create a slot. Committed state retires the
// exact frame by its digest; recovery never clears or recreates lost intent.
func (store *runtimeLifecycleStore) ensureIntentSlot(journal runtimeLifecycleJournal, anchor runtimeLifecycleAnchor) error {
	if err := store.attestDirectory(); err != nil {
		return err
	}
	_, err := store.root.Lstat(runtimeIntentSlotName)
	if errors.Is(err, fs.ErrNotExist) && journal.Initializing {
		wire, err := encodeRuntimeIntentFrame(runtimeIntentFrame{Version: 1, Anchor: anchor})
		if err != nil {
			return err
		}
		if err := publishHAFileAtomically(store.root, runtimeIntentSlotName, wire); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	return store.openIntentSlot()
}
