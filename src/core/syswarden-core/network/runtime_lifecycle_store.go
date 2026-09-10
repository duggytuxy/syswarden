package network

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

const maximumRuntimeLifecycleBytes = 16 * 1024 * 1024

type runtimeLifecycleAnchor struct {
	Version  int    `json:"version"`
	Identity string `json:"identity"`
	Sequence uint64 `json:"sequence"`
	Digest   string `json:"digest"`
}

// A prepared intent is not evidence of a completed kernel mutation. Recovery
// must obtain fresh native witnesses before supplying a candidate model.
type runtimeLifecycleIntent struct {
	Entry            string `json:"entry"`
	Present          bool   `json:"present"`
	Permanent        bool   `json:"permanent"`
	ExpiresAt        string `json:"expires_at,omitempty"`
	PreparedAt       string `json:"prepared_at"`
	PreserveStronger bool   `json:"preserve_stronger,omitempty"`
}

type runtimeLifecycleJournal struct {
	Version      int                     `json:"version"`
	Initializing bool                    `json:"initializing,omitempty"`
	Before       *runtimeLifecycleModel  `json:"before,omitempty"`
	Intent       *runtimeLifecycleIntent `json:"intent,omitempty"`
	Candidate    *runtimeLifecycleModel  `json:"candidate,omitempty"`
}

// The caller serializes operations and holds this store's instance lease
// until shutdown. Separate instances cannot concurrently publish a head.
type runtimeLifecycleStore struct {
	root         *os.Root
	parent       *os.Root
	name         string
	lease        *os.File
	path         string
	ownerUID     int
	observedHead string
	afterPublish func(string) error
}

func openRuntimeLifecycleStore(directory string, ownerUID int) (*runtimeLifecycleStore, error) {
	if ownerUID < 0 || !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return nil, fmt.Errorf("invalid runtime lifecycle store location or owner")
	}
	parent, err := os.OpenRoot(filepath.Dir(directory))
	if err != nil {
		return nil, err
	}
	root, _, err := openHAReplicationStoreDirectory(filepath.Join(directory, "state.json"), ownerUID)
	if err != nil {
		_ = parent.Close()
		return nil, err
	}
	lease, err := root.Open(".")
	if err != nil {
		_ = root.Close()
		_ = parent.Close()
		return nil, err
	}
	if err := syscall.Flock(int(lease.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = lease.Close()
		_ = root.Close()
		_ = parent.Close()
		return nil, fmt.Errorf("another runtime lifecycle instance owns the store: %w", err)
	}
	store := &runtimeLifecycleStore{root: root, parent: parent, name: filepath.Base(directory), lease: lease, path: directory, ownerUID: ownerUID}
	if err := store.attestDirectory(); err != nil {
		store.close()
		return nil, err
	}
	return store, nil
}

func (store *runtimeLifecycleStore) close() {
	if store.lease != nil {
		_ = syscall.Flock(int(store.lease.Fd()), syscall.LOCK_UN)
		_ = store.lease.Close()
		store.lease = nil
	}
	if store.root != nil {
		_ = store.root.Close()
		store.root = nil
	}
	if store.parent != nil {
		_ = store.parent.Close()
		store.parent = nil
	}
}

func (store *runtimeLifecycleStore) attestDirectory() error {
	if store.root == nil || store.parent == nil || store.lease == nil {
		return fmt.Errorf("runtime lifecycle store is closed")
	}
	current, err := store.parent.Lstat(store.name)
	opened, openErr := store.root.Stat(".")
	leased, leaseErr := store.lease.Stat()
	if err != nil || openErr != nil || leaseErr != nil || !os.SameFile(current, opened) || !os.SameFile(opened, leased) {
		return fmt.Errorf("runtime lifecycle directory changed identity")
	}
	owner, ownerErr := haFenceOwnerUID(opened)
	if ownerErr != nil || owner != store.ownerUID || !opened.IsDir() || opened.Mode().Perm() != 0700 {
		return fmt.Errorf("runtime lifecycle directory must remain private and owner-controlled")
	}
	return nil
}

func (store *runtimeLifecycleStore) readFile(name string, destination any) (bool, error) {
	if err := store.attestDirectory(); err != nil {
		return false, err
	}
	info, err := store.root.Lstat(name)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	owner, ownerErr := haFenceOwnerUID(info)
	stat, statOK := info.Sys().(*syscall.Stat_t)
	if ownerErr != nil || owner != store.ownerUID || !statOK || stat.Nlink != 1 || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return false, fmt.Errorf("runtime lifecycle file %s is not a private single-link regular file", name)
	}
	wire, err := readHARegularFileBounded(store.root, name, maximumRuntimeLifecycleBytes)
	if err != nil {
		return false, err
	}
	if err := rejectHADuplicateJSONKeys(wire); err != nil {
		return false, err
	}
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return false, err
	}
	canonical, err := json.Marshal(destination)
	if err != nil || !bytes.Equal(wire, append(canonical, '\n')) {
		return false, fmt.Errorf("runtime lifecycle file %s is not canonical", name)
	}
	return true, nil
}

func (store *runtimeLifecycleStore) publish(name string, value any) error {
	// Attest an existing destination before the atomic publisher touches it.
	var previous json.RawMessage
	if _, err := store.readFile(name, &previous); err != nil {
		return err
	}
	wire, err := json.Marshal(value)
	if err != nil {
		return err
	}
	wire = append(wire, '\n')
	if len(wire) > maximumRuntimeLifecycleBytes {
		return fmt.Errorf("runtime lifecycle publication exceeds bounds")
	}
	if err := publishHAFileAtomically(store.root, name, wire); err != nil {
		return err
	}
	if store.afterPublish != nil {
		return store.afterPublish(name)
	}
	return nil
}

func lifecycleAnchor(model runtimeLifecycleModel) (runtimeLifecycleAnchor, error) {
	digest, err := model.digest()
	if err != nil {
		return runtimeLifecycleAnchor{}, err
	}
	return runtimeLifecycleAnchor{Version: 1, Identity: model.Identity, Sequence: model.Sequence, Digest: digest}, nil
}

func (journal runtimeLifecycleJournal) validate() error {
	if journal.Version != 1 || journal.Initializing != (journal.Before == nil) || journal.Intent == nil && journal.Candidate == nil {
		return fmt.Errorf("runtime lifecycle journal shape is invalid")
	}
	if journal.Initializing && (journal.Intent != nil || journal.Candidate.Sequence != 1 || len(journal.Candidate.Records) != 0) {
		return fmt.Errorf("runtime lifecycle genesis is invalid")
	}
	if journal.Before != nil {
		if err := journal.Before.validate(); err != nil {
			return err
		}
	}
	if journal.Candidate != nil {
		if err := journal.Candidate.validate(); err != nil {
			return err
		}
		if journal.Before != nil {
			beforeTime, _ := runtimeLifecycleTime(journal.Before.UpdatedAt)
			afterTime, _ := runtimeLifecycleTime(journal.Candidate.UpdatedAt)
			beforeDigest, _ := journal.Before.digest()
			afterDigest, _ := journal.Candidate.digest()
			noOp := journal.Intent != nil && beforeDigest == afterDigest
			if journal.Before.Identity != journal.Candidate.Identity || !noOp && journal.Candidate.Sequence <= journal.Before.Sequence || afterTime.Before(beforeTime) {
				return fmt.Errorf("runtime lifecycle candidate does not advance the same history")
			}
		}
	}
	if journal.Intent != nil {
		intent := journal.Intent
		prepared, err := runtimeLifecycleTime(intent.PreparedAt)
		beforeTime, _ := runtimeLifecycleTime(journal.Before.UpdatedAt)
		if err != nil || prepared.Before(beforeTime) || !canonicalRuntimeLifecycleEntry(intent.Entry) {
			return fmt.Errorf("runtime lifecycle intent chronology or entry is invalid")
		}
		if !intent.Present && (intent.Permanent || intent.ExpiresAt != "" || intent.PreserveStronger) || intent.Permanent && intent.ExpiresAt != "" {
			return fmt.Errorf("runtime lifecycle intent has contradictory lifetime metadata")
		}
		if intent.Present && !intent.Permanent {
			expiry, expiryErr := runtimeLifecycleTime(intent.ExpiresAt)
			if expiryErr != nil || !expiry.After(prepared) || expiry.Sub(prepared) > 30*24*time.Hour+2*time.Second {
				return fmt.Errorf("runtime lifecycle intent expiry is invalid")
			}
		}
	}
	return nil
}

// load finishes only a previously witnessed candidate. An intent without a
// candidate is returned for native recovery; it never becomes a ban claim.
func (store *runtimeLifecycleStore) load() (runtimeLifecycleModel, *runtimeLifecycleJournal, error) {
	var state runtimeLifecycleModel
	var anchor runtimeLifecycleAnchor
	var journal runtimeLifecycleJournal
	stateExists, err := store.readFile("state.json", &state)
	if err != nil {
		return state, nil, err
	}
	anchorExists, err := store.readFile("anchor.json", &anchor)
	if err != nil {
		return state, nil, err
	}
	pending, err := store.readFile("pending.json", &journal)
	if err != nil {
		return state, nil, err
	}
	if pending {
		if err := journal.validate(); err != nil {
			return state, nil, err
		}
		if store.observedHead != "" {
			if journal.Before == nil {
				return state, nil, fmt.Errorf("runtime lifecycle genesis replaced existing history")
			}
			beforeDigest, _ := journal.Before.digest()
			if store.observedHead != beforeDigest {
				return state, nil, fmt.Errorf("runtime lifecycle pending journal replaced this instance's head")
			}
		}
		if err := validateRuntimeLifecycleHead(state, stateExists, anchor, anchorExists, journal); err != nil {
			return state, nil, err
		}
		if journal.Candidate != nil {
			if err := store.finish(journal); err != nil {
				return state, nil, err
			}
			return *journal.Candidate, nil, nil
		}
		beforeAnchor, _ := lifecycleAnchor(*journal.Before)
		if store.observedHead != "" && store.observedHead != beforeAnchor.Digest {
			return state, nil, fmt.Errorf("runtime lifecycle head changed outside this instance")
		}
		store.observedHead = beforeAnchor.Digest
		return *journal.Before, &journal, nil
	}
	if !stateExists || !anchorExists {
		return state, nil, fmt.Errorf("runtime lifecycle head or anchor is missing; explicit recovery is required")
	}
	expected, err := lifecycleAnchor(state)
	if err != nil || anchor != expected || store.observedHead != "" && store.observedHead != expected.Digest {
		return state, nil, fmt.Errorf("runtime lifecycle head and anchor disagree or changed unexpectedly")
	}
	store.observedHead = expected.Digest
	return state, nil, nil
}

func validateRuntimeLifecycleHead(state runtimeLifecycleModel, stateExists bool, anchor runtimeLifecycleAnchor, anchorExists bool, journal runtimeLifecycleJournal) error {
	var before, candidate runtimeLifecycleAnchor
	if journal.Before != nil {
		before, _ = lifecycleAnchor(*journal.Before)
	}
	if journal.Candidate != nil {
		candidate, _ = lifecycleAnchor(*journal.Candidate)
	}
	if !stateExists && !journal.Initializing || !anchorExists && !journal.Initializing {
		return fmt.Errorf("existing runtime lifecycle history lost its head or anchor")
	}
	if stateExists {
		actual, err := lifecycleAnchor(state)
		if err != nil || actual != before && actual != candidate {
			return fmt.Errorf("runtime lifecycle head is outside the journal transition")
		}
		if anchorExists && anchor == candidate && actual != candidate {
			return fmt.Errorf("runtime lifecycle anchor advanced before its durable state")
		}
	} else if anchorExists {
		return fmt.Errorf("runtime lifecycle anchor exists without its preceding state")
	}
	if anchorExists && anchor != before && anchor != candidate {
		return fmt.Errorf("runtime lifecycle anchor is outside the journal transition")
	}
	return nil
}

// initialize is permitted only by the caller that just created the private
// directory. An existing empty directory must never silently reset history.
func (store *runtimeLifecycleStore) initialize(now time.Time) (runtimeLifecycleModel, error) {
	for _, name := range []string{"state.json", "anchor.json", "pending.json"} {
		var existing json.RawMessage
		present, err := store.readFile(name, &existing)
		if err != nil || present {
			return runtimeLifecycleModel{}, fmt.Errorf("runtime lifecycle initialization requires an empty new store: %s", name)
		}
	}
	identity := make([]byte, 32)
	if _, err := rand.Read(identity); err != nil {
		return runtimeLifecycleModel{}, err
	}
	model := runtimeLifecycleModel{SchemaVersion: 1, Identity: hex.EncodeToString(identity), Sequence: 1,
		UpdatedAt: now.UTC().Format(time.RFC3339Nano), Records: []runtimeLifecycleRecord{}}
	journal := runtimeLifecycleJournal{Version: 1, Initializing: true, Candidate: &model}
	if err := journal.validate(); err != nil {
		return model, err
	}
	if err := store.publish("pending.json", journal); err != nil {
		return model, err
	}
	return model, store.finish(journal)
}

func (store *runtimeLifecycleStore) prepare(intent runtimeLifecycleIntent) error {
	model, pending, err := store.load()
	if err != nil {
		return err
	}
	if pending != nil {
		return fmt.Errorf("runtime lifecycle recovery is pending")
	}
	journal := runtimeLifecycleJournal{Version: 1, Before: &model, Intent: &intent}
	if err := journal.validate(); err != nil {
		return err
	}
	return store.publish("pending.json", journal)
}

func (store *runtimeLifecycleStore) commit(candidate runtimeLifecycleModel) error {
	model, pending, err := store.load()
	if err != nil {
		return err
	}
	journal := runtimeLifecycleJournal{Version: 1, Before: &model, Candidate: &candidate}
	if pending != nil {
		journal = *pending
		journal.Candidate = &candidate
	}
	if err := journal.validate(); err != nil {
		return err
	}
	if err := store.publish("pending.json", journal); err != nil {
		return err
	}
	return store.finish(journal)
}

func (store *runtimeLifecycleStore) finish(journal runtimeLifecycleJournal) error {
	if err := journal.validate(); err != nil {
		return err
	}
	if journal.Candidate == nil {
		return fmt.Errorf("runtime lifecycle intent has no witnessed candidate")
	}
	anchor, _ := lifecycleAnchor(*journal.Candidate)
	if err := store.publish("state.json", journal.Candidate); err != nil {
		return err
	}
	if err := store.publish("anchor.json", anchor); err != nil {
		return err
	}
	if err := store.attestDirectory(); err != nil {
		return err
	}
	if err := store.root.Remove("pending.json"); err != nil {
		return err
	}
	if err := store.lease.Sync(); err != nil {
		return err
	}
	store.observedHead = anchor.Digest
	return nil
}
