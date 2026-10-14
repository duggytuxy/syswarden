package journal

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strconv"

	"golang.org/x/sys/unix"
	contracts "syswarden-core/contracts/v5"
)

const (
	anchorRecoverySchema = "syswarden.journal-anchor-recovery.v1"
	anchorRecoveryDomain = "syswarden/journal-anchor-recovery/v1\x00"
	maxRecoveryPlanBytes = 16384
)

var (
	ErrRecoveryIneligible = errors.New("recovery requires exactly one complete authenticated anchor after independent expected state")
	ErrRecoveryApproval   = errors.New("recovery requires the exact independently reviewed plan digest")
)

// AnchorRecoveryPlan owns a canonical private document and its domain-separated
// digest. It is an inspection result, not authority or a committed next anchor.
// Review and authorization belong outside this package. Apply reconstructs it
// from storage and independent trust, never from these mutable returned bytes.
type AnchorRecoveryPlan struct {
	Document []byte
	SHA256   string
}

type recoveryResource struct {
	Device           string `json:"device"`
	Inode            string `json:"inode"`
	Mode             string `json:"mode"`
	UID              string `json:"uid"`
	GID              string `json:"gid"`
	Links            string `json:"links"`
	Size             string `json:"size"`
	MtimeSeconds     string `json:"mtime_seconds"`
	MtimeNanoseconds string `json:"mtime_nanoseconds"`
	CtimeSeconds     string `json:"ctime_seconds"`
	CtimeNanoseconds string `json:"ctime_nanoseconds"`
}

func bindRecoveryResource(st unix.Stat_t) recoveryResource {
	return recoveryResource{Device: strconv.FormatUint(uint64(st.Dev), 10), Inode: strconv.FormatUint(uint64(st.Ino), 10), Mode: strconv.FormatUint(uint64(st.Mode), 10),
		UID: strconv.FormatUint(uint64(st.Uid), 10), GID: strconv.FormatUint(uint64(st.Gid), 10), Links: strconv.FormatUint(uint64(st.Nlink), 10), Size: strconv.FormatInt(st.Size, 10),
		MtimeSeconds: strconv.FormatInt(int64(st.Mtim.Sec), 10), MtimeNanoseconds: strconv.FormatInt(int64(st.Mtim.Nsec), 10),
		CtimeSeconds: strconv.FormatInt(int64(st.Ctim.Sec), 10), CtimeNanoseconds: strconv.FormatInt(int64(st.Ctim.Nsec), 10)}
}

type recoveryDocument struct {
	Schema           string           `json:"schema"`
	Operation        string           `json:"operation"`
	Initial          json.RawMessage  `json:"initial"`
	Expected         json.RawMessage  `json:"expected"`
	Candidate        json.RawMessage  `json:"candidate"`
	Records          string           `json:"records"`
	AnchorSHA256     string           `json:"anchor_sha256"`
	SegmentName      string           `json:"segment_name"`
	SegmentSHA256    string           `json:"segment_sha256"`
	CheckpointSHA256 string           `json:"checkpoint_bundle_sha256"`
	MaxSegmentBytes  string           `json:"max_segment_bytes"`
	MaxSegmentFrames string           `json:"max_segment_frames"`
	KeyID            string           `json:"key_id"`
	PublicKeySHA256  string           `json:"public_key_sha256"`
	FirstSequence    string           `json:"first_sequence"`
	LastSequence     string           `json:"last_sequence"`
	AnchorDirectory  recoveryResource `json:"anchor_directory"`
	AnchorFile       recoveryResource `json:"anchor_file"`
	JournalDirectory recoveryResource `json:"journal_directory"`
	SegmentFile      recoveryResource `json:"segment_file"`
	CheckpointFile   recoveryResource `json:"checkpoint_file"`
}

func recoveryDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// inspectRecoveryTail first rejects all incomplete or corrupt chains. No valid
// prefix is exposed. The whole prefix before the final record must end at the
// independently retained expected head; multiple new records are ineligible.
func inspectRecoveryTail(data []byte, initial, expected contracts.JournalCheckpointAnchor) (anchorState, error) {
	state, err := scanAnchors(data, initial)
	if err != nil || state.count < 2 {
		return anchorState{}, errors.Join(ErrRecoveryIneligible, err)
	}
	last := 0
	for offset := 0; offset < len(data); {
		// The preceding full scan checked each length and bounded every offset.
		last = offset
		size := binary.BigEndian.Uint32(data[offset : offset+4])
		if size == 0 || size > maxAnchorDocument {
			return anchorState{}, ErrRecoveryIneligible
		}
		offset += 4 + int(size) + sha256.Size
	}
	before, err := scanAnchors(data[:last], initial)
	if err != nil || before.head != expected || before.count+1 != state.count {
		return anchorState{}, errors.Join(ErrRecoveryIneligible, err)
	}
	return state, nil
}

type recoverySession struct {
	anchor    *AnchorStore
	segment   *Segment
	expected  contracts.JournalCheckpointAnchor
	authority contracts.JournalCheckpointAuthority
	state     anchorState
}

func (r *recoverySession) close() error {
	var err error
	if r.segment != nil {
		err = r.segment.Close()
	}
	return errors.Join(err, r.anchor.Close())
}

func openRecovery(anchorDirectory, journalDirectory *os.File, initial, expected contracts.JournalCheckpointAnchor, name string, authority contracts.JournalCheckpointAuthority, limits Limits) (*recoverySession, AnchorRecoveryPlan, error) {
	if _, err := encodeAnchor(expected); err != nil {
		return nil, AnchorRecoveryPlan{}, err
	}
	a, err := acquireAnchorMode(anchorDirectory, initial, false, true)
	if err != nil {
		return nil, AnchorRecoveryPlan{}, err
	}
	r := &recoverySession{anchor: a, expected: expected, authority: authority}
	data, err := a.readExact()
	if err == nil {
		r.state, err = inspectRecoveryTail(data, initial, expected)
	}
	if err == nil {
		r.segment, err = OpenPublishedSegment(journalDirectory, name, contracts.JournalCheckpointContext{Anchor: expected, Authority: authority}, limits)
	}
	if err != nil {
		return nil, AnchorRecoveryPlan{}, errors.Join(err, r.close())
	}
	plan, err := r.plan()
	if err != nil {
		return nil, AnchorRecoveryPlan{}, errors.Join(err, r.close())
	}
	return r, plan, nil
}

func (r *recoverySession) plan() (AnchorRecoveryPlan, error) {
	a, s := r.anchor, r.segment
	ledger, err := a.readExact()
	if err != nil {
		return AnchorRecoveryPlan{}, err
	}
	state, err := inspectRecoveryTail(ledger, a.initial, r.expected)
	if err != nil || state != r.state {
		return AnchorRecoveryPlan{}, errors.Join(ErrChanged, err)
	}
	pending, final := checkpointNames(s.name)
	if err = requireAbsent(s.directory, pending); err != nil {
		return AnchorRecoveryPlan{}, err
	}
	bundle, checkpointStamp, err := readCheckpointSnapshot(s.directory, final)
	if err != nil {
		return AnchorRecoveryPlan{}, err
	}
	cp, sig, err := decodeCheckpointBundle(bundle)
	if err != nil {
		return AnchorRecoveryPlan{}, err
	}
	snapshot, err := s.snapshot()
	if err != nil {
		return AnchorRecoveryPlan{}, err
	}
	_, next, err := contracts.ReadAuthenticatedJournalSegment(snapshot.Data, cp, sig, contracts.JournalCheckpointContext{Anchor: r.expected, Authority: r.authority}, s.limits.MaxBytes, s.limits.MaxFrames)
	if err != nil || next != state.head {
		return AnchorRecoveryPlan{}, errors.Join(ErrRecoveryIneligible, err)
	}
	var anchorDir, journalDir, currentCheckpoint unix.Stat_t
	if err = unix.Fstat(int(a.directory.Fd()), &anchorDir); err != nil || !privateDirectory(anchorDir) {
		return AnchorRecoveryPlan{}, errors.Join(ErrUnsafeStorage, err)
	}
	if err = unix.Fstat(int(s.directory.Fd()), &journalDir); err != nil || !privateDirectory(journalDir) {
		return AnchorRecoveryPlan{}, errors.Join(ErrUnsafeStorage, err)
	}
	if err = unix.Fstatat(int(s.directory.Fd()), final, &currentCheckpoint, unix.AT_SYMLINK_NOFOLLOW); err != nil || !sameStamp(checkpointStamp, currentCheckpoint) {
		return AnchorRecoveryPlan{}, errors.Join(ErrChanged, err)
	}
	if err = a.unchanged(); err != nil {
		return AnchorRecoveryPlan{}, err
	}
	if err = s.unchanged(); err != nil {
		return AnchorRecoveryPlan{}, err
	}
	initial, err := encodeAnchor(a.initial)
	if err != nil {
		return AnchorRecoveryPlan{}, err
	}
	expected, err := encodeAnchor(r.expected)
	if err != nil {
		return AnchorRecoveryPlan{}, err
	}
	candidate, err := encodeAnchor(state.head)
	if err != nil {
		return AnchorRecoveryPlan{}, err
	}
	d := recoveryDocument{Schema: anchorRecoverySchema, Operation: "resynchronize-complete-anchor", Initial: initial, Expected: expected, Candidate: candidate,
		Records: strconv.Itoa(state.count), AnchorSHA256: recoveryDigest(ledger), SegmentName: s.name, SegmentSHA256: recoveryDigest(snapshot.Data), CheckpointSHA256: recoveryDigest(bundle),
		MaxSegmentBytes: strconv.Itoa(s.limits.MaxBytes), MaxSegmentFrames: strconv.Itoa(s.limits.MaxFrames), KeyID: r.authority.KeyID, PublicKeySHA256: recoveryDigest(r.authority.PublicKey),
		FirstSequence: strconv.FormatUint(r.authority.FirstSequence, 10), LastSequence: strconv.FormatUint(r.authority.LastSequence, 10),
		AnchorDirectory: bindRecoveryResource(anchorDir), AnchorFile: bindRecoveryResource(a.stamp), JournalDirectory: bindRecoveryResource(journalDir), SegmentFile: bindRecoveryResource(s.stamp), CheckpointFile: bindRecoveryResource(checkpointStamp)}
	document, err := json.Marshal(d)
	if err != nil || len(document) > maxRecoveryPlanBytes {
		return AnchorRecoveryPlan{}, ErrRecoveryIneligible
	}
	return AnchorRecoveryPlan{Document: document, SHA256: recoveryDigest(append([]byte(anchorRecoveryDomain), document...))}, nil
}

// PlanAnchorRecovery performs read-only inspection under separate directory
// locks. It neither synchronizes storage nor returns an accepted next anchor.
// Only one complete extra anchor with exact authenticated publication is eligible.
func PlanAnchorRecovery(anchorDirectory, journalDirectory *os.File, initial, expected contracts.JournalCheckpointAnchor, name string, authority contracts.JournalCheckpointAuthority, limits Limits) (AnchorRecoveryPlan, error) {
	r, plan, err := openRecovery(anchorDirectory, journalDirectory, initial, expected, name, authority, limits)
	if err != nil {
		return AnchorRecoveryPlan{}, err
	}
	if err = r.close(); err != nil {
		return AnchorRecoveryPlan{}, err
	}
	return plan, nil
}

func validRecoveryApproval(digest string) bool {
	if len(digest) != sha256.Size*2 {
		return false
	}
	b, err := hex.DecodeString(digest)
	return err == nil && hex.EncodeToString(b) == digest
}

type recoverySyncOps struct {
	publication func(contracts.JournalCheckpointContext) (contracts.JournalCheckpointAnchor, error)
	anchor      func() error
	directory   func() error
}

func (r *recoverySession) synchronize(approved string, ops recoverySyncOps) error {
	plan, err := r.plan()
	if err != nil {
		return err
	}
	if plan.SHA256 != approved {
		return ErrRecoveryApproval
	}
	next, err := ops.publication(contracts.JournalCheckpointContext{Anchor: r.expected, Authority: r.authority})
	if err == nil && next != r.state.head {
		err = ErrChanged
	}
	if err == nil {
		err = ops.anchor()
	}
	if err == nil {
		err = ops.directory()
	}
	if err == nil {
		plan, err = r.plan()
		if err == nil && plan.SHA256 != approved {
			err = ErrChanged
		}
	}
	if err != nil {
		return errors.Join(ErrCommitUncertain, err)
	}
	return nil
}

// ApplyAnchorRecovery requires a digest supplied through an independent review
// and authorization path. It reconstructs the plan with current caller-resolved
// key authority and exact files, then resynchronizes the existing publication
// and complete anchor file. No bytes are appended, repaired or deleted. Success
// returns a local recovery result; independent restart-head custody is external.
func ApplyAnchorRecovery(anchorDirectory, journalDirectory *os.File, initial, expected contracts.JournalCheckpointAnchor, name string, authority contracts.JournalCheckpointAuthority, limits Limits, approvedSHA256 string) (contracts.JournalCheckpointAnchor, error) {
	if !validRecoveryApproval(approvedSHA256) {
		return contracts.JournalCheckpointAnchor{}, ErrRecoveryApproval
	}
	r, plan, err := openRecovery(anchorDirectory, journalDirectory, initial, expected, name, authority, limits)
	if err != nil {
		return contracts.JournalCheckpointAnchor{}, err
	}
	if plan.SHA256 != approvedSHA256 {
		return contracts.JournalCheckpointAnchor{}, errors.Join(ErrRecoveryApproval, r.close())
	}
	ops := recoverySyncOps{publication: r.segment.synchronizePublication, anchor: r.anchor.file.Sync, directory: r.anchor.directory.Sync}
	return r.apply(approvedSHA256, ops)
}

func (r *recoverySession) apply(approvedSHA256 string, ops recoverySyncOps) (contracts.JournalCheckpointAnchor, error) {
	err := errors.Join(r.synchronize(approvedSHA256, ops), r.close())
	if err != nil {
		return contracts.JournalCheckpointAnchor{}, errors.Join(ErrCommitUncertain, err)
	}
	return r.state.head, nil
}
