package journal

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"
	"net"
	"os"
	"strconv"
	"time"

	"golang.org/x/sys/unix"
)

var ErrEndpointRecoveryApproval = errors.New("endpoint recovery requires independent ownership, quiescence, exact-plan authorization and audit")

const endpointRecoveryDomain = "syswarden/authority-endpoint-recovery/v1\x00"

// EndpointRecoveryConfig is trusted offline provisioning, never request data.
// ExpectedRecordSHA256 must be retained independently while the creator is known
// and attested. Hashing discovered stale bytes is not an acceptable trust source.
// Alternatively, PinDirectory supplies the server's separately protected durable
// pin. Exactly one source is required. The local pin is included in the review
// and retired only after the complete endpoint removal is synchronized.
// Peer supplies kernel credentials of the administrator's authenticated channel.
// The executor uses the service UID; the requester needs no protected file access.
type EndpointRecoveryConfig struct {
	Directory            *os.File
	PinDirectory         *os.File
	GroupID              uint32
	ExpectedRecordSHA256 string
	Peer                 *net.UnixConn
	Now                  func() time.Time
	Authorizer           EndpointRecoveryAuthorizer
}

type EndpointRecoveryPlan struct {
	Document []byte
	SHA256   string
}

type EndpointRecoveryRequest struct {
	Mode     string
	Plan     EndpointRecoveryPlan
	UID, GID uint32
	PID      int32
}

type EndpointRecoveryDecision struct {
	Mode, PlanSHA256, DecisionSHA256 string
	UID                              uint32
	NotBefore, NotAfter              int64
}

// EndpointRecoveryAuthorizer is distinct from operational policy grants and
// journal/policy recovery. It must authenticate the administrator, verify current
// scope and independent apply approval, and durably audit the complete plan and
// decision before returning. It must establish and maintain supervisor quiescence
// for the entire call: directory locks and refused connects alone cannot prove
// that an old service or accepted peer has stopped durable work. No permissive
// default, administrative route, MFA or production provider is supplied here.
// Callbacks must be bounded, concurrency-safe and must not reenter this lease.
type EndpointRecoveryAuthorizer interface {
	AuthorizeEndpointRecovery(EndpointRecoveryRequest) (EndpointRecoveryDecision, error)
}

// EndpointRecoveryResult identifies the external pre-mutation audit, not a
// replacement journal checkpoint or a credential. Any error returns a zero value.
type EndpointRecoveryResult struct {
	PlanSHA256, DecisionSHA256 string
}

type endpointRecoveryDocument struct {
	Schema       string               `json:"schema"`
	Operation    string               `json:"operation"`
	RecordSHA256 string               `json:"record_sha256"`
	Record       json.RawMessage      `json:"record"`
	Directory    recoveryResource     `json:"directory"`
	Socket       recoveryResource     `json:"socket"`
	RecordFile   recoveryResource     `json:"record_file"`
	Pin          *endpointRecoveryPin `json:"pin,omitempty"`
	UID          string               `json:"actor_uid"`
	GID          string               `json:"actor_gid"`
	PID          string               `json:"actor_pid"`
}

type endpointRecoveryPin struct {
	Directory recoveryResource `json:"directory"`
	File      recoveryResource `json:"file"`
	SHA256    string           `json:"sha256"`
}

// The attestation adapter owns no socket and must never use authoritySocket.Close:
// that method belongs exclusively to a live creator's lifecycle.
type endpointRecoveryLease struct {
	s        authoritySocket
	config   EndpointRecoveryConfig
	peer     unix.Ucred
	last     time.Time
	decision *EndpointRecoveryDecision
}

func (l *endpointRecoveryLease) close() error {
	err := l.s.pin.close()
	if l.s.recordFile != nil {
		err = errors.Join(err, l.s.recordFile.Close())
	}
	if l.s.directory != nil {
		err = errors.Join(err, l.s.directory.Close())
	}
	return err
}

func openEndpointRecovery(c EndpointRecoveryConfig) (_ *endpointRecoveryLease, err error) {
	if c.Directory == nil || c.GroupID > math.MaxInt32 || c.Now == nil || c.Authorizer == nil ||
		(c.PinDirectory == nil && !validRecoveryApproval(c.ExpectedRecordSHA256)) || (c.PinDirectory != nil && c.ExpectedRecordSHA256 != "") {
		return nil, ErrEndpointRecoveryApproval
	}
	l := &endpointRecoveryLease{config: c}
	defer func() {
		if err != nil {
			err = errors.Join(err, l.close())
		}
	}()
	if err = l.guard(); err != nil {
		return nil, err
	}
	if c.PinDirectory != nil {
		l.s.pin, err = readEndpointPin(c.PinDirectory)
		if err != nil {
			return nil, err
		}
		l.config.ExpectedRecordSHA256 = recoveryDigest(l.s.pin.record)
	}
	raw, err := c.Directory.SyscallConn()
	if err != nil {
		return nil, err
	}
	fd := -1
	var openErr error
	err = raw.Control(func(parent uintptr) {
		fd, openErr = unix.Openat(int(parent), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	})
	if err != nil || openErr != nil {
		return nil, errors.Join(ErrAuthorityEndpoint, err, openErr)
	}
	s := &l.s
	s.directory = os.NewFile(uintptr(fd), "endpoint-recovery-directory")
	s.dirStamp, err = authoritySocketDirectory(s.directory, c.GroupID)
	if err != nil {
		return nil, err
	}
	if err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return nil, errors.Join(ErrLocked, err)
	}
	s.path = "/proc/self/fd/" + strconv.Itoa(fd) + "/" + AuthoritySocketName
	if err = unix.Fstatat(fd, AuthoritySocketName, &s.entry, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return nil, errors.Join(ErrAuthorityEndpoint, err)
	}
	s.bound = true // Attestation only; never ownership or cleanup authorization.
	if err = s.attestSocketLocked(); err != nil {
		return nil, err
	}
	recordFD, err := unix.Openat(fd, AuthorityEndpointRecordName, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK|unix.O_NOCTTY, 0)
	if err != nil {
		return nil, errors.Join(ErrAuthorityEndpoint, err)
	}
	s.recordFile = diskFile{os.NewFile(uintptr(recordFD), "endpoint-recovery-owner")}
	s.recordStamp, err = s.endpointRecordStamp()
	if err != nil || s.recordStamp.Size <= 0 {
		return nil, errors.Join(ErrAuthorityEndpoint, err)
	}
	s.record = make([]byte, int(s.recordStamp.Size))
	n, err := s.recordFile.ReadAt(s.record, 0)
	if err != nil || n != len(s.record) || recoveryDigest(s.record) != l.config.ExpectedRecordSHA256 {
		return nil, errors.Join(ErrAuthorityEndpoint, err)
	}
	var record endpointOwnershipRecord
	if err = json.Unmarshal(s.record, &record); err != nil || !validRecoveryApproval(record.Nonce) {
		return nil, errors.Join(ErrAuthorityEndpoint, err)
	}
	expected, err := encodeEndpointRecord(s.dirStamp, s.entry, record.Nonce)
	if err != nil || !bytes.Equal(s.record, expected) {
		return nil, errors.Join(ErrAuthorityEndpoint, err)
	}
	s.recordReady = true
	if err = l.attest(); err != nil {
		return nil, err
	}
	return l, nil
}

func (l *endpointRecoveryLease) guard() error {
	now := l.config.Now().Round(0)
	if now.IsZero() || now.Unix() <= 0 || now.Unix() > maxPolicyTime || (!l.last.IsZero() && now.Before(l.last)) {
		return ErrEndpointRecoveryApproval
	}
	peer, err := custodyPeer(l.config.Peer)
	if err != nil || (!l.last.IsZero() && peer != l.peer) {
		return errors.Join(ErrEndpointRecoveryApproval, err)
	}
	if l.decision != nil && (now.Unix() < l.decision.NotBefore || now.Unix() >= l.decision.NotAfter) {
		return ErrEndpointRecoveryApproval
	}
	l.peer, l.last = peer, now
	return nil
}

func (l *endpointRecoveryLease) attest() error {
	if err := l.guard(); err != nil {
		return err
	}
	if err := l.s.attestLocked(); err != nil {
		return err
	}
	// A nonblocking probe sends no application bytes. Only ECONNREFUSED is
	// eligible; a live listener, full backlog or indeterminate result is refused.
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	err = unix.Connect(fd, &unix.SockaddrUnix{Name: l.s.path})
	closeErr := unix.Close(fd)
	if !errors.Is(err, unix.ECONNREFUSED) || closeErr != nil {
		return errors.Join(ErrAuthorityEndpoint, err, closeErr)
	}
	return l.s.attestLocked()
}

func (l *endpointRecoveryLease) plan() (EndpointRecoveryPlan, error) {
	if err := l.attest(); err != nil {
		return EndpointRecoveryPlan{}, err
	}
	dir, err := authoritySocketDirectory(l.s.directory, l.config.GroupID)
	if err != nil {
		return EndpointRecoveryPlan{}, err
	}
	var pin *endpointRecoveryPin
	if p := l.s.pin; p != nil {
		var st unix.Stat_t
		if err = unix.Fstat(int(p.directory.Fd()), &st); err != nil {
			return EndpointRecoveryPlan{}, err
		}
		pin = &endpointRecoveryPin{Directory: bindRecoveryResource(st), File: bindRecoveryResource(p.stamp), SHA256: recoveryDigest(p.data)}
	}
	data, err := json.Marshal(endpointRecoveryDocument{
		Schema: "syswarden.authority-endpoint-recovery.v1", Operation: "retire-stale-endpoint",
		RecordSHA256: l.config.ExpectedRecordSHA256, Record: l.s.record,
		Directory: bindRecoveryResource(dir), Socket: bindRecoveryResource(l.s.entry), RecordFile: bindRecoveryResource(l.s.recordStamp),
		Pin: pin,
		UID: strconv.FormatUint(uint64(l.peer.Uid), 10), GID: strconv.FormatUint(uint64(l.peer.Gid), 10), PID: strconv.FormatInt(int64(l.peer.Pid), 10),
	})
	if err != nil {
		return EndpointRecoveryPlan{}, err
	}
	return EndpointRecoveryPlan{Document: data, SHA256: recoveryDigest(append([]byte(endpointRecoveryDomain), data...))}, nil
}

func (l *endpointRecoveryLease) authorize(mode string, plan EndpointRecoveryPlan) error {
	d, err := l.config.Authorizer.AuthorizeEndpointRecovery(EndpointRecoveryRequest{
		Mode: mode, Plan: EndpointRecoveryPlan{Document: bytes.Clone(plan.Document), SHA256: plan.SHA256}, UID: l.peer.Uid, GID: l.peer.Gid, PID: l.peer.Pid,
	})
	if err != nil || d.Mode != mode || d.PlanSHA256 != plan.SHA256 || d.UID != l.peer.Uid || !validRecoveryApproval(d.DecisionSHA256) || d.NotBefore <= 0 || d.NotAfter > maxPolicyTime || d.NotAfter <= d.NotBefore || d.NotAfter-d.NotBefore > MaxPolicyApprovalSeconds {
		return errors.Join(ErrEndpointRecoveryApproval, err)
	}
	l.decision = &d
	if err = l.guard(); err != nil {
		return err
	}
	after, err := l.plan()
	if err != nil || after.SHA256 != plan.SHA256 || !bytes.Equal(after.Document, plan.Document) {
		return errors.Join(ErrAuthorityEndpoint, err)
	}
	return nil
}

// PlanEndpointRecovery inspects only a complete, independently pinned pair. The
// returned digest identifies the review; it cannot replace apply authorization.
func PlanEndpointRecovery(c EndpointRecoveryConfig) (plan EndpointRecoveryPlan, err error) {
	l, err := openEndpointRecovery(c)
	if err != nil {
		return plan, err
	}
	defer func() {
		err = errors.Join(err, l.close())
		if err != nil {
			plan = EndpointRecoveryPlan{}
		}
	}()
	plan, err = l.plan()
	if err == nil {
		err = l.authorize("inspect", plan)
	}
	return plan, err
}

type endpointRecoveryOps struct {
	unlink func(int, string, int) error
	sync   func(*os.File) error
}

// ApplyEndpointRecovery reconstructs and independently authorizes the exact plan,
// removes only its socket and receipt, and synchronizes the directory. Partial
// removal or failed synchronization is uncertain, never automatically retried.
func ApplyEndpointRecovery(c EndpointRecoveryConfig, approvedSHA256 string) (EndpointRecoveryResult, error) {
	return applyEndpointRecovery(c, approvedSHA256, endpointRecoveryOps{unlink: unix.Unlinkat, sync: (*os.File).Sync})
}

func applyEndpointRecovery(c EndpointRecoveryConfig, approved string, ops endpointRecoveryOps) (result EndpointRecoveryResult, err error) {
	if !validRecoveryApproval(approved) {
		return result, ErrEndpointRecoveryApproval
	}
	l, err := openEndpointRecovery(c)
	if err != nil {
		return result, err
	}
	mutated := false
	defer func() {
		if mutated {
			err = errors.Join(err, ops.sync(l.s.directory), l.guard())
			if err == nil {
				dir, checkErr := authoritySocketDirectory(l.s.directory, c.GroupID)
				if checkErr != nil || dir.Dev != l.s.dirStamp.Dev || dir.Ino != l.s.dirStamp.Ino {
					err = errors.Join(ErrAuthorityEndpoint, checkErr)
				}
				err = errors.Join(err, endpointAbsent(int(l.s.directory.Fd()), AuthoritySocketName), endpointAbsent(int(l.s.directory.Fd()), AuthorityEndpointRecordName))
			}
			if err == nil {
				err = errors.Join(l.s.pin.retire(ops), l.guard())
			}
		}
		err = errors.Join(err, l.close())
		if err != nil {
			result = EndpointRecoveryResult{}
			if mutated {
				err = errors.Join(ErrCommitUncertain, err)
			}
		}
	}()
	plan, err := l.plan()
	if err != nil || plan.SHA256 != approved {
		return result, errors.Join(ErrEndpointRecoveryApproval, err)
	}
	if err = l.authorize("apply", plan); err != nil {
		return result, err
	}
	fd := int(l.s.directory.Fd())
	mutated = true // Once attempted, an I/O error must not imply a known outcome.
	if err = ops.unlink(fd, AuthoritySocketName, 0); err != nil {
		return result, err
	}
	// Removing a directory entry changes directory timestamps. Recheck identity,
	// protections and exact remaining receipt, not the obsolete pre-unlink plan.
	dir, err := authoritySocketDirectory(l.s.directory, c.GroupID)
	if err != nil || dir.Dev != l.s.dirStamp.Dev || dir.Ino != l.s.dirStamp.Ino {
		return result, errors.Join(ErrAuthorityEndpoint, err)
	}
	if err = errors.Join(l.guard(), l.s.attestEndpointRecord(), l.s.pin.attest(), endpointAbsent(fd, AuthoritySocketName)); err != nil {
		return result, err
	}
	if err = ops.unlink(fd, AuthorityEndpointRecordName, 0); err != nil {
		return result, err
	}
	if err = errors.Join(endpointAbsent(fd, AuthoritySocketName), endpointAbsent(fd, AuthorityEndpointRecordName), l.guard()); err != nil {
		return result, err
	}
	return EndpointRecoveryResult{PlanSHA256: plan.SHA256, DecisionSHA256: l.decision.DecisionSHA256}, nil
}

func endpointAbsent(fd int, name string) error {
	var st unix.Stat_t
	err := unix.Fstatat(fd, name, &st, unix.AT_SYMLINK_NOFOLLOW)
	if !errors.Is(err, unix.ENOENT) {
		return errors.Join(ErrAuthorityEndpoint, err)
	}
	return nil
}
