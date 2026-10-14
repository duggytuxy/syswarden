package journal

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"os"
	"strconv"
	"time"

	"golang.org/x/sys/unix"
	contracts "syswarden-core/contracts/v5"
)

const AuthorityLaunchSchema = "syswarden.authority-launch.v1"
const MaxAuthorityLaunchBytes = 8192

var ErrAuthorityLaunch = errors.New("invalid protected authority launch configuration")

// AuthorityLaunch is offline provisioning, never an operation or request. Its
// encoding authenticates nothing by itself. A trusted launcher separately pins
// the exact digest and passes a protected descriptor to the service process.
// This contains public trust only; no private key or approval provider is encoded.
type AuthorityLaunch struct {
	ServiceUID, ServiceGID, EndpointGID uint32
	PolicyRoot                          CustodyPolicyTrust
	Enrollment                          CustodyEnrollment
	Limits                              Limits
	Transport                           AuthorityTransportLimits
	AcceptInterval                      time.Duration
}

type launchPolicyWire struct {
	Enabled   bool   `json:"enabled"`
	PolicyID  string `json:"policy_id"`
	Revision  string `json:"revision"`
	SHA256    string `json:"sha256"`
	IssuerID  string `json:"issuer_id"`
	IssuerKey string `json:"issuer_key"`
}
type launchLimitsWire struct {
	Bytes       string `json:"segment_bytes"`
	Frames      string `json:"segment_frames"`
	Peers       string `json:"peers"`
	PeersPerUID string `json:"peers_per_uid"`
	ReadNS      string `json:"read_timeout_ns"`
	WriteNS     string `json:"write_timeout_ns"`
	Requests    string `json:"requests_per_uid"`
	RateUIDs    string `json:"rate_uids"`
	WindowNS    string `json:"rate_window_ns"`
	AcceptNS    string `json:"accept_interval_ns"`
}
type authorityLaunchWire struct {
	Schema      string           `json:"schema"`
	UID         string           `json:"service_uid"`
	GID         string           `json:"service_gid"`
	EndpointGID string           `json:"endpoint_gid"`
	Policy      launchPolicyWire `json:"policy_root"`
	Enrollment  custodyStateWire `json:"enrollment"`
	Limits      launchLimitsWire `json:"limits"`
}

// EncodeAuthorityLaunch returns owned canonical bytes for separately authorized
// provisioning. It grants no access, writes no file and discovers no trust.
func EncodeAuthorityLaunch(c AuthorityLaunch) ([]byte, error) {
	s, err := custodyEnrollment(c.Enrollment)
	if err != nil || !validPolicyRoot(c.PolicyRoot) || c.PolicyRoot.Initial != c.Enrollment.Initial || bytes.Equal(c.PolicyRoot.IssuerPublicKey, c.Enrollment.Authority.PublicKey) ||
		c.ServiceUID == 0 || c.ServiceUID > math.MaxInt32 || c.ServiceGID == 0 || c.ServiceGID > math.MaxInt32 || c.EndpointGID == 0 || c.EndpointGID > math.MaxInt32 ||
		!validAuthorityTransportLimits(c.Transport) || c.AcceptInterval < MinAuthorityAcceptInterval || c.AcceptInterval > MaxAuthorityAcceptInterval {
		return nil, ErrAuthorityLaunch
	}
	if _, err := contracts.ScanEventJournal(nil, contracts.JournalReadContext{Start: c.Enrollment.Initial.Cursor, MaxBytes: c.Limits.MaxBytes, MaxFrames: c.Limits.MaxFrames}); err != nil {
		return nil, ErrAuthorityLaunch
	}
	enrollment, err := custodyWire(s)
	if err != nil {
		return nil, ErrAuthorityLaunch
	}
	t, p := c.Transport, c.PolicyRoot
	w := authorityLaunchWire{Schema: AuthorityLaunchSchema, UID: strconv.FormatUint(uint64(c.ServiceUID), 10), GID: strconv.FormatUint(uint64(c.ServiceGID), 10), EndpointGID: strconv.FormatUint(uint64(c.EndpointGID), 10),
		Policy: launchPolicyWire{p.Enabled, p.PolicyID, strconv.FormatUint(p.Revision, 10), p.PolicySHA256, p.IssuerKeyID, hex.EncodeToString(p.IssuerPublicKey)}, Enrollment: enrollment,
		Limits: launchLimitsWire{strconv.Itoa(c.Limits.MaxBytes), strconv.Itoa(c.Limits.MaxFrames), strconv.Itoa(t.MaxPeers), strconv.Itoa(t.MaxPeersPerUID), strconv.FormatInt(int64(t.ReadTimeout), 10), strconv.FormatInt(int64(t.WriteTimeout), 10), strconv.Itoa(t.RequestsPerUID), strconv.Itoa(t.MaxRateUIDs), strconv.FormatInt(int64(t.RateWindow), 10), strconv.FormatInt(int64(c.AcceptInterval), 10)}}
	data, err := json.Marshal(w)
	if err != nil || len(data) > MaxAuthorityLaunchBytes {
		return nil, ErrAuthorityLaunch
	}
	return data, nil
}

// DecodeAuthorityLaunch rejects duplicate, unknown, missing, null, alternate and
// noncanonical fields by exact re-encoding after bounded semantic validation.
func DecodeAuthorityLaunch(data []byte) (AuthorityLaunch, error) {
	var c AuthorityLaunch
	if len(data) == 0 || len(data) > MaxAuthorityLaunchBytes {
		return c, ErrAuthorityLaunch
	}
	var w authorityLaunchWire
	if json.Unmarshal(data, &w) != nil || w.Schema != AuthorityLaunchSchema {
		return c, ErrAuthorityLaunch
	}
	state, err := custodyStateFromWire(w.Enrollment)
	if err != nil || state.Head != state.Initial || state.Pending != (CustodyIntent{}) {
		return c, ErrAuthorityLaunch
	}
	var bad bool
	readID := func(s string) uint32 {
		n, err := strconv.ParseUint(s, 10, 31)
		if err != nil || n == 0 || strconv.FormatUint(n, 10) != s {
			bad = true
			return 0
		}
		return uint32(n)
	}
	readInt := func(s string) int {
		n, err := strconv.Atoi(s)
		if err != nil || n <= 0 || strconv.Itoa(n) != s {
			bad = true
			return 0
		}
		return n
	}
	readDuration := func(s string) time.Duration {
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil || n <= 0 || strconv.FormatInt(n, 10) != s {
			bad = true
			return 0
		}
		return time.Duration(n)
	}
	c.ServiceUID = readID(w.UID)
	c.ServiceGID = readID(w.GID)
	c.EndpointGID = readID(w.EndpointGID)
	revision, err := custodyUint(w.Policy.Revision, math.MaxUint64-1)
	if err != nil {
		return AuthorityLaunch{}, ErrAuthorityLaunch
	}
	pub, err := hex.DecodeString(w.Policy.IssuerKey)
	if err != nil {
		return AuthorityLaunch{}, ErrAuthorityLaunch
	}
	c.PolicyRoot = CustodyPolicyTrust{Enabled: w.Policy.Enabled, PolicyID: w.Policy.PolicyID, Revision: revision, PolicySHA256: w.Policy.SHA256, IssuerKeyID: w.Policy.IssuerID, IssuerPublicKey: pub, Initial: state.Initial}
	c.Enrollment = CustodyEnrollment{Initial: state.Initial, Authority: state.Authority}
	b := w.Limits
	c.Limits = Limits{MaxBytes: readInt(b.Bytes), MaxFrames: readInt(b.Frames)}
	c.Transport = AuthorityTransportLimits{MaxPeers: readInt(b.Peers), MaxPeersPerUID: readInt(b.PeersPerUID), ReadTimeout: readDuration(b.ReadNS), WriteTimeout: readDuration(b.WriteNS), RequestsPerUID: readInt(b.Requests), MaxRateUIDs: readInt(b.RateUIDs), RateWindow: readDuration(b.WindowNS)}
	c.AcceptInterval = readDuration(b.AcceptNS)
	if bad {
		return AuthorityLaunch{}, ErrAuthorityLaunch
	}
	encoded, err := EncodeAuthorityLaunch(c)
	if err != nil || !bytes.Equal(data, encoded) {
		return AuthorityLaunch{}, ErrAuthorityLaunch
	}
	return c, nil
}

// LoadAuthorityLaunch reads one explicitly supplied root-owned 0400 regular
// file through its descriptor, using an independent expected lowercase digest.
// It requires a read-only descriptor, one link and no ACL, bounds allocation
// before reading, checks exact metadata again afterwards, and changes no offset.
// Caller retains the file. It performs no pathname discovery or mutation. Root
// provisioning, digest provenance and the host user namespace remain trusted.
func LoadAuthorityLaunch(file *os.File, expectedSHA256 string) (AuthorityLaunch, error) {
	if file == nil || !validRecoveryApproval(expectedSHA256) {
		return AuthorityLaunch{}, ErrAuthorityLaunch
	}
	raw, err := file.SyscallConn()
	if err != nil {
		return AuthorityLaunch{}, ErrAuthorityLaunch
	}
	var data []byte
	var readErr error
	err = raw.Control(func(fd uintptr) {
		var before, after unix.Stat_t
		flags, e := unix.FcntlInt(fd, unix.F_GETFL, 0)
		if e != nil || flags&unix.O_ACCMODE != unix.O_RDONLY {
			readErr = ErrAuthorityLaunch
			return
		}
		if e = unix.Fstat(int(fd), &before); e != nil || before.Mode&(unix.S_IFMT|07777) != unix.S_IFREG|0400 || before.Uid != 0 || before.Gid != 0 || before.Nlink != 1 || before.Size <= 0 || before.Size > MaxAuthorityLaunchBytes {
			readErr = ErrAuthorityLaunch
			return
		}
		if e = noAuthorityACL(func(name string) (int, error) { return unix.Fgetxattr(int(fd), name, nil) }); e != nil {
			readErr = ErrAuthorityLaunch
			return
		}
		data = make([]byte, int(before.Size)+1)
		var n int
		n, e = unix.Pread(int(fd), data, 0)
		if e != nil || n != int(before.Size) {
			readErr = ErrAuthorityLaunch
			return
		}
		data = data[:n]
		if e = unix.Fstat(int(fd), &after); e != nil || !sameStamp(before, after) {
			readErr = ErrAuthorityLaunch
			return
		}
	})
	if err != nil || readErr != nil || recoveryDigest(data) != expectedSHA256 {
		return AuthorityLaunch{}, ErrAuthorityLaunch
	}
	return DecodeAuthorityLaunch(data)
}

// OpenAuthorityFromLaunch reads trusted startup data, binds the effective service
// UID/GID, then opens the existing protected layout. Approval callbacks and clock
// remain explicit trusted Go inputs; nil callbacks retain independent denial.
// State and endpoint descriptors still come from trusted provisioning, not JSON.
func OpenAuthorityFromLaunch(file *os.File, digest string, state, endpoint *os.File, now func() time.Time, recovery CustodyRecoveryAuthorizer, admin PolicyAdministrationAuthorizer) (*LocalAuthorityServer, error) {
	c, err := LoadAuthorityLaunch(file, digest)
	if err != nil || int64(c.ServiceUID) != int64(os.Geteuid()) || int64(c.ServiceGID) != int64(os.Getegid()) {
		return nil, ErrAuthorityLaunch
	}
	return OpenProvisionedAuthorityServer(state, AuthorityServerConfig{Authority: LocalAuthorityConfig{PolicyRoot: c.PolicyRoot, Enrollment: c.Enrollment, Limits: c.Limits, Now: now, RecoveryAuthorizer: recovery, PolicyAdministrator: admin}, Transport: c.Transport, Directory: endpoint, GroupID: c.EndpointGID, AcceptInterval: c.AcceptInterval})
}
