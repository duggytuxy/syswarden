package journal

import (
	"errors"
	"math"
	"net"
	"time"

	"golang.org/x/sys/unix"
)

// CustodyAdmission is a point-in-time, owned admission result for one connection
// and high-level operation. It is not a bearer credential, custody lease, recovery
// approval or durable audit. Do not accept a serialized result from any client.
// Peer PID/GID are diagnostic kernel observations, never authorization inputs.
type CustodyAdmission struct {
	Enrollment             CustodyEnrollment
	PolicyID, PolicySHA256 string
	Revision               uint64
	Operation              CustodyOperation
	UID, GID               uint32
	PID                    int32
	NotAfter               int64
}

func custodyPeer(conn *net.UnixConn) (unix.Ucred, error) {
	if conn == nil {
		return unix.Ucred{}, ErrCustodyAdmission
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		return unix.Ucred{}, errors.Join(ErrCustodyAdmission, err)
	}
	var cred *unix.Ucred
	var peerErr error
	err = raw.Control(func(fd uintptr) {
		var kind int
		kind, peerErr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_TYPE)
		if peerErr != nil || kind != unix.SOCK_STREAM {
			peerErr = errors.Join(ErrCustodyAdmission, peerErr)
			return
		}
		// Getpeername rejects unconnected/listening sockets before SO_PEERCRED.
		var peer unix.Sockaddr
		peer, peerErr = unix.Getpeername(int(fd))
		if peerErr != nil {
			return
		}
		if _, ok := peer.(*unix.SockaddrUnix); !ok {
			peerErr = ErrCustodyAdmission
			return
		}
		cred, peerErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	})
	if err != nil || peerErr != nil || cred == nil || cred.Pid <= 0 || cred.Uid == math.MaxUint32 || cred.Gid == math.MaxUint32 {
		return unix.Ucred{}, errors.Join(ErrCustodyAdmission, err, peerErr)
	}
	return *cred, nil
}

// AdmitLocalCustody verifies current policy, then reads credentials directly from
// the accepted connected Linux Unix stream socket. It neither reads request bytes
// nor owns/closes the socket. Usernames, request UID fields and bearer tokens are
// not inputs. Call in the authority process for each operation under its policy
// lease, before any journal access. Root needs an explicit grant like every UID.
// SO_PEERCRED identifies the peer at connection creation, not every subsequent
// sender after descriptor delegation. Service isolation must prevent untrusted
// delegation and same-UID access to authority storage. This helper does not
// establish that isolation, create a listener or activate the coordinator.
// Apply admission still requires the coordinator's independent exact-plan
// recovery authorization and durable audit. A grant cannot bypass them.
func AdmitLocalCustody(conn *net.UnixConn, data, signature []byte, trust CustodyPolicyTrust, now time.Time, operation CustodyOperation) (CustodyAdmission, error) {
	if !custodyOperation(operation) {
		return CustodyAdmission{}, ErrCustodyAdmission
	}
	p, err := VerifyCustodyAccessPolicy(data, signature, trust, now)
	if err != nil {
		return CustodyAdmission{}, err
	}
	peer, err := custodyPeer(conn)
	if err != nil {
		return CustodyAdmission{}, err
	}
	for _, grant := range p.Grants {
		if grant.UID != peer.Uid {
			continue
		}
		for _, op := range grant.Operations {
			if op == operation {
				return CustodyAdmission{Enrollment: p.Enrollment, PolicyID: p.PolicyID, PolicySHA256: trust.PolicySHA256,
					Revision: p.Revision, Operation: op, UID: peer.Uid, GID: peer.Gid, PID: peer.Pid, NotAfter: p.NotAfter}, nil
			}
		}
	}
	return CustodyAdmission{}, ErrCustodyAdmission
}
