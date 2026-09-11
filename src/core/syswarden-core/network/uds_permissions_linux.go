package network

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/user"
	"strconv"

	"golang.org/x/sys/unix"
)

func resolveUDSProducerIdentity(ownerUID, ownerGID int, lookupUser func(string) (*user.User, error), lookupGroup func(string) (*user.Group, error)) (udsProducerIdentity, error) {
	if ownerUID < 0 || uint64(ownerUID) >= 1<<32-1 || ownerGID < 0 || uint64(ownerGID) >= 1<<32-1 {
		return udsProducerIdentity{}, fmt.Errorf("invalid socket owner identity")
	}
	identity := udsProducerIdentity{group: ownerGID, uids: []uint32{uint32(ownerUID)}} // #nosec G115 -- UID is bounded to the Linux uint32 range above
	if ownerUID != 0 {
		return identity, nil
	}
	account, err := lookupUser("syslog")
	if err != nil {
		var absent user.UnknownUserError
		if errors.As(err, &absent) {
			return identity, nil
		}
		return identity, fmt.Errorf("resolve rsyslog producer account: %w", err)
	}
	group, err := lookupGroup("syslog")
	if err != nil {
		return identity, fmt.Errorf("resolve rsyslog producer group: %w", err)
	}
	if account == nil || group == nil || account.Username != "syslog" || group.Name != "syslog" || account.Gid != group.Gid {
		return identity, fmt.Errorf("rsyslog producer identity does not match its private group")
	}
	uid, uidErr := strconv.ParseUint(account.Uid, 10, 32)
	gid, gidErr := strconv.ParseUint(group.Gid, 10, 32)
	if uidErr != nil || gidErr != nil || uid == 0 || gid == 0 || uid == 1<<32-1 || gid == 1<<32-1 ||
		strconv.FormatUint(uid, 10) != account.Uid || strconv.FormatUint(gid, 10) != group.Gid {
		return identity, fmt.Errorf("invalid rsyslog producer UID or GID")
	}
	identity.group = int(gid)                          // #nosec G115 -- supported Linux builds use 64-bit int and ParseUint bounds GID to 32 bits
	identity.uids = append(identity.uids, uint32(uid)) // #nosec G115 -- ParseUint above bounds UID to 32 bits
	return identity, nil
}

func configureUDSProducerAccess(conn *net.UnixConn, path string) (udsProducerIdentity, error) {
	identity, err := resolveUDSProducerIdentity(os.Geteuid(), os.Getegid(), user.Lookup, user.LookupGroup)
	if err != nil {
		return identity, err
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		return identity, err
	}
	var credentialErr error
	if err := raw.Control(func(fd uintptr) {
		credentialErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_PASSCRED, 1)
	}); err != nil {
		return identity, err
	}
	if credentialErr != nil {
		return identity, fmt.Errorf("require kernel UDS sender credentials: %w", credentialErr)
	}
	if os.Geteuid() == 0 {
		if err := os.Chown(path, 0, identity.group); err != nil {
			return identity, fmt.Errorf("set private UDS producer group: %w", err)
		}
	}
	if err := os.Chmod(path, 0660); err != nil { // #nosec G302 -- only the logging group can write; every datagram additionally requires an authorized kernel UID
		return identity, fmt.Errorf("set private UDS permissions: %w", err)
	}
	return identity, nil
}

func newUDSCredentialsBuffer() []byte {
	return make([]byte, unix.CmsgSpace(unix.SizeofUcred))
}

func authorizedUDSCredentials(control []byte, flags int, allowed []uint32) bool {
	if flags&unix.MSG_CTRUNC != 0 {
		return false
	}
	messages, err := unix.ParseSocketControlMessage(control)
	if err != nil || len(messages) != 1 {
		return false
	}
	credentials, err := unix.ParseUnixCredentials(&messages[0])
	if err != nil || credentials.Pid <= 0 {
		return false
	}
	for _, uid := range allowed {
		if credentials.Uid == uid {
			return true
		}
	}
	return false
}
