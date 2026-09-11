package system

import (
	"fmt"
	"os"
	"os/user"
	"strconv"
)

// The core grants its logging socket to the canonical syslog private group.
// Keep the parent directory and the separate control socket root:root. Legacy
// root:root sockets and absent sockets need no logging-account lookup.
func removePackageRuntimeSocketAt(path string, uid, gid uint32) error {
	if path != "/run/syswarden.sock" {
		return removeExactRuntimeSocketAt(path, uid, gid)
	}
	return removeExactRuntimeSocketWithPrivateGroupAt(path, uid, gid, func() (uint32, error) {
		return resolveRemovalSyslogGroup(user.Lookup, user.LookupGroup)
	})
}

func resolveRemovalSyslogGroup(lookupUser func(string) (*user.User, error), lookupGroup func(string) (*user.Group, error)) (uint32, error) {
	account, err := lookupUser("syslog")
	if err != nil {
		return 0, fmt.Errorf("resolve runtime socket producer account: %w", err)
	}
	group, err := lookupGroup("syslog")
	if err != nil {
		return 0, fmt.Errorf("resolve runtime socket producer group: %w", err)
	}
	if account == nil || group == nil || account.Username != "syslog" || group.Name != "syslog" || account.Gid != group.Gid {
		return 0, fmt.Errorf("runtime socket producer does not match its private group")
	}
	uid, uidErr := strconv.ParseUint(account.Uid, 10, 32)
	gid, gidErr := strconv.ParseUint(group.Gid, 10, 32)
	if uidErr != nil || gidErr != nil || uid == 0 || gid == 0 || uid == 1<<32-1 || gid == 1<<32-1 ||
		strconv.FormatUint(uid, 10) != account.Uid || strconv.FormatUint(gid, 10) != group.Gid {
		return 0, fmt.Errorf("invalid runtime socket producer UID or GID")
	}
	return uint32(gid), nil // #nosec G115 -- ParseUint above bounds the canonical nonzero GID to 32 bits
}

func attestRuntimeSocketIdentity(info os.FileInfo, uid, gid uint32, privateGroup func() (uint32, error)) (removalArtifactIdentity, error) {
	identity, err := exactRemovalArtifactIdentity(info)
	if err != nil {
		return identity, err
	}
	if info.Mode()&os.ModeType != os.ModeSocket || identity.uid != uid || identity.nlink != 1 {
		return identity, fmt.Errorf("runtime target is not an owned single-link Unix socket")
	}
	if identity.gid == gid {
		return identity, nil
	}
	if privateGroup == nil || info.Mode() != os.ModeSocket|0660 {
		return identity, fmt.Errorf("runtime socket has an unexpected group or mode")
	}
	producerGID, err := privateGroup()
	if err != nil {
		return identity, fmt.Errorf("verify private runtime socket producer group: %w", err)
	}
	if producerGID == 0 || identity.gid != producerGID {
		return identity, fmt.Errorf("runtime socket does not match the verified private producer group")
	}
	return identity, nil
}
