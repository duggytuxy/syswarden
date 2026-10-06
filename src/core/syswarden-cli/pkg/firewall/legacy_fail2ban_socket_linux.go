//go:build linux

package firewall

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// The peer identity must come from an independent service/process attestation.
// A root-owned socket or a product-looking jail name does not prove provenance.
// The guard must reattest the process start time, executable, configuration
// entry points and removal barrier. Queries never authorize runtime mutation.
type legacyFail2banReadOnlySocket struct {
	host  nftPersistenceFilesystem
	path  string
	peer  syscall.Ucred
	guard func() error
}

func (client legacyFail2banReadOnlySocket) query(ctx context.Context, query []string) (legacyFail2banValue, error) {
	var empty legacyFail2banValue
	request, err := encodeLegacyFail2banQuery(query)
	if err != nil {
		return empty, err
	}
	return exchangeLegacyFail2banSocket(ctx, client, request)
}

// Only the read-only query encoder and the narrowly bounded retirement
// encoder may supply requests. Peer, path and caller guards are repeated
// immediately before sending and after receiving any response.
func exchangeLegacyFail2banSocket(ctx context.Context, client legacyFail2banReadOnlySocket, request []byte) (legacyFail2banValue, error) {
	var empty legacyFail2banValue
	deadline, bounded := ctx.Deadline()
	if !bounded || time.Until(deadline) > 30*time.Second || client.guard == nil || client.peer.Pid <= 0 ||
		client.peer.Uid != client.host.expectedUID || client.peer.Gid != client.host.expectedGID || !canonicalNFTPersistencePath(client.path, false) {
		return empty, fmt.Errorf("Fail2ban exchange lacks bounded peer and service evidence")
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	if err := client.guard(); err != nil {
		return empty, err
	}
	directory, err := client.host.openDirectory(filepath.Dir(client.path))
	if err != nil {
		return empty, err
	}
	defer func() { _ = directory.Close() }()
	parentIdentity, err := directory.Stat(".")
	if err != nil {
		return empty, err
	}
	name := filepath.Base(client.path)
	before, err := directory.Lstat(name)
	if err != nil {
		return empty, fmt.Errorf("inspect Fail2ban control socket: %w", err)
	}
	stat, ok := before.Sys().(*syscall.Stat_t)
	if !ok || before.Mode().Type() != os.ModeSocket || before.Mode().Perm()&0022 != 0 ||
		stat.Uid != client.peer.Uid || stat.Gid != client.peer.Gid || stat.Nlink != 1 {
		return empty, fmt.Errorf("Fail2ban control socket has unsafe metadata")
	}
	parent, err := directory.Open(".")
	if err != nil {
		return empty, err
	}
	defer func() { _ = parent.Close() }()
	// Dial through the pinned parent descriptor. Reattest the logical parent
	// afterwards as well, so moving a directory cannot substitute a detached
	// socket for the current service entry point.
	address := fmt.Sprintf("/proc/self/fd/%d/%s", parent.Fd(), name)
	dialer := net.Dialer{}
	connection, err := dialer.DialContext(ctx, "unix", address)
	if err != nil {
		return empty, fmt.Errorf("connect to attested Fail2ban control socket: %w", err)
	}
	defer func() { _ = connection.Close() }()
	unix, ok := connection.(*net.UnixConn)
	if !ok {
		return empty, fmt.Errorf("Fail2ban control connection is not a Unix socket")
	}
	if err := unix.SetDeadline(deadline); err != nil {
		return empty, err
	}
	raw, err := unix.SyscallConn()
	if err != nil {
		return empty, err
	}
	var peer *syscall.Ucred
	var peerErr error
	if err := raw.Control(func(fd uintptr) {
		peer, peerErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return empty, err
	}
	if peerErr != nil || peer == nil || *peer != client.peer {
		return empty, fmt.Errorf("Fail2ban control socket peer differs from the attested process")
	}
	reattest := func() error {
		current, err := client.host.openDirectory(filepath.Dir(client.path))
		if err != nil {
			return err
		}
		defer func() { _ = current.Close() }()
		currentIdentity, err := current.Stat(".")
		if err != nil || !sameNFTPersistenceIdentity(parentIdentity, currentIdentity) {
			return fmt.Errorf("Fail2ban socket parent changed during inspection")
		}
		named, err := current.Lstat(name)
		if err != nil || !sameNFTPersistenceIdentity(before, named) {
			return fmt.Errorf("Fail2ban control socket changed during inspection")
		}
		return client.guard()
	}
	if err := reattest(); err != nil {
		return empty, err
	}
	n, err := unix.Write(request)
	if err != nil || n != len(request) {
		return empty, fmt.Errorf("Fail2ban request could not be sent completely; inspect its durable intent before retrying")
	}
	var reply bytes.Buffer
	var chunk [4096]byte
	for reply.Len() <= maximumLegacyFail2banReply+len(legacyFail2banEnd) {
		searchStart := max(0, reply.Len()-len(legacyFail2banEnd)+1)
		n, err := unix.Read(chunk[:])
		if n > 0 {
			_, _ = reply.Write(chunk[:n])
		}
		if relativeEnd := bytes.Index(reply.Bytes()[searchStart:], []byte(legacyFail2banEnd)); relativeEnd >= 0 {
			end := searchStart + relativeEnd
			if reply.Len() != end+len(legacyFail2banEnd) || end > maximumLegacyFail2banReply {
				return empty, fmt.Errorf("Fail2ban response has trailing data or exceeds its limit")
			}
			value, decodeErr := decodeLegacyFail2banReply(reply.Bytes()[:end])
			if decodeErr != nil {
				return empty, decodeErr
			}
			if err := reattest(); err != nil {
				return empty, err
			}
			if err := ctx.Err(); err != nil {
				return empty, err
			}
			return value, nil
		}
		if err != nil {
			if err == io.EOF {
				return empty, fmt.Errorf("incomplete Fail2ban response before socket close")
			}
			return empty, fmt.Errorf("Fail2ban response unavailable within its deadline")
		}
	}
	return empty, fmt.Errorf("Fail2ban response exceeds its limit")
}
