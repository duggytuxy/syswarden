//go:build linux

package sshpolicy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const maxSSHProcessFDs = 4096
const maxSSHProcessSockets = 256

// These raw observations stay private. A duplicated descriptor is closed before
// any manager query and never used for socket I/O or changing shared flags.
type sshListenerSocket struct {
	FD            int
	Device        uint64
	Inode         uint64
	Cookie        uint64
	NetNSCookie   uint64
	Family        int
	Address       netip.Addr
	Port          uint16
	Zone          uint32
	V6Only        bool
	DeviceBinding string
}

func validSSHListenerSocket(s sshListenerSocket) bool {
	if s.FD < 0 || s.FD > 1<<31-1 || s.Inode == 0 || s.Cookie == 0 || s.NetNSCookie == 0 ||
		!s.Address.IsValid() || s.Address.Zone() != "" || s.Port == 0 || len(s.DeviceBinding) >= unix.IFNAMSIZ {
		return false
	}
	return (s.Family == unix.AF_INET && s.Address.Is4() && s.Zone == 0 && !s.V6Only) ||
		(s.Family == unix.AF_INET6 && s.Address.Is6())
}

func sshSocketLink(value string) (uint64, bool, error) {
	if !strings.HasPrefix(value, "socket:") {
		return 0, false, nil
	}
	if !strings.HasPrefix(value, "socket:[") || !strings.HasSuffix(value, "]") {
		return 0, false, ErrInventoryUnsafe
	}
	inode, err := sshSystemdUint(value[len("socket:["):len(value)-1], 64)
	if err != nil || inode == 0 {
		return 0, false, ErrInventoryUnsafe
	}
	return inode, true, nil
}

func sshSocketFDs(ctx context.Context, proc *os.File) (_ map[int]uint64, err error) {
	if ctx == nil || proc == nil {
		return nil, ErrInventoryUnsafe
	}
	dir, err := openSSHProcDirectory(proc, "fd")
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, dir.Close()) }()
	entries, err := dir.ReadDir(maxSSHProcessFDs + 1)
	if (err != nil && !errors.Is(err, io.EOF)) || len(entries) > maxSSHProcessFDs {
		return nil, errors.Join(ErrInventoryBounds, err)
	}
	result := make(map[int]uint64)
	seen := make(map[int]bool)
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		fd, err := sshSystemdUint(entry.Name(), 31)
		if err != nil || fd > 1<<31-1 || entry.Type()&os.ModeSymlink == 0 {
			return nil, ErrInventoryUnsafe
		}
		number := int(fd)
		if seen[number] {
			return nil, ErrInventoryUnsafe
		}
		seen[number] = true
		var target [4097]byte
		n, err := unix.Readlinkat(int(dir.Fd()), entry.Name(), target[:])
		if err != nil || n == len(target) {
			return nil, errors.Join(ErrInventoryChanged, err)
		}
		inode, socket, err := sshSocketLink(string(target[:n]))
		if err != nil {
			return nil, err
		}
		if socket {
			if len(result) == maxSSHProcessSockets {
				return nil, ErrInventoryBounds
			}
			result[number] = inode
		}
	}
	return result, nil
}

// inspectSSHSocket only reads an already owned duplicate. It does not close the
// descriptor; the caller must close it on every path, including unsupported types.
func inspectSSHSocket(fd int, inode uint64) (sshListenerSocket, bool, error) {
	var state unix.Stat_t
	if err := unix.Fstat(fd, &state); err != nil || state.Mode&unix.S_IFMT != unix.S_IFSOCK || state.Ino != inode {
		return sshListenerSocket{}, false, errors.Join(ErrInventoryChanged, err)
	}
	family, familyErr := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_DOMAIN)
	kind, kindErr := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_TYPE)
	accepting, acceptErr := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ACCEPTCONN)
	if err := errors.Join(familyErr, kindErr, acceptErr); err != nil || (accepting != 0 && accepting != 1) {
		return sshListenerSocket{}, false, errors.Join(ErrInventoryUnsafe, err)
	}
	if (family != unix.AF_INET && family != unix.AF_INET6) || kind != unix.SOCK_STREAM || accepting != 1 {
		return sshListenerSocket{}, false, nil
	}
	protocol, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_PROTOCOL)
	if err != nil {
		return sshListenerSocket{}, false, err
	}
	if protocol != unix.IPPROTO_TCP {
		return sshListenerSocket{}, false, nil
	}
	cookie, cookieErr := unix.GetsockoptUint64(fd, unix.SOL_SOCKET, unix.SO_COOKIE)
	netCookie, netErr := unix.GetsockoptUint64(fd, unix.SOL_SOCKET, unix.SO_NETNS_COOKIE)
	device, deviceErr := unix.GetsockoptString(fd, unix.SOL_SOCKET, unix.SO_BINDTODEVICE)
	if err := errors.Join(cookieErr, netErr, deviceErr); err != nil || cookie == 0 || netCookie == 0 || len(device) >= unix.IFNAMSIZ {
		return sshListenerSocket{}, false, errors.Join(ErrInventoryUnsafe, err)
	}
	result := sshListenerSocket{Device: uint64(state.Dev), Inode: inode, Cookie: cookie,
		NetNSCookie: netCookie, Family: family, DeviceBinding: device}
	address, err := unix.Getsockname(fd)
	if err != nil {
		return sshListenerSocket{}, false, err
	}
	var port int
	switch address := address.(type) {
	case *unix.SockaddrInet4:
		if family != unix.AF_INET {
			return sshListenerSocket{}, false, ErrInventoryChanged
		}
		result.Address, port = netip.AddrFrom4(address.Addr), address.Port
	case *unix.SockaddrInet6:
		if family != unix.AF_INET6 {
			return sshListenerSocket{}, false, ErrInventoryChanged
		}
		v6only, err := unix.GetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_V6ONLY)
		if err != nil || (v6only != 0 && v6only != 1) {
			return sshListenerSocket{}, false, errors.Join(ErrInventoryUnsafe, err)
		}
		result.Address, port, result.Zone, result.V6Only = netip.AddrFrom16(address.Addr), address.Port, address.ZoneId, v6only == 1
	default:
		return sshListenerSocket{}, false, ErrInventoryUnsafe
	}
	if port < 1 || port > 65535 {
		return sshListenerSocket{}, false, ErrInventoryUnsafe
	}
	result.Port = uint16(port)
	after, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ACCEPTCONN)
	if err != nil || after != 1 {
		return sshListenerSocket{}, false, errors.Join(ErrInventoryChanged, err)
	}
	return result, true, nil
}

func duplicateSSHSocket(pidfd, remoteFD int, inode uint64) (_ sshListenerSocket, _ bool, err error) {
	fd, err := unix.PidfdGetfd(pidfd, remoteFD, 0)
	if err != nil {
		return sshListenerSocket{}, false, fmt.Errorf("SSH socket descriptor cannot be pinned: %w", err)
	}
	defer func() { err = errors.Join(err, unix.Close(fd)) }()
	result, listening, err := inspectSSHSocket(fd, inode)
	result.FD = remoteFD
	return result, listening, err
}

func collectSSHListeners(ctx context.Context, list func(context.Context) (map[int]uint64, error),
	probe func(int, uint64) (sshListenerSocket, bool, error)) ([]sshListenerSocket, error) {
	return collectSSHListenerState(ctx, list, probe, false)
}

// Only the bounded reload observer permits a stable empty interval. An empty
// sample is pending, never listener readiness or successful activation.
func collectSSHListenerState(ctx context.Context, list func(context.Context) (map[int]uint64, error),
	probe func(int, uint64) (sshListenerSocket, bool, error), allowEmpty bool) ([]sshListenerSocket, error) {
	if ctx == nil || list == nil || probe == nil {
		return nil, ErrInventoryUnsafe
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	before, err := list(ctx)
	if err != nil || (!allowEmpty && len(before) == 0) || len(before) > maxSSHProcessSockets {
		return nil, errors.Join(ErrInventoryBounds, err)
	}
	var descriptors []int
	for fd, inode := range before {
		if fd < 0 || fd > 1<<31-1 || inode == 0 {
			return nil, ErrInventoryUnsafe
		}
		descriptors = append(descriptors, fd)
	}
	slices.Sort(descriptors)
	var result []sshListenerSocket
	for _, fd := range descriptors {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		value, listening, err := probe(fd, before[fd])
		if err != nil {
			return nil, err
		}
		if listening {
			if value.FD != fd || value.Inode != before[fd] || !validSSHListenerSocket(value) {
				return nil, ErrInventoryUnsafe
			}
			result = append(result, value)
		}
	}
	after, err := list(ctx)
	if err = errors.Join(err, ctx.Err()); err != nil || !reflect.DeepEqual(before, after) || (!allowEmpty && len(result) == 0) {
		return nil, errors.Join(ErrInventoryChanged, err)
	}
	return result, nil
}

func (b *sshProcessBinding) listeners(ctx context.Context) ([]sshListenerSocket, error) {
	return b.listenerState(ctx, false)
}

func (b *sshProcessBinding) listenerState(ctx context.Context, allowEmpty bool) ([]sshListenerSocket, error) {
	if b == nil || b.proc == nil || b.pidfd < 0 {
		return nil, ErrInventoryClosed
	}
	return collectSSHListenerState(ctx, func(ctx context.Context) (map[int]uint64, error) {
		if err := b.alive(); err != nil {
			return nil, err
		}
		return sshSocketFDs(ctx, b.proc)
	}, func(fd int, inode uint64) (sshListenerSocket, bool, error) {
		return duplicateSSHSocket(b.pidfd, fd, inode)
	}, allowEmpty)
}

func sshListenerKey(s sshListenerSocket) string {
	return strconv.FormatUint(s.Device, 10) + ":" + strconv.FormatUint(s.Inode, 10) + ":" +
		strconv.FormatUint(s.Cookie, 10) + ":" + strconv.FormatUint(s.NetNSCookie, 10)
}
