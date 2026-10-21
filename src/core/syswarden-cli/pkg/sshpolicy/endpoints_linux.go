//go:build linux

package sshpolicy

import (
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"runtime"
	"slices"
	"strconv"

	"golang.org/x/sys/unix"
)

// Expectations are private, freshly parsed values, not caller-supplied public
// summaries or authority to activate SSH. Scoped and mapped endpoints require
// their own future qualified policy and are refused here without guessing.
func sshExpectedEndpoints(values sshEffective) ([]netip.AddrPort, error) {
	if _, _, err := effectivePorts(values); err != nil {
		return nil, err
	}
	families := values["addressfamily"]
	if len(families) != 1 || (families[0] != "any" && families[0] != "inet" && families[0] != "inet6") || len(values["listenaddress"]) > maxSSHProcessSockets {
		return nil, ErrInventoryUnsafe
	}
	var result []netip.AddrPort
	seen := make(map[netip.AddrPort]bool)
	for _, value := range values["listenaddress"] {
		endpoint, err := netip.ParseAddrPort(value)
		if err != nil || endpoint.Port() == 0 || endpoint.Addr().Zone() != "" || endpoint.Addr().Is4In6() || endpoint.Addr().IsMulticast() ||
			endpoint.Addr().IsLinkLocalUnicast() || seen[endpoint] ||
			(families[0] == "inet" && !endpoint.Addr().Is4()) || (families[0] == "inet6" && !endpoint.Addr().Is6()) {
			return nil, ErrInventoryUnsafe
		}
		seen[endpoint] = true
		result = append(result, endpoint)
	}
	slices.SortFunc(result, func(a, b netip.AddrPort) int { return a.Compare(b) })
	return result, nil
}

func matchSSHEndpoints(expected []netip.AddrPort, sockets []sshListenerSocket, namespace uint64) error {
	if len(expected) == 0 || len(expected) > maxSSHProcessSockets || len(sockets) == 0 || len(sockets) > maxSSHProcessSockets || namespace == 0 {
		return ErrInventoryUnsafe
	}
	want := make(map[netip.AddrPort]bool)
	for _, endpoint := range expected {
		address := endpoint.Addr()
		if !endpoint.IsValid() || endpoint.Port() == 0 || address.Zone() != "" || address.Is4In6() || address.IsMulticast() || address.IsLinkLocalUnicast() || want[endpoint] {
			return ErrInventoryUnsafe
		}
		want[endpoint] = true
	}
	seen := make(map[netip.AddrPort]string)
	objects := make(map[string]sshListenerSocket)
	lastFD := -1
	for _, socket := range sockets {
		if !validSSHListenerSocket(socket) || socket.FD <= lastFD || socket.NetNSCookie != namespace || socket.Zone != 0 || socket.DeviceBinding != "" ||
			(socket.Family == unix.AF_INET6 && !socket.V6Only) {
			return ErrInventoryUnsafe
		}
		lastFD = socket.FD
		endpoint := netip.AddrPortFrom(socket.Address, socket.Port)
		key := sshListenerKey(socket)
		socket.FD = 0
		if !want[endpoint] || (seen[endpoint] != "" && seen[endpoint] != key) {
			return ErrInventoryChanged
		}
		if prior, exists := objects[key]; exists && prior != socket {
			return ErrInventoryChanged
		}
		seen[endpoint], objects[key] = key, socket
	}
	if len(seen) != len(want) {
		return ErrInventoryChanged
	}
	return nil
}

func sshEndpointDigest(endpoints []netip.AddrPort) (string, error) {
	wire, err := json.Marshal(endpoints)
	if err != nil {
		return "", err
	}
	return digestBytes(wire), nil
}

// Bind SO_NETNS_COOKIE to the held target namespace using the calling thread.
// The temporary socket is never bound, connected or used for traffic. No setns
// call, capability adjustment or firewall operation is performed.
func sshNamespaceCookie(expected *os.File) (cookie uint64, err error) {
	defer func() {
		if err != nil {
			cookie = 0
		}
	}()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	want, err := sshKernelFileIdentity(expected)
	if err != nil || want.Inode == 0 {
		return 0, errors.Join(ErrInventoryUnsafe, err)
	}
	root, err := os.Open("/")
	if err != nil {
		return 0, err
	}
	defer func() { err = errors.Join(err, root.Close()) }()
	proc, err := openSSHProcDirectory(root, "proc")
	if err != nil {
		return 0, err
	}
	defer func() { err = errors.Join(err, proc.Close()) }()
	var link [32]byte
	n, err := unix.Readlinkat(int(proc.Fd()), "self", link[:])
	if err != nil || string(link[:n]) != strconv.Itoa(os.Getpid()) {
		return 0, errors.Join(ErrInventoryUnsafe, err)
	}
	thread, err := openSSHProcDirectory(proc, strconv.Itoa(unix.Gettid()))
	if err != nil {
		return 0, err
	}
	defer func() { err = errors.Join(err, thread.Close()) }()
	check := func() error {
		ns, err := openSSHProcessLink(thread, "ns/net")
		if err != nil {
			return err
		}
		got, readErr := sshKernelFileIdentity(ns)
		if err := errors.Join(readErr, ns.Close()); err != nil || got != want {
			return errors.Join(ErrInventoryChanged, err)
		}
		return nil
	}
	if err := check(); err != nil {
		return 0, err
	}
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return 0, err
	}
	defer func() { err = errors.Join(err, unix.Close(fd)) }()
	cookie, err = unix.GetsockoptUint64(fd, unix.SOL_SOCKET, unix.SO_NETNS_COOKIE)
	if err = errors.Join(err, check()); err != nil || cookie == 0 {
		return 0, errors.Join(ErrInventoryUnsafe, err)
	}
	return cookie, nil
}
