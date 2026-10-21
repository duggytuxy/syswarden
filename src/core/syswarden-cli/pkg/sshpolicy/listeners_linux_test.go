//go:build linux

package sshpolicy

import (
	"context"
	"errors"
	"maps"
	"net/netip"
	"os"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestSSHSocketLinksRejectAmbiguousKernelIdentities(t *testing.T) {
	if inode, socket, err := sshSocketLink("socket:[12345]"); err != nil || !socket || inode != 12345 {
		t.Fatal(inode, socket, err)
	}
	for _, value := range []string{"socket:", "socket:123", "socket:[0]", "socket:[01]", "socket:[+1]", "socket:[-1]", "socket:[1]\n", "socket:[18446744073709551616]", "socket:[1\x00]"} {
		if _, _, err := sshSocketLink(value); err == nil {
			t.Fatal("accepted malformed socket identity")
		}
	}
	for _, value := range []string{"/etc/ssh/sshd_config", "pipe:[123]", "anon_inode:[eventpoll]"} {
		if _, socket, err := sshSocketLink(value); err != nil || socket {
			t.Fatal("treated a non-socket link as a socket", err)
		}
	}
}

func sshTestTCPListener(t *testing.T, family int) (int, uint64) {
	t.Helper()
	fd, err := unix.Socket(family, unix.SOCK_STREAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, unix.IPPROTO_TCP)
	if err != nil {
		if family == unix.AF_INET6 && errors.Is(err, unix.EAFNOSUPPORT) {
			t.Skip("kernel IPv6 is unavailable")
		}
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	if family == unix.AF_INET {
		err = unix.Bind(fd, &unix.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}})
	} else {
		if err := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_V6ONLY, 1); err != nil {
			t.Fatal(err)
		}
		err = unix.Bind(fd, &unix.SockaddrInet6{Addr: [16]byte{15: 1}})
	}
	if err != nil {
		if family == unix.AF_INET6 && errors.Is(err, unix.EADDRNOTAVAIL) {
			t.Skip("IPv6 loopback is unavailable")
		}
		t.Fatal(err)
	}
	if err := unix.Listen(fd, 1); err != nil {
		t.Fatal(err)
	}
	var state unix.Stat_t
	if err := unix.Fstat(fd, &state); err != nil {
		t.Fatal(err)
	}
	return fd, state.Ino
}

func TestSSHSocketNativeInspectionUsesKernelMetadataWithoutChangingFlags(t *testing.T) {
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		t.Run(map[int]string{unix.AF_INET: "ipv4", unix.AF_INET6: "ipv6"}[family], func(t *testing.T) {
			fd, inode := sshTestTCPListener(t, family)
			flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
			if err != nil {
				t.Fatal(err)
			}
			first, listening, err := inspectSSHSocket(fd, inode)
			if err != nil || !listening || !first.Address.IsLoopback() || first.Port == 0 || first.Cookie == 0 || first.NetNSCookie == 0 || first.Family != family || first.V6Only != (family == unix.AF_INET6) {
				t.Fatal("incomplete kernel listener observation", err)
			}
			second, listening, err := inspectSSHSocket(fd, inode)
			if err != nil || !listening || first != second {
				t.Fatal("unstable unchanged listener", err)
			}
			after, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
			if err != nil || flags != after {
				t.Fatal("observation changed shared socket flags", err)
			}
			if _, _, err := inspectSSHSocket(fd, inode+1); err == nil {
				t.Fatal("accepted a substituted inode")
			}
		})
	}
	file, err := os.Open("/dev/null")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if _, _, err := inspectSSHSocket(int(file.Fd()), 1); err == nil {
		t.Fatal("accepted a regular descriptor")
	}
	for _, kind := range []int{unix.SOCK_STREAM, unix.SOCK_DGRAM} {
		fd, err := unix.Socket(unix.AF_INET, kind|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		var state unix.Stat_t
		statErr := unix.Fstat(fd, &state)
		_, listening, inspectErr := inspectSSHSocket(fd, state.Ino)
		closeErr := unix.Close(fd)
		if err := errors.Join(statErr, inspectErr, closeErr); err != nil || listening {
			t.Fatal("unbound or datagram socket became a TCP listener", err)
		}
	}
}

func TestSSHSocketNativePidfdDuplicationAndDescriptorReplacement(t *testing.T) {
	fd, inode := sshTestTCPListener(t, unix.AF_INET)
	pidfd, err := unix.PidfdOpen(os.Getpid(), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(pidfd)
	result, listening, err := duplicateSSHSocket(pidfd, fd, inode)
	if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) || errors.Is(err, unix.ENOSYS) {
		t.Skip("kernel policy does not permit pidfd_getfd; the production adapter refuses without fallback")
	}
	if err != nil || !listening || result.FD != fd || result.Inode != inode {
		t.Fatal("pidfd socket observation failed", err)
	}
	if _, _, err := duplicateSSHSocket(pidfd, fd, inode+1); err == nil {
		t.Fatal("accepted a replaced socket")
	}
	if _, _, err := duplicateSSHSocket(pidfd, 1<<30, inode); err == nil {
		t.Fatal("accepted a closed descriptor")
	}
	// Inspecting a duplicate must never close the source descriptor.
	if _, listening, err := inspectSSHSocket(fd, inode); err != nil || !listening {
		t.Fatal("source listener was damaged by observation", err)
	}
}

func sshListenerFixture(fd int, inode uint64) sshListenerSocket {
	return sshListenerSocket{FD: fd, Device: 2, Inode: inode, Cookie: inode + 100, NetNSCookie: 7,
		Family: unix.AF_INET, Address: netip.MustParseAddr("192.0.2.1"), Port: 2222}
}

func TestSSHListenerMetadataMustAgreeWithItsAddressFamily(t *testing.T) {
	for _, scenario := range []string{"ipv4", "ipv6", "wrong-family", "wrong-v4-address", "wrong-v6-address", "v4-zone", "v4-v6only", "text-zone", "long-device", "large-fd"} {
		t.Run(scenario, func(t *testing.T) {
			socket := sshListenerFixture(3, 33)
			switch scenario {
			case "ipv6":
				socket.Family, socket.Address, socket.V6Only = unix.AF_INET6, netip.MustParseAddr("2001:db8::1"), true
			case "wrong-family":
				socket.Family = unix.AF_UNIX
			case "wrong-v4-address":
				socket.Address = netip.MustParseAddr("2001:db8::1")
			case "wrong-v6-address":
				socket.Family = unix.AF_INET6
			case "v4-zone":
				socket.Zone = 1
			case "v4-v6only":
				socket.V6Only = true
			case "text-zone":
				socket.Family, socket.Address = unix.AF_INET6, netip.MustParseAddr("fe80::1%test")
			case "long-device":
				socket.DeviceBinding = strings.Repeat("x", unix.IFNAMSIZ)
			case "large-fd":
				socket.FD = 1 << 31
			}
			if got, want := validSSHListenerSocket(socket), scenario == "ipv4" || scenario == "ipv6"; got != want {
				t.Fatal("inconsistent socket metadata validation")
			}
		})
	}
}

func TestSSHListenerCollectionRejectsPartialAndChangingSnapshots(t *testing.T) {
	for _, scenario := range []string{"stable", "no-sockets", "too-many", "negative-fd", "zero-inode", "first-error", "second-error", "replacement", "addition", "probe-error", "wrong-fd", "wrong-inode", "missing-cookie", "not-listening", "cancel"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			entries := map[int]uint64{4: 44, 3: 33}
			switch scenario {
			case "no-sockets":
				entries = nil
			case "too-many":
				for i := 0; i <= maxSSHProcessSockets; i++ {
					entries[i] = uint64(i + 1)
				}
			case "negative-fd":
				entries[-1] = 1
			case "zero-inode":
				entries[3] = 0
			}
			reads := 0
			list := func(context.Context) (map[int]uint64, error) {
				reads++
				if (scenario == "first-error" && reads == 1) || (scenario == "second-error" && reads == 2) {
					return nil, ErrInventoryChanged
				}
				copy := maps.Clone(entries)
				if reads == 2 {
					switch scenario {
					case "replacement":
						copy[3]++
					case "addition":
						copy[5] = 55
					}
				}
				return copy, nil
			}
			probe := func(fd int, inode uint64) (sshListenerSocket, bool, error) {
				value := sshListenerFixture(fd, inode)
				switch scenario {
				case "probe-error":
					return sshListenerSocket{}, false, unix.EPERM
				case "wrong-fd":
					value.FD++
				case "wrong-inode":
					value.Inode++
				case "missing-cookie":
					value.Cookie = 0
				case "not-listening":
					return sshListenerSocket{}, false, nil
				case "cancel":
					cancel()
				}
				return value, true, nil
			}
			got, err := collectSSHListeners(ctx, list, probe)
			if scenario != "stable" {
				if err == nil || got != nil {
					t.Fatal("accepted incomplete observation", err)
				}
				return
			}
			if err != nil || !reflect.DeepEqual(got, []sshListenerSocket{sshListenerFixture(3, 33), sshListenerFixture(4, 44)}) {
				t.Fatal("stable sockets not collected canonically", err)
			}
		})
	}
	if _, err := collectSSHListeners(context.Background(), nil, nil); err == nil {
		t.Fatal("accepted missing dependencies")
	}
}

func TestSSHSocketProcEnumerationIsBoundedAndDoesNotFollowTargets(t *testing.T) {
	fd, inode := sshTestTCPListener(t, unix.AF_INET)
	proc, err := os.Open("/proc/self")
	if err != nil {
		t.Fatal(err)
	}
	defer proc.Close()
	got, err := sshSocketFDs(context.Background(), proc)
	if err != nil || got[fd] != inode {
		t.Fatal("missing own kernel socket descriptor", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := sshSocketFDs(ctx, proc); err == nil {
		t.Fatal("ignored cancellation")
	}
	fake, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer fake.Close()
	if _, err := sshSocketFDs(context.Background(), fake); err == nil || strings.Contains(err.Error(), "192.0.2.") {
		t.Fatal("accepted fake procfs or reflected socket data", err)
	}
}
