//go:build linux

package sshpolicy

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestSSHExpectedEndpointsUseFullAddressesAndExplicitFamilies(t *testing.T) {
	for _, tc := range []struct {
		name, output string
		want         []netip.AddrPort
	}{
		{"ipv4", "port 22\naddressfamily inet\nlistenaddress 127.0.0.1:2222\n", []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:2222")}},
		{"ipv6", "port 22\naddressfamily inet6\nlistenaddress [::1]:22\n", []netip.AddrPort{netip.MustParseAddrPort("[::1]:22")}},
		{"dual-wildcard", "port 22\naddressfamily any\nlistenaddress [::]:22\nlistenaddress 0.0.0.0:22\n", []netip.AddrPort{netip.MustParseAddrPort("0.0.0.0:22"), netip.MustParseAddrPort("[::]:22")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			values, err := parseEffective([]byte(tc.output))
			if err != nil {
				t.Fatal(err)
			}
			got, err := sshExpectedEndpoints(values)
			if err != nil || !reflect.DeepEqual(got, tc.want) {
				t.Fatal("incorrect endpoint expectations", err)
			}
		})
	}
	for _, output := range []string{
		"port 22\nlistenaddress 0.0.0.0:22\n",
		"port 22\naddressfamily unknown\nlistenaddress 0.0.0.0:22\n",
		"port 22\naddressfamily any\naddressfamily any\nlistenaddress 0.0.0.0:22\n",
		"port 22\naddressfamily inet\nlistenaddress [::]:22\n",
		"port 22\naddressfamily inet6\nlistenaddress 0.0.0.0:22\n",
		"port 22\naddressfamily any\nlistenaddress [::ffff:192.0.2.1]:22\n",
		"port 22\naddressfamily any\nlistenaddress [fe80::1%private]:22\n",
		"port 22\naddressfamily any\nlistenaddress [fe80::1]:22\n",
		"port 22\naddressfamily any\nlistenaddress 169.254.1.2:22\n",
		"port 22\naddressfamily any\nlistenaddress 224.0.0.1:22\n",
		"port 22\naddressfamily any\nlistenaddress private.invalid:22\n",
		"port 22\naddressfamily any\nlistenaddress [::1]:022\n",
		"port 22\naddressfamily any\nlistenaddress [::1]:22 rdomain private\n",
		"port 22\naddressfamily any\nlistenaddress [::1]:22\nlistenaddress [0:0:0:0:0:0:0:1]:22\n",
		"port 22\naddressfamily any\n" + strings.Repeat("listenaddress 0.0.0.0:22\n", 257),
	} {
		values, err := parseEffective([]byte(output))
		if err != nil {
			t.Fatal(err)
		}
		got, err := sshExpectedEndpoints(values)
		if err == nil || got != nil || strings.Contains(err.Error(), "private") {
			t.Fatal("accepted ambiguous endpoints or disclosed configuration", err)
		}
	}
}

func TestSSHEndpointMatchingRejectsExpandedOrIncompleteExposure(t *testing.T) {
	for _, scenario := range []string{"exact", "same-object-two-fds", "missing", "extra", "wildcard-expansion", "wildcard-narrowing", "wrong-port", "wrong-namespace", "bound-device", "wrong-scope", "dual-stack", "mapped-v4", "different-object-same-endpoint", "object-conflict", "unsorted", "zero-cookie", "invalid-expected", "duplicate-expected", "ipv6-exact"} {
		t.Run(scenario, func(t *testing.T) {
			first := sshListenerFixture(3, 33)
			expected := []netip.AddrPort{netip.AddrPortFrom(first.Address, first.Port)}
			sockets := []sshListenerSocket{first}
			switch scenario {
			case "same-object-two-fds":
				second := first
				second.FD = 4
				sockets = append(sockets, second)
			case "missing":
				expected = append(expected, netip.MustParseAddrPort("[::1]:2222"))
			case "extra":
				second := sshListenerFixture(4, 44)
				second.Port++
				sockets = append(sockets, second)
			case "wildcard-expansion":
				sockets[0].Address = netip.IPv4Unspecified()
			case "wildcard-narrowing":
				expected[0] = netip.AddrPortFrom(netip.IPv4Unspecified(), 2222)
			case "wrong-port":
				sockets[0].Port++
			case "wrong-namespace":
				sockets[0].NetNSCookie++
			case "bound-device":
				sockets[0].DeviceBinding = "private-interface"
			case "wrong-scope":
				sockets[0].Zone = 2
			case "dual-stack":
				sockets[0].Family = unix.AF_INET6
				sockets[0].Address = netip.IPv6Unspecified()
				expected[0] = netip.MustParseAddrPort("[::]:2222")
			case "mapped-v4":
				sockets[0].Family = unix.AF_INET6
				sockets[0].Address = netip.MustParseAddr("::ffff:192.0.2.1")
				sockets[0].V6Only = true
				expected[0] = netip.AddrPortFrom(sockets[0].Address, 2222)
			case "different-object-same-endpoint":
				sockets = append(sockets, sshListenerFixture(4, 44))
			case "object-conflict":
				second := first
				second.FD = 4
				second.Port++
				sockets = append(sockets, second)
				expected = append(expected, netip.AddrPortFrom(first.Address, second.Port))
			case "unsorted":
				second := first
				second.FD = 2
				sockets = append(sockets, second)
			case "zero-cookie":
				sockets[0].Cookie = 0
			case "invalid-expected":
				expected[0] = netip.AddrPort{}
			case "duplicate-expected":
				expected = append(expected, expected[0])
			case "ipv6-exact":
				sockets[0].Family = unix.AF_INET6
				sockets[0].Address = netip.IPv6Loopback()
				sockets[0].V6Only = true
				expected[0] = netip.AddrPortFrom(sockets[0].Address, 2222)
			}
			err := matchSSHEndpoints(expected, sockets, 7)
			success := scenario == "exact" || scenario == "same-object-two-fds" || scenario == "ipv6-exact"
			if (err == nil) != success {
				t.Fatal("incorrect exposure correspondence", err)
			}
			if err != nil && (strings.Contains(err.Error(), "192.0.2.") || strings.Contains(err.Error(), "private")) {
				t.Fatal("disclosed endpoint details")
			}
		})
	}
	if matchSSHEndpoints(nil, nil, 0) == nil {
		t.Fatal("accepted absent observation")
	}
}

func TestSSHEndpointsNativeNamespaceAndProcessLease(t *testing.T) {
	fd, inode := sshTestTCPListener(t, unix.AF_INET)
	socket, listening, err := inspectSSHSocket(fd, inode)
	if err != nil || !listening {
		t.Fatal(err)
	}
	state, digest, group := sshProcessOracleExpectation(t)
	binding, err := bindSSHProcess(os.Getpid(), os.Geteuid(), group, state, digest)
	if err != nil {
		t.Fatal(err)
	}
	defer binding.Close()
	cookie, err := sshNamespaceCookie(binding.namespaces["net"])
	if err != nil || cookie != socket.NetNSCookie {
		t.Fatal("socket namespace was not bound to the held namespace", err)
	}
	if got, err := sshNamespaceCookie(binding.root); err == nil || got != 0 {
		t.Fatal("accepted an unrelated kernel object")
	}
	expected := []netip.AddrPort{netip.AddrPortFrom(socket.Address, socket.Port)}
	capture := &sshListenerCapture{}
	checks := 0
	lease := configuredSSHListenerLease(context.Background(), binding, expected, func() error { checks++; return nil }, capture)
	for i := 0; i < 2; i++ {
		_, err = lease.observe()
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) || errors.Is(err, unix.ENOSYS) {
			t.Skip("kernel policy denies descriptor inspection; production refuses")
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	if capture.samples != 2 || checks != 4 {
		t.Fatal("incomplete native correspondence checks")
	}
	wrong := []netip.AddrPort{netip.AddrPortFrom(netip.IPv4Unspecified(), socket.Port)}
	lease = configuredSSHListenerLease(context.Background(), binding, wrong, func() error { return nil }, &sshListenerCapture{})
	if _, err := lease.observe(); err == nil {
		t.Fatal("accepted a broader configured endpoint")
	}
	if os.Geteuid() != 0 {
		if got, err := ObserveSystemdEndpoints(); err == nil || !reflect.DeepEqual(got, EndpointSummary{}) {
			t.Fatal("unprivileged endpoint proof")
		}
	}
}

func TestOpenSSHEndpointCorrespondenceOracle(t *testing.T) {
	if os.Getenv("SYSWARDEN_SSH_ORACLE_TEST") != "1" {
		t.Skip("set SYSWARDEN_SSH_ORACLE_TEST=1 for the installed parser oracle")
	}
	root, err := os.Open("/")
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	daemon, err := openSSHD(root, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer daemon.file.Close()
	key := sshOracleKey(t, t.TempDir())
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		t.Run(map[int]string{unix.AF_INET: "inet", unix.AF_INET6: "inet6"}[family], func(t *testing.T) {
			fd, inode := sshTestTCPListener(t, family)
			socket, listening, err := inspectSSHSocket(fd, inode)
			if err != nil || !listening {
				t.Fatal(err)
			}
			socket.FD = fd
			endpoint := netip.AddrPortFrom(socket.Address, socket.Port)
			image, err := newParserImage(map[string][]byte{MainPath: []byte("HostKey " + key + "\nUsePAM no\nPort 22\nAddressFamily " + map[int]string{unix.AF_INET: "inet", unix.AF_INET6: "inet6"}[family] + "\nListenAddress " + endpoint.String() + "\nAllowTcpForwarding local\nPasswordAuthentication no\n")})
			if err != nil {
				t.Fatal(err)
			}
			defer image.Close()
			if _, err := daemon.run(context.Background(), image, "syntax", ""); err != nil {
				t.Fatal(err)
			}
			output, err := daemon.run(context.Background(), image, "effective", "")
			if err != nil {
				t.Fatal(err)
			}
			values, err := parseEffective(output)
			if err != nil {
				t.Fatal(err)
			}
			expected, err := sshExpectedEndpoints(values)
			if err != nil {
				t.Fatal(err)
			}
			if len(expected) != 1 || expected[0] != endpoint {
				t.Fatal("installed parser selected different endpoints")
			}
			if err := matchSSHEndpoints(expected, []sshListenerSocket{socket}, socket.NetNSCookie); err != nil {
				t.Fatal(err)
			}
			socket.Port = 0
			if matchSSHEndpoints(expected, []sshListenerSocket{socket}, socket.NetNSCookie) == nil {
				t.Fatal("accepted a changed native endpoint")
			}
		})
	}
}
