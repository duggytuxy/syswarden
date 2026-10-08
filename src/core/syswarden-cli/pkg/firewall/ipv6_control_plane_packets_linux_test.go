//go:build linux

package firewall

import (
	"encoding/binary"
	"encoding/json"
	"net"
	"net/netip"
	"os/exec"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// This helper is called only after the parent kernel test proves it is inside
// fresh user and network namespaces. All frames stay on a private veth pair.
func runIPv6ControlPlanePackets(t *testing.T, nft func(string, ...string) []byte) {
	t.Helper()
	run := func(name string, args ...string) []byte {
		t.Helper()
		out, err := exec.Command(name, args...).CombinedOutput() // #nosec G204 -- fixed test commands after isolated namespace attestation
		if err != nil {
			t.Fatalf("%s %v: %v: %s", name, args, err, out)
		}
		return out
	}
	nft("flush ruleset\n", "-f", "-")
	run("ip", "link", "delete", "swv0")
	run("ip", "link", "add", "swv0", "type", "veth", "peer", "name", "swpeer")
	run("ip", "link", "set", "swv0", "up")
	run("ip", "link", "set", "swpeer", "up")
	run("ip", "-6", "addr", "add", "2001:db8:ffff::2/64", "dev", "swv0", "nodad")
	host, err := net.InterfaceByName("swv0")
	if err != nil {
		t.Fatal(err)
	}
	peer, err := net.InterfaceByName("swpeer")
	if err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, int(htonsIPv6Test(unix.ETH_P_IPV6)))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(fd) }()
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Ifindex: peer.Index, Protocol: htonsIPv6Test(unix.ETH_P_IPV6)}); err != nil {
		t.Fatal(err)
	}
	send := func(src, dst string, hop, next byte, payload []byte) {
		t.Helper()
		source, destination := netip.MustParseAddr(src).As16(), netip.MustParseAddr(dst).As16()
		packet := make([]byte, 14+40+len(payload))
		copy(packet[:6], host.HardwareAddr)
		copy(packet[6:12], peer.HardwareAddr)
		binary.BigEndian.PutUint16(packet[12:14], unix.ETH_P_IPV6)
		packet[14] = 0x60
		binary.BigEndian.PutUint16(packet[18:20], uint16(len(payload))) // #nosec G115 -- test payloads are fixed and below 1280 bytes
		packet[20], packet[21] = next, hop
		copy(packet[22:38], source[:])
		copy(packet[38:54], destination[:])
		copy(packet[54:], payload)
		checksumOffset := 56
		if next == 17 {
			checksumOffset = 60
		}
		pseudo := append(append([]byte{}, source[:]...), destination[:]...)
		pseudo = append(pseudo, 0, 0, byte(len(payload)>>8), byte(len(payload)), 0, 0, 0, next) // #nosec G115 -- fixed bounded test payload length
		pseudo = append(pseudo, payload...)
		binary.BigEndian.PutUint16(packet[checksumOffset:checksumOffset+2], ipv6TestChecksum(pseudo))
		if err := unix.Sendto(fd, packet, 0, &unix.SockaddrLinklayer{Ifindex: peer.Index, Protocol: htonsIPv6Test(unix.ETH_P_IPV6)}); err != nil {
			t.Fatal(err)
		}
	}
	var lastCount float64
	observe := func() float64 {
		var d struct {
			NFTables []struct {
				Rule *struct {
					Expr []map[string]json.RawMessage `json:"expr"`
				} `json:"rule"`
			} `json:"nftables"`
		}
		if err := json.Unmarshal(nft("", "-j", "list", "chain", "inet", "sw_ipv6_probe", "input"), &d); err != nil {
			t.Fatal(err)
		}
		var total float64
		for _, entry := range d.NFTables {
			if entry.Rule != nil {
				for _, expr := range entry.Rule.Expr {
					if raw := expr["counter"]; raw != nil {
						var c struct {
							Packets float64 `json:"packets"`
						}
						if err := json.Unmarshal(raw, &c); err != nil {
							t.Fatal(err)
						}
						total += c.Packets
					}
				}
			}
		}
		return total
	}
	probe := func(name string, allow bool, src string, hop byte, payload []byte) {
		t.Helper()
		lastCount = observe()
		send(src, "2001:db8:ffff::2", hop, 58, payload)
		time.Sleep(15 * time.Millisecond)
		accepted := observe() > lastCount
		if accepted != allow {
			t.Fatalf("%s: input accepted=%t, expected %t", name, accepted, allow)
		}
	}
	ra := make([]byte, 16)
	ra[0], ra[4], ra[5] = 134, 64, 0x80
	binary.BigEndian.PutUint16(ra[6:8], 3)
	neighbor := make([]byte, 24)
	neighbor[0] = 135
	target := netip.MustParseAddr("2001:db8:ffff::2").As16()
	copy(neighbor[8:], target[:])
	mld := make([]byte, 24)
	mld[0] = 130
	fixture := fixtureNFTCurrentFiles(t)[7]
	for _, corrected := range []bool{false, true, true} {
		source := fixture.Source
		if corrected {
			source = ipv6ControlPlaneFixtureSource(t, source)
		}
		// An independent frontend allows traffic first. Its accept must not
		// conceal a later SysWarden drop. The observer runs after both chains.
		monitor := "table inet sw_ipv6_frontend { chain input { type filter hook input priority -20; policy accept; }\n}\n" +
			"table inet sw_ipv6_probe { chain input { type filter hook input priority 100; policy accept; ip6 daddr 2001:db8:ffff::2 counter; }\n}\n"
		nft("flush ruleset\n"+source+monitor, "-f", "-")
		probe("router advertisement", corrected, "fe80::123", 255, ra)
		probe("global neighbour solicitation", corrected, "2001:db8:abcd::1", 255, neighbor)
		probe("DAD unspecified source", corrected, "::", 255, neighbor)
		advert := append([]byte{}, neighbor...)
		advert[0] = 136
		probe("global neighbour advertisement", corrected, "2001:db8:abcd::1", 255, advert)
		probe("multicast listener query", corrected, "fe80::123", 1, mld)
		for _, kind := range []byte{1, 2, 3, 4} {
			failure := make([]byte, 8+40+8)
			failure[0] = kind
			if kind == 2 {
				binary.BigEndian.PutUint32(failure[4:8], 1280)
			}
			failure[8], failure[14], failure[15] = 0x60, 17, 64
			binary.BigEndian.PutUint16(failure[12:14], 8)
			local, remote := netip.MustParseAddr("2001:db8:ffff::2").As16(), netip.MustParseAddr("2001:db8:abcd::1").As16()
			copy(failure[16:32], local[:])
			copy(failure[32:48], remote[:])
			binary.BigEndian.PutUint16(failure[48:50], 19000)
			binary.BigEndian.PutUint16(failure[50:52], 19001)
			binary.BigEndian.PutUint16(failure[52:54], 8)
			probe("ICMPv6 error without live conntrack", corrected, "2001:db8:abcd::1", 64, failure)
		}
		bad := append([]byte{}, ra...)
		bad[1] = 1
		probe("invalid RA code", false, "fe80::123", 255, bad)
		probe("off-link RA", false, "2001:db8:abcd::1", 255, ra)
		probe("routed RA hop limit", false, "fe80::123", 254, ra)
		probe("routed ND hop limit", false, "2001:db8:abcd::1", 254, neighbor)
		probe("unsolicited echo", false, "2001:db8:abcd::1", 64, []byte{128, 0, 0, 0, 0, 1, 0, 1})
		probe("redirect", false, "fe80::123", 255, []byte{137, 0, 0, 0, 0, 0, 0, 0})
		for _, port := range []uint16{547, 1547} {
			udp := make([]byte, 12)
			binary.BigEndian.PutUint16(udp[0:2], port)
			binary.BigEndian.PutUint16(udp[2:4], 546)
			binary.BigEndian.PutUint16(udp[4:6], 12)
			udp[8] = 7 // DHCPv6 Reply, not an application permission.
			before := observe()
			send("2001:db8:abcd::1", "2001:db8:ffff::2", 64, 17, udp)
			time.Sleep(15 * time.Millisecond)
			if accepted := observe() > before; accepted != corrected {
				t.Fatalf("DHCPv6 source port %d: accepted=%t, expected %t", port, accepted, corrected)
			}
		}
		if corrected {
			// Actual kernel RA consumption: route creation, refresh beyond its
			// original lifetime despite strict source filtering.
			for round := 0; round < 5; round++ {
				send("fe80::123", "ff02::1", 255, 58, ra)
				time.Sleep(time.Second)
				if !strings.Contains(string(run("ip", "-6", "route", "show", "default", "dev", "swv0")), "fe80::123") {
					t.Fatal("kernel did not install or refresh the RA default route")
				}
			}
		} else if strings.Contains(string(run("ip", "-6", "route", "show", "default", "dev", "swv0")), "fe80::123") {
			t.Fatal("baseline unexpectedly retained the blocked RA")
		}
		t.Logf("corrected=%t: live IPv6 frames, strict-policy refusals, frontend coexistence and reload passed", corrected)
	}
}

func htonsIPv6Test(value uint16) uint16 { return value<<8 | value>>8 }

func ipv6TestChecksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if len(data)%2 != 0 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum) // #nosec G115 -- carry folding bounds the checksum to 16 bits
}
