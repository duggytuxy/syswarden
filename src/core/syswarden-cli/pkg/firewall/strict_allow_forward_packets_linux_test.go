//go:build linux

package firewall

import (
	"encoding/binary"
	"encoding/json"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Called only inside the attested private network namespace. Raw frames enter
// local veth pairs and are routed to a dummy backend. No host interface or
// external network is reachable. The observer runs after the product chain.
func runStrictAllowForwardPackets(t *testing.T, nft func(string, ...string) []byte) {
	t.Helper()
	run := func(args ...string) {
		t.Helper()
		if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil { // #nosec G204 -- fixed namespace-local test commands
			t.Fatalf("ip %v: %v: %s", args, err, out)
		}
	}
	for _, name := range []string{"swext", "swint"} {
		run("link", "add", name, "type", "veth", "peer", "name", name+"p")
		run("link", "set", name, "up")
		run("link", "set", name+"p", "up")
		if err := os.WriteFile("/proc/sys/net/ipv4/conf/"+name+"/rp_filter", []byte("0\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, path := range []string{"/proc/sys/net/ipv4/ip_forward", "/proc/sys/net/ipv6/conf/all/forwarding"} {
		if err := os.WriteFile(path, []byte("1\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile("/proc/sys/net/ipv4/conf/all/rp_filter", []byte("0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	run("link", "add", "swback", "type", "dummy")
	run("link", "set", "swback", "up")
	run("address", "add", "192.0.2.1/24", "dev", "swback")
	run("-6", "address", "add", "2001:db8:ff::1/64", "dev", "swback", "nodad")
	run("neigh", "add", "192.0.2.200", "lladdr", "02:00:00:00:00:02", "dev", "swback")
	run("-6", "neigh", "add", "2001:db8:ff::200", "lladdr", "02:00:00:00:00:02", "dev", "swback")
	sequence := uint16(20000)
	send := func(iface, source string) {
		t.Helper()
		host, err := net.InterfaceByName(iface)
		if err != nil {
			t.Fatal(err)
		}
		peer, err := net.InterfaceByName(iface + "p")
		if err != nil {
			t.Fatal(err)
		}
		address := netip.MustParseAddr(source)
		protocol := uint16(unix.ETH_P_IP)
		if address.Is6() {
			protocol = unix.ETH_P_IPV6
		}
		fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, int(htonsIPv6Test(protocol)))
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = unix.Close(fd) }()
		const udpSize uint16 = 12
		udp := make([]byte, udpSize)
		sequence++ // Distinct five-tuples keep every probe a new connection.
		binary.BigEndian.PutUint16(udp[0:2], sequence)
		binary.BigEndian.PutUint16(udp[2:4], 18080)
		binary.BigEndian.PutUint16(udp[4:6], udpSize)
		var header []byte
		if address.Is4() {
			header = make([]byte, 20)
			header[0], header[8], header[9] = 0x45, 64, 17
			binary.BigEndian.PutUint16(header[2:4], 20+udpSize)
			src, dst := address.As4(), netip.MustParseAddr("192.0.2.200").As4()
			copy(header[12:16], src[:])
			copy(header[16:20], dst[:])
			binary.BigEndian.PutUint16(header[10:12], ipv6TestChecksum(header))
		} else {
			header = make([]byte, 40)
			header[0], header[6], header[7] = 0x60, 17, 64
			binary.BigEndian.PutUint16(header[4:6], udpSize)
			src, dst := address.As16(), netip.MustParseAddr("2001:db8:ff::200").As16()
			copy(header[8:24], src[:])
			copy(header[24:40], dst[:])
			pseudo := append(append([]byte{}, src[:]...), dst[:]...)
			pseudo = append(pseudo, 0, 0, 0, 12, 0, 0, 0, 17)
			pseudo = append(pseudo, udp...)
			binary.BigEndian.PutUint16(udp[6:8], ipv6TestChecksum(pseudo))
		}
		packet := make([]byte, 14)
		copy(packet[:6], host.HardwareAddr)
		copy(packet[6:12], peer.HardwareAddr)
		binary.BigEndian.PutUint16(packet[12:14], protocol)
		packet = append(append(packet, header...), udp...)
		if err := unix.Sendto(fd, packet, 0, &unix.SockaddrLinklayer{Ifindex: peer.Index, Protocol: htonsIPv6Test(protocol)}); err != nil {
			t.Fatal(err)
		}
	}
	observe := func(table string) uint64 {
		t.Helper()
		document, err := decodeNFTJSON(nft("", "-j", "list", "chain", "inet", table, "forward"))
		if err != nil {
			t.Fatal(err)
		}
		var total uint64
		for _, entry := range document.NFTables {
			if entry.Rule == nil {
				continue
			}
			for _, expression := range entry.Rule.Expressions {
				var value struct {
					Counter *struct {
						Packets uint64 `json:"packets"`
					} `json:"counter"`
				}
				if err := json.Unmarshal(expression, &value); err != nil {
					t.Fatal(err)
				}
				if value.Counter != nil {
					total += value.Counter.Packets
				}
			}
		}
		return total
	}
	probe := func(name, iface, source string, allowed bool) {
		t.Helper()
		before, arrivedBefore := observe("sw_probe"), observe("sw_frontend")
		send(iface, source)
		deadline := time.Now().Add(time.Second)
		for observe("sw_frontend") == arrivedBefore && time.Now().Before(deadline) {
			time.Sleep(5 * time.Millisecond)
		}
		if observe("sw_frontend") != arrivedBefore+1 {
			t.Fatalf("%s: frame did not reach the forward hook exactly once", name)
		}
		// The same packet traverses the product chain synchronously after the
		// first observer. Give deferred processing a bounded completion window.
		time.Sleep(20 * time.Millisecond)
		if got := observe("sw_probe") > before; got != allowed {
			t.Fatalf("%s: forwarded=%t expected=%t", name, got, allowed)
		}
	}
	var original string
	for _, fixture := range strictForwardFixtures(t) {
		if fixture.inputs().Base.Inet.Strict {
			start := strings.Index(fixture.Source, "table inet syswarden {")
			end := start + strings.Index(fixture.Source[start:], "\n}\n\n") + len("\n}\n")
			original = fixture.Source[start:end]
			break
		}
	}
	if original == "" {
		t.Fatal("strict forwarding fixture missing")
	}
	for _, corrected := range []bool{false, true, true} {
		source := original
		if corrected {
			source = scopedForwardFixture(t, source, []string{"swext"})
		}
		monitor := "table inet sw_frontend { chain forward { type filter hook forward priority -20; policy accept; udp dport 18080 counter; }\n}\n" +
			"table inet sw_probe { chain forward { type filter hook forward priority 100; policy accept; udp dport 18080 counter; }\n}\n"
		populations := "add element inet syswarden syswarden_zt_allowed { 198.51.100.0/24 }\nadd element inet syswarden syswarden_zt_allowed6 { 2001:db8:1::/64 }\n"
		nft("flush ruleset\n"+source+monitor+populations, "-f", "-")
		for _, flow := range []struct{ allowed, denied, private, destination, ban, list string }{
			{"198.51.100.10", "203.0.113.10", "172.30.0.10", "192.0.2.200", "banned_ips", "syswarden_blacklist"},
			{"2001:db8:1::10", "2001:db8:2::10", "fd00:30::10", "2001:db8:ff::200", "banned_ips6", "syswarden_blacklist6"},
		} {
			probe("allowed visitor", "swext", flow.allowed, true)
			probe("rejected visitor", "swext", flow.denied, false)
			probe("private source on external ingress", "swext", flow.private, false)
			probe("container to backend", "swint", flow.private, corrected)
			for _, set := range []string{flow.ban, flow.list} {
				nft("", "add", "element", "inet", "syswarden", set, "{", flow.destination, "}")
				probe("blocked backend destination", "swint", flow.private, false)
				nft("", "delete", "element", "inet", "syswarden", set, "{", flow.destination, "}")
				nft("", "add", "element", "inet", "syswarden", set, "{", flow.private, "}")
				probe("banned container source", "swint", flow.private, false)
				nft("", "delete", "element", "inet", "syswarden", set, "{", flow.private, "}")
				nft("", "add", "element", "inet", "syswarden", set, "{", flow.allowed, "}")
				probe("banned allowed-country visitor", "swext", flow.allowed, false)
				nft("", "delete", "element", "inet", "syswarden", set, "{", flow.allowed, "}")
			}
		}
	}
	t.Log("Actual forwarded IPv4/IPv6 frames reproduce the historical backend drop; scoped ingress preserves visitor filtering and bidirectional bans across policy replay. No host or real Docker daemon was changed.")
}
