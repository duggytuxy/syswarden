//go:build linux

package firewall

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"golang.org/x/sys/unix"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func listPolicyFixture(t *testing.T) ([]byte, *nftPolicyGeneration) {
	t.Helper()
	fixture := fixtureNFTCurrentFiles(t)[0]
	source := ipv6ControlPlaneFixtureSource(t, fixture.Source)
	projected, err := listPolicySource([]byte(source))
	if err != nil {
		t.Fatal(err)
	}
	generation := fixtureNFTPolicyGeneration(t, fixture)
	generation.PolicyMode = listPolicyVersion
	generation.IPv6ControlPlane = ipv6ControlPlaneVersion
	return projected, generation
}

func TestListPolicyOwnershipRequiresExactGeneration(t *testing.T) {
	source, generation := listPolicyFixture(t)
	record, err := prepareNFTPolicyOwnership(source, generation, recoveryFixtureTransactionID)
	if err != nil {
		t.Fatal(err)
	}
	input, err := currentNFTInputsFromOwnership(source, record)
	if err != nil {
		t.Fatal(err)
	}
	if input.PolicyMode != listPolicyVersion {
		t.Fatal("missing policy mode")
	}
	if _, err := inspectNFTCurrentPersistentFile(source, input); err != nil {
		t.Fatal(err)
	}
	for _, changed := range [][]byte{
		bytes.Replace(source, []byte("policy accept;"), []byte("policy drop;"), 1),
		bytes.Replace(source, []byte("iifname \"lo\" accept"), []byte("iifname \"lo\" drop"), 1),
		append(bytes.Clone(source), []byte("include \"/etc/operator.nft\"\n")...),
	} {
		if bytes.Equal(source, changed) {
			t.Fatal("mutation missing")
		}
		if _, err := inspectNFTCurrentPersistentFile(changed, input); err == nil {
			t.Fatal("modified source adopted")
		}
	}
	for _, mode := range []string{"", "future-list-mode"} {
		input.PolicyMode = mode
		if _, err := inspectNFTCurrentPersistentFile(source, input); err == nil {
			t.Fatal("unbound policy adopted", mode)
		}
	}
	if bytes.Contains(source, []byte("policy drop;")) || bytes.Contains(source, []byte("dport 53")) || bytes.Contains(source, []byte("tcp flags")) {
		t.Fatal("host filtering leaked into list policy")
	}
}

func TestListPolicyLiveOwnershipAndDrift(t *testing.T) {
	if os.Getenv("SYSWARDEN_TEST_LIST_POLICY_LIVE") != "1" {
		t.Skip("requires disposable list-policy namespace")
	}
	parent := os.Getenv("SYSWARDEN_TEST_PARENT_NETNS")
	current, err := os.Readlink("/proc/self/ns/net")
	mapping, mapErr := os.ReadFile("/proc/self/uid_map")
	fields := strings.Fields(string(mapping))
	if err != nil || mapErr != nil || parent == "" || parent == current || os.Geteuid() != 0 || len(fields) != 3 || fields[0] != "0" || fields[2] != "1" {
		t.Fatal("requires distinct single-user network namespace")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	run := func(binary string, input []byte, args ...string) []byte {
		t.Helper()
		if binary != "/usr/bin/nft" && binary != "/usr/bin/ip" {
			t.Fatal("invalid executable")
		}
		cmd := exec.CommandContext(ctx, binary, args...) // #nosec G204 -- Fixed executables in an attested disposable namespace.
		cmd.Stdin = bytes.NewReader(input)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%s: %v: %s", binary, err, out)
		}
		return out
	}
	nft := func(input []byte, args ...string) []byte { return run("/usr/bin/nft", input, args...) }
	if strings.Contains(string(nft(nil, "-j", "list", "tables")), `"table"`) {
		t.Fatal("namespace not empty")
	}
	run("/usr/bin/ip", nil, "link", "add", "swv0", "type", "veth", "peer", "name", "swv1")
	source, generation := listPolicyFixture(t)
	record, err := prepareNFTPolicyOwnership(source, generation, recoveryFixtureTransactionID)
	if err != nil {
		t.Fatal(err)
	}
	input, err := currentNFTInputsFromOwnership(source, record)
	if err != nil {
		t.Fatal(err)
	}
	nft(source, "-f", "-")
	observe := func() ([]byte, []byte) {
		return nft(nil, "-j", "list", "table", "inet", "syswarden"), nft(nil, "-j", "list", "table", "netdev", "syswarden_hw_drop")
	}
	inet, ingress := observe()
	if _, err := inspectNFTCurrentPersistenceRuntime(source, inet, ingress, nil, input); err != nil {
		t.Fatal(err)
	}
	all := nft(nil, "-j", "list", "ruleset")
	if err := verifyListPolicyRuntimeShape(all, *generation); err != nil {
		t.Fatal(err)
	}
	runListPolicyPackets(t, run, nft)
	// An unrelated administrator table survives product verification.
	nft([]byte("table inet operator_fixture { chain guard { type filter hook input priority 10; policy accept; }; }\n"), "-f", "-")
	if err := verifyListPolicyRuntimeShape(nft(nil, "-j", "list", "ruleset"), *generation); err != nil {
		t.Fatal(err)
	}
	nft(nil, "add", "rule", "inet", "syswarden", "stateful_protect", "tcp", "dport", "64001", "drop")
	if err := verifyListPolicyRuntimeShape(nft(nil, "-j", "list", "ruleset"), *generation); err == nil {
		t.Fatal("unattributed live rule accepted")
	}
	inet, ingress = observe()
	if _, err := inspectNFTCurrentPersistenceRuntime(source, inet, ingress, nil, input); err == nil {
		t.Fatal("modified runtime eligible for retirement")
	}
	// The kernel's actual accept policy must be verified, not inferred from source.
	var doc map[string]any
	if err := json.Unmarshal(all, &doc); err != nil {
		t.Fatal(err)
	}
	for _, entry := range doc["nftables"].([]any) {
		if body, ok := entry.(map[string]any)["chain"].(map[string]any); ok && body["name"] == "stateful_protect" {
			body["policy"] = "drop"
		}
	}
	changed, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyListPolicyRuntimeShape(changed, *generation); err == nil {
		t.Fatal("default-deny drift accepted")
	}
}

// This helper is called only after the namespace/UID-map attestation above.
// Both endpoints are synthetic veth devices in that namespace.
func runListPolicyPackets(t *testing.T, run func(string, []byte, ...string) []byte, nft func([]byte, ...string) []byte) {
	t.Helper()
	for _, iface := range []string{"swv0", "swv1"} {
		run("/usr/bin/ip", nil, "link", "set", iface, "up")
	}
	run("/usr/bin/ip", nil, "address", "add", "192.0.2.1/24", "dev", "swv0")
	run("/usr/bin/ip", nil, "-6", "address", "add", "2001:db8::1/64", "dev", "swv0", "nodad")
	for _, iface := range []string{"all", "swv0"} {
		if err := os.WriteFile("/proc/sys/net/ipv4/conf/"+iface+"/rp_filter", []byte("0\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	host, err := net.InterfaceByName("swv0")
	if err != nil {
		t.Fatal(err)
	}
	peer, err := net.InterfaceByName("swv1")
	if err != nil {
		t.Fatal(err)
	}
	for _, flow := range []struct{ src, dst, network, set, proto string }{{"203.0.113.20", "192.0.2.1", "udp4", "syswarden_blacklist", "ip"}, {"2001:db8:1::20", "2001:db8::1", "udp6", "syswarden_blacklist6", "ip6"}} {
		listener, err := net.ListenUDP(flow.network, &net.UDPAddr{IP: net.ParseIP(flow.dst), Port: 64000})
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		source, destination := netip.MustParseAddr(flow.src), netip.MustParseAddr(flow.dst)
		protocol := uint16(unix.ETH_P_IP)
		if source.Is6() {
			protocol = unix.ETH_P_IPV6
		}
		fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, int(htonsIPv6Test(protocol)))
		if err != nil {
			t.Fatal(err)
		}
		defer unix.Close(fd)
		sequence := uint16(30000)
		probe := func(want bool) {
			t.Helper()
			sequence++
			udp := make([]byte, 12)
			binary.BigEndian.PutUint16(udp[:2], sequence)
			binary.BigEndian.PutUint16(udp[2:4], 64000)
			binary.BigEndian.PutUint16(udp[4:6], 12)
			copy(udp[8:], []byte("test"))
			var header []byte
			if source.Is4() {
				header = make([]byte, 20)
				header[0], header[8], header[9] = 0x45, 64, 17
				binary.BigEndian.PutUint16(header[2:4], 32)
				src, dst := source.As4(), destination.As4()
				copy(header[12:16], src[:])
				copy(header[16:20], dst[:])
				binary.BigEndian.PutUint16(header[10:12], ipv6TestChecksum(header))
			} else {
				header = make([]byte, 40)
				header[0], header[6], header[7] = 0x60, 17, 64
				binary.BigEndian.PutUint16(header[4:6], 12)
				src, dst := source.As16(), destination.As16()
				copy(header[8:24], src[:])
				copy(header[24:40], dst[:])
				pseudo := append(append([]byte{}, src[:]...), dst[:]...)
				pseudo = append(pseudo, 0, 0, 0, 12, 0, 0, 0, 17)
				pseudo = append(pseudo, udp...)
				binary.BigEndian.PutUint16(udp[6:8], ipv6TestChecksum(pseudo))
			}
			frame := make([]byte, 14)
			copy(frame[:6], host.HardwareAddr)
			copy(frame[6:12], peer.HardwareAddr)
			binary.BigEndian.PutUint16(frame[12:14], protocol)
			frame = append(append(frame, header...), udp...)
			if err := listener.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
				t.Fatal(err)
			}
			if err := unix.Sendto(fd, frame, 0, &unix.SockaddrLinklayer{Ifindex: peer.Index, Protocol: htonsIPv6Test(protocol)}); err != nil {
				t.Fatal(err)
			}
			var data [32]byte
			n, from, err := listener.ReadFromUDP(data[:])
			if want {
				if err != nil || n != 4 || string(data[:n]) != "test" || from.IP.String() != flow.src {
					t.Fatalf("new service not reachable: %s %v", flow.network, err)
				}
			} else {
				if neterr, ok := err.(net.Error); !ok || !neterr.Timeout() {
					t.Fatalf("expected blocked packet: %s %v", flow.network, err)
				}
			}
		}
		probe(true)
		nft(nil, "add", "element", "inet", "syswarden", flow.set, "{", flow.src, "}")
		probe(false)
		nft(nil, "delete", "element", "inet", "syswarden", flow.set, "{", flow.src, "}")
		probe(true)
		nft([]byte("table inet external_guard { chain input { type filter hook input priority 10; policy accept; "+flow.proto+" saddr "+flow.src+" udp dport 64000 drop; }; }\n"), "-f", "-")
		probe(false)
		nft(nil, "delete", "table", "inet", "external_guard")
		probe(true)
	}
	t.Log("New UDP listeners remain reachable; IPv4/IPv6 list blocks and independent administrator filtering remain effective.")
}
