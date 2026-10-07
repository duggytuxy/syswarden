//go:build linux

package firewall

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func fixtureNFTGenerationBody(generation uint32) []byte {
	body := make([]byte, 12)
	binary.BigEndian.PutUint16(body[2:], uint16(generation&0xffff))
	binary.NativeEndian.PutUint16(body[4:], 8)
	binary.NativeEndian.PutUint16(body[6:], unix.NFTA_GEN_ID)
	binary.BigEndian.PutUint32(body[8:], generation)
	return body
}

func fixtureNFTGenerationReply(request nftGenerationMessage, kind, flags uint16, body []byte) []byte {
	packet := make([]byte, 16+len(body))
	size := len(packet)
	if size < 16 || size > maximumNFTGenerationPacket {
		panic("fixture packet exceeds the bounded protocol size")
	}
	binary.NativeEndian.PutUint32(packet, uint32(size))
	binary.NativeEndian.PutUint16(packet[4:], kind)
	binary.NativeEndian.PutUint16(packet[6:], flags)
	binary.NativeEndian.PutUint32(packet[8:], request.sequence)
	binary.NativeEndian.PutUint32(packet[12:], 1234)
	copy(packet[16:], body)
	return packet
}

func TestNFTGenerationRejectsAmbiguousGeneration(t *testing.T) {
	valid := fixtureNFTGenerationBody(0x01020003)
	value, err := decodeNFTGeneration(valid)
	if err != nil || value != 0x01020003 {
		t.Fatal(value, err)
	}
	cases := map[string][]byte{
		"empty":       nil,
		"zero bypass": fixtureNFTGenerationBody(0),
		"truncated":   valid[:11],
		"duplicate":   append(bytes.Clone(valid), valid[4:]...),
		"oversized":   make([]byte, 4097),
	}
	for name, offset := range map[string]int{"family": 0, "version": 1, "header generation": 3, "width": 4, "attribute kind": 6} {
		body := bytes.Clone(valid)
		body[offset] ^= 1
		cases[name] = body
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeNFTGeneration(body); err == nil {
				t.Fatal("ambiguous generation was accepted")
			}
		})
	}
}

func TestNFTGenerationRequiresExactAcknowledgements(t *testing.T) {
	socket := &nftGenerationSocket{sequence: 10}
	requests, err := socket.deleteRequests(3, []nftTableTarget{{family: "inet", name: "fixture"}})
	if err != nil {
		t.Fatal(err)
	}
	pending := make(map[uint32]nftGenerationMessage)
	var packets []byte
	for _, request := range requests {
		pending[request.sequence] = request
		body := append(make([]byte, 4), request.wire[:16]...)
		packets = append(packets, fixtureNFTGenerationReply(request, unix.NLMSG_ERROR, unix.NLM_F_CAPPED, body)...)
	}
	received := make(map[uint32][]byte)
	if err := decodeNFTGenerationReplies(packets, 1234, pending, received); err != nil || len(received) != 3 {
		t.Fatal(received, err)
	}
	if err := decodeNFTGenerationReplies(packets, 1234, pending, received); err == nil {
		t.Fatal("duplicate acknowledgements were accepted")
	}
	cases := map[string][]byte{"empty": nil, "short": packets[:15], "truncated": packets[:len(packets)-1], "oversized": make([]byte, maximumNFTGenerationPacket+1)}
	for name, offset := range map[string]int{"message length": 0, "message type": 4, "flags": 6, "sequence": 8, "port": 12, "echoed request": 20} {
		packet := bytes.Clone(packets)
		packet[offset] ^= 1
		cases[name] = packet
	}
	for name, packet := range cases {
		t.Run(name, func(t *testing.T) {
			if err := decodeNFTGenerationReplies(packet, 1234, pending, make(map[uint32][]byte)); err == nil {
				t.Fatal("invalid acknowledgement accepted")
			}
		})
	}
	// An acknowledgement for an individual delete does not establish that
	// the batch committed. The end acknowledgement must also be received.
	received = make(map[uint32][]byte)
	if err := decodeNFTGenerationReplies(packets[:len(packets)-36], 1234, pending, received); err != nil || len(received) == len(pending) {
		t.Fatal("incomplete batch appeared complete", err)
	}
	request := requests[0]
	body := append(make([]byte, 4), request.wire...)
	binary.NativeEndian.PutUint32(body, ^uint32(84)) // Kernel -ERESTART, without a signed conversion.
	if err := decodeNFTGenerationAck(body, 0, request); !errors.Is(err, unix.ERESTART) {
		t.Fatal("generation refusal lost its cause", err)
	}
	for _, code := range []uint32{1, 4095, 0xffff0000} {
		binary.NativeEndian.PutUint32(body, code)
		if err := decodeNFTGenerationAck(body, 0, request); err == nil {
			t.Fatal("invalid errno accepted")
		}
	}
}

func TestNFTGenerationRequiresBoundedTargetsAndNonzeroGeneration(t *testing.T) {
	target := nftTableTarget{family: "inet", name: "fixture"}
	for _, targets := range [][]nftTableTarget{nil, {target, target}, {{family: "unknown", name: "fixture"}}, {{family: "inet", name: "bad name"}}, {{family: "inet", name: "x\x00y"}}, {{family: "inet", name: strings.Repeat("a", 256)}}, {target, target, target, target, target}} {
		if err := validateNFTGenerationTargets(targets); err == nil {
			t.Fatal("invalid targets accepted", targets)
		}
	}
	socket := &nftGenerationSocket{sequence: 1}
	if _, err := socket.deleteRequests(0, []nftTableTarget{target}); err == nil {
		t.Fatal("zero bypass accepted")
	}
	requests, err := socket.deleteRequests(0x01020003, []nftTableTarget{target})
	if err != nil {
		t.Fatal(err)
	}
	if len(requests) != 3 || !bytes.Equal(requests[0].wire[16:20], []byte{0, 0, 0, 10}) || binary.BigEndian.Uint32(requests[0].wire[24:28]) != 0x01020003 {
		t.Fatal("batch lost its nonzero generation fence")
	}
	if _, err := newNFTGenerationFence(context.Background(), nil); err == nil {
		t.Fatal("missing ownership inspector accepted")
	}
	for _, test := range []struct {
		name       string
		expiry     time.Time
		generation uint32
		guard      func() error
	}{
		{"expired", time.Now().Add(-time.Second), 3, func() error { return nil }},
		{"zero", time.Now().Add(time.Second), 0, func() error { return nil }},
		{"missing guard", time.Now().Add(time.Second), 3, nil},
		{"refused guard", time.Now().Add(time.Second), 3, func() error { return errors.New("ownership changed") }},
	} {
		t.Run(test.name, func(t *testing.T) {
			fence := &nftGenerationFence{socket: &nftGenerationSocket{fd: -1}, generation: test.generation, expires: test.expiry, targets: []nftTableTarget{target}}
			if err := fence.apply(context.Background(), test.guard); err == nil {
				t.Fatal("unsafe fence accepted")
			}
			if fence.socket != nil {
				t.Fatal("refused fence was reusable")
			}
		})
	}
}

// Synthetic traffic and nftables objects exist only in a distinct single-user
// network namespace. This proves transaction behavior, not product ownership.
func TestNFTGenerationLiveFixture(t *testing.T) {
	if os.Getenv("SYSWARDEN_TEST_NFT_GENERATION_LIVE") != "1" {
		t.Skip("requires a disposable network namespace")
	}
	parent := os.Getenv("SYSWARDEN_TEST_PARENT_NETNS")
	current, err := os.Readlink("/proc/self/ns/net")
	mapping, mapErr := os.ReadFile("/proc/self/uid_map")
	fields := strings.Fields(string(mapping))
	if err != nil || mapErr != nil || parent == "" || parent == current || os.Geteuid() != 0 || len(fields) != 3 || fields[0] != "0" || fields[2] != "1" {
		t.Fatal("fixture requires a distinct single-user network namespace")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	nft := func(args ...string) string {
		output, err := exec.CommandContext(ctx, "/usr/bin/nft", args...).CombinedOutput() // #nosec G204 -- Fixed fixture binary and synthetic test arguments, guarded by a distinct single-user network namespace.
		if err != nil {
			t.Fatalf("fixture nft command failed: %v: %s", err, output)
		}
		return string(output)
	}
	if strings.Contains(nft("-j", "list", "tables"), `"table"`) {
		t.Fatal("fixture namespace is not empty")
	}
	if output, err := exec.CommandContext(ctx, "/usr/bin/ip", "link", "set", "lo", "up").CombinedOutput(); err != nil {
		t.Fatal(string(output), err)
	}
	nft("add", "table", "inet", "sw_generation_fixture")
	nft("add", "chain", "inet", "sw_generation_fixture", "input", "{ type filter hook input priority -2; policy accept; }")
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	go func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			_ = connection.Close()
		}
	}()
	connection := func(source string) bool {
		address := net.ParseIP(source)
		dialer := net.Dialer{Timeout: 150 * time.Millisecond, LocalAddr: &net.TCPAddr{IP: address}}
		conn, err := dialer.DialContext(ctx, "tcp4", listener.Addr().String())
		if err != nil {
			return false
		}
		_ = conn.Close()
		return true
	}
	if !connection("127.0.0.2") || !connection("127.0.0.3") {
		t.Fatal("initial TCP fixture is unavailable")
	}
	target := nftTableTarget{family: "inet", name: "sw_generation_fixture"}
	newFence := func(targets []nftTableTarget) *nftGenerationFence {
		fence, err := newNFTGenerationFence(ctx, func(context.Context) ([]nftTableTarget, error) { return targets, nil })
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(fence.close)
		return fence
	}
	stale := newFence([]nftTableTarget{target})
	nft("add", "rule", "inet", target.name, "input", "ip", "saddr", "127.0.0.2", "drop")
	before := nft("-j", "list", "ruleset")
	if err := stale.apply(ctx, func() error { return nil }); !errors.Is(err, unix.ERESTART) {
		t.Fatal("stale generation was not rejected", err)
	}
	if nft("-j", "list", "ruleset") != before || connection("127.0.0.2") || !connection("127.0.0.3") {
		t.Fatal("concurrent administrator rule or traffic behavior changed")
	}
	if err := stale.apply(ctx, func() error { return nil }); err == nil {
		t.Fatal("stale fence was reusable")
	}
	t.Log("Stale generation refused; concurrent administrator rule, blocked TCP and allowed TCP preserved.")
	empty := nftTableTarget{family: "inet", name: "sw_generation_empty"}
	nft("add", "table", "inet", empty.name)
	before = nft("-j", "list", "ruleset")
	failed := newFence([]nftTableTarget{empty, {family: "inet", name: "sw_generation_missing"}})
	if err := failed.apply(ctx, func() error { return nil }); !errors.Is(err, unix.ENOENT) {
		t.Fatal("missing table did not abort the batch", err)
	}
	if nft("-j", "list", "ruleset") != before {
		t.Fatal("failed multi-operation batch changed the kernel")
	}
	t.Log("A later failed delete aborted the entire batch, including its earlier valid delete.")
	_, err = newNFTGenerationFence(ctx, func(context.Context) ([]nftTableTarget, error) {
		nft("add", "table", "inet", "sw_generation_raced")
		return []nftTableTarget{empty}, nil
	})
	if err == nil || !strings.Contains(err.Error(), "changed during ownership inspection") {
		t.Fatal("inspection race accepted", err)
	}
	targets := []nftTableTarget{empty}
	valid := newFence(targets)
	targets[0] = target
	if err := valid.apply(ctx, func() error { return nil }); err != nil {
		t.Fatal("matching generation failed", err)
	}
	tables := nft("-j", "list", "tables")
	if strings.Contains(tables, empty.name) || !strings.Contains(tables, target.name) || connection("127.0.0.2") || !connection("127.0.0.3") {
		t.Fatal("frozen target or unrelated protection changed")
	}
	t.Log("Matching generation removed only the frozen empty target; administrator protection remains effective.")
	refused := newFence([]nftTableTarget{target})
	before = nft("-j", "list", "ruleset")
	if err := refused.apply(ctx, func() error { return fmt.Errorf("producer guard changed") }); err == nil || nft("-j", "list", "ruleset") != before {
		t.Fatal("final guard refusal changed the kernel", err)
	}
	canceled := newFence([]nftTableTarget{target})
	canceledCtx, cancelNow := context.WithCancel(ctx)
	cancelNow()
	if err := canceled.apply(canceledCtx, func() error { return nil }); !errors.Is(err, context.Canceled) || nft("-j", "list", "ruleset") != before {
		t.Fatal("canceled context changed the kernel", err)
	}
	t.Log("Final producer refusal and canceled context preserved the complete ruleset.")
	testNFTGenerationLiveRuleRetirement(t, ctx, nft, connection)
}

func FuzzNFTGenerationProtocol(f *testing.F) {
	f.Add(fixtureNFTGenerationBody(3))
	socket := &nftGenerationSocket{sequence: 10}
	requests, err := socket.deleteRequests(3, []nftTableTarget{{family: "inet", name: "fixture"}})
	if err != nil {
		f.Fatal(err)
	}
	request := requests[0]
	body := append(make([]byte, 4), request.wire[:16]...)
	f.Add(fixtureNFTGenerationReply(request, unix.NLMSG_ERROR, unix.NLM_F_CAPPED, body))
	pending := map[uint32]nftGenerationMessage{request.sequence: request}
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = decodeNFTGeneration(data)
		_ = decodeNFTGenerationReplies(data, 1234, pending, make(map[uint32][]byte))
	})
}
