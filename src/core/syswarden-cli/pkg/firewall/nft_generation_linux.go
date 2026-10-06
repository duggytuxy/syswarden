//go:build linux

package firewall

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"runtime"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

const maximumNFTGenerationPacket = 16384

// A generation fence prevents a verified table from being removed after any
// intervening nftables transaction. It does not establish table ownership.
// The inspector must independently prove complete ownership, dependencies and
// producer quiescence. Its returned targets are frozen before the fence is
// issued. The caller must durably record intent and reconcile an uncertain
// outcome before retrying with a newly inspected plan.
type nftGenerationFence struct {
	mu         sync.Mutex
	socket     *nftGenerationSocket
	generation uint32
	targets    []nftTableTarget
	expires    time.Time
}

type nftGenerationSocket struct {
	fd        int
	port      uint32
	sequence  uint32
	namespace *os.File
}

type nftGenerationMessage struct {
	wire      []byte
	sequence  uint32
	replyType uint16
}

func newNFTGenerationFence(ctx context.Context, inspect func(context.Context) ([]nftTableTarget, error)) (*nftGenerationFence, error) {
	if inspect == nil {
		return nil, fmt.Errorf("nftables generation fence requires an independent ownership inspector")
	}
	child, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	socket, err := openNFTGenerationSocket()
	if err != nil {
		return nil, err
	}
	accepted := false
	defer func() {
		if !accepted {
			socket.close()
		}
	}()
	before, err := socket.generation(child)
	if err != nil {
		return nil, err
	}
	targets, err := inspect(child)
	if err != nil {
		return nil, err
	}
	// Do not retain a caller-owned slice that could be changed after review.
	targets = append([]nftTableTarget(nil), targets...)
	if err := validateNFTGenerationTargets(targets); err != nil {
		return nil, err
	}
	after, err := socket.generation(child)
	if err != nil {
		return nil, err
	}
	if before != after {
		return nil, fmt.Errorf("nftables changed during ownership inspection; preserve the reviewed evidence")
	}
	accepted = true
	return &nftGenerationFence{socket: socket, generation: after, targets: targets, expires: time.Now().Add(10 * time.Second)}, nil
}

// Apply is single-use even on refusal. Never refresh the generation or retry a
// rejected batch automatically: doing so would authorize unreviewed rules.
func (fence *nftGenerationFence) apply(ctx context.Context, guard func() error) error {
	fence.mu.Lock()
	defer fence.mu.Unlock()
	if fence.socket == nil {
		return fmt.Errorf("nftables generation fence is closed or already consumed")
	}
	socket := fence.socket
	fence.socket = nil
	defer socket.close()
	if guard == nil || fence.generation == 0 || !time.Now().Before(fence.expires) {
		return fmt.Errorf("nftables generation fence is expired or lacks a final ownership guard")
	}
	child, cancel := context.WithDeadline(ctx, fence.expires)
	defer cancel()
	if err := child.Err(); err != nil {
		return err
	}
	if err := guard(); err != nil {
		return err
	}
	if err := child.Err(); err != nil {
		return err
	}
	requests, err := socket.deleteRequests(fence.generation, fence.targets)
	if err != nil {
		return err
	}
	if _, err := socket.exchange(child, requests); err != nil {
		return fmt.Errorf("nftables generation-bound retirement was not confirmed; reconcile durable intent before another inspection: %w", err)
	}
	return nil
}

func (fence *nftGenerationFence) close() {
	fence.mu.Lock()
	defer fence.mu.Unlock()
	if fence.socket != nil {
		fence.socket.close()
		fence.socket = nil
	}
}

func openNFTGenerationSocket() (*nftGenerationSocket, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	namespace, err := os.Open("/proc/thread-self/ns/net")
	if err != nil {
		return nil, err
	}
	socket := &nftGenerationSocket{fd: -1, namespace: namespace}
	accepted := false
	defer func() {
		if !accepted {
			socket.close()
		}
	}()
	socket.fd, err = unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, unix.NETLINK_NETFILTER)
	if err != nil {
		return nil, err
	}
	if socket.fd > 1<<31-1 {
		return nil, fmt.Errorf("nftables netlink descriptor exceeds the poll bound")
	}
	if err := unix.Bind(socket.fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, err
	}
	address, err := unix.Getsockname(socket.fd)
	if err != nil {
		return nil, err
	}
	local, ok := address.(*unix.SockaddrNetlink)
	if !ok || local.Pid == 0 || local.Groups != 0 {
		return nil, fmt.Errorf("nftables netlink socket has an invalid local identity")
	}
	socket.port = local.Pid
	var seed [4]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return nil, err
	}
	socket.sequence = binary.NativeEndian.Uint32(seed[:]) & 0x7fffffff
	if socket.sequence == 0 {
		socket.sequence = 1
	}
	if err := socket.verifyNamespace(); err != nil {
		return nil, err
	}
	accepted = true
	return socket, nil
}

func (socket *nftGenerationSocket) close() {
	if socket.fd >= 0 {
		_ = unix.Close(socket.fd)
		socket.fd = -1
	}
	if socket.namespace != nil {
		_ = socket.namespace.Close()
		socket.namespace = nil
	}
}

func (socket *nftGenerationSocket) verifyNamespace() error {
	if socket.fd < 0 || socket.namespace == nil {
		return fmt.Errorf("nftables generation socket is closed")
	}
	pinned, err := socket.namespace.Stat()
	if err != nil {
		return err
	}
	current, err := os.Stat("/proc/thread-self/ns/net")
	if err != nil || !os.SameFile(pinned, current) {
		return fmt.Errorf("nftables network namespace changed during retirement")
	}
	return nil
}

func (socket *nftGenerationSocket) request(kind, flags, replyType uint16, body []byte) (nftGenerationMessage, error) {
	if len(body) > maximumNFTGenerationPacket-16 || socket.sequence == 0 || socket.sequence >= 0xfffffff0 {
		return nftGenerationMessage{}, fmt.Errorf("nftables request exceeds protocol bounds")
	}
	wire := make([]byte, 16+len(body))
	size := len(wire)
	if size < 16 || size > maximumNFTGenerationPacket {
		return nftGenerationMessage{}, fmt.Errorf("nftables message length exceeds its bound")
	}
	binary.NativeEndian.PutUint32(wire, uint32(size))
	binary.NativeEndian.PutUint16(wire[4:], kind)
	binary.NativeEndian.PutUint16(wire[6:], flags)
	binary.NativeEndian.PutUint32(wire[8:], socket.sequence)
	copy(wire[16:], body)
	request := nftGenerationMessage{wire: wire, sequence: socket.sequence, replyType: replyType}
	socket.sequence++
	return request, nil
}

func nftGenerationAttribute(kind uint16, value []byte) ([]byte, error) {
	if len(value) > 256 {
		return nil, fmt.Errorf("nftables generation attribute exceeds its bound")
	}
	length := 4 + len(value)
	if length < 4 || length > 260 {
		return nil, fmt.Errorf("nftables attribute length exceeds its bound")
	}
	wire := make([]byte, (length+3)&^3)
	binary.NativeEndian.PutUint16(wire, uint16(length))
	binary.NativeEndian.PutUint16(wire[2:], kind)
	copy(wire[4:], value)
	return wire, nil
}

func validateNFTGenerationTargets(targets []nftTableTarget) error {
	if len(targets) == 0 || len(targets) > 4 {
		return fmt.Errorf("nftables generation fence requires one to four exact tables")
	}
	seen := make(map[nftTableTarget]bool)
	for _, target := range targets {
		if _, ok := nftGenerationFamily(target.family); !ok || seen[target] || len(target.name) == 0 || len(target.name) > 255 {
			return fmt.Errorf("nftables generation fence has invalid or duplicate table targets")
		}
		for _, c := range target.name {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
				return fmt.Errorf("nftables generation fence table name is outside the bounded identifier profile")
			}
		}
		seen[target] = true
	}
	return nil
}

func nftGenerationFamily(family string) (byte, bool) {
	switch family {
	case "inet":
		return unix.NFPROTO_INET, true
	case "ip":
		return unix.NFPROTO_IPV4, true
	case "ip6":
		return unix.NFPROTO_IPV6, true
	case "arp":
		return unix.NFPROTO_ARP, true
	case "bridge":
		return unix.NFPROTO_BRIDGE, true
	case "netdev":
		return unix.NFPROTO_NETDEV, true
	default:
		return 0, false
	}
}

func (socket *nftGenerationSocket) deleteRequests(generation uint32, targets []nftTableTarget) ([]nftGenerationMessage, error) {
	// Zero explicitly disables the kernel generation check and is forbidden.
	if generation == 0 {
		return nil, fmt.Errorf("zero nftables generation cannot authorize retirement")
	}
	if err := validateNFTGenerationTargets(targets); err != nil {
		return nil, err
	}
	var encoded [4]byte
	binary.BigEndian.PutUint32(encoded[:], generation)
	attribute, err := nftGenerationAttribute(unix.NFNL_BATCH_GENID, encoded[:])
	if err != nil {
		return nil, err
	}
	begin, err := socket.request(unix.NFNL_MSG_BATCH_BEGIN, unix.NLM_F_REQUEST|unix.NLM_F_ACK, unix.NLMSG_ERROR, append([]byte{0, 0, 0, unix.NFNL_SUBSYS_NFTABLES}, attribute...))
	if err != nil {
		return nil, err
	}
	requests := []nftGenerationMessage{begin}
	for _, target := range targets {
		family, _ := nftGenerationFamily(target.family)
		attribute, err := nftGenerationAttribute(unix.NFTA_TABLE_NAME, append([]byte(target.name), 0))
		if err != nil {
			return nil, err
		}
		request, err := socket.request(unix.NFNL_SUBSYS_NFTABLES<<8|unix.NFT_MSG_DELTABLE, unix.NLM_F_REQUEST|unix.NLM_F_ACK, unix.NLMSG_ERROR, append([]byte{family, 0, 0, 0}, attribute...))
		if err != nil {
			return nil, err
		}
		requests = append(requests, request)
	}
	end, err := socket.request(unix.NFNL_MSG_BATCH_END, unix.NLM_F_REQUEST|unix.NLM_F_ACK, unix.NLMSG_ERROR, []byte{0, 0, 0, unix.NFNL_SUBSYS_NFTABLES})
	if err != nil {
		return nil, err
	}
	return append(requests, end), nil
}

func (socket *nftGenerationSocket) generation(ctx context.Context) (uint32, error) {
	request, err := socket.request(unix.NFNL_SUBSYS_NFTABLES<<8|unix.NFT_MSG_GETGEN, unix.NLM_F_REQUEST, unix.NFNL_SUBSYS_NFTABLES<<8|unix.NFT_MSG_NEWGEN, make([]byte, 4))
	if err != nil {
		return 0, err
	}
	replies, err := socket.exchange(ctx, []nftGenerationMessage{request})
	if err != nil {
		return 0, err
	}
	return decodeNFTGeneration(replies[request.sequence])
}

func (socket *nftGenerationSocket) exchange(ctx context.Context, requests []nftGenerationMessage) (map[uint32][]byte, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := socket.verifyNamespace(); err != nil {
		return nil, err
	}
	deadline, ok := ctx.Deadline()
	if !ok || time.Until(deadline) > 30*time.Second {
		return nil, fmt.Errorf("nftables netlink exchange requires a bounded deadline")
	}
	pending := make(map[uint32]nftGenerationMessage)
	var packet []byte
	for _, request := range requests {
		if _, duplicate := pending[request.sequence]; duplicate || len(request.wire) < 16 || len(packet)+len(request.wire) > maximumNFTGenerationPacket {
			return nil, fmt.Errorf("nftables netlink batch is malformed or unbounded")
		}
		pending[request.sequence] = request
		packet = append(packet, request.wire...)
	}
	if len(pending) == 0 || len(pending) > 6 {
		return nil, fmt.Errorf("nftables netlink batch has an invalid operation count")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := unix.Sendto(socket.fd, packet, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, err
	}
	received := make(map[uint32][]byte)
	buffer := make([]byte, maximumNFTGenerationPacket)
	for len(received) < len(pending) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		n, ancillary, flags, peer, err := unix.Recvmsg(socket.fd, buffer, nil, unix.MSG_DONTWAIT)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if errors.Is(err, unix.EAGAIN) {
			if socket.fd < 0 || socket.fd > 1<<31-1 {
				return nil, fmt.Errorf("nftables netlink descriptor is invalid")
			}
			poll := []unix.PollFd{{Fd: int32(socket.fd), Events: unix.POLLIN}}
			if _, err := unix.Poll(poll, 25); err != nil && !errors.Is(err, unix.EINTR) {
				return nil, err
			}
			if poll[0].Revents&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 {
				return nil, fmt.Errorf("nftables netlink socket became unavailable")
			}
			continue
		}
		if err != nil {
			return nil, err
		}
		sender, ok := peer.(*unix.SockaddrNetlink)
		if !ok || sender.Family != unix.AF_NETLINK || sender.Pid != 0 || sender.Groups != 0 || ancillary != 0 || flags != 0 || n <= 0 || n > len(buffer) {
			return nil, fmt.Errorf("nftables response has an untrusted sender or truncated envelope")
		}
		if err := decodeNFTGenerationReplies(buffer[:n], socket.port, pending, received); err != nil {
			return nil, err
		}
	}
	if err := socket.verifyNamespace(); err != nil {
		return nil, err
	}
	return received, nil
}

func decodeNFTGenerationReplies(packet []byte, port uint32, pending map[uint32]nftGenerationMessage, received map[uint32][]byte) error {
	if len(packet) == 0 || len(packet) > maximumNFTGenerationPacket || port == 0 {
		return fmt.Errorf("invalid nftables response packet")
	}
	for len(packet) > 0 {
		if len(packet) < 16 {
			return fmt.Errorf("truncated nftables response header")
		}
		length := binary.NativeEndian.Uint32(packet)
		if length < 16 || uint64(length) > uint64(len(packet)) {
			return fmt.Errorf("invalid nftables response length")
		}
		size := int(length)
		padded := (size + 3) &^ 3
		if padded > len(packet) {
			return fmt.Errorf("truncated nftables response padding")
		}
		for _, value := range packet[size:padded] {
			if value != 0 {
				return fmt.Errorf("nonzero nftables response padding")
			}
		}
		kind := binary.NativeEndian.Uint16(packet[4:])
		flags := binary.NativeEndian.Uint16(packet[6:])
		sequence := binary.NativeEndian.Uint32(packet[8:])
		request, expected := pending[sequence]
		_, duplicate := received[sequence]
		if !expected || duplicate || binary.NativeEndian.Uint32(packet[12:]) != port {
			return fmt.Errorf("nftables response identity differs from its request")
		}
		body := packet[16:size]
		if kind == unix.NLMSG_ERROR {
			if err := decodeNFTGenerationAck(body, flags, request); err != nil {
				return err
			}
			if request.replyType != unix.NLMSG_ERROR {
				return fmt.Errorf("nftables generation query returned an unexpected acknowledgement")
			}
		} else if kind != request.replyType || flags != 0 {
			return fmt.Errorf("unexpected nftables response type or flags")
		}
		received[sequence] = bytes.Clone(body)
		packet = packet[padded:]
	}
	return nil
}

func decodeNFTGenerationAck(body []byte, flags uint16, request nftGenerationMessage) error {
	if len(body) < 20 || len(request.wire) < 16 || flags & ^uint16(unix.NLM_F_CAPPED) != 0 || !bytes.Equal(body[4:20], request.wire[:16]) {
		return fmt.Errorf("nftables acknowledgement does not attest the exact request")
	}
	if flags&unix.NLM_F_CAPPED != 0 {
		if len(body) != 20 {
			return fmt.Errorf("invalid capped nftables acknowledgement")
		}
	} else if !bytes.Equal(body[4:], request.wire) {
		return fmt.Errorf("nftables acknowledgement has an incomplete or altered request")
	}
	code := binary.NativeEndian.Uint32(body)
	if code == 0 {
		return nil
	}
	// Linux errno replies are negative signed 32-bit values. Decode through a
	// wider signed representation without accepting positive or wrapped codes.
	signed := int64(code) - 1<<32
	if signed < -4095 || signed >= 0 {
		return fmt.Errorf("invalid nftables kernel error code")
	}
	return fmt.Errorf("nftables kernel refused the generation-bound request: %w", unix.Errno(-signed))
}

func decodeNFTGeneration(body []byte) (uint32, error) {
	if len(body) < 12 || len(body) > 4096 || body[0] != 0 || body[1] != 0 {
		return 0, fmt.Errorf("invalid nftables generation response")
	}
	attributes := body[4:]
	seen := make(map[uint16]bool)
	var generation uint32
	for len(attributes) > 0 {
		if len(attributes) < 4 {
			return 0, fmt.Errorf("truncated nftables generation attribute")
		}
		size := int(binary.NativeEndian.Uint16(attributes))
		kind := binary.NativeEndian.Uint16(attributes[2:])
		if size < 4 || size > len(attributes) || (size+3)&^3 > len(attributes) || seen[kind] {
			return 0, fmt.Errorf("invalid or duplicate nftables generation attribute")
		}
		seen[kind] = true
		value := attributes[4:size]
		switch kind {
		case unix.NFTA_GEN_ID:
			if len(value) != 4 {
				return 0, fmt.Errorf("invalid nftables generation identifier width")
			}
			generation = binary.BigEndian.Uint32(value)
		case unix.NFTA_GEN_PROC_PID:
			if len(value) != 4 {
				return 0, fmt.Errorf("invalid nftables generation process width")
			}
		case unix.NFTA_GEN_PROC_NAME:
			if len(value) == 0 || len(value) > 256 || value[len(value)-1] != 0 || bytes.IndexByte(value[:len(value)-1], 0) >= 0 {
				return 0, fmt.Errorf("invalid nftables generation process name")
			}
		default:
			return 0, fmt.Errorf("unsupported nftables generation attribute")
		}
		for _, pad := range attributes[size : (size+3)&^3] {
			if pad != 0 {
				return 0, fmt.Errorf("invalid nftables generation padding")
			}
		}
		attributes = attributes[(size+3)&^3:]
	}
	if generation == 0 || binary.BigEndian.Uint16(body[2:4]) != uint16(generation&0xffff) {
		return 0, fmt.Errorf("nftables generation identifier is zero or inconsistent")
	}
	return generation, nil
}
