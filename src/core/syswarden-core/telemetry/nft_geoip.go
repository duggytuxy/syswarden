package telemetry

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	maxNftGeoIPSetJSONBytes       = 32 * 1024 * 1024
	maxNftGeoIPSetStderrBytes     = 32 * 1024
	maxNftGeoIPLogicalEntries     = 300000
	maxNftGeoIPExecutableBytes    = 128 * 1024 * 1024
	nftGeoIPTelemetryQueryTimeout = 15 * time.Second
)

type nftGeoIPSetSpec struct {
	name     string
	dataType string
	ipv6     bool
}

var nftGeoIPSetSpecs = [...]nftGeoIPSetSpec{
	{name: "syswarden_geoip", dataType: "ipv4_addr"},
	{name: "syswarden_geoip6", dataType: "ipv6_addr", ipv6: true},
}

// nftGeoIPSetJSONSource isolates the fixed nftables query from the parser so
// fixtures can attest the wire contract without requiring kernel privileges.
type nftGeoIPSetJSONSource interface {
	listGeoIPSet(context.Context, nftGeoIPSetSpec) ([]byte, error)
}

type commandNftGeoIPSetJSONSource struct {
	executable string
	identity   nftGeoIPExecutableIdentity
	attestor   nftGeoIPExecutableAttestor
}

type nftGeoIPExecutableIdentity struct {
	digest [sha256.Size]byte
	device uint64
	inode  uint64
	mode   os.FileMode
	uid    uint32
	gid    uint32
	nlink  uint64
	size   int64
}

type nftGeoIPExecutableAttestor struct {
	expectedUID uint32
	trustedRoot string
}

func newCommandNftGeoIPSetJSONSource() (commandNftGeoIPSetJSONSource, error) {
	attestor := nftGeoIPExecutableAttestor{expectedUID: 0, trustedRoot: "/"}
	for _, candidate := range []string{"/usr/sbin/nft", "/usr/bin/nft", "/sbin/nft"} {
		source, err := newCommandNftGeoIPSetJSONSourceForCandidate(candidate, attestor)
		if err == nil {
			return source, nil
		}
	}
	return commandNftGeoIPSetJSONSource{}, fmt.Errorf("trusted nftables executable is unavailable")
}

func newCommandNftGeoIPSetJSONSourceForCandidate(
	candidate string,
	attestor nftGeoIPExecutableAttestor,
) (commandNftGeoIPSetJSONSource, error) {
	resolved, err := attestor.resolve(candidate)
	if err != nil {
		return commandNftGeoIPSetJSONSource{}, err
	}
	executable, identity, err := attestor.pin(resolved)
	if err != nil {
		return commandNftGeoIPSetJSONSource{}, err
	}
	if err := executable.Close(); err != nil {
		return commandNftGeoIPSetJSONSource{}, fmt.Errorf("close pinned nftables executable: %w", err)
	}
	return commandNftGeoIPSetJSONSource{
		executable: resolved,
		identity:   identity,
		attestor:   attestor,
	}, nil
}

func (attestor nftGeoIPExecutableAttestor) resolve(candidate string) (string, error) {
	if err := attestor.validate(); err != nil {
		return "", err
	}
	if candidate == "" || !filepath.IsAbs(candidate) || filepath.Clean(candidate) != candidate {
		return "", fmt.Errorf("nftables executable path is not clean and absolute")
	}
	resolved, err := filepath.EvalSymlinks(candidate)
	if err != nil {
		return "", fmt.Errorf("resolve nftables executable: %w", err)
	}
	resolved = filepath.Clean(resolved)
	if !filepath.IsAbs(resolved) || !pathWithinTrustedRoot(resolved, attestor.trustedRoot) {
		return "", fmt.Errorf("resolved nftables executable is outside the trusted root")
	}
	revalidated, err := filepath.EvalSymlinks(resolved)
	if err != nil || revalidated != resolved {
		return "", fmt.Errorf("nftables executable did not resolve to a canonical path")
	}
	return resolved, nil
}

func (attestor nftGeoIPExecutableAttestor) validate() error {
	if attestor.trustedRoot == "" || !filepath.IsAbs(attestor.trustedRoot) || filepath.Clean(attestor.trustedRoot) != attestor.trustedRoot {
		return fmt.Errorf("nftables executable trusted root is invalid")
	}
	resolved, err := filepath.EvalSymlinks(attestor.trustedRoot)
	if err != nil || resolved != attestor.trustedRoot {
		return fmt.Errorf("nftables executable trusted root is not canonical")
	}
	return nil
}

func pathWithinTrustedRoot(path, trustedRoot string) bool {
	relative, err := filepath.Rel(trustedRoot, path)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func (attestor nftGeoIPExecutableAttestor) attestParents(path string) error {
	if !pathWithinTrustedRoot(path, attestor.trustedRoot) {
		return fmt.Errorf("nftables executable is outside the trusted root")
	}
	for current := filepath.Dir(path); ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil {
			return fmt.Errorf("inspect nftables executable parent %s: %w", current, err)
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
			info.Mode().Perm()&0022 != 0 || stat.Uid != attestor.expectedUID {
			return fmt.Errorf("nftables executable parent %s is not trusted", current)
		}
		if current == attestor.trustedRoot {
			return nil
		}
		parent := filepath.Dir(current)
		if parent == current || !pathWithinTrustedRoot(parent, attestor.trustedRoot) {
			return fmt.Errorf("nftables executable parent chain escaped the trusted root")
		}
	}
}

func (attestor nftGeoIPExecutableAttestor) pin(path string) (*os.File, nftGeoIPExecutableIdentity, error) {
	if err := attestor.validate(); err != nil {
		return nil, nftGeoIPExecutableIdentity{}, err
	}
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, nftGeoIPExecutableIdentity{}, fmt.Errorf("nftables executable path is not canonical and absolute")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return nil, nftGeoIPExecutableIdentity{}, fmt.Errorf("nftables executable path is no longer canonical")
	}
	if err := attestor.attestParents(path); err != nil {
		return nil, nftGeoIPExecutableIdentity{}, err
	}
	before, err := os.Lstat(path)
	if err != nil {
		return nil, nftGeoIPExecutableIdentity{}, fmt.Errorf("inspect nftables executable: %w", err)
	}
	if err := validateNftGeoIPExecutableInfo(before, attestor.expectedUID); err != nil {
		return nil, nftGeoIPExecutableIdentity{}, err
	}

	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, nftGeoIPExecutableIdentity{}, fmt.Errorf("pin nftables executable: %w", err)
	}
	executable := os.NewFile(uintptr(fd), path)
	if executable == nil {
		_ = syscall.Close(fd)
		return nil, nftGeoIPExecutableIdentity{}, fmt.Errorf("pin nftables executable")
	}
	closeWithError := func(pinErr error) (*os.File, nftGeoIPExecutableIdentity, error) {
		_ = executable.Close()
		return nil, nftGeoIPExecutableIdentity{}, pinErr
	}

	opened, err := executable.Stat()
	if err != nil {
		return closeWithError(fmt.Errorf("inspect pinned nftables executable: %w", err))
	}
	if err := validateNftGeoIPExecutableInfo(opened, attestor.expectedUID); err != nil {
		return closeWithError(err)
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, io.LimitReader(executable, maxNftGeoIPExecutableBytes+1)); err != nil {
		return closeWithError(fmt.Errorf("hash pinned nftables executable: %w", err))
	}
	if _, err := executable.Seek(0, io.SeekStart); err != nil {
		return closeWithError(fmt.Errorf("rewind pinned nftables executable: %w", err))
	}
	var digest [sha256.Size]byte
	copy(digest[:], hash.Sum(nil))
	identity, err := nftGeoIPExecutableIdentityFromInfo(opened, digest)
	if err != nil {
		return closeWithError(err)
	}
	after, err := os.Lstat(path)
	if err != nil {
		return closeWithError(fmt.Errorf("reattest nftables executable path: %w", err))
	}
	afterIdentity, err := nftGeoIPExecutableIdentityFromInfo(after, digest)
	if err != nil || identity != afterIdentity || !os.SameFile(before, opened) || !os.SameFile(opened, after) {
		return closeWithError(fmt.Errorf("nftables executable identity changed while pinning"))
	}
	if err := attestor.attestParents(path); err != nil {
		return closeWithError(fmt.Errorf("reattest nftables executable parents: %w", err))
	}
	return executable, identity, nil
}

func validateNftGeoIPExecutableInfo(info os.FileInfo, expectedUID uint32) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm()&0111 == 0 || info.Mode().Perm()&0022 != 0 ||
		stat.Uid != expectedUID || stat.Nlink == 0 || info.Size() < 1 ||
		info.Size() > maxNftGeoIPExecutableBytes {
		return fmt.Errorf("nftables executable has an unsafe identity")
	}
	return nil
}

func nftGeoIPExecutableIdentityFromInfo(
	info os.FileInfo,
	digest [sha256.Size]byte,
) (nftGeoIPExecutableIdentity, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nftGeoIPExecutableIdentity{}, fmt.Errorf("nftables executable identity is unavailable")
	}
	return nftGeoIPExecutableIdentity{
		digest: digest,
		device: uint64(stat.Dev),
		inode:  uint64(stat.Ino),
		mode:   info.Mode(),
		uid:    stat.Uid,
		gid:    stat.Gid,
		nlink:  uint64(stat.Nlink),
		size:   info.Size(),
	}, nil
}

func (source commandNftGeoIPSetJSONSource) listGeoIPSet(ctx context.Context, spec nftGeoIPSetSpec) ([]byte, error) {
	if source.executable == "" {
		return nil, fmt.Errorf("nftables executable is unavailable")
	}
	if spec != nftGeoIPSetSpecs[0] && spec != nftGeoIPSetSpecs[1] {
		return nil, fmt.Errorf("unsupported nftables GeoIP set identity")
	}

	executable, identity, err := source.attestor.pin(source.executable)
	if err != nil {
		return nil, fmt.Errorf("reattest nftables executable immediately before start: %w", err)
	}
	defer func() { _ = executable.Close() }()
	if identity != source.identity {
		return nil, fmt.Errorf("nftables executable changed identity before start")
	}

	// Every command argument is fixed by the two allowlisted set specifications.
	// The executable is the exact attested inode exposed to the child as fd 3.
	// No shell, configuration value, filename, or network input reaches argv.
	cmd := exec.CommandContext( // #nosec G204 -- executable is resolved from a fixed absolute allowlist and every argument is fixed above
		ctx,
		"/proc/self/fd/3",
		"--json",
		"--numeric",
		"list",
		"set",
		"inet",
		"syswarden",
		spec.name,
	)
	cmd.ExtraFiles = []*os.File{executable}
	cmd.Env = []string{
		"LANG=C",
		"LC_ALL=C",
		"PATH=/usr/sbin:/usr/bin:/sbin:/bin",
	}
	stdout := newBoundedCommandCapture(maxNftGeoIPSetJSONBytes)
	stderr := newBoundedCommandCapture(maxNftGeoIPSetStderrBytes)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("query active nftables GeoIP set: %w", err)
	}
	if stdout.exceeded || stderr.exceeded {
		return nil, fmt.Errorf("nftables GeoIP set query exceeded its output bound")
	}
	return stdout.bytes(), nil
}

type boundedCommandCapture struct {
	buffer   bytes.Buffer
	limit    int
	exceeded bool
}

func newBoundedCommandCapture(limit int) *boundedCommandCapture {
	return &boundedCommandCapture{limit: limit}
}

func (capture *boundedCommandCapture) Write(p []byte) (int, error) {
	written := len(p)
	remaining := capture.limit - capture.buffer.Len()
	if remaining <= 0 {
		if len(p) > 0 {
			capture.exceeded = true
		}
		return written, nil
	}
	if len(p) > remaining {
		capture.exceeded = true
		p = p[:remaining]
	}
	_, _ = capture.buffer.Write(p)
	return written, nil
}

func (capture *boundedCommandCapture) bytes() []byte {
	return append([]byte(nil), capture.buffer.Bytes()...)
}

func liveNftGeoIPBlockedCount() int {
	source, err := newCommandNftGeoIPSetJSONSource()
	if err != nil {
		return 0
	}
	return countLiveNftGeoIPEntries(source)
}

func countLiveNftGeoIPEntries(source nftGeoIPSetJSONSource) int {
	if source == nil {
		return 0
	}
	ctx, cancel := context.WithTimeout(context.Background(), nftGeoIPTelemetryQueryTimeout)
	defer cancel()

	total := 0
	for _, spec := range nftGeoIPSetSpecs {
		wire, err := source.listGeoIPSet(ctx, spec)
		if err != nil {
			// The field is an aggregate. A partial family count would look
			// authoritative while understating the active kernel policy.
			return 0
		}
		count, err := parseNftGeoIPSetCount(wire, spec)
		if err != nil {
			return 0
		}
		total += count
	}
	return total
}

func parseNftGeoIPSetCount(wire []byte, spec nftGeoIPSetSpec) (int, error) {
	if len(wire) == 0 {
		return 0, fmt.Errorf("empty nftables JSON output")
	}
	if len(wire) > maxNftGeoIPSetJSONBytes {
		return 0, fmt.Errorf("nftables JSON output exceeds %d bytes", maxNftGeoIPSetJSONBytes)
	}
	if err := rejectDuplicateJSONKeys(wire); err != nil {
		return 0, fmt.Errorf("invalid nftables JSON: %w", err)
	}

	var document struct {
		Nftables []json.RawMessage `json:"nftables"`
	}
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return 0, fmt.Errorf("decode nftables JSON document: %w", err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return 0, err
	}
	if document.Nftables == nil {
		return 0, fmt.Errorf("nftables JSON document has no object list")
	}

	setCount := -1
	metainfoSeen := false
	for _, objectWire := range document.Nftables {
		var object map[string]json.RawMessage
		if err := json.Unmarshal(objectWire, &object); err != nil || len(object) != 1 {
			return 0, fmt.Errorf("nftables JSON list contains an invalid object")
		}
		if metainfo, ok := object["metainfo"]; ok {
			if metainfoSeen || !isJSONObject(metainfo) {
				return 0, fmt.Errorf("nftables JSON contains invalid metainfo")
			}
			metainfoSeen = true
			continue
		}
		setWire, ok := object["set"]
		if !ok || setCount >= 0 {
			return 0, fmt.Errorf("nftables JSON contains an unexpected object")
		}
		count, err := parseNftGeoIPSetObject(setWire, spec)
		if err != nil {
			return 0, err
		}
		setCount = count
	}
	if setCount < 0 {
		return 0, fmt.Errorf("nftables JSON does not contain the requested set")
	}
	return setCount, nil
}

func parseNftGeoIPSetObject(wire json.RawMessage, spec nftGeoIPSetSpec) (int, error) {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(wire, &object); err != nil || object == nil {
		return 0, fmt.Errorf("requested nftables set is malformed")
	}
	allowed := map[string]struct{}{
		"family": {}, "table": {}, "name": {}, "handle": {}, "type": {},
		"policy": {}, "flags": {}, "elem": {}, "timeout": {},
		"gc-interval": {}, "size": {}, "auto-merge": {}, "comment": {},
	}
	for field := range object {
		if _, ok := allowed[field]; !ok {
			return 0, fmt.Errorf("requested nftables set contains unsupported field %q", field)
		}
	}
	if err := requireExactJSONString(object, "family", "inet"); err != nil {
		return 0, err
	}
	if err := requireExactJSONString(object, "table", "syswarden"); err != nil {
		return 0, err
	}
	if err := requireExactJSONString(object, "name", spec.name); err != nil {
		return 0, err
	}
	if err := requireExactJSONString(object, "type", spec.dataType); err != nil {
		return 0, err
	}
	if err := validateNftSetFlags(object["flags"]); err != nil {
		return 0, err
	}
	for _, field := range []string{"handle", "timeout", "gc-interval", "size"} {
		if raw, ok := object[field]; ok {
			if err := validateNonNegativeJSONInteger(raw); err != nil {
				return 0, fmt.Errorf("invalid nftables set %s: %w", field, err)
			}
		}
	}
	if raw, ok := object["auto-merge"]; ok {
		raw = bytes.TrimSpace(raw)
		if bytes.Equal(raw, []byte("null")) {
			return 0, fmt.Errorf("invalid nftables set auto-merge value")
		}
		var value bool
		if err := json.Unmarshal(raw, &value); err != nil {
			return 0, fmt.Errorf("invalid nftables set auto-merge value")
		}
	}
	if raw, ok := object["policy"]; ok {
		var value string
		if err := json.Unmarshal(raw, &value); err != nil || (value != "performance" && value != "memory") {
			return 0, fmt.Errorf("invalid nftables set policy")
		}
	}
	if raw, ok := object["comment"]; ok {
		raw = bytes.TrimSpace(raw)
		if bytes.Equal(raw, []byte("null")) {
			return 0, fmt.Errorf("invalid nftables set comment")
		}
		var value string
		if err := json.Unmarshal(raw, &value); err != nil {
			return 0, fmt.Errorf("invalid nftables set comment")
		}
	}

	elementsWire, ok := object["elem"]
	if !ok {
		return 0, nil
	}
	return parseNftGeoIPElements(elementsWire, spec.ipv6)
}

func validateNftSetFlags(wire json.RawMessage) error {
	wire = bytes.TrimSpace(wire)
	if len(wire) == 0 {
		return fmt.Errorf("requested nftables set has no flags")
	}
	var flags []string
	if wire[0] == '"' {
		var flag string
		if err := json.Unmarshal(wire, &flag); err != nil {
			return fmt.Errorf("requested nftables set has malformed flags")
		}
		flags = []string{flag}
	} else if err := json.Unmarshal(wire, &flags); err != nil {
		return fmt.Errorf("requested nftables set has malformed flags")
	}
	if len(flags) != 1 || flags[0] != "interval" {
		return fmt.Errorf("requested nftables set does not have the exact interval contract")
	}
	return nil
}

type nftAddressInterval struct {
	start netip.Addr
	end   netip.Addr
}

func parseNftGeoIPElements(wire json.RawMessage, ipv6 bool) (int, error) {
	wire = bytes.TrimSpace(wire)
	var elements []json.RawMessage
	if len(wire) > 0 && wire[0] == '[' {
		if err := json.Unmarshal(wire, &elements); err != nil {
			return 0, fmt.Errorf("nftables set has malformed elements")
		}
	} else {
		elements = []json.RawMessage{wire}
	}
	if len(elements) > maxNftGeoIPLogicalEntries {
		return 0, fmt.Errorf("nftables set exceeds %d logical elements", maxNftGeoIPLogicalEntries)
	}

	intervals := make([]nftAddressInterval, 0, len(elements))
	for index, elementWire := range elements {
		interval, err := parseNftGeoIPElement(elementWire, ipv6)
		if err != nil {
			return 0, fmt.Errorf("invalid nftables set element %d: %w", index+1, err)
		}
		intervals = append(intervals, interval)
	}
	sort.Slice(intervals, func(left, right int) bool {
		comparison := intervals[left].start.Compare(intervals[right].start)
		if comparison == 0 {
			return intervals[left].end.Compare(intervals[right].end) < 0
		}
		return comparison < 0
	})
	for index := 1; index < len(intervals); index++ {
		if intervals[index].start.Compare(intervals[index-1].end) <= 0 {
			return 0, fmt.Errorf("nftables set contains overlapping logical elements")
		}
	}
	return len(elements), nil
}

func parseNftGeoIPElement(wire json.RawMessage, ipv6 bool) (nftAddressInterval, error) {
	wire = bytes.TrimSpace(wire)
	if len(wire) == 0 {
		return nftAddressInterval{}, fmt.Errorf("empty expression")
	}
	if wire[0] == '"' {
		address, err := parseCanonicalNftAddress(wire, ipv6)
		return nftAddressInterval{start: address, end: address}, err
	}

	var expression map[string]json.RawMessage
	if err := json.Unmarshal(wire, &expression); err != nil || len(expression) != 1 {
		return nftAddressInterval{}, fmt.Errorf("unsupported expression")
	}
	if prefixWire, ok := expression["prefix"]; ok {
		return parseNftPrefixExpression(prefixWire, ipv6)
	}
	if rangeWire, ok := expression["range"]; ok {
		return parseNftRangeExpression(rangeWire, ipv6)
	}
	return nftAddressInterval{}, fmt.Errorf("unsupported expression")
}

func parseNftPrefixExpression(wire json.RawMessage, ipv6 bool) (nftAddressInterval, error) {
	var prefixObject map[string]json.RawMessage
	if err := json.Unmarshal(wire, &prefixObject); err != nil || len(prefixObject) != 2 {
		return nftAddressInterval{}, fmt.Errorf("malformed prefix expression")
	}
	addressWire, addressOK := prefixObject["addr"]
	lengthWire, lengthOK := prefixObject["len"]
	if !addressOK || !lengthOK {
		return nftAddressInterval{}, fmt.Errorf("malformed prefix expression")
	}
	address, err := parseCanonicalNftAddress(addressWire, ipv6)
	if err != nil {
		return nftAddressInterval{}, err
	}
	length, err := parseJSONInteger(lengthWire)
	if err != nil {
		return nftAddressInterval{}, fmt.Errorf("invalid prefix length")
	}
	maximum := int64(32)
	if ipv6 {
		maximum = 128
	}
	if length < 0 || length > maximum {
		return nftAddressInterval{}, fmt.Errorf("invalid prefix length")
	}
	prefix := netip.PrefixFrom(address, int(length))
	if !prefix.IsValid() || prefix.Masked().Addr() != address {
		return nftAddressInterval{}, fmt.Errorf("prefix address is not canonical")
	}
	return nftAddressInterval{start: address, end: prefixLastAddress(prefix)}, nil
}

func parseNftRangeExpression(wire json.RawMessage, ipv6 bool) (nftAddressInterval, error) {
	var boundaries []json.RawMessage
	if err := json.Unmarshal(wire, &boundaries); err != nil || len(boundaries) != 2 {
		return nftAddressInterval{}, fmt.Errorf("malformed range expression")
	}
	start, err := parseCanonicalNftAddress(boundaries[0], ipv6)
	if err != nil {
		return nftAddressInterval{}, err
	}
	end, err := parseCanonicalNftAddress(boundaries[1], ipv6)
	if err != nil {
		return nftAddressInterval{}, err
	}
	if start.Compare(end) > 0 {
		return nftAddressInterval{}, fmt.Errorf("range boundaries are reversed")
	}
	return nftAddressInterval{start: start, end: end}, nil
}

func parseCanonicalNftAddress(wire json.RawMessage, ipv6 bool) (netip.Addr, error) {
	var raw string
	if err := json.Unmarshal(wire, &raw); err != nil {
		return netip.Addr{}, fmt.Errorf("address is not a string")
	}
	address, err := netip.ParseAddr(raw)
	if err != nil || address.Zone() != "" || address.Is4In6() || address.String() != raw {
		return netip.Addr{}, fmt.Errorf("address %q is not canonical", raw)
	}
	if ipv6 == address.Is4() {
		return netip.Addr{}, fmt.Errorf("address %q has the wrong family", raw)
	}
	return address, nil
}

func prefixLastAddress(prefix netip.Prefix) netip.Addr {
	address := prefix.Masked().Addr()
	bytesValue := address.As16()
	if address.Is4() {
		v4 := address.As4()
		for bit := prefix.Bits(); bit < 32; bit++ {
			v4[bit/8] |= 1 << (7 - uint(bit%8))
		}
		return netip.AddrFrom4(v4)
	}
	for bit := prefix.Bits(); bit < 128; bit++ {
		bytesValue[bit/8] |= 1 << (7 - uint(bit%8))
	}
	return netip.AddrFrom16(bytesValue)
}

func requireExactJSONString(object map[string]json.RawMessage, field, wanted string) error {
	wire, ok := object[field]
	if !ok {
		return fmt.Errorf("requested nftables set has no %s", field)
	}
	var value string
	if err := json.Unmarshal(wire, &value); err != nil || value != wanted {
		return fmt.Errorf("requested nftables set has unexpected %s", field)
	}
	return nil
}

func validateNonNegativeJSONInteger(wire json.RawMessage) error {
	value, err := parseJSONInteger(wire)
	if err != nil || value < 0 {
		return fmt.Errorf("expected a non-negative integer")
	}
	return nil
}

func parseJSONInteger(wire json.RawMessage) (int64, error) {
	var number json.Number
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.UseNumber()
	if err := decoder.Decode(&number); err != nil {
		return 0, err
	}
	return strconv.ParseInt(number.String(), 10, 64)
}

func isJSONObject(wire json.RawMessage) bool {
	var object map[string]json.RawMessage
	return json.Unmarshal(wire, &object) == nil && object != nil
}

func requireJSONEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("nftables JSON has trailing content")
		}
		return fmt.Errorf("decode trailing nftables JSON: %w", err)
	}
	return nil
}

func rejectDuplicateJSONKeys(wire []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.UseNumber()
	if err := scanUniqueJSONValue(decoder); err != nil {
		return err
	}
	if err := requireJSONEOF(decoder); err != nil {
		return err
	}
	return nil
}

func scanUniqueJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return fmt.Errorf("object key is not a string")
			}
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("duplicate object key %q", key)
			}
			seen[key] = struct{}{}
			if err := scanUniqueJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return fmt.Errorf("malformed JSON object")
		}
	case '[':
		for decoder.More() {
			if err := scanUniqueJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return fmt.Errorf("malformed JSON array")
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delimiter)
	}
	return nil
}
