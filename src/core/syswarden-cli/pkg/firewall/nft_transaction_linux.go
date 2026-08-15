//go:build linux

package firewall

import (
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	nftStateDirectory = "/etc/syswarden"
	nftStateFile      = "/etc/syswarden/syswarden.nft"
)

var (
	nftReloadMu        sync.Mutex
	nftRuntimeLockPath = "/run/syswarden-firewall.lock"
	nftSetNameRE       = regexp.MustCompile(`^[a-zA-Z0-9_]+$`)
)

type nftCommandRunner interface {
	Run(ctx context.Context, stdin []byte, args ...string) ([]byte, error)
}

type execNFTCommandRunner struct{}

func (execNFTCommandRunner) Run(ctx context.Context, stdin []byte, args ...string) ([]byte, error) {
	if stdin != nil {
		return nil, fmt.Errorf("nft command input is unsupported")
	}
	var cmd *exec.Cmd
	var commandFile *os.File
	defer func() {
		if commandFile != nil {
			_ = commandFile.Close()
		}
	}()
	switch {
	case len(args) == 3 && args[0] == "-j" && args[1] == "list" && args[2] == "tables":
		cmd = exec.CommandContext(ctx, "nft", "-j", "list", "tables")
	case len(args) == 3 && args[0] == "-j" && args[1] == "list" && args[2] == "ruleset":
		cmd = exec.CommandContext(ctx, "nft", "-j", "list", "ruleset")
	case len(args) == 4 && args[0] == "list" && args[1] == "table":
		target := nftTableTarget{family: args[2], name: args[3]}
		switch target {
		case nftTableTarget{family: "inet", name: "syswarden"}:
			cmd = exec.CommandContext(ctx, "nft", "list", "table", "inet", "syswarden")
		case nftTableTarget{family: "inet", name: "syswarden_table"}:
			cmd = exec.CommandContext(ctx, "nft", "list", "table", "inet", "syswarden_table")
		case nftTableTarget{family: "netdev", name: "syswarden_hw_drop"}:
			cmd = exec.CommandContext(ctx, "nft", "list", "table", "netdev", "syswarden_hw_drop")
		case nftTableTarget{family: "arp", name: "syswarden_arp"}:
			cmd = exec.CommandContext(ctx, "nft", "list", "table", "arp", "syswarden_arp")
		default:
			return nil, fmt.Errorf("refuse unexpected nftables table %s %s", target.family, target.name)
		}
	case len(args) == 3 && args[0] == "-c" && args[1] == "-f":
		var err error
		commandFile, err = openPrivateNFTCommandFile(args[2])
		if err != nil {
			return nil, err
		}
		cmd = exec.CommandContext(ctx, "nft", "-c", "-f", "/proc/self/fd/3")
		cmd.ExtraFiles = []*os.File{commandFile}
	case len(args) == 2 && args[0] == "-f":
		var err error
		commandFile, err = openPrivateNFTCommandFile(args[1])
		if err != nil {
			return nil, err
		}
		cmd = exec.CommandContext(ctx, "nft", "-f", "/proc/self/fd/3")
		cmd.ExtraFiles = []*os.File{commandFile}
	default:
		return nil, fmt.Errorf("refuse unsupported nft command")
	}
	return cmd.CombinedOutput()
}

type nftListSource struct {
	path     string
	required bool
}

type nftSetPopulation struct {
	name    string
	entries []string
}

type nftObjectKey struct {
	family string
	table  string
	name   string
}

type nftVerificationPlan struct {
	tables map[nftObjectKey]struct{}
	chains map[nftObjectKey]string
	sets   map[nftObjectKey]int // negative cardinality means existence-only for runtime-owned sets
}

type nftTableTarget struct {
	family string
	name   string
}

var syswardenNFTTables = []nftTableTarget{
	{family: "inet", name: "syswarden"},
	{family: "inet", name: "syswarden_table"},
	{family: "netdev", name: "syswarden_hw_drop"},
	{family: "arp", name: "syswarden_arp"},
}

func isSyswardenNFTTable(target nftTableTarget) bool {
	for _, allowed := range syswardenNFTTables {
		if target == allowed {
			return true
		}
	}
	return false
}

func openRootedNFTFile(path string, flags int, permission fs.FileMode) (*os.File, error) {
	cleanPath := filepath.Clean(path)
	if !filepath.IsAbs(cleanPath) || cleanPath != path {
		return nil, fmt.Errorf("nftables file path is not absolute and canonical: %q", path)
	}
	name := filepath.Base(cleanPath)
	if name == "." || name == string(filepath.Separator) {
		return nil, fmt.Errorf("nftables file path has no safe basename: %q", path)
	}
	root, err := os.OpenRoot(filepath.Dir(cleanPath))
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	return root.OpenFile(name, flags|syscall.O_NOFOLLOW, permission)
}

func readRootedNFTFile(path string) ([]byte, error) {
	file, err := openRootedNFTFile(path, os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("nftables input is not a regular file: %s", path)
	}
	return io.ReadAll(file)
}

func openPrivateNFTCommandFile(path string) (*os.File, error) {
	if filepath.Ext(path) != ".nft" {
		return nil, fmt.Errorf("nftables command file does not use the .nft suffix")
	}
	file, err := openRootedNFTFile(path, os.O_RDONLY, 0)
	if err != nil {
		return nil, fmt.Errorf("open nftables command file: %w", err)
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("inspect nftables command file: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		_ = file.Close()
		return nil, fmt.Errorf("nftables command file is not a private regular file")
	}
	return file, nil
}

type nftJSONDocument struct {
	NFTables []nftJSONEntry `json:"nftables"`
}

type nftJSONEntry struct {
	Table   *nftJSONTable   `json:"table,omitempty"`
	Chain   *nftJSONChain   `json:"chain,omitempty"`
	Set     *nftJSONSet     `json:"set,omitempty"`
	Element *nftJSONElement `json:"element,omitempty"`
}

type nftJSONTable struct {
	Family string `json:"family"`
	Name   string `json:"name"`
}

type nftJSONChain struct {
	Family string `json:"family"`
	Table  string `json:"table"`
	Name   string `json:"name"`
	Hook   string `json:"hook"`
}

type nftJSONSet struct {
	Family   string            `json:"family"`
	Table    string            `json:"table"`
	Name     string            `json:"name"`
	Elements []json.RawMessage `json:"elem"`
}

type nftJSONElement struct {
	Family   string            `json:"family"`
	Table    string            `json:"table"`
	Name     string            `json:"name"`
	Elements []json.RawMessage `json:"elem"`
}

type nftDynamicBan struct {
	start   netip.Addr
	end     netip.Addr
	timeout time.Duration
	expires time.Duration
}

type nftDynamicSnapshot struct {
	capturedAt time.Time
	sets       map[nftObjectKey]map[string]nftDynamicBan
}

var nftDynamicBanSets = []nftObjectKey{
	{family: "inet", table: "syswarden", name: "banned_ips"},
	{family: "inet", table: "syswarden", name: "banned_ips6"},
	{family: "netdev", table: "syswarden_hw_drop", name: "banned_ips"},
	{family: "netdev", table: "syswarden_hw_drop", name: "banned_ips6"},
}

func newNFTDynamicSnapshot(capturedAt time.Time) nftDynamicSnapshot {
	snapshot := nftDynamicSnapshot{
		capturedAt: capturedAt,
		sets:       make(map[nftObjectKey]map[string]nftDynamicBan, len(nftDynamicBanSets)),
	}
	for _, key := range nftDynamicBanSets {
		snapshot.sets[key] = make(map[string]nftDynamicBan)
	}
	return snapshot
}

func dynamicBanIdentity(ban nftDynamicBan) string {
	return ban.start.String() + "-" + ban.end.String()
}

func dynamicBanExpression(ban nftDynamicBan) string {
	if ban.start == ban.end {
		return ban.start.String()
	}
	return ban.start.String() + "-" + ban.end.String()
}

func parseNFTDuration(raw json.RawMessage, label string) (time.Duration, error) {
	if len(bytes.TrimSpace(raw)) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return 0, nil
	}
	var milliseconds int64
	if err := json.Unmarshal(raw, &milliseconds); err != nil || milliseconds < 0 {
		return 0, fmt.Errorf("%s is not a non-negative millisecond integer", label)
	}
	if milliseconds > int64((time.Duration(1<<63-1))/time.Millisecond) {
		return 0, fmt.Errorf("%s exceeds the supported duration", label)
	}
	return time.Duration(milliseconds) * time.Millisecond, nil
}

func parseNFTAddressExpression(raw json.RawMessage) (netip.Addr, netip.Addr, error) {
	var text string
	if err := json.Unmarshal(raw, &text); err == nil {
		interval, intervalErr := nftIntervalForEntry(text)
		if intervalErr != nil {
			return netip.Addr{}, netip.Addr{}, intervalErr
		}
		return interval.start, interval.end, nil
	}

	var expression struct {
		Prefix *struct {
			Address string `json:"addr"`
			Length  int    `json:"len"`
		} `json:"prefix"`
		Range []json.RawMessage `json:"range"`
	}
	if err := json.Unmarshal(raw, &expression); err != nil {
		return netip.Addr{}, netip.Addr{}, fmt.Errorf("decode nftables address expression: %w", err)
	}
	if expression.Prefix != nil {
		prefix, err := netip.ParsePrefix(fmt.Sprintf("%s/%d", expression.Prefix.Address, expression.Prefix.Length))
		if err != nil || prefix.Addr().Is4In6() {
			return netip.Addr{}, netip.Addr{}, fmt.Errorf("invalid nftables prefix expression")
		}
		interval, err := nftIntervalForEntry(prefix.Masked().String())
		if err != nil {
			return netip.Addr{}, netip.Addr{}, err
		}
		return interval.start, interval.end, nil
	}
	if len(expression.Range) == 2 {
		var first, last string
		if err := json.Unmarshal(expression.Range[0], &first); err != nil {
			return netip.Addr{}, netip.Addr{}, fmt.Errorf("decode nftables range start: %w", err)
		}
		if err := json.Unmarshal(expression.Range[1], &last); err != nil {
			return netip.Addr{}, netip.Addr{}, fmt.Errorf("decode nftables range end: %w", err)
		}
		start, startErr := netip.ParseAddr(first)
		end, endErr := netip.ParseAddr(last)
		if startErr != nil || endErr != nil || start.Is4In6() || end.Is4In6() || start.Is4() != end.Is4() || start.Compare(end) > 0 {
			return netip.Addr{}, netip.Addr{}, fmt.Errorf("invalid nftables range expression")
		}
		return start, end, nil
	}
	return netip.Addr{}, netip.Addr{}, fmt.Errorf("unsupported nftables address expression")
}

func parseNFTDynamicBan(raw json.RawMessage) (nftDynamicBan, error) {
	value := raw
	var explicit struct {
		Element *struct {
			Value   json.RawMessage `json:"val"`
			Timeout json.RawMessage `json:"timeout"`
			Expires json.RawMessage `json:"expires"`
		} `json:"elem"`
	}
	if err := json.Unmarshal(raw, &explicit); err == nil && explicit.Element != nil {
		value = explicit.Element.Value
	}
	start, end, err := parseNFTAddressExpression(value)
	if err != nil {
		return nftDynamicBan{}, err
	}
	ban := nftDynamicBan{start: start, end: end}
	if explicit.Element == nil {
		return ban, nil
	}
	ban.timeout, err = parseNFTDuration(explicit.Element.Timeout, "element timeout")
	if err != nil {
		return nftDynamicBan{}, err
	}
	ban.expires, err = parseNFTDuration(explicit.Element.Expires, "element expiry")
	if err != nil {
		return nftDynamicBan{}, err
	}
	if (ban.timeout == 0) != (ban.expires == 0) || ban.expires > ban.timeout {
		return nftDynamicBan{}, fmt.Errorf("nftables element has inconsistent timeout and expiry")
	}
	return ban, nil
}

func extractNFTDynamicSnapshot(document nftJSONDocument, capturedAt time.Time) (nftDynamicSnapshot, error) {
	snapshot := newNFTDynamicSnapshot(capturedAt)
	appendElements := func(key nftObjectKey, elements []json.RawMessage) error {
		destination, wanted := snapshot.sets[key]
		if !wanted {
			return nil
		}
		wantIPv6 := strings.HasSuffix(key.name, "6")
		for _, raw := range elements {
			ban, err := parseNFTDynamicBan(raw)
			if err != nil {
				return fmt.Errorf("parse dynamic set %s %s %s: %w", key.family, key.table, key.name, err)
			}
			if ban.start.Is6() != wantIPv6 || ban.end.Is6() != wantIPv6 {
				return fmt.Errorf("dynamic set %s %s %s contains the wrong address family", key.family, key.table, key.name)
			}
			identity := dynamicBanIdentity(ban)
			if previous, exists := destination[identity]; exists && previous != ban {
				return fmt.Errorf("dynamic set %s %s %s contains conflicting duplicate %s", key.family, key.table, key.name, identity)
			}
			destination[identity] = ban
		}
		return nil
	}
	for _, entry := range document.NFTables {
		if entry.Set != nil {
			key := nftObjectKey{family: entry.Set.Family, table: entry.Set.Table, name: entry.Set.Name}
			if err := appendElements(key, entry.Set.Elements); err != nil {
				return nftDynamicSnapshot{}, err
			}
		}
		if entry.Element != nil {
			key := nftObjectKey{family: entry.Element.Family, table: entry.Element.Table, name: entry.Element.Name}
			if err := appendElements(key, entry.Element.Elements); err != nil {
				return nftDynamicSnapshot{}, err
			}
		}
	}
	return snapshot, nil
}

func snapshotNFTDynamicBans(ctx context.Context, runner nftCommandRunner, capturedAt time.Time) (nftDynamicSnapshot, error) {
	output, err := runner.Run(ctx, nil, "-j", "list", "ruleset")
	if err != nil {
		return nftDynamicSnapshot{}, fmt.Errorf("list dynamic nftables bans: %w: %s", err, strings.TrimSpace(string(output)))
	}
	document, err := decodeNFTJSON(output)
	if err != nil {
		return nftDynamicSnapshot{}, fmt.Errorf("decode dynamic nftables bans: %w", err)
	}
	return extractNFTDynamicSnapshot(document, capturedAt)
}

func buildNFTDynamicBanRules(snapshot nftDynamicSnapshot, renderedAt time.Time) (string, nftDynamicSnapshot, error) {
	elapsed := renderedAt.Sub(snapshot.capturedAt)
	if elapsed < 0 {
		return "", nftDynamicSnapshot{}, fmt.Errorf("dynamic ban snapshot clock moved backwards")
	}
	expected := newNFTDynamicSnapshot(renderedAt)
	var builder strings.Builder
	for _, key := range nftDynamicBanSets {
		identities := make([]string, 0, len(snapshot.sets[key]))
		for identity := range snapshot.sets[key] {
			identities = append(identities, identity)
		}
		sort.Strings(identities)
		for _, identity := range identities {
			ban := snapshot.sets[key][identity]
			if ban.expires > 0 {
				if ban.expires <= elapsed {
					continue
				}
				ban.expires -= elapsed
				ban.expires = ban.expires.Truncate(time.Second)
				if ban.expires < time.Second {
					continue
				}
				if ban.timeout%time.Second != 0 {
					return "", nftDynamicSnapshot{}, fmt.Errorf("dynamic ban %s in %s %s %s has sub-second configured timeout %s", identity, key.family, key.table, key.name, ban.timeout)
				}
			}
			expected.sets[key][identity] = ban
			_, _ = fmt.Fprintf(&builder, "add element %s %s %s { %s", key.family, key.table, key.name, dynamicBanExpression(ban))
			if ban.timeout > 0 {
				_, _ = fmt.Fprintf(&builder, " timeout %ds expires %ds", int64(ban.timeout/time.Second), int64(ban.expires/time.Second))
			}
			_, _ = builder.WriteString(" }\n")
		}
	}
	return builder.String(), expected, nil
}

// buildNFTDynamicBanRollbackRules replaces every dynamic element contained in
// the textual table snapshot with a freshly rendered copy. This keeps rollback
// atomic while subtracting the time spent validating and applying the failed
// candidate instead of extending temporary bans back to their captured expiry.
func buildNFTDynamicBanRollbackRules(snapshot nftDynamicSnapshot, renderedAt time.Time) (string, error) {
	additions, _, err := buildNFTDynamicBanRules(snapshot, renderedAt)
	if err != nil {
		return "", err
	}
	var builder strings.Builder
	for _, key := range nftDynamicBanSets {
		identities := make([]string, 0, len(snapshot.sets[key]))
		for identity := range snapshot.sets[key] {
			identities = append(identities, identity)
		}
		sort.Strings(identities)
		for _, identity := range identities {
			ban := snapshot.sets[key][identity]
			_, _ = fmt.Fprintf(&builder, "delete element %s %s %s { %s }\n", key.family, key.table, key.name, dynamicBanExpression(ban))
		}
	}
	builder.WriteString(additions)
	return builder.String(), nil
}

func populateSet(ctx context.Context, sources []nftListSource, setName string) (nftSetPopulation, error) {
	population := nftSetPopulation{name: setName}
	if !nftSetNameRE.MatchString(setName) {
		return population, fmt.Errorf("invalid nftables set name %q", setName)
	}
	wantIPv6 := strings.HasSuffix(setName, "6")
	seen := make(map[string]struct{})
	var errs []error
	for _, source := range sources {
		if err := ctx.Err(); err != nil {
			errs = append(errs, err)
			break
		}
		content, err := readRootedNFTFile(source.path)
		if errors.Is(err, fs.ErrNotExist) && !source.required {
			continue
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: read %s: %w", setName, source.path, err))
			continue
		}

		validInFile := 0
		for lineNumber, rawLine := range strings.Split(string(content), "\n") {
			line := strings.TrimSpace(rawLine)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			canonical, isIPv4, parseErr := canonicalIPOrPrefix(line)
			if parseErr != nil {
				errs = append(errs, fmt.Errorf("%s: %s:%d: %w", setName, source.path, lineNumber+1, parseErr))
				continue
			}
			if wantIPv6 == isIPv4 {
				errs = append(errs, fmt.Errorf("%s: %s:%d: address family does not match the destination set", setName, source.path, lineNumber+1))
				continue
			}
			validInFile++
			if _, exists := seen[canonical]; exists {
				continue
			}
			seen[canonical] = struct{}{}
			population.entries = append(population.entries, canonical)
		}
		if source.required && validInFile == 0 {
			errs = append(errs, fmt.Errorf("%s: required list %s contains no valid entries", setName, source.path))
		}
	}
	normalized, err := normalizeNFTIntervals(setName, population.entries)
	if err != nil {
		errs = append(errs, err)
	} else {
		population.entries = normalized
	}
	return population, errors.Join(errs...)
}

type nftAddressInterval struct {
	text  string
	start netip.Addr
	end   netip.Addr
}

func nftIntervalForEntry(value string) (nftAddressInterval, error) {
	canonical, _, err := canonicalIPOrPrefix(value)
	if err != nil {
		return nftAddressInterval{}, err
	}
	if address, parseErr := netip.ParseAddr(canonical); parseErr == nil {
		return nftAddressInterval{text: canonical, start: address, end: address}, nil
	}
	prefix, err := netip.ParsePrefix(canonical)
	if err != nil {
		return nftAddressInterval{}, err
	}
	prefix = prefix.Masked()
	start := prefix.Addr()
	if start.Is4() {
		bytes := start.As4()
		for bit := prefix.Bits(); bit < 32; bit++ {
			bytes[bit/8] |= 1 << (7 - uint(bit%8))
		}
		return nftAddressInterval{text: canonical, start: start, end: netip.AddrFrom4(bytes)}, nil
	}
	bytes := start.As16()
	for bit := prefix.Bits(); bit < 128; bit++ {
		bytes[bit/8] |= 1 << (7 - uint(bit%8))
	}
	return nftAddressInterval{text: canonical, start: start, end: netip.AddrFrom16(bytes)}, nil
}

func normalizeNFTIntervals(setName string, entries []string) ([]string, error) {
	intervals := make([]nftAddressInterval, 0, len(entries))
	for _, entry := range entries {
		interval, err := nftIntervalForEntry(entry)
		if err != nil {
			return nil, fmt.Errorf("%s: derive interval for %q: %w", setName, entry, err)
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
	if len(intervals) == 0 {
		return []string{}, nil
	}
	merged := []nftAddressInterval{intervals[0]}
	for index := 1; index < len(intervals); index++ {
		current := intervals[index]
		previous := &merged[len(merged)-1]
		overlaps := current.start.Compare(previous.end) <= 0
		adjacent := false
		if next := previous.end.Next(); next.IsValid() {
			adjacent = current.start == next
		}
		if overlaps || adjacent {
			if current.end.Compare(previous.end) > 0 {
				previous.end = current.end
				previous.text = ""
			}
			continue
		}
		merged = append(merged, current)
	}
	normalized := make([]string, 0, len(merged))
	for _, interval := range merged {
		if interval.text != "" {
			normalized = append(normalized, interval.text)
			continue
		}
		if interval.start == interval.end {
			normalized = append(normalized, interval.start.String())
			continue
		}
		normalized = append(normalized, interval.start.String()+"-"+interval.end.String())
	}
	return normalized, nil
}

func canonicalNFTIntervalExpression(value string) (string, error) {
	if canonical, _, err := canonicalIPOrPrefix(value); err == nil {
		return canonical, nil
	}
	parts := strings.Split(value, "-")
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid nftables address interval %q", value)
	}
	start, startErr := netip.ParseAddr(parts[0])
	end, endErr := netip.ParseAddr(parts[1])
	if startErr != nil || endErr != nil || start.Zone() != "" || end.Zone() != "" {
		return "", fmt.Errorf("invalid nftables address interval %q", value)
	}
	start = start.Unmap()
	end = end.Unmap()
	if start.Is4() != end.Is4() || start.Compare(end) >= 0 {
		return "", fmt.Errorf("invalid nftables address interval %q", value)
	}
	return start.String() + "-" + end.String(), nil
}

func applyChunk(builder *strings.Builder, setName string, chunk []string) error {
	if !nftSetNameRE.MatchString(setName) {
		return fmt.Errorf("invalid nftables set name %q", setName)
	}
	if len(chunk) == 0 {
		return nil
	}
	canonical := make([]string, 0, len(chunk))
	for _, entry := range chunk {
		expression, err := canonicalNFTIntervalExpression(entry)
		if err != nil {
			return fmt.Errorf("%s: %w", setName, err)
		}
		canonical = append(canonical, expression)
	}
	serialized := strings.Join(canonical, ", ")
	_, _ = fmt.Fprintf(builder, "add element netdev syswarden_hw_drop %s { %s }\n", setName, serialized)
	_, _ = fmt.Fprintf(builder, "add element inet syswarden %s { %s }\n", setName, serialized)
	return nil
}

func buildPopulationRules(populations []nftSetPopulation) (string, error) {
	var builder strings.Builder
	const maximumElementsPerStatement = 4096
	var errs []error
	for _, population := range populations {
		for start := 0; start < len(population.entries); start += maximumElementsPerStatement {
			end := start + maximumElementsPerStatement
			if end > len(population.entries) {
				end = len(population.entries)
			}
			if err := applyChunk(&builder, population.name, population.entries[start:end]); err != nil {
				errs = append(errs, fmt.Errorf("prepare %s population: %w", population.name, err))
			}
		}
	}
	return builder.String(), errors.Join(errs...)
}

func applyNftablesTransaction(ctx context.Context, runner nftCommandRunner, stateDirectory, baseRules string, populations []nftSetPopulation, verification nftVerificationPlan) (string, error) {
	transactionID, err := newFirewallTransactionID()
	if err != nil {
		return "", err
	}
	lock, err := acquireNFTReloadGuard()
	if err != nil {
		return transactionID, fmt.Errorf("firewall transaction %s preserved the previous ruleset: acquire reload lock: %w", transactionID, err)
	}
	defer releaseNFTReloadGuard(lock)
	return applyNftablesTransactionLocked(ctx, runner, stateDirectory, baseRules, populations, verification, transactionID)
}

// applyNftablesTransactionLocked executes a complete transaction while the
// caller holds both the in-process mutex and the shared firewall flock. Keeping
// this split lets ApplyPolicies retain the same lock until its non-authoritative
// compatibility wrappers have also been reconciled.
func applyNftablesTransactionLocked(ctx context.Context, runner nftCommandRunner, stateDirectory, baseRules string, populations []nftSetPopulation, verification nftVerificationPlan, transactionID string) (string, error) {
	fail := func(format string, args ...any) (string, error) {
		return transactionID, fmt.Errorf("firewall transaction %s preserved the previous ruleset: %s", transactionID, fmt.Sprintf(format, args...))
	}

	if err := os.MkdirAll(stateDirectory, 0750); err != nil {
		return fail("create state directory: %v", err)
	}
	workDirectory, err := os.MkdirTemp(stateDirectory, ".firewall-transaction-"+transactionID+"-")
	if err != nil {
		return fail("create private candidate directory: %v", err)
	}
	workInfo, err := os.Lstat(workDirectory)
	if err != nil || !workInfo.IsDir() || workInfo.Mode().Perm() != 0700 {
		_ = os.RemoveAll(workDirectory)
		return fail("private candidate directory has unsafe type or permissions: %v", err)
	}
	defer func() { _ = os.RemoveAll(workDirectory) }()

	populationRules, err := buildPopulationRules(populations)
	if err != nil {
		return fail("prepare set elements: %v", err)
	}
	persistentRules := baseRules + populationRules
	dynamicSnapshot, err := snapshotNFTDynamicBans(ctx, runner, time.Now())
	if err != nil {
		return fail("snapshot dynamic bans: %v", err)
	}

	existing, err := listExistingSyswardenTables(ctx, runner)
	if err != nil {
		return fail("inspect current tables: %v", err)
	}
	rollbackRules, err := snapshotSyswardenTables(ctx, runner, existing)
	if err != nil {
		return fail("snapshot current tables: %v", err)
	}
	dynamicRules, expectedDynamicBans, err := buildNFTDynamicBanRules(dynamicSnapshot, time.Now())
	if err != nil {
		return fail("prepare preserved dynamic bans: %v", err)
	}

	var transaction strings.Builder
	for _, target := range syswardenNFTTables {
		if existing[target] {
			_, _ = fmt.Fprintf(&transaction, "delete table %s %s\n", target.family, target.name)
		}
	}
	transaction.WriteString(persistentRules)
	transaction.WriteString(dynamicRules)

	transactionPath := filepath.Join(workDirectory, "candidate.nft")
	if err := writePrivateFile(transactionPath, []byte(transaction.String())); err != nil {
		return fail("write candidate: %v", err)
	}
	persistentPath := filepath.Join(workDirectory, "syswarden.nft")
	if err := writePrivateFile(persistentPath, []byte(persistentRules)); err != nil {
		return fail("write persistent candidate: %v", err)
	}

	if output, checkErr := runner.Run(ctx, nil, "-c", "-f", transactionPath); checkErr != nil {
		return fail("candidate validation failed: %v: %s", checkErr, strings.TrimSpace(string(output)))
	}

	if output, applyErr := runner.Run(ctx, nil, "-f", transactionPath); applyErr != nil {
		return fail("candidate apply failed: %v: %s", applyErr, strings.TrimSpace(string(output)))
	}

	if err := verifyNftablesStateWithDynamicBans(ctx, runner, verification, &expectedDynamicBans); err != nil {
		rollbackErr := rollbackNftables(runner, rollbackRules, dynamicSnapshot)
		if rollbackErr != nil {
			return transactionID, fmt.Errorf("firewall transaction %s verification failed (%v) and rollback failed: %w", transactionID, err, rollbackErr)
		}
		return fail("post-apply verification failed: %v", err)
	}

	statePath := filepath.Join(stateDirectory, filepath.Base(nftStateFile))
	if err := publishNftablesFile(stateDirectory, persistentPath, statePath); err != nil {
		rollbackErr := rollbackNftables(runner, rollbackRules, dynamicSnapshot)
		if rollbackErr != nil {
			return transactionID, fmt.Errorf("firewall transaction %s persistence failed (%v) and rollback failed: %w", transactionID, err, rollbackErr)
		}
		return fail("publish verified ruleset: %v", err)
	}

	return transactionID, nil
}

func acquireNFTReloadGuard() (*os.File, error) {
	nftReloadMu.Lock()
	lock, err := openNFTReloadLock(nftRuntimeLockPath)
	if err != nil {
		nftReloadMu.Unlock()
		return nil, err
	}
	return lock, nil
}

func releaseNFTReloadGuard(lock *os.File) {
	closeNFTReloadLock(lock)
	nftReloadMu.Unlock()
}

func newFirewallTransactionID() (string, error) {
	var random [8]byte
	if _, err := cryptorand.Read(random[:]); err != nil {
		return "", fmt.Errorf("generate firewall transaction identifier: %w", err)
	}
	return hex.EncodeToString(random[:]), nil
}

func openNFTReloadLock(path string) (*os.File, error) {
	file, err := openRootedNFTFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		_ = file.Close()
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("reload lock is not a regular file")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int64(stat.Uid) != int64(os.Geteuid()) {
		_ = file.Close()
		return nil, fmt.Errorf("reload lock is not owned by the effective user")
	}
	if err := file.Chmod(0600); err != nil {
		_ = file.Close()
		return nil, err
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}

func closeNFTReloadLock(file *os.File) {
	_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
	_ = file.Close()
}

func writePrivateFile(path string, content []byte) error {
	file, err := openRootedNFTFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	if err := file.Chmod(0600); err != nil {
		return err
	}
	written, err := file.Write(content)
	if err != nil {
		return err
	}
	if written != len(content) {
		return io.ErrShortWrite
	}
	if err := file.Sync(); err != nil {
		return err
	}
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return fmt.Errorf("candidate is not a private regular file")
	}
	return nil
}

func listExistingSyswardenTables(ctx context.Context, runner nftCommandRunner) (map[nftTableTarget]bool, error) {
	output, err := runner.Run(ctx, nil, "-j", "list", "tables")
	if err != nil {
		return nil, fmt.Errorf("nft list tables: %w: %s", err, strings.TrimSpace(string(output)))
	}
	document, err := decodeNFTJSON(output)
	if err != nil {
		return nil, fmt.Errorf("decode nft list tables: %w", err)
	}
	existing := make(map[nftTableTarget]bool)
	for _, entry := range document.NFTables {
		if entry.Table == nil {
			continue
		}
		target := nftTableTarget{family: entry.Table.Family, name: entry.Table.Name}
		for _, allowed := range syswardenNFTTables {
			if target == allowed {
				existing[target] = true
				break
			}
		}
	}
	return existing, nil
}

func snapshotSyswardenTables(ctx context.Context, runner nftCommandRunner, existing map[nftTableTarget]bool) (string, error) {
	var snapshot strings.Builder
	for _, target := range syswardenNFTTables {
		if !existing[target] {
			continue
		}
		output, err := runner.Run(ctx, nil, "list", "table", target.family, target.name)
		if err != nil {
			return "", fmt.Errorf("snapshot table %s %s: %w: %s", target.family, target.name, err, strings.TrimSpace(string(output)))
		}
		snapshot.Write(output)
		if len(output) > 0 && output[len(output)-1] != '\n' {
			snapshot.WriteByte('\n')
		}
	}
	return snapshot.String(), nil
}

func rollbackNftables(runner nftCommandRunner, snapshot string, dynamicSnapshot nftDynamicSnapshot) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	existing, err := listExistingSyswardenTables(ctx, runner)
	if err != nil {
		return fmt.Errorf("inspect tables before rollback: %w", err)
	}
	var rollback strings.Builder
	for _, target := range syswardenNFTTables {
		if existing[target] {
			_, _ = fmt.Fprintf(&rollback, "delete table %s %s\n", target.family, target.name)
		}
	}
	rollback.WriteString(snapshot)
	dynamicRules, err := buildNFTDynamicBanRollbackRules(dynamicSnapshot, time.Now())
	if err != nil {
		return fmt.Errorf("prepare rollback dynamic bans: %w", err)
	}
	rollback.WriteString(dynamicRules)
	pathDirectory, err := os.MkdirTemp("", "syswarden-firewall-rollback-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(pathDirectory) }()
	path := filepath.Join(pathDirectory, "rollback.nft")
	if err := writePrivateFile(path, []byte(rollback.String())); err != nil {
		return err
	}
	output, err := runner.Run(ctx, nil, "-f", path)
	if err != nil {
		return fmt.Errorf("apply rollback: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func verifyNftablesState(ctx context.Context, runner nftCommandRunner, expected nftVerificationPlan) error {
	return verifyNftablesStateWithDynamicBans(ctx, runner, expected, nil)
}

func verifyNftablesStateWithDynamicBans(ctx context.Context, runner nftCommandRunner, expected nftVerificationPlan, expectedDynamic *nftDynamicSnapshot) error {
	output, err := runner.Run(ctx, nil, "-j", "list", "ruleset")
	if err != nil {
		return fmt.Errorf("list applied ruleset: %w: %s", err, strings.TrimSpace(string(output)))
	}
	document, err := decodeNFTJSON(output)
	if err != nil {
		return fmt.Errorf("decode applied ruleset: %w", err)
	}

	tables := make(map[nftObjectKey]struct{})
	chains := make(map[nftObjectKey]string)
	setDefinitions := make(map[nftObjectKey]struct{})
	setCounts := make(map[nftObjectKey]int)
	for _, entry := range document.NFTables {
		switch {
		case entry.Table != nil:
			tables[nftObjectKey{family: entry.Table.Family, name: entry.Table.Name}] = struct{}{}
		case entry.Chain != nil:
			chains[nftObjectKey{family: entry.Chain.Family, table: entry.Chain.Table, name: entry.Chain.Name}] = entry.Chain.Hook
		case entry.Set != nil:
			key := nftObjectKey{family: entry.Set.Family, table: entry.Set.Table, name: entry.Set.Name}
			setDefinitions[key] = struct{}{}
			setCounts[key] = len(entry.Set.Elements)
		case entry.Element != nil:
			key := nftObjectKey{family: entry.Element.Family, table: entry.Element.Table, name: entry.Element.Name}
			setCounts[key] += len(entry.Element.Elements)
		}
	}

	var errs []error
	for key := range expected.tables {
		if _, exists := tables[key]; !exists {
			errs = append(errs, fmt.Errorf("required table %s %s is missing", key.family, key.name))
		}
	}
	for key, hook := range expected.chains {
		actual, exists := chains[key]
		if !exists {
			errs = append(errs, fmt.Errorf("required chain %s %s %s is missing", key.family, key.table, key.name))
		} else if actual != hook {
			errs = append(errs, fmt.Errorf("chain %s %s %s has hook %q, expected %q", key.family, key.table, key.name, actual, hook))
		}
	}
	for key, count := range expected.sets {
		_, exists := setDefinitions[key]
		if !exists {
			errs = append(errs, fmt.Errorf("required set %s %s %s is missing", key.family, key.table, key.name))
		} else if actual := setCounts[key]; count >= 0 && actual != count {
			errs = append(errs, fmt.Errorf("set %s %s %s contains %d elements, expected %d", key.family, key.table, key.name, actual, count))
		}
	}
	if expectedDynamic != nil {
		observedAt := time.Now()
		observed, snapshotErr := extractNFTDynamicSnapshot(document, observedAt)
		if snapshotErr != nil {
			errs = append(errs, fmt.Errorf("inspect preserved dynamic bans: %w", snapshotErr))
		} else if comparisonErr := compareNFTDynamicSnapshots(*expectedDynamic, observed, observedAt); comparisonErr != nil {
			errs = append(errs, comparisonErr)
		}
	}
	return errors.Join(errs...)
}

func compareNFTDynamicSnapshots(expected, observed nftDynamicSnapshot, observedAt time.Time) error {
	elapsed := observedAt.Sub(expected.capturedAt)
	if elapsed < 0 {
		return fmt.Errorf("cannot verify dynamic bans after a backwards clock step")
	}
	elapsed = elapsed.Truncate(time.Millisecond)
	const expiryTolerance = 1500 * time.Millisecond
	var errs []error
	for _, key := range nftDynamicBanSets {
		activeExpected := make(map[string]nftDynamicBan, len(expected.sets[key]))
		for identity, ban := range expected.sets[key] {
			if ban.expires > 0 {
				if ban.expires <= elapsed {
					continue
				}
				ban.expires -= elapsed
			}
			activeExpected[identity] = ban
		}
		actual := observed.sets[key]
		for identity, wanted := range activeExpected {
			found, exists := actual[identity]
			if !exists {
				errs = append(errs, fmt.Errorf("dynamic set %s %s %s lost %s", key.family, key.table, key.name, identity))
				continue
			}
			if wanted.timeout == 0 {
				if found.timeout != 0 || found.expires != 0 {
					errs = append(errs, fmt.Errorf("dynamic set %s %s %s changed permanent element %s into a timed element", key.family, key.table, key.name, identity))
				}
				continue
			}
			if found.timeout != wanted.timeout {
				errs = append(errs, fmt.Errorf("dynamic set %s %s %s timeout for %s is %s, expected %s", key.family, key.table, key.name, identity, found.timeout, wanted.timeout))
			}
			minimum := wanted.expires - expiryTolerance
			if minimum < time.Millisecond {
				minimum = time.Millisecond
			}
			maximum := wanted.expires + expiryTolerance
			if found.expires < minimum || found.expires > maximum {
				errs = append(errs, fmt.Errorf("dynamic set %s %s %s remaining expiry for %s is %s, expected %s within %s", key.family, key.table, key.name, identity, found.expires, wanted.expires, expiryTolerance))
			}
		}
		for identity := range actual {
			if _, exists := activeExpected[identity]; !exists {
				errs = append(errs, fmt.Errorf("dynamic set %s %s %s contains unexpected element %s", key.family, key.table, key.name, identity))
			}
		}
	}
	return errors.Join(errs...)
}

func decodeNFTJSON(content []byte) (nftJSONDocument, error) {
	var document nftJSONDocument
	if len(bytes.TrimSpace(content)) == 0 {
		return document, fmt.Errorf("nft returned an empty JSON document")
	}
	if err := json.Unmarshal(content, &document); err != nil {
		return document, err
	}
	if document.NFTables == nil {
		return document, fmt.Errorf("nftables array is missing")
	}
	return document, nil
}

func publishNftablesFile(stateDirectory, candidatePath, targetPath string) error {
	previous, readErr := readRootedNFTFile(targetPath)
	previousExists := readErr == nil
	if readErr != nil && !errors.Is(readErr, fs.ErrNotExist) {
		return readErr
	}
	if err := os.Rename(candidatePath, targetPath); err != nil {
		return err
	}
	if err := syncDirectory(stateDirectory); err != nil {
		restoreErr := restoreNftablesFile(stateDirectory, targetPath, previous, previousExists)
		if restoreErr != nil {
			return fmt.Errorf("sync published rules: %v; restore previous file: %w", err, restoreErr)
		}
		return err
	}
	info, err := os.Lstat(targetPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		restoreErr := restoreNftablesFile(stateDirectory, targetPath, previous, previousExists)
		if restoreErr != nil {
			return fmt.Errorf("verify published rules: %v; restore previous file: %w", err, restoreErr)
		}
		if err != nil {
			return err
		}
		return fmt.Errorf("published ruleset is not a private regular file")
	}
	return nil
}

func restoreNftablesFile(stateDirectory, targetPath string, content []byte, existed bool) error {
	if !existed {
		if err := os.Remove(targetPath); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		return syncDirectory(stateDirectory)
	}
	file, err := os.CreateTemp(stateDirectory, ".syswarden.nft.restore-")
	if err != nil {
		return err
	}
	name := file.Name()
	defer func() { _ = os.Remove(name) }()
	if err := file.Chmod(0600); err != nil {
		_ = file.Close()
		return err
	}
	if _, err := file.Write(content); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, targetPath); err != nil {
		return err
	}
	return syncDirectory(stateDirectory)
}

func syncDirectory(path string) error {
	root, err := os.OpenRoot(filepath.Clean(path))
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	directory, err := root.Open(".")
	if err != nil {
		return err
	}
	defer func() { _ = directory.Close() }()
	return directory.Sync()
}
