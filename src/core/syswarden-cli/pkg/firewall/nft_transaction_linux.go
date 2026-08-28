//go:build linux

package firewall

import (
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"crypto/sha256"
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
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"syswarden-cli/config"
)

const (
	nftStateDirectory        = "/etc/syswarden"
	nftStateFile             = "/etc/syswarden/syswarden.nft"
	maximumNFTCommandOutput  = 64 << 20
	maximumNFTExecutableSize = 128 << 20
	nftCommandProcessWait    = time.Second
)

var (
	nftReloadMu             sync.Mutex
	nftRuntimeLockPath      = "/run/syswarden-firewall.lock"
	nftSetNameRE            = regexp.MustCompile(`^[a-zA-Z0-9_]+$`)
	nftExecutableLookPath   = exec.LookPath
	nftExecutableValidator  = validateResolvedLinuxWrapperExecutable
	nftExecutablePinnedHook = func() {}
	nftCommandOutputLimit   = maximumNFTCommandOutput
)

type nftCommandRunner interface {
	Run(ctx context.Context, stdin []byte, args ...string) ([]byte, error)
}

type execNFTCommandRunner struct {
	path     string
	identity nftExecutableIdentity
}

type nftExecutableIdentity struct {
	digest [sha256.Size]byte
	mode   os.FileMode
	uid    uint32
	gid    uint32
	nlink  uint64
	device uint64
	inode  uint64
	size   int64
}

type boundedNFTCommandOutput struct {
	content  bytes.Buffer
	limit    int
	exceeded bool
}

func (output *boundedNFTCommandOutput) Write(content []byte) (int, error) {
	remaining := output.limit - output.content.Len()
	if remaining > 0 {
		written := len(content)
		if written > remaining {
			written = remaining
		}
		_, _ = output.content.Write(content[:written])
	}
	if len(content) > remaining {
		output.exceeded = true
	}
	return len(content), nil
}

func pinNFTExecutable(path string) (*os.File, nftExecutableIdentity, error) {
	if err := nftExecutableValidator(path); err != nil {
		return nil, nftExecutableIdentity{}, err
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, nftExecutableIdentity{}, fmt.Errorf("pin nft executable: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = syscall.Close(fd)
		return nil, nftExecutableIdentity{}, fmt.Errorf("pin nft executable")
	}
	before, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, nftExecutableIdentity{}, fmt.Errorf("inspect pinned nft executable: %w", err)
	}
	stat, ok := before.Sys().(*syscall.Stat_t)
	if !ok || !before.Mode().IsRegular() || before.Mode().Perm()&0111 == 0 ||
		before.Mode().Perm()&0022 != 0 || stat.Uid != 0 && int64(stat.Uid) != int64(os.Geteuid()) ||
		stat.Nlink == 0 || before.Size() < 1 ||
		before.Size() > maximumNFTExecutableSize {
		_ = file.Close()
		return nil, nftExecutableIdentity{}, fmt.Errorf("pinned nft executable has an unsafe identity")
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, io.LimitReader(file, maximumNFTExecutableSize+1)); err != nil {
		_ = file.Close()
		return nil, nftExecutableIdentity{}, fmt.Errorf("hash pinned nft executable: %w", err)
	}
	var digest [sha256.Size]byte
	copy(digest[:], hash.Sum(nil))
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		_ = file.Close()
		return nil, nftExecutableIdentity{}, fmt.Errorf("rewind pinned nft executable: %w", err)
	}
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() ||
		before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		_ = file.Close()
		return nil, nftExecutableIdentity{}, fmt.Errorf("nft executable path changed while pinning")
	}
	afterStat, ok := after.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != afterStat.Uid || stat.Gid != afterStat.Gid ||
		stat.Nlink != afterStat.Nlink || stat.Dev != afterStat.Dev || stat.Ino != afterStat.Ino {
		_ = file.Close()
		return nil, nftExecutableIdentity{}, fmt.Errorf("nft executable identity changed while pinning")
	}
	if err := nftExecutableValidator(path); err != nil {
		_ = file.Close()
		return nil, nftExecutableIdentity{}, fmt.Errorf("reattest pinned nft executable: %w", err)
	}
	return file, nftExecutableIdentity{
		digest: digest, mode: before.Mode(), uid: stat.Uid, gid: stat.Gid,
		nlink: uint64(stat.Nlink), device: uint64(stat.Dev), inode: stat.Ino, size: before.Size(),
	}, nil
}

func captureNFTExecutableIdentity(path string) (nftExecutableIdentity, error) {
	file, identity, err := pinNFTExecutable(path)
	if err != nil {
		return nftExecutableIdentity{}, err
	}
	if err := file.Close(); err != nil {
		return nftExecutableIdentity{}, fmt.Errorf("close pinned nft executable: %w", err)
	}
	return identity, nil
}

func newExecNFTCommandRunner() (nftCommandRunner, error) {
	path, err := nftExecutableLookPath("nft")
	if err != nil {
		return nil, fmt.Errorf("resolve nft executable: %w", err)
	}
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, fmt.Errorf("nft executable did not resolve to a clean absolute path")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return nil, fmt.Errorf("resolve nft executable target: %w", err)
	}
	resolved = filepath.Clean(resolved)
	if err := nftExecutableValidator(resolved); err != nil {
		return nil, fmt.Errorf("validate nft executable: %w", err)
	}
	identity, err := captureNFTExecutableIdentity(resolved)
	if err != nil {
		return nil, fmt.Errorf("capture nft executable identity: %w", err)
	}
	return execNFTCommandRunner{path: resolved, identity: identity}, nil
}

func (runner execNFTCommandRunner) Run(ctx context.Context, stdin []byte, args ...string) ([]byte, error) {
	if stdin != nil {
		return nil, fmt.Errorf("nft command input is unsupported")
	}
	if runner.path == "" || !filepath.IsAbs(runner.path) || filepath.Clean(runner.path) != runner.path {
		return nil, fmt.Errorf("nft runner has no pinned clean absolute executable")
	}
	if err := nftExecutableValidator(runner.path); err != nil {
		return nil, fmt.Errorf("reattest nft executable: %w", err)
	}
	if nftCommandOutputLimit <= 0 || nftCommandOutputLimit > maximumNFTCommandOutput {
		return nil, fmt.Errorf("invalid nft command output limit")
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
		cmd = exec.CommandContext(ctx, "/proc/self/fd/3", "-j", "list", "tables")
	case len(args) == 3 && args[0] == "-j" && args[1] == "list" && args[2] == "ruleset":
		cmd = exec.CommandContext(ctx, "/proc/self/fd/3", "-j", "list", "ruleset")
	case len(args) == 4 && args[0] == "list" && args[1] == "table":
		target := nftTableTarget{family: args[2], name: args[3]}
		switch target {
		case nftTableTarget{family: "inet", name: "syswarden"}:
			cmd = exec.CommandContext(ctx, "/proc/self/fd/3", "list", "table", "inet", "syswarden")
		case nftTableTarget{family: "inet", name: "syswarden_table"}:
			cmd = exec.CommandContext(ctx, "/proc/self/fd/3", "list", "table", "inet", "syswarden_table")
		case nftTableTarget{family: "netdev", name: "syswarden_hw_drop"}:
			cmd = exec.CommandContext(ctx, "/proc/self/fd/3", "list", "table", "netdev", "syswarden_hw_drop")
		case nftTableTarget{family: "arp", name: "syswarden_arp"}:
			cmd = exec.CommandContext(ctx, "/proc/self/fd/3", "list", "table", "arp", "syswarden_arp")
		default:
			return nil, fmt.Errorf("refuse unexpected nftables table %s %s", target.family, target.name)
		}
	case len(args) == 4 && args[0] == "delete" && args[1] == "table":
		target := nftTableTarget{family: args[2], name: args[3]}
		if !isReservedNFTTableForUninstall(target) {
			return nil, fmt.Errorf("refuse unexpected nftables uninstall target %s %s", target.family, target.name)
		}
		cmd = exec.CommandContext(ctx, "/proc/self/fd/3", "delete", "table", target.family, target.name) // #nosec G204 -- executable is fd-bound and target passed the exact reserved-table allowlist
	case len(args) == 3 && args[0] == "-c" && args[1] == "-f":
		var err error
		commandFile, err = openPrivateNFTCommandFile(args[2])
		if err != nil {
			return nil, err
		}
		cmd = exec.CommandContext(ctx, "/proc/self/fd/3", "-c", "-f", "/proc/self/fd/4")
	case len(args) == 2 && args[0] == "-f":
		var err error
		commandFile, err = openPrivateNFTCommandFile(args[1])
		if err != nil {
			return nil, err
		}
		cmd = exec.CommandContext(ctx, "/proc/self/fd/3", "-f", "/proc/self/fd/4")
	default:
		return nil, fmt.Errorf("refuse unsupported nft command")
	}
	cmd.Env = fixedLinuxWrapperCommandEnvironment()
	cmd.WaitDelay = nftCommandProcessWait
	output := &boundedNFTCommandOutput{limit: nftCommandOutputLimit}
	cmd.Stdout = output
	cmd.Stderr = output
	executableFile, identity, identityErr := pinNFTExecutable(runner.path)
	if identityErr != nil {
		return nil, fmt.Errorf("reattest nft executable immediately before start: %w", identityErr)
	}
	defer func() { _ = executableFile.Close() }()
	if identity != runner.identity {
		return nil, fmt.Errorf("nft executable changed identity before start")
	}
	cmd.ExtraFiles = []*os.File{executableFile}
	if commandFile != nil {
		cmd.ExtraFiles = append(cmd.ExtraFiles, commandFile)
	}
	nftExecutablePinnedHook()
	err := cmd.Run()
	content := append([]byte(nil), output.content.Bytes()...)
	if output.exceeded {
		return content, fmt.Errorf("nft command output exceeds %d bytes", nftCommandOutputLimit)
	}
	if ctx.Err() != nil {
		return content, fmt.Errorf("nft command context ended: %w", ctx.Err())
	}
	return content, err
}

type nftListSource struct {
	path     string
	required bool
}

type nftSetPopulation struct {
	name     string
	entries  []string
	kind     nftSetPopulationKind
	inetOnly bool
}

type nftSetPopulationKind uint8

const (
	nftAddressPopulation nftSetPopulationKind = iota
	nftAddressPortPopulation
)

type nftObjectKey struct {
	family string
	table  string
	name   string
}

type nftVerificationPlan struct {
	tables         map[nftObjectKey]struct{}
	chains         map[nftObjectKey]string
	sets           map[nftObjectKey]int // negative cardinality means existence-only for runtime-owned sets
	operatorPolicy operatorPolicyVerification
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

var reservedNFTTablesForUninstall = []nftTableTarget{
	{family: "inet", name: "syswarden"},
	{family: "inet", name: "syswarden_table"},
	{family: "netdev", name: "syswarden_hw_drop"},
	{family: "arp", name: "syswarden_arp"},
	{family: "inet", name: "syswarden_wg"},
}

func isSyswardenNFTTable(target nftTableTarget) bool {
	for _, allowed := range syswardenNFTTables {
		if target == allowed {
			return true
		}
	}
	return false
}

func isReservedNFTTableForUninstall(target nftTableTarget) bool {
	for _, allowed := range reservedNFTTablesForUninstall {
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
	Rule    *nftJSONRule    `json:"rule,omitempty"`
}

type nftJSONTable struct {
	Family string `json:"family"`
	Name   string `json:"name"`
}

type nftJSONChain struct {
	Family  string `json:"family"`
	Table   string `json:"table"`
	Name    string `json:"name"`
	Hook    string `json:"hook"`
	Handle  uint64 `json:"handle"`
	present map[string]struct{}
}

func (chain *nftJSONChain) UnmarshalJSON(content []byte) error {
	type chainAlias nftJSONChain
	var decoded chainAlias
	if err := json.Unmarshal(content, &decoded); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(content, &fields); err != nil {
		return err
	}
	if rawHandle, exists := fields["handle"]; exists && bytes.Equal(bytes.TrimSpace(rawHandle), []byte("null")) {
		return fmt.Errorf("nftables chain handle must be an unsigned integer")
	}
	decoded.present = make(map[string]struct{}, len(fields))
	for name := range fields {
		decoded.present[name] = struct{}{}
	}
	*chain = nftJSONChain(decoded)
	return nil
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

type nftJSONRule struct {
	Family      string            `json:"family"`
	Table       string            `json:"table"`
	Chain       string            `json:"chain"`
	Handle      uint64            `json:"handle"`
	Expressions []json.RawMessage `json:"expr"`
	Comment     string            `json:"comment"`
	unknown     []string
	present     map[string]struct{}
}

func (rule *nftJSONRule) UnmarshalJSON(content []byte) error {
	type ruleAlias nftJSONRule
	var decoded ruleAlias
	if err := json.Unmarshal(content, &decoded); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(content, &fields); err != nil {
		return err
	}
	if rawHandle, exists := fields["handle"]; exists && bytes.Equal(bytes.TrimSpace(rawHandle), []byte("null")) {
		return fmt.Errorf("nftables rule handle must be an unsigned integer")
	}
	decoded.present = make(map[string]struct{}, len(fields))
	for name := range fields {
		decoded.present[name] = struct{}{}
	}
	for _, name := range []string{"family", "table", "chain", "handle", "expr", "comment"} {
		delete(fields, name)
	}
	decoded.unknown = make([]string, 0, len(fields))
	for name := range fields {
		decoded.unknown = append(decoded.unknown, name)
	}
	sort.Strings(decoded.unknown)
	*rule = nftJSONRule(decoded)
	return nil
}

type nftDynamicBan struct {
	start                 netip.Addr
	end                   netip.Addr
	timeout               time.Duration
	expires               time.Duration
	ambiguousOpenInterval bool
	omitFromMigration     bool
}

type nftDynamicSnapshot struct {
	capturedAt time.Time
	sets       map[nftObjectKey]map[string]nftDynamicBan
	discarded  map[nftObjectKey]map[string]nftDynamicBan
	present    map[nftObjectKey]bool
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
		discarded:  make(map[nftObjectKey]map[string]nftDynamicBan, len(nftDynamicBanSets)),
		present:    make(map[nftObjectKey]bool, len(nftDynamicBanSets)),
	}
	for _, key := range nftDynamicBanSets {
		snapshot.sets[key] = make(map[string]nftDynamicBan)
		snapshot.discarded[key] = make(map[string]nftDynamicBan)
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
	var seconds int64
	if err := json.Unmarshal(raw, &seconds); err != nil || seconds < 0 {
		return 0, fmt.Errorf("%s is not a non-negative second integer", label)
	}
	if seconds > int64((time.Duration(1<<63-1))/time.Second) {
		return 0, fmt.Errorf("%s exceeds the supported duration", label)
	}
	return time.Duration(seconds) * time.Second, nil
}

func nftDurationSpecified(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) > 0 && !bytes.Equal(trimmed, []byte("null"))
}

func isAmbiguousNFTMaximumEndingRange(start, end netip.Addr) bool {
	return start.IsValid() && end.IsValid() && start != end && !end.Next().IsValid()
}

func parseNFTAddressExpression(raw json.RawMessage) (netip.Addr, netip.Addr, bool, error) {
	var text string
	if err := json.Unmarshal(raw, &text); err == nil {
		interval, intervalErr := nftIntervalForEntry(text)
		if intervalErr != nil {
			return netip.Addr{}, netip.Addr{}, false, intervalErr
		}
		return interval.start, interval.end, isAmbiguousNFTMaximumEndingRange(interval.start, interval.end), nil
	}

	var expression struct {
		Prefix *struct {
			Address string `json:"addr"`
			Length  int    `json:"len"`
		} `json:"prefix"`
		Range []json.RawMessage `json:"range"`
	}
	if err := json.Unmarshal(raw, &expression); err != nil {
		return netip.Addr{}, netip.Addr{}, false, fmt.Errorf("decode nftables address expression: %w", err)
	}
	if expression.Prefix != nil {
		prefix, err := netip.ParsePrefix(fmt.Sprintf("%s/%d", expression.Prefix.Address, expression.Prefix.Length))
		if err != nil || prefix.Addr().Is4In6() {
			return netip.Addr{}, netip.Addr{}, false, fmt.Errorf("invalid nftables prefix expression")
		}
		interval, err := nftIntervalForEntry(prefix.Masked().String())
		if err != nil {
			return netip.Addr{}, netip.Addr{}, false, err
		}
		return interval.start, interval.end, isAmbiguousNFTMaximumEndingRange(interval.start, interval.end), nil
	}
	if len(expression.Range) == 2 {
		var first, last string
		if err := json.Unmarshal(expression.Range[0], &first); err != nil {
			return netip.Addr{}, netip.Addr{}, false, fmt.Errorf("decode nftables range start: %w", err)
		}
		if err := json.Unmarshal(expression.Range[1], &last); err != nil {
			return netip.Addr{}, netip.Addr{}, false, fmt.Errorf("decode nftables range end: %w", err)
		}
		start, startErr := netip.ParseAddr(first)
		end, endErr := netip.ParseAddr(last)
		if startErr != nil || endErr != nil || start.Is4In6() || end.Is4In6() || start.Is4() != end.Is4() || start.Compare(end) > 0 {
			return netip.Addr{}, netip.Addr{}, false, fmt.Errorf("invalid nftables range expression")
		}
		return start, end, isAmbiguousNFTMaximumEndingRange(start, end), nil
	}
	return netip.Addr{}, netip.Addr{}, false, fmt.Errorf("unsupported nftables address expression")
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
	start, end, ambiguousOpenInterval, err := parseNFTAddressExpression(value)
	if err != nil {
		return nftDynamicBan{}, err
	}
	ban := nftDynamicBan{start: start, end: end, ambiguousOpenInterval: ambiguousOpenInterval}
	if explicit.Element == nil {
		return ban, nil
	}
	timeoutSpecified := nftDurationSpecified(explicit.Element.Timeout)
	expiresSpecified := nftDurationSpecified(explicit.Element.Expires)
	if timeoutSpecified != expiresSpecified {
		return nftDynamicBan{}, fmt.Errorf("nftables element has incomplete timeout and expiry metadata")
	}
	if !timeoutSpecified {
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
	if (ban.timeout == 0 && ban.expires != 0) || ban.expires > ban.timeout {
		return nftDynamicBan{}, fmt.Errorf("nftables element has inconsistent timeout and expiry")
	}
	if ban.timeout > 0 && ban.expires == 0 {
		// libnftables JSON reports integer seconds and can round a still-listed
		// timed element's final sub-second lifetime down to zero. Omitting that
		// imminently expiring record is safe; treating it as permanent is not.
		ban.omitFromMigration = true
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
			if _, tracked := snapshot.sets[key]; tracked {
				snapshot.present[key] = true
			}
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
	quarantineAmbiguousNFTDynamicFamilies(&snapshot)
	return snapshot, nil
}

func quarantineAmbiguousNFTDynamicFamilies(snapshot *nftDynamicSnapshot) {
	for _, family := range []struct {
		name string
		keys []nftObjectKey
	}{
		{name: "IPv4", keys: []nftObjectKey{
			{family: "inet", table: "syswarden", name: "banned_ips"},
			{family: "netdev", table: "syswarden_hw_drop", name: "banned_ips"},
		}},
		{name: "IPv6", keys: []nftObjectKey{
			{family: "inet", table: "syswarden", name: "banned_ips6"},
			{family: "netdev", table: "syswarden_hw_drop", name: "banned_ips6"},
		}},
	} {
		ambiguous := false
		for _, key := range family.keys {
			for _, ban := range snapshot.sets[key] {
				if ban.ambiguousOpenInterval {
					ambiguous = true
					break
				}
			}
			if ambiguous {
				break
			}
		}
		if !ambiguous {
			continue
		}
		for _, key := range family.keys {
			for identity, ban := range snapshot.sets[key] {
				snapshot.discarded[key][identity] = ban
			}
			clear(snapshot.sets[key])
		}
	}
}

func writeNFTDynamicSnapshotWarnings(writer io.Writer, snapshot nftDynamicSnapshot, committed bool) {
	for _, family := range []struct {
		name string
		keys []nftObjectKey
	}{
		{name: "IPv4", keys: []nftObjectKey{
			{family: "inet", table: "syswarden", name: "banned_ips"},
			{family: "netdev", table: "syswarden_hw_drop", name: "banned_ips"},
		}},
		{name: "IPv6", keys: []nftObjectKey{
			{family: "inet", table: "syswarden", name: "banned_ips6"},
			{family: "netdev", table: "syswarden_hw_drop", name: "banned_ips6"},
		}},
	} {
		count := 0
		for _, key := range family.keys {
			count += len(snapshot.discarded[key])
		}
		if count == 0 {
			continue
		}
		if committed {
			_, _ = fmt.Fprintf(
				writer,
				"[WARN] Quarantined %d dynamic %s ban elements from the completed migration after detecting an unbounded legacy interval suffix across sets %s %s %s and %s %s %s; persistent firewall lists were not changed.\n",
				count,
				family.name,
				family.keys[0].family,
				family.keys[0].table,
				family.keys[0].name,
				family.keys[1].family,
				family.keys[1].table,
				family.keys[1].name,
			)
			continue
		}
		_, _ = fmt.Fprintf(
			writer,
			"[WARN] Detected %d dynamic %s ban elements with an unbounded legacy interval suffix across sets %s %s %s and %s %s %s and excluded them from the candidate migration; live firewall state remains unchanged until this transaction commits successfully; persistent firewall lists were not changed.\n",
			count,
			family.name,
			family.keys[0].family,
			family.keys[0].table,
			family.keys[0].name,
			family.keys[1].family,
			family.keys[1].table,
			family.keys[1].name,
		)
	}
}

func nftDynamicSnapshotQuarantinedFamilies(snapshot nftDynamicSnapshot) []string {
	var families []string
	for _, family := range []struct {
		name string
		keys []nftObjectKey
	}{
		{name: "IPv4", keys: []nftObjectKey{
			{family: "inet", table: "syswarden", name: "banned_ips"},
			{family: "netdev", table: "syswarden_hw_drop", name: "banned_ips"},
		}},
		{name: "IPv6", keys: []nftObjectKey{
			{family: "inet", table: "syswarden", name: "banned_ips6"},
			{family: "netdev", table: "syswarden_hw_drop", name: "banned_ips6"},
		}},
	} {
		for _, key := range family.keys {
			if len(snapshot.discarded[key]) > 0 {
				families = append(families, family.name)
				break
			}
		}
	}
	return families
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

// QuarantineLegacyDynamicBanIntervals removes only volatile address-family
// state that is ambiguous because an inherited interval ends at the address
// maximum. Persistent operator lists and the surrounding firewall policy are
// not changed. This is an availability recovery step for package upgrades from
// the affected historical encoder, before the candidate installation performs
// any network-dependent configuration.
func QuarantineLegacyDynamicBanIntervals() (bool, error) {
	lock, err := acquireNFTReloadGuard()
	if err != nil {
		return false, fmt.Errorf("acquire legacy dynamic-ban quarantine lock: %w", err)
	}
	defer releaseNFTReloadGuard(lock)

	runner, err := newExecNFTCommandRunner()
	if err != nil {
		return false, fmt.Errorf("prepare legacy dynamic-ban quarantine runner: %w", err)
	}
	workDirectory, err := os.MkdirTemp("", "syswarden-dynamic-quarantine-")
	if err != nil {
		return false, fmt.Errorf("create legacy dynamic-ban quarantine directory: %w", err)
	}
	defer func() { _ = os.RemoveAll(workDirectory) }()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return quarantineLegacyDynamicBanIntervals(ctx, runner, workDirectory)
}

func quarantineLegacyDynamicBanIntervals(
	ctx context.Context,
	runner nftCommandRunner,
	workDirectory string,
) (bool, error) {
	snapshot, err := snapshotNFTDynamicBans(ctx, runner, time.Now())
	if err != nil {
		return false, fmt.Errorf("snapshot legacy dynamic bans before quarantine: %w", err)
	}
	if len(nftDynamicSnapshotQuarantinedFamilies(snapshot)) == 0 {
		return false, nil
	}

	var transaction strings.Builder
	for _, key := range nftDynamicBanSets {
		if len(snapshot.discarded[key]) == 0 {
			continue
		}
		_, _ = fmt.Fprintf(&transaction, "flush set %s %s %s\n", key.family, key.table, key.name)
	}
	if transaction.Len() == 0 {
		return false, fmt.Errorf("legacy dynamic-ban quarantine selected no exact set")
	}
	transactionPath := filepath.Join(workDirectory, "quarantine.nft")
	if err := writePrivateFile(transactionPath, []byte(transaction.String())); err != nil {
		return false, fmt.Errorf("write legacy dynamic-ban quarantine transaction: %w", err)
	}
	if output, checkErr := runner.Run(ctx, nil, "-c", "-f", transactionPath); checkErr != nil {
		return false, fmt.Errorf("validate legacy dynamic-ban quarantine transaction: %w: %s", checkErr, strings.TrimSpace(string(output)))
	}
	if output, applyErr := runner.Run(ctx, nil, "-f", transactionPath); applyErr != nil {
		return false, fmt.Errorf("apply legacy dynamic-ban quarantine transaction: %w: %s", applyErr, strings.TrimSpace(string(output)))
	}

	observedAt := time.Now()
	observed, err := snapshotNFTDynamicBans(ctx, runner, observedAt)
	if err != nil {
		return true, fmt.Errorf("legacy dynamic-ban quarantine committed but verification failed: %w", err)
	}
	if len(nftDynamicSnapshotQuarantinedFamilies(observed)) != 0 {
		return true, fmt.Errorf("legacy dynamic-ban quarantine committed but an ambiguous maximum-ending interval remains")
	}
	if err := compareNFTDynamicSnapshots(snapshot, observed, observedAt); err != nil {
		return true, fmt.Errorf("legacy dynamic-ban quarantine committed but exact state verification failed: %w", err)
	}
	writeNFTDynamicSnapshotWarnings(os.Stderr, snapshot, true)
	return true, nil
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
			if ban.omitFromMigration {
				continue
			}
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

// buildNFTDynamicBanRollbackRules replaces every captured dynamic set with a
// freshly rendered copy. Flushing the set avoids a race where an element expires
// between the JSON capture and the textual table snapshot, which would make an
// individual delete fail. This keeps rollback atomic while subtracting the time
// spent validating and applying the failed candidate instead of extending
// temporary bans back to their captured expiry.
func buildNFTDynamicBanRollbackRules(snapshot nftDynamicSnapshot, renderedAt time.Time, previousSets nftDynamicSetPresence) (string, error) {
	filtered := newNFTDynamicSnapshot(snapshot.capturedAt)
	for _, key := range nftDynamicBanSets {
		if !previousSets.contains(key) {
			continue
		}
		filtered.present[key] = true
		for identity, ban := range snapshot.sets[key] {
			filtered.sets[key][identity] = ban
		}
		for identity, ban := range snapshot.discarded[key] {
			filtered.discarded[key][identity] = ban
		}
	}
	additions, _, err := buildNFTDynamicBanRules(filtered, renderedAt)
	if err != nil {
		return "", err
	}
	var builder strings.Builder
	for _, key := range nftDynamicBanSets {
		if previousSets.contains(key) {
			_, _ = fmt.Fprintf(&builder, "flush set %s %s %s\n", key.family, key.table, key.name)
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
			canonical, isIPv4, parseErr := canonicalFirewallListNetwork(line)
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

func populateWhitelistSets(ctx context.Context, sources []nftListSource, addressSetName, portSetName string) (nftSetPopulation, nftSetPopulation, error) {
	addresses := nftSetPopulation{name: addressSetName}
	ports := nftSetPopulation{name: portSetName, kind: nftAddressPortPopulation}
	if !nftSetNameRE.MatchString(addressSetName) || !nftSetNameRE.MatchString(portSetName) {
		return addresses, ports, fmt.Errorf("invalid nftables whitelist set name")
	}
	wantIPv6 := strings.HasSuffix(addressSetName, "6")
	seenAddresses := make(map[string]struct{})
	seenPorts := make(map[string]struct{})
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
			errs = append(errs, fmt.Errorf("%s: read %s: %w", addressSetName, source.path, err))
			continue
		}
		validInFile := 0
		for lineNumber, rawLine := range strings.Split(string(content), "\n") {
			line := strings.TrimSpace(rawLine)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			entry, parseErr := parseCanonicalListEntry(line, true)
			if parseErr != nil {
				errs = append(errs, fmt.Errorf("%s: %s:%d: %w", addressSetName, source.path, lineNumber+1, parseErr))
				continue
			}
			if wantIPv6 == entry.isIPv4 {
				errs = append(errs, fmt.Errorf("%s: %s:%d: address family does not match the destination set", addressSetName, source.path, lineNumber+1))
				continue
			}
			validInFile++
			if entry.port == "" {
				if _, duplicate := seenAddresses[entry.network]; !duplicate {
					seenAddresses[entry.network] = struct{}{}
					addresses.entries = append(addresses.entries, entry.network)
				}
				continue
			}
			expression := entry.network + " . " + entry.port
			if _, duplicate := seenPorts[expression]; !duplicate {
				seenPorts[expression] = struct{}{}
				ports.entries = append(ports.entries, expression)
			}
		}
		if source.required && validInFile == 0 {
			errs = append(errs, fmt.Errorf("%s: required list %s contains no valid entries", addressSetName, source.path))
		}
	}
	normalized, err := normalizeNFTIntervals(addressSetName, addresses.entries)
	if err != nil {
		errs = append(errs, err)
	} else {
		addresses.entries = normalized
	}
	normalizedPorts, normalizePortsErr := normalizeNFTAddressPortEntries(portSetName, ports.entries)
	if normalizePortsErr != nil {
		errs = append(errs, normalizePortsErr)
	} else {
		ports.entries = normalizedPorts
	}
	return addresses, ports, errors.Join(errs...)
}

func normalizeNFTAddressPortEntries(setName string, entries []string) ([]string, error) {
	byPort := make(map[string][]string)
	for _, value := range entries {
		parts := strings.Split(value, " . ")
		if len(parts) != 2 {
			return nil, fmt.Errorf("%s: invalid address and port expression %q", setName, value)
		}
		network, _, err := canonicalIPOrPrefix(parts[0])
		if err != nil {
			return nil, fmt.Errorf("%s: %w", setName, err)
		}
		port, err := canonicalPort(parts[1])
		if err != nil {
			return nil, fmt.Errorf("%s: %w", setName, err)
		}
		byPort[port] = append(byPort[port], network)
	}

	ports := make([]string, 0, len(byPort))
	for port := range byPort {
		ports = append(ports, port)
	}
	sort.Strings(ports)
	normalized := make([]string, 0, len(entries))
	for _, port := range ports {
		networks, err := normalizeNFTIntervals(setName+" port "+port, byPort[port])
		if err != nil {
			return nil, err
		}
		for _, network := range networks {
			normalized = append(normalized, network+" . "+port)
		}
	}
	sort.Strings(normalized)
	return normalized, nil
}

func populateSSHBypassSets(ctx context.Context, source nftListSource, effectivePort string) (nftSetPopulation, nftSetPopulation, error) {
	ipv4 := nftSetPopulation{name: "syswarden_ssh_bypass", inetOnly: true}
	ipv6 := nftSetPopulation{name: "syswarden_ssh_bypass6", inetOnly: true}
	canonicalEffectivePort, err := canonicalPort(effectivePort)
	if err != nil {
		return ipv4, ipv6, fmt.Errorf("invalid effective SSH port: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return ipv4, ipv6, err
	}
	content, err := readRootedNFTFile(source.path)
	if errors.Is(err, fs.ErrNotExist) && !source.required {
		return ipv4, ipv6, nil
	}
	if err != nil {
		return ipv4, ipv6, fmt.Errorf("read SSH bypass list %s: %w", source.path, err)
	}
	seenIPv4 := make(map[string]struct{})
	seenIPv6 := make(map[string]struct{})
	var errs []error
	valid := 0
	for lineNumber, rawLine := range strings.Split(string(content), "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		entry, parseErr := parseCanonicalListEntry(line, true)
		if parseErr != nil {
			errs = append(errs, fmt.Errorf("SSH bypass list %s:%d: %w", source.path, lineNumber+1, parseErr))
			continue
		}
		if entry.port != "" && entry.port != canonicalEffectivePort {
			errs = append(errs, fmt.Errorf("SSH bypass list %s:%d: port %s does not match the effective SSH port %s", source.path, lineNumber+1, entry.port, canonicalEffectivePort))
			continue
		}
		valid++
		if entry.isIPv4 {
			if _, duplicate := seenIPv4[entry.network]; !duplicate {
				seenIPv4[entry.network] = struct{}{}
				ipv4.entries = append(ipv4.entries, entry.network)
			}
		} else if _, duplicate := seenIPv6[entry.network]; !duplicate {
			seenIPv6[entry.network] = struct{}{}
			ipv6.entries = append(ipv6.entries, entry.network)
		}
	}
	if source.required && valid == 0 {
		errs = append(errs, fmt.Errorf("required SSH bypass list %s contains no valid entries", source.path))
	}
	normalizedIPv4, normalizeIPv4Err := normalizeNFTIntervals(ipv4.name, ipv4.entries)
	if normalizeIPv4Err != nil {
		errs = append(errs, normalizeIPv4Err)
	} else {
		ipv4.entries = normalizedIPv4
	}
	normalizedIPv6, normalizeIPv6Err := normalizeNFTIntervals(ipv6.name, ipv6.entries)
	if normalizeIPv6Err != nil {
		errs = append(errs, normalizeIPv6Err)
	} else {
		ipv6.entries = normalizedIPv6
	}
	return ipv4, ipv6, errors.Join(errs...)
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
	return applyPopulationChunk(builder, nftSetPopulation{name: setName}, chunk)
}

func applyPopulationChunk(builder *strings.Builder, population nftSetPopulation, chunk []string) error {
	setName := population.name
	if !nftSetNameRE.MatchString(setName) {
		return fmt.Errorf("invalid nftables set name %q", setName)
	}
	if len(chunk) == 0 {
		return nil
	}
	canonical := make([]string, 0, len(chunk))
	for _, entry := range chunk {
		var expression string
		var err error
		switch population.kind {
		case nftAddressPopulation:
			expression, err = canonicalNFTIntervalExpression(entry)
		case nftAddressPortPopulation:
			expression, err = canonicalNFTAddressPortExpression(entry)
		default:
			err = fmt.Errorf("unsupported nftables population kind %d", population.kind)
		}
		if err != nil {
			return fmt.Errorf("%s: %w", setName, err)
		}
		canonical = append(canonical, expression)
	}
	serialized := strings.Join(canonical, ", ")
	if !population.inetOnly {
		_, _ = fmt.Fprintf(builder, "add element netdev syswarden_hw_drop %s { %s }\n", setName, serialized)
	}
	_, _ = fmt.Fprintf(builder, "add element inet syswarden %s { %s }\n", setName, serialized)
	return nil
}

func canonicalNFTAddressPortExpression(value string) (string, error) {
	parts := strings.Split(value, " . ")
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid nftables address and port expression %q", value)
	}
	network, err := canonicalNFTIntervalExpression(parts[0])
	if err != nil {
		return "", err
	}
	port, err := canonicalPort(parts[1])
	if err != nil {
		return "", err
	}
	return network + " . " + port, nil
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
			if err := applyPopulationChunk(&builder, population, population.entries[start:end]); err != nil {
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
	return applyNftablesTransactionLocked(ctx, runner, stateDirectory, baseRules, populations, verification, transactionID, nil)
}

// applyNftablesTransactionLocked executes a complete transaction while the
// caller holds both the in-process mutex and the shared firewall flock. Keeping
// this split lets ApplyPolicies retain the same lock until its non-authoritative
// compatibility wrappers have also been reconciled.
func applyNftablesTransactionLocked(ctx context.Context, runner nftCommandRunner, stateDirectory, baseRules string, populations []nftSetPopulation, verification nftVerificationPlan, transactionID string, precommit func() error) (string, error) {
	fail := func(format string, args ...any) (string, error) {
		return transactionID, fmt.Errorf("firewall transaction %s preserved the previous ruleset: %s", transactionID, fmt.Sprintf(format, args...))
	}

	if err := os.MkdirAll(stateDirectory, 0750); err != nil {
		return fail("create state directory: %v", err)
	}
	if err := attestNFTStateDirectory(stateDirectory); err != nil {
		return fail("attest state directory: %v", err)
	}
	if err := recoverPendingNftablesTransaction(ctx, runner, stateDirectory); err != nil {
		return fail("recover pending transaction before preparing a candidate: %v", err)
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
	rollbackRestored := func(label string, cause error) (string, error) {
		families := nftDynamicSnapshotQuarantinedFamilies(dynamicSnapshot)
		if len(families) == 0 {
			return transactionID, fmt.Errorf("firewall transaction %s preserved the previous ruleset: %s: %w", transactionID, label, cause)
		}
		return transactionID, fmt.Errorf(
			"firewall transaction %s restored the previous persistent policy; quarantined dynamic %s family state was intentionally omitted after rollback: %s: %w",
			transactionID,
			strings.Join(families, " and "),
			label,
			cause,
		)
	}
	writeNFTDynamicSnapshotWarnings(os.Stderr, dynamicSnapshot, false)

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
	if precommit != nil {
		if err := precommit(); err != nil {
			return transactionID, fmt.Errorf("firewall transaction %s preserved the previous ruleset: precommit firewall backend reattestation failed: %w", transactionID, err)
		}
	}
	journal, err := newNFTTransactionJournal(
		stateDirectory,
		transactionID,
		rollbackRules,
		len(existing) > 0,
		nftDynamicSetPresenceFromSnapshot(dynamicSnapshot),
		[]byte(persistentRules),
	)
	if err != nil {
		return fail("create durable recovery journal: %v", err)
	}

	if output, applyErr := runner.Run(ctx, nil, "-f", transactionPath); applyErr != nil {
		rollbackErr := rollbackJournaledNftables(runner, stateDirectory, journal, dynamicSnapshot)
		if rollbackErr != nil {
			return transactionID, fmt.Errorf(
				"firewall transaction %s candidate apply returned an indeterminate result (%v: %s) and rollback failed; durable recovery journal retained: %w",
				transactionID,
				applyErr,
				strings.TrimSpace(string(output)),
				rollbackErr,
			)
		}
		return rollbackRestored(
			"rolled back after candidate apply returned an indeterminate result",
			fmt.Errorf("%w: %s", applyErr, strings.TrimSpace(string(output))),
		)
	}
	// The expiry values in expectedDynamicBans are the exact relative values
	// submitted to the successful atomic apply. Start their verification clock
	// when that apply completes. Anchoring them before the potentially expensive
	// `nft -c` validation incorrectly treats validation time as elapsed kernel
	// lifetime and can reject an otherwise exact restored element.
	expectedDynamicBans.capturedAt = time.Now()
	if err := updateNFTTransactionJournal(stateDirectory, journal, nftTransactionApplied); err != nil {
		rollbackErr := rollbackJournaledNftables(runner, stateDirectory, journal, dynamicSnapshot)
		if rollbackErr != nil {
			return transactionID, fmt.Errorf("firewall transaction %s could not persist its applied phase (%v) and rollback failed: %w", transactionID, err, rollbackErr)
		}
		return rollbackRestored("rolled back after durable applied-phase update failed", err)
	}

	if err := verifyNftablesStateWithDynamicBans(ctx, runner, verification, &expectedDynamicBans); err != nil {
		rollbackErr := rollbackJournaledNftables(runner, stateDirectory, journal, dynamicSnapshot)
		if rollbackErr != nil {
			return transactionID, fmt.Errorf("firewall transaction %s verification failed (%v) and rollback failed: %w", transactionID, err, rollbackErr)
		}
		return rollbackRestored("post-apply verification failed", err)
	}
	if err := updateNFTTransactionJournal(stateDirectory, journal, nftTransactionVerified); err != nil {
		rollbackErr := rollbackJournaledNftables(runner, stateDirectory, journal, dynamicSnapshot)
		if rollbackErr != nil {
			return transactionID, fmt.Errorf("firewall transaction %s could not persist its verified phase (%v) and rollback failed: %w", transactionID, err, rollbackErr)
		}
		return rollbackRestored("rolled back after durable verified-phase update failed", err)
	}
	if precommit != nil {
		if err := precommit(); err != nil {
			rollbackErr := rollbackJournaledNftables(runner, stateDirectory, journal, dynamicSnapshot)
			if rollbackErr != nil {
				return transactionID, fmt.Errorf(
					"firewall transaction %s post-apply backend reattestation failed (%v) and rollback failed: %w",
					transactionID,
					err,
					rollbackErr,
				)
			}
			return rollbackRestored("rolled back before persistence: post-apply firewall backend reattestation failed", err)
		}
	}

	statePath := filepath.Join(stateDirectory, filepath.Base(nftStateFile))
	if err := publishNftablesFile(stateDirectory, persistentPath, statePath); err != nil {
		rollbackErr := rollbackJournaledNftables(runner, stateDirectory, journal, dynamicSnapshot)
		if rollbackErr != nil {
			return transactionID, fmt.Errorf("firewall transaction %s persistence failed (%v) and rollback failed: %w", transactionID, err, rollbackErr)
		}
		return rollbackRestored("publish verified ruleset", err)
	}
	if err := verifyNFTPersistentPolicy(statePath, true, journal.CandidatePersistentSHA256); err != nil {
		rollbackErr := rollbackJournaledNftables(runner, stateDirectory, journal, dynamicSnapshot)
		if rollbackErr != nil {
			return transactionID, fmt.Errorf("firewall transaction %s published candidate digest verification failed (%v) and rollback failed: %w", transactionID, err, rollbackErr)
		}
		return rollbackRestored("verify published ruleset digest", err)
	}
	if err := updateNFTTransactionJournal(stateDirectory, journal, nftTransactionPersisted); err != nil {
		if nftJournalWriteWasPublished(err) {
			return transactionID, fmt.Errorf(
				"firewall transaction %s is committed, verified and persisted; persisted journal phase durability is uncertain and cleanup will be retried: %w",
				transactionID,
				err,
			)
		}
		rollbackErr := rollbackJournaledNftables(runner, stateDirectory, journal, dynamicSnapshot)
		if rollbackErr != nil {
			return transactionID, fmt.Errorf("firewall transaction %s persisted the candidate but could not persist its journal phase (%v) and rollback failed: %w", transactionID, err, rollbackErr)
		}
		return rollbackRestored("rolled back after durable persisted-phase update failed", err)
	}
	if err := removeNFTTransactionJournal(stateDirectory); err != nil {
		if nftJournalWasUnlinked(err) {
			return transactionID, fmt.Errorf(
				"firewall transaction %s is committed, verified and persisted; recovery journal cleanup durability is uncertain: %w",
				transactionID,
				err,
			)
		}
		return transactionID, fmt.Errorf(
			"firewall transaction %s is committed, verified and persisted; recovery journal cleanup is incomplete and will be retried: %w",
			transactionID,
			err,
		)
	}
	writeNFTDynamicSnapshotWarnings(os.Stderr, dynamicSnapshot, true)

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
		if isSyswardenNFTTable(target) {
			existing[target] = true
		}
	}
	return existing, nil
}

func listExistingReservedNFTablesForUninstall(ctx context.Context, runner nftCommandRunner) (map[nftTableTarget]bool, error) {
	output, err := runner.Run(ctx, nil, "-j", "list", "tables")
	if err != nil {
		return nil, fmt.Errorf("nft list tables for uninstall: %w: %s", err, strings.TrimSpace(string(output)))
	}
	document, err := decodeNFTJSON(output)
	if err != nil {
		return nil, fmt.Errorf("decode nft list tables for uninstall: %w", err)
	}
	existing := make(map[nftTableTarget]bool)
	for _, entry := range document.NFTables {
		if entry.Table == nil {
			continue
		}
		target := nftTableTarget{family: entry.Table.Family, name: entry.Table.Name}
		if isReservedNFTTableForUninstall(target) {
			existing[target] = true
		}
	}
	return existing, nil
}

func legacyWireGuardForwardRuleHandle(rule *nftJSONRule) (uint64, bool) {
	if rule == nil || rule.Family != "inet" || rule.Table != "filter" || rule.Chain != "forward" ||
		rule.Handle == 0 || len(rule.Expressions) != 2 {
		return 0, false
	}
	var expression map[string]json.RawMessage
	if err := json.Unmarshal(rule.Expressions[0], &expression); err != nil || len(expression) != 1 {
		return 0, false
	}
	matchRaw, ok := expression["match"]
	if !ok {
		return 0, false
	}
	var match map[string]json.RawMessage
	if err := json.Unmarshal(matchRaw, &match); err != nil || len(match) != 3 {
		return 0, false
	}
	var operation string
	if err := json.Unmarshal(match["op"], &operation); err != nil || operation != "==" {
		return 0, false
	}
	var left map[string]json.RawMessage
	if err := json.Unmarshal(match["left"], &left); err != nil || len(left) != 1 {
		return 0, false
	}
	metaRaw, ok := left["meta"]
	if !ok {
		return 0, false
	}
	var meta map[string]json.RawMessage
	if err := json.Unmarshal(metaRaw, &meta); err != nil || len(meta) != 1 {
		return 0, false
	}
	var key string
	if err := json.Unmarshal(meta["key"], &key); err != nil || (key != "iifname" && key != "oifname") {
		return 0, false
	}
	var right string
	if err := json.Unmarshal(match["right"], &right); err != nil || right != "wg-syswarden" {
		return 0, false
	}
	var verdict map[string]json.RawMessage
	if err := json.Unmarshal(rule.Expressions[1], &verdict); err != nil || len(verdict) != 1 {
		return 0, false
	}
	accept, ok := verdict["accept"]
	if !ok || !bytes.Equal(bytes.TrimSpace(accept), []byte("null")) {
		return 0, false
	}
	return rule.Handle, true
}

func listLegacyWireGuardForwardRuleHandles(ctx context.Context, runner nftCommandRunner) ([]uint64, error) {
	output, err := runner.Run(ctx, nil, "-j", "list", "ruleset")
	if err != nil {
		return nil, fmt.Errorf("nft list ruleset for legacy WireGuard cleanup: %w: %s", err, strings.TrimSpace(string(output)))
	}
	document, err := decodeNFTJSON(output)
	if err != nil {
		return nil, fmt.Errorf("decode nft ruleset for legacy WireGuard cleanup: %w", err)
	}
	seen := make(map[uint64]struct{})
	handles := make([]uint64, 0, 2)
	for _, entry := range document.NFTables {
		handle, matched := legacyWireGuardForwardRuleHandle(entry.Rule)
		if !matched {
			continue
		}
		if _, duplicate := seen[handle]; duplicate {
			return nil, fmt.Errorf("duplicate legacy WireGuard nftables rule handle %d", handle)
		}
		seen[handle] = struct{}{}
		handles = append(handles, handle)
	}
	sort.Slice(handles, func(i, j int) bool { return handles[i] < handles[j] })
	return handles, nil
}

func cleanupReservedNFTablesForUninstall(ctx context.Context, runner nftCommandRunner) error {
	legacyHandles, err := listLegacyWireGuardForwardRuleHandles(ctx, runner)
	if err != nil {
		return err
	}
	if len(legacyHandles) > 0 {
		values := make([]string, 0, len(legacyHandles))
		for _, handle := range legacyHandles {
			values = append(values, strconv.FormatUint(handle, 10))
		}
		return fmt.Errorf("refusing to remove unowned legacy WireGuard nftables rules: handles %s; remove or attest them explicitly before retrying", strings.Join(values, ", "))
	}

	existing, err := listExistingReservedNFTablesForUninstall(ctx, runner)
	if err != nil {
		return err
	}
	wireGuardTarget := nftTableTarget{family: "inet", name: "syswarden_wg"}
	if existing[wireGuardTarget] {
		return fmt.Errorf("refusing to remove an unowned WireGuard nftables table; verified manifest-bound cleanup is required before retrying")
	}
	for _, target := range syswardenNFTTables {
		if !existing[target] {
			continue
		}
		output, deleteErr := runner.Run(ctx, nil, "delete", "table", target.family, target.name)
		if deleteErr != nil {
			return fmt.Errorf("delete reserved nftables table %s %s: %w: %s", target.family, target.name, deleteErr, strings.TrimSpace(string(output)))
		}
	}
	remaining, err := listExistingReservedNFTablesForUninstall(ctx, runner)
	if err != nil {
		return fmt.Errorf("verify reserved nftables cleanup: %w", err)
	}
	if len(remaining) > 0 {
		identities := make([]string, 0, len(remaining))
		for _, target := range syswardenNFTTables {
			if remaining[target] {
				identities = append(identities, target.family+" "+target.name)
			}
		}
		return fmt.Errorf("reserved nftables tables remain after uninstall cleanup: %s", strings.Join(identities, ", "))
	}
	return nil
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
		separatorBytes := 0
		if len(output) > 0 && output[len(output)-1] != '\n' {
			separatorBytes = 1
		}
		if len(output) > maximumNFTJournalFieldBytes-snapshot.Len()-separatorBytes {
			return "", fmt.Errorf("snapshot of SysWarden nftables tables exceeds %d bytes", maximumNFTJournalFieldBytes)
		}
		snapshot.Write(output)
		if len(output) > 0 && output[len(output)-1] != '\n' {
			snapshot.WriteByte('\n')
		}
	}
	return snapshot.String(), nil
}

func rollbackNftables(runner nftCommandRunner, snapshot string, dynamicSnapshot nftDynamicSnapshot, previousSets nftDynamicSetPresence) error {
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
	dynamicRules, err := buildNFTDynamicBanRollbackRules(dynamicSnapshot, time.Now(), previousSets)
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
	if expected.operatorPolicy.chainName != "" {
		if policyErr := verifyOperatorPolicyNFTState(document, expected.operatorPolicy); policyErr != nil {
			errs = append(errs, policyErr)
		}
	}
	if expectedDynamic != nil {
		observedAt := time.Now()
		observed, snapshotErr := extractNFTDynamicSnapshot(document, observedAt)
		if snapshotErr != nil {
			errs = append(errs, fmt.Errorf("inspect preserved dynamic bans: %w", snapshotErr))
		} else {
			for _, key := range nftDynamicBanSets {
				if len(observed.discarded[key]) > 0 {
					errs = append(errs, fmt.Errorf(
						"dynamic set %s %s %s still contains ambiguous maximum-ending interval state after apply",
						key.family,
						key.table,
						key.name,
					))
				}
			}
			if comparisonErr := compareNFTDynamicSnapshots(*expectedDynamic, observed, observedAt); comparisonErr != nil {
				errs = append(errs, comparisonErr)
			}
		}
	}
	return errors.Join(errs...)
}

const nftCatchAllLogPrefix = "[SYSWARDEN-BLOCK] [CATCH-ALL] "

func verifyOperatorPolicyNFTState(document nftJSONDocument, expected operatorPolicyVerification) error {
	if expected.chainName == "" || expected.chainName != operatorPolicyChainName ||
		expected.dispatchComment == "" || expected.returnComment == "" {
		return fmt.Errorf("operator policy verification plan is invalid")
	}

	var errs []error
	operatorChainDefinitions := 0
	var operatorRules []*nftJSONRule
	var statefulRules []*nftJSONRule
	var syswardenRules []*nftJSONRule
	for index := range document.NFTables {
		entry := &document.NFTables[index]
		if entry.Chain != nil && entry.Chain.Family == "inet" &&
			entry.Chain.Table == "syswarden" && entry.Chain.Name == expected.chainName {
			operatorChainDefinitions++
			if chainErr := verifyOperatorPolicyChainEnvelope(entry.Chain); chainErr != nil {
				errs = append(errs, chainErr)
			}
		}
		if entry.Rule == nil {
			continue
		}
		rule := entry.Rule
		if rule.Family == "inet" && rule.Table == "syswarden" {
			syswardenRules = append(syswardenRules, rule)
			if rule.Chain == expected.chainName {
				operatorRules = append(operatorRules, rule)
			}
			if rule.Chain == "stateful_protect" {
				statefulRules = append(statefulRules, rule)
			}
		}
	}

	if operatorChainDefinitions != 1 {
		errs = append(errs, fmt.Errorf("operator policy chain definition count is %d, expected 1", operatorChainDefinitions))
	}
	if len(operatorRules) != len(expected.rules)+1 {
		errs = append(errs, fmt.Errorf(
			"operator policy chain contains %d rules, expected %d policy rules plus one terminal return",
			len(operatorRules),
			len(expected.rules),
		))
	} else {
		for index, ruleExpectation := range expected.rules {
			expressions, expressionErr := expectedOperatorPolicyExpressions(ruleExpectation)
			if expressionErr != nil {
				errs = append(errs, fmt.Errorf("operator policy verification rule %d is invalid: %w", index, expressionErr))
				continue
			}
			if ruleErr := verifyNFTJSONRuleExact(
				operatorRules[index],
				"inet",
				"syswarden",
				expected.chainName,
				ruleExpectation.comment,
				expressions,
			); ruleErr != nil {
				errs = append(errs, fmt.Errorf("operator policy rule %d mismatch: %w", index, ruleErr))
			}
		}
		terminal := operatorRules[len(operatorRules)-1]
		if terminalErr := verifyNFTJSONRuleExact(
			terminal,
			"inet",
			"syswarden",
			expected.chainName,
			expected.returnComment,
			[]any{map[string]any{"return": nil}},
		); terminalErr != nil {
			errs = append(errs, fmt.Errorf("operator policy terminal return mismatch: %w", terminalErr))
		}
	}

	var dispatch *nftJSONRule
	if len(statefulRules) < 3 {
		errs = append(errs, fmt.Errorf("stateful_protect contains %d rules and cannot hold the required terminal dispatch/log/drop sequence", len(statefulRules)))
	} else {
		dispatch = statefulRules[len(statefulRules)-3]
		if dispatchErr := verifyNFTJSONRuleExact(
			dispatch,
			"inet",
			"syswarden",
			"stateful_protect",
			expected.dispatchComment,
			[]any{map[string]any{"jump": map[string]any{"target": expected.chainName}}},
		); dispatchErr != nil {
			errs = append(errs, fmt.Errorf("operator policy dispatch mismatch: %w", dispatchErr))
		}
		if catchAllErr := verifyNFTCatchAllLogRule(statefulRules[len(statefulRules)-2]); catchAllErr != nil {
			errs = append(errs, fmt.Errorf("operator policy terminal catch-all log mismatch: %w", catchAllErr))
		}
		if dropErr := verifyNFTJSONRuleExact(
			statefulRules[len(statefulRules)-1],
			"inet",
			"syswarden",
			"stateful_protect",
			"",
			[]any{
				nftCTStateNewExpression(),
				map[string]any{"counter": map[string]any{}},
				map[string]any{"drop": nil},
			},
		); dropErr != nil {
			errs = append(errs, fmt.Errorf("operator policy terminal catch-all drop mismatch: %w", dropErr))
		}
	}

	operatorReferences := 0
	for _, rule := range syswardenRules {
		for _, expression := range rule.Expressions {
			kind, target, found := nftJSONVerdictTarget(expression)
			if found && target == expected.chainName {
				operatorReferences++
				if rule != dispatch || kind != "jump" {
					errs = append(errs, fmt.Errorf(
						"operator policy chain has an unexpected %s reference from %s %s %s",
						kind,
						rule.Family,
						rule.Table,
						rule.Chain,
					))
				}
			}
		}
		if strings.Contains(rule.Comment, operatorPolicyCommentPrefix) {
			inOperatorChain := rule.Family == "inet" && rule.Table == "syswarden" && rule.Chain == expected.chainName
			if !inOperatorChain && rule != dispatch {
				errs = append(errs, fmt.Errorf(
					"operator policy comment marker exists outside the verified policy surface at %s %s %s",
					rule.Family,
					rule.Table,
					rule.Chain,
				))
			}
		}
	}
	if operatorReferences != 1 {
		errs = append(errs, fmt.Errorf("operator policy chain reference count is %d, expected exactly one jump", operatorReferences))
	}

	return errors.Join(errs...)
}

func expectedOperatorPolicyExpressions(expected operatorPolicyRuleExpectation) ([]any, error) {
	var source any = expected.source
	if strings.Contains(expected.source, "/") {
		prefix, err := netip.ParsePrefix(expected.source)
		if err != nil || !prefix.IsValid() || prefix.String() != expected.source {
			return nil, fmt.Errorf("source %q is not a canonical prefix", expected.source)
		}
		if prefix.Bits() == prefix.Addr().BitLen() {
			source = prefix.Addr().String()
		} else {
			source = map[string]any{"prefix": map[string]any{"addr": prefix.Addr().String(), "len": prefix.Bits()}}
		}
	}

	sourceProtocol := "ip"
	transportProtocol := "icmp"
	protocolExpression := map[string]any{"match": map[string]any{
		"op":    "==",
		"left":  map[string]any{"payload": map[string]any{"protocol": "ip", "field": "protocol"}},
		"right": "icmp",
	}}
	if expected.family == config.OperatorPolicyFamilyIPv6 {
		sourceProtocol = "ip6"
		transportProtocol = "icmpv6"
	} else if expected.family != config.OperatorPolicyFamilyIPv4 {
		return nil, fmt.Errorf("unsupported family %q", expected.family)
	}

	expressions := []any{
		map[string]any{"match": map[string]any{
			"op":    "==",
			"left":  map[string]any{"payload": map[string]any{"protocol": sourceProtocol, "field": "saddr"}},
			"right": source,
		}},
	}
	if expected.family == config.OperatorPolicyFamilyIPv4 {
		expressions = append(expressions, protocolExpression)
	}
	expressions = append(expressions,
		map[string]any{"match": map[string]any{
			"op":    "==",
			"left":  map[string]any{"payload": map[string]any{"protocol": transportProtocol, "field": "type"}},
			"right": "echo-request",
		}},
		map[string]any{"counter": map[string]any{}},
		map[string]any{"accept": nil},
	)
	return expressions, nil
}

func nftCTStateNewExpression() any {
	return map[string]any{"match": map[string]any{
		"op":    "in",
		"left":  map[string]any{"ct": map[string]any{"key": "state"}},
		"right": "new",
	}}
}

func verifyNFTCatchAllLogRule(rule *nftJSONRule) error {
	if err := verifyNFTJSONRuleEnvelope(rule, "inet", "syswarden", "stateful_protect", ""); err != nil {
		return err
	}
	if len(rule.Expressions) != 3 {
		return fmt.Errorf("expression count is %d, expected 3", len(rule.Expressions))
	}
	if err := verifyNFTJSONExpressionExact(rule.Expressions[0], nftCTStateNewExpression()); err != nil {
		return fmt.Errorf("ct state new expression: %w", err)
	}
	if err := verifyNFTLimitExpression(rule.Expressions[1]); err != nil {
		return err
	}
	if err := verifyNFTJSONExpressionExact(
		rule.Expressions[2],
		map[string]any{"log": map[string]any{"prefix": nftCatchAllLogPrefix}},
	); err != nil {
		return fmt.Errorf("log prefix expression: %w", err)
	}
	return nil
}

func verifyNFTLimitExpression(raw json.RawMessage) error {
	object, err := decodeNFTJSONObject(raw)
	if err != nil {
		return fmt.Errorf("catch-all limit expression: %w", err)
	}
	if len(object) != 1 {
		return fmt.Errorf("catch-all limit expression has unexpected fields")
	}
	value, exists := object["limit"]
	if !exists {
		return fmt.Errorf("catch-all limit expression is missing")
	}
	limit, ok := value.(map[string]any)
	if !ok {
		return fmt.Errorf("catch-all limit expression is not an object")
	}
	for name := range limit {
		switch name {
		case "rate", "per", "burst", "rate_unit", "burst_unit", "inv":
		default:
			return fmt.Errorf("catch-all limit contains unexpected field %q", name)
		}
	}
	if !nftJSONExactNumber(limit["rate"], "2") || limit["per"] != "second" || !nftJSONExactNumber(limit["burst"], "5") {
		return fmt.Errorf("catch-all limit rate/per/burst differs from 2/second burst 5")
	}
	if unit, present := limit["rate_unit"]; present && unit != "packets" {
		return fmt.Errorf("catch-all rate unit is %v, expected packets", unit)
	}
	if unit, present := limit["burst_unit"]; present && unit != "packets" {
		return fmt.Errorf("catch-all burst unit is %v, expected packets", unit)
	}
	if inverse, present := limit["inv"]; present && inverse != false {
		return fmt.Errorf("catch-all limit unexpectedly uses inversion")
	}
	return nil
}

func nftJSONExactNumber(value any, expected string) bool {
	number, ok := value.(json.Number)
	return ok && number.String() == expected
}

func verifyNFTJSONRuleExact(rule *nftJSONRule, family, table, chain, comment string, expectedExpressions []any) error {
	if err := verifyNFTJSONRuleEnvelope(rule, family, table, chain, comment); err != nil {
		return err
	}
	if len(rule.Expressions) != len(expectedExpressions) {
		return fmt.Errorf("expression count is %d, expected %d", len(rule.Expressions), len(expectedExpressions))
	}
	for index := range expectedExpressions {
		if err := verifyNFTJSONExpressionExact(rule.Expressions[index], expectedExpressions[index]); err != nil {
			return fmt.Errorf("expression %d: %w", index, err)
		}
	}
	return nil
}

func verifyNFTJSONRuleEnvelope(rule *nftJSONRule, family, table, chain, comment string) error {
	if rule == nil {
		return fmt.Errorf("rule is missing")
	}
	if len(rule.unknown) != 0 {
		return fmt.Errorf("rule contains unexpected top-level field %q", rule.unknown[0])
	}
	for _, required := range []string{"family", "table", "chain", "handle", "expr"} {
		if _, present := rule.present[required]; !present {
			return fmt.Errorf("rule field %q is missing", required)
		}
	}
	_, commentPresent := rule.present["comment"]
	if comment != "" && !commentPresent {
		return fmt.Errorf("rule comment field is missing")
	}
	if comment == "" && commentPresent {
		return fmt.Errorf("rule contains an unexpected empty comment field")
	}
	if rule.Family != family || rule.Table != table || rule.Chain != chain {
		return fmt.Errorf(
			"rule location is %s %s %s, expected %s %s %s",
			rule.Family,
			rule.Table,
			rule.Chain,
			family,
			table,
			chain,
		)
	}
	if rule.Comment != comment {
		return fmt.Errorf("rule comment is %q, expected %q", rule.Comment, comment)
	}
	return nil
}

func verifyOperatorPolicyChainEnvelope(chain *nftJSONChain) error {
	if chain == nil {
		return fmt.Errorf("operator policy chain is missing")
	}
	required := map[string]struct{}{
		"family": {},
		"table":  {},
		"name":   {},
		"handle": {},
	}
	for name := range required {
		if _, present := chain.present[name]; !present {
			return fmt.Errorf("operator policy chain field %q is missing", name)
		}
	}
	var unexpected []string
	for name := range chain.present {
		if _, allowed := required[name]; !allowed {
			unexpected = append(unexpected, name)
		}
	}
	if len(unexpected) != 0 {
		sort.Strings(unexpected)
		return fmt.Errorf("operator policy regular chain contains unexpected field %q", unexpected[0])
	}
	return nil
}

func verifyNFTJSONExpressionExact(raw json.RawMessage, expected any) error {
	actual, err := canonicalNFTJSONExpression(raw)
	if err != nil {
		return err
	}
	wanted, err := json.Marshal(expected)
	if err != nil {
		return err
	}
	if !bytes.Equal(actual, wanted) {
		return fmt.Errorf("expression is %s, expected %s", actual, wanted)
	}
	return nil
}

func canonicalNFTJSONExpression(raw json.RawMessage) ([]byte, error) {
	object, err := decodeNFTJSONObject(raw)
	if err != nil {
		return nil, err
	}
	if counter, exists := object["counter"]; exists {
		if len(object) != 1 {
			return nil, fmt.Errorf("counter expression contains sibling fields")
		}
		counterObject, ok := counter.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("counter expression is not an object")
		}
		if len(counterObject) != 2 {
			return nil, fmt.Errorf("counter expression must contain exactly packets and bytes")
		}
		for _, name := range []string{"packets", "bytes"} {
			value, present := counterObject[name]
			if !present {
				return nil, fmt.Errorf("counter expression field %q is missing", name)
			}
			if !nftJSONNonNegativeInteger(value) {
				return nil, fmt.Errorf("counter expression field %q must be a non-negative integer", name)
			}
		}
		object["counter"] = map[string]any{}
	}
	return json.Marshal(object)
}

func nftJSONNonNegativeInteger(value any) bool {
	number, ok := value.(json.Number)
	if !ok {
		return false
	}
	text := number.String()
	if text == "" || strings.HasPrefix(text, "-") || strings.ContainsAny(text, ".eE+") {
		return false
	}
	_, err := strconv.ParseUint(text, 10, 64)
	return err == nil
}

func decodeNFTJSONObject(raw json.RawMessage) (map[string]any, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("expression is not an object")
	}
	return object, nil
}

func nftJSONVerdictTarget(raw json.RawMessage) (string, string, bool) {
	object, err := decodeNFTJSONObject(raw)
	if err != nil || len(object) != 1 {
		return "", "", false
	}
	for _, kind := range []string{"jump", "goto"} {
		value, exists := object[kind]
		if !exists {
			continue
		}
		verdict, ok := value.(map[string]any)
		if !ok {
			return "", "", false
		}
		target, ok := verdict["target"].(string)
		return kind, target, ok
	}
	return "", "", false
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
			timeoutMatches := found.timeout == wanted.timeout
			if !timeoutMatches {
				errs = append(errs, fmt.Errorf("dynamic set %s %s %s timeout for %s is %s, expected %s", key.family, key.table, key.name, identity, found.timeout, wanted.timeout))
			}
			if found.omitFromMigration {
				if timeoutMatches && wanted.expires <= expiryTolerance {
					continue
				}
				errs = append(errs, fmt.Errorf("dynamic set %s %s %s reached a zero-second reported expiry for %s outside the expected final-second tolerance", key.family, key.table, key.name, identity))
				continue
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
	previous, readErr := readPrivateRootedNFTFile(targetPath, maximumNFTJournalFieldBytes)
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
