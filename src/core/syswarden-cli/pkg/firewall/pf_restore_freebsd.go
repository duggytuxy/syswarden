//go:build freebsd

package firewall

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
)

const (
	maxPersistedPFConfigBytes = 8 << 20
	maxPFViewBytes            = 8 << 20
	maxPFLiveSnapshotBytes    = 24 << 20
	maxPFSnapshotBytes        = 64 << 20
	maxPFAnchors              = 128
	pfSnapshotSchemaVersion   = 2
	pfSnapshotTemporaryName   = ".pf-policy-snapshot.tmp"
	pfModuleName              = "pf"
)

// PFSnapshotProvenance describes what can truthfully be reconstructed.
type PFSnapshotProvenance string

const (
	// PFSnapshotExactLive records the live policy before the first candidate mutation.
	PFSnapshotExactLive PFSnapshotProvenance = "exact_live"
	// PFSnapshotLegacyDerived records only the configured policy when v4.02.8
	// has already overwritten the live PF policy.
	PFSnapshotLegacyDerived PFSnapshotProvenance = "legacy_derived"
)

// PFInitialKernelState records whether the PF control plane existed before
// SysWarden first acquired its runtime lock for this installation lifecycle.
type PFInitialKernelState string

const (
	PFInitialKernelAvailable    PFInitialKernelState = "available"
	PFInitialKernelModuleAbsent PFInitialKernelState = "module_absent"
)

type pfSourceIdentity struct {
	Path   string `json:"path"`
	Exists bool   `json:"exists"`
	Mode   uint32 `json:"mode"`
	UID    uint32 `json:"uid"`
	GID    uint32 `json:"gid"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type pfTableSnapshot struct {
	Name    string `json:"name"`
	Entries string `json:"entries"`
}

type pfAnchorSnapshot struct {
	Name         string            `json:"name"`
	FilterRules  string            `json:"filter_rules"`
	NATRules     string            `json:"nat_rules"`
	Tables       string            `json:"tables"`
	AnchorNames  string            `json:"anchor_names"`
	TableEntries []pfTableSnapshot `json:"table_entries"`
}

type pfLivePolicy struct {
	FilterRules  string             `json:"filter_rules"`
	NATRules     string             `json:"nat_rules"`
	Tables       string             `json:"tables"`
	AnchorNames  string             `json:"anchor_names"`
	States       string             `json:"states"`
	TableEntries []pfTableSnapshot  `json:"table_entries"`
	Anchors      []pfAnchorSnapshot `json:"anchors"`
}

type pfPolicySnapshot struct {
	SchemaVersion      int                  `json:"schema_version"`
	Provenance         PFSnapshotProvenance `json:"provenance"`
	InitialKernelState PFInitialKernelState `json:"initial_kernel_state"`
	MutationStarted    bool                 `json:"mutation_started"`
	RuntimeStatus      string               `json:"runtime_status"`
	ConfiguredStatus   string               `json:"configured_status"`
	LivePolicy         pfLivePolicy         `json:"live_policy"`
	Source             pfSourceIdentity     `json:"source"`
	SourceContent      []byte               `json:"source_content"`
}

type safePFSource struct {
	identity pfSourceIdentity
	content  []byte
}

var (
	pfSnapshotDirectory = "/var/db/syswarden"
	pfSnapshotName      = "pf-policy-snapshot.json"
	pfExpectedOwner     = func() int { return 0 }
	pfControlDevicePath = "/dev/pf"
	newPFCTLCommand     = func(arguments ...string) *exec.Cmd {
		return exec.Command("/sbin/pfctl", arguments...) // #nosec G204 -- the absolute binary and every argument come from fixed internal call sites
	}
	newPFSysrcCommand = func(arguments ...string) *exec.Cmd {
		return exec.Command("/usr/sbin/sysrc", arguments...) // #nosec G204 -- the absolute binary and every argument come from fixed internal call sites
	}
	newPFKLDStatCommand = func(arguments ...string) *exec.Cmd {
		return exec.Command("/sbin/kldstat", arguments...) // #nosec G204 -- the absolute binary and every argument come from fixed internal call sites
	}
	newPFKLDLoadCommand = func(arguments ...string) *exec.Cmd {
		return exec.Command("/sbin/kldload", arguments...) // #nosec G204 -- the absolute binary and every argument come from fixed internal call sites
	}
	newPFKLDUnloadCommand = func(arguments ...string) *exec.Cmd {
		return exec.Command("/sbin/kldunload", arguments...) // #nosec G204 -- the absolute binary and every argument come from fixed internal call sites
	}
	inspectPFKernelState = inspectPFInitialKernelStateNative
)

func normalizedPFConfiguredStatus() (string, error) {
	output, err := boundedCommandOutput(4096, newPFSysrcCommand("-n", "pf_enable"))
	if err != nil {
		return "", fmt.Errorf("read configured PF enablement: %w", err)
	}
	value := strings.ToUpper(strings.Trim(strings.TrimSpace(string(output)), `"'`))
	switch value {
	case "YES", "TRUE", "ON", "1":
		return "Enabled", nil
	case "NO", "FALSE", "OFF", "0":
		return "Disabled", nil
	default:
		return "", fmt.Errorf("unrecognized configured pf_enable value %q", value)
	}
}

func configuredPFRulesPath() (string, error) {
	output, err := boundedCommandOutput(4096, newPFSysrcCommand("-n", "pf_rules"))
	if err != nil {
		return "", fmt.Errorf("read configured PF rules path: %w", err)
	}
	path := strings.Trim(strings.TrimSpace(string(output)), `"'`)
	clean := filepath.Clean(path)
	if path == "" || !filepath.IsAbs(clean) || clean != path || clean == string(filepath.Separator) {
		return "", fmt.Errorf("configured pf_rules path is not an absolute canonical file: %q", path)
	}
	resolvedDirectory, err := filepath.EvalSymlinks(filepath.Dir(clean))
	if err != nil {
		return "", fmt.Errorf("resolve configured PF rules directory: %w", err)
	}
	if resolvedDirectory != filepath.Dir(clean) {
		return "", fmt.Errorf("configured PF rules directory traverses a symbolic link")
	}
	return clean, nil
}

func readSafePFSource(path string) (safePFSource, error) {
	clean := filepath.Clean(path)
	if !filepath.IsAbs(clean) || clean != path {
		return safePFSource{}, fmt.Errorf("PF source path is not absolute and canonical")
	}
	root, err := os.OpenRoot(filepath.Dir(clean))
	if err != nil {
		return safePFSource{}, fmt.Errorf("open PF source directory: %w", err)
	}
	defer func() { _ = root.Close() }()
	name := filepath.Base(clean)
	before, err := root.Lstat(name)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			directory, directoryErr := os.Stat(filepath.Dir(clean))
			if directoryErr != nil {
				return safePFSource{}, fmt.Errorf("inspect missing PF source directory: %w", directoryErr)
			}
			stat, ok := directory.Sys().(*syscall.Stat_t)
			if !directory.IsDir() || !ok || int(stat.Uid) != pfExpectedOwner() ||
				directory.Mode().Perm()&0022 != 0 {
				return safePFSource{}, fmt.Errorf("missing PF source parent is not a safe root-owned directory")
			}
			digest := sha256.Sum256(nil)
			return safePFSource{identity: pfSourceIdentity{
				Path: clean, Exists: false, SHA256: hex.EncodeToString(digest[:]),
			}}, nil
		}
		return safePFSource{}, fmt.Errorf("inspect PF source: %w", err)
	}
	if !before.Mode().IsRegular() || before.Mode().Perm()&0022 != 0 ||
		before.Size() < 0 || before.Size() > maxPersistedPFConfigBytes {
		return safePFSource{}, fmt.Errorf("PF source is not a bounded safe regular file")
	}
	stat, ok := before.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != pfExpectedOwner() {
		return safePFSource{}, fmt.Errorf("PF source is not owned by root")
	}
	file, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return safePFSource{}, fmt.Errorf("open PF source: %w", err)
	}
	defer func() { _ = file.Close() }()
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) {
		if err != nil {
			return safePFSource{}, fmt.Errorf("inspect opened PF source: %w", err)
		}
		return safePFSource{}, fmt.Errorf("PF source changed while opening")
	}
	content, err := io.ReadAll(io.LimitReader(file, maxPersistedPFConfigBytes+1))
	if err != nil {
		return safePFSource{}, fmt.Errorf("read PF source: %w", err)
	}
	if len(content) > maxPersistedPFConfigBytes || int64(len(content)) != after.Size() {
		return safePFSource{}, fmt.Errorf("PF source changed or exceeds the size bound")
	}
	digest := sha256.Sum256(content)
	return safePFSource{
		identity: pfSourceIdentity{
			Path:   clean,
			Exists: true,
			Mode:   uint32(after.Mode().Perm()),
			UID:    stat.Uid,
			GID:    stat.Gid,
			Size:   after.Size(),
			SHA256: hex.EncodeToString(digest[:]),
		},
		content: content,
	}, nil
}

type boundedBuffer struct {
	buffer   bytes.Buffer
	limit    int
	overflow bool
}

func (writer *boundedBuffer) Write(data []byte) (int, error) {
	remaining := writer.limit + 1 - writer.buffer.Len()
	if remaining > 0 {
		if remaining > len(data) {
			remaining = len(data)
		}
		_, _ = writer.buffer.Write(data[:remaining])
	}
	if writer.buffer.Len() > writer.limit {
		writer.overflow = true
	}
	return len(data), nil
}

func boundedCommandOutput(limit int, command *exec.Cmd) ([]byte, error) {
	stdout := &boundedBuffer{limit: limit}
	stderr := &boundedBuffer{limit: 4096}
	command.Stdout = stdout
	command.Stderr = stderr
	if err := command.Run(); err != nil {
		return nil, fmt.Errorf("%s: %s: %w", command.Path, strings.TrimSpace(stderr.buffer.String()), err)
	}
	if stdout.overflow || stderr.overflow {
		return nil, fmt.Errorf("%s output exceeds its bound", command.Path)
	}
	return stdout.buffer.Bytes(), nil
}

func boundedPFInput(content []byte, command *exec.Cmd) error {
	stdout := &boundedBuffer{limit: 4096}
	stderr := &boundedBuffer{limit: 4096}
	command.Stdin = bytes.NewReader(content)
	command.Stdout = stdout
	command.Stderr = stderr
	if err := command.Run(); err != nil {
		return fmt.Errorf("%s: %s: %w", strings.Join(command.Args, " "), strings.TrimSpace(stderr.buffer.String()), err)
	}
	if stdout.overflow || stderr.overflow {
		return fmt.Errorf("%s output exceeds its bound", strings.Join(command.Args, " "))
	}
	return nil
}

func runBoundedQuietCommand(command *exec.Cmd) error {
	stdout := &boundedBuffer{limit: 4096}
	stderr := &boundedBuffer{limit: 4096}
	command.Stdout = stdout
	command.Stderr = stderr
	if err := command.Run(); err != nil {
		return fmt.Errorf("%s: %s: %w", command.Path, strings.TrimSpace(stderr.buffer.String()), err)
	}
	if stdout.overflow || stderr.overflow {
		return fmt.Errorf("%s output exceeds its bound", command.Path)
	}
	if stdout.buffer.Len() != 0 || stderr.buffer.Len() != 0 {
		return fmt.Errorf("%s emitted unexpected output", command.Path)
	}
	return nil
}

func pfKernelModulePresent() (bool, error) {
	command := newPFKLDStatCommand("-q", "-m", pfModuleName)
	stdout := &boundedBuffer{limit: 4096}
	stderr := &boundedBuffer{limit: 4096}
	command.Stdout = stdout
	command.Stderr = stderr
	err := command.Run()
	if stdout.overflow || stderr.overflow {
		return false, fmt.Errorf("query PF kernel module output exceeds its bound")
	}
	if stdout.buffer.Len() != 0 || stderr.buffer.Len() != 0 {
		return false, fmt.Errorf("query PF kernel module emitted unexpected output")
	}
	if err == nil {
		return true, nil
	}
	var exitError *exec.ExitError
	if errors.As(err, &exitError) && exitError.ExitCode() == 1 {
		return false, nil
	}
	return false, fmt.Errorf("query PF kernel module: %w", err)
}

func inspectPFInitialKernelStateNative() (PFInitialKernelState, error) {
	info, deviceErr := os.Lstat(pfControlDevicePath)
	deviceAbsent := errors.Is(deviceErr, fs.ErrNotExist)
	if deviceErr != nil && !deviceAbsent {
		return "", fmt.Errorf("inspect PF control device: %w", deviceErr)
	}
	modulePresent, err := pfKernelModulePresent()
	if err != nil {
		return "", err
	}
	if deviceAbsent && !modulePresent {
		return PFInitialKernelModuleAbsent, nil
	}
	if deviceAbsent {
		return "", fmt.Errorf("PF kernel module is present while its control device is absent")
	}
	mode := info.Mode()
	if mode&os.ModeSymlink != 0 || mode&os.ModeDevice == 0 || mode&os.ModeCharDevice == 0 {
		return "", fmt.Errorf("PF control device is not a nonsymlink character device")
	}
	if !modulePresent {
		return "", fmt.Errorf("PF control device exists while its kernel module is absent")
	}
	return PFInitialKernelAvailable, nil
}

func loadPFKernelModule() error {
	if err := runBoundedQuietCommand(newPFKLDLoadCommand("-n", "-q", pfModuleName)); err != nil {
		return fmt.Errorf("load PF kernel module: %w", err)
	}
	state, err := inspectPFKernelState()
	if err != nil {
		return fmt.Errorf("verify loaded PF kernel module: %w", err)
	}
	if state != PFInitialKernelAvailable {
		return fmt.Errorf("PF kernel module load did not publish its control device")
	}
	return nil
}

func unloadPFKernelModule() error {
	if err := runBoundedQuietCommand(newPFKLDUnloadCommand("-n", pfModuleName)); err != nil {
		return fmt.Errorf("unload PF kernel module: %w", err)
	}
	state, err := inspectPFKernelState()
	if err != nil {
		return fmt.Errorf("verify unloaded PF kernel module: %w", err)
	}
	if state != PFInitialKernelModuleAbsent {
		return fmt.Errorf("PF kernel module remains available after unload")
	}
	return nil
}

func requirePFKernelState(expected PFInitialKernelState) error {
	actual, err := inspectPFKernelState()
	if err != nil {
		return err
	}
	if actual != expected {
		return fmt.Errorf("PF kernel state mismatch: expected=%s current=%s", expected, actual)
	}
	return nil
}

func currentPFStatus() (string, error) {
	output, err := boundedCommandOutput(4096, newPFCTLCommand("-s", "info"))
	if err != nil {
		return "", fmt.Errorf("query PF status: %w", err)
	}
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "Status:" &&
			(fields[1] == "Enabled" || fields[1] == "Disabled") {
			return fields[1], nil
		}
	}
	return "", fmt.Errorf("PF status output lacks an exact Enabled or Disabled state")
}

type pfDynamicOperation string

const (
	pfDynamicTableShow      pfDynamicOperation = "table_show"
	pfDynamicTableReplace   pfDynamicOperation = "table_replace"
	pfDynamicAnchorRules    pfDynamicOperation = "anchor_rules"
	pfDynamicAnchorNAT      pfDynamicOperation = "anchor_nat"
	pfDynamicAnchorTables   pfDynamicOperation = "anchor_tables"
	pfDynamicAnchorNames    pfDynamicOperation = "anchor_names"
	pfDynamicAnchorValidate pfDynamicOperation = "anchor_validate"
	pfDynamicAnchorLoad     pfDynamicOperation = "anchor_load"
)

var runDynamicPFCommand = runDynamicPFCommandNative

func validPFObjectName(value string, allowSlash bool) bool {
	if value == "" || len(value) > 255 || strings.HasPrefix(value, "/") || strings.HasSuffix(value, "/") {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' || character == '_' || character == '-' ||
			character == '.' || character == ':' ||
			allowSlash && (character == '/' || character == '(' || character == ')') {
			continue
		}
		return false
	}
	return true
}

func runDynamicPFCommandNative(operation pfDynamicOperation, anchor, table string, input []byte) ([]byte, error) {
	if anchor != "" && !validPFObjectName(anchor, true) {
		return nil, fmt.Errorf("invalid PF anchor name %q", anchor)
	}
	if table != "" && !validPFObjectName(table, false) {
		return nil, fmt.Errorf("invalid PF table name %q", table)
	}
	var command *exec.Cmd
	switch operation {
	case pfDynamicTableShow:
		command = exec.Command("/bin/sh", "-c", `if [ -n "$SYSWARDEN_PF_ANCHOR" ]; then exec /sbin/pfctl -a "$SYSWARDEN_PF_ANCHOR" -t "$SYSWARDEN_PF_TABLE" -T show; fi; exec /sbin/pfctl -t "$SYSWARDEN_PF_TABLE" -T show`)
	case pfDynamicTableReplace:
		command = exec.Command("/bin/sh", "-c", `if [ -n "$SYSWARDEN_PF_ANCHOR" ]; then exec /sbin/pfctl -a "$SYSWARDEN_PF_ANCHOR" -t "$SYSWARDEN_PF_TABLE" -T replace -f -; fi; exec /sbin/pfctl -t "$SYSWARDEN_PF_TABLE" -T replace -f -`)
	case pfDynamicAnchorRules:
		command = exec.Command("/bin/sh", "-c", `exec /sbin/pfctl -a "$SYSWARDEN_PF_ANCHOR" -sr`)
	case pfDynamicAnchorNAT:
		command = exec.Command("/bin/sh", "-c", `exec /sbin/pfctl -a "$SYSWARDEN_PF_ANCHOR" -sn`)
	case pfDynamicAnchorTables:
		command = exec.Command("/bin/sh", "-c", `exec /sbin/pfctl -a "$SYSWARDEN_PF_ANCHOR" -s Tables`)
	case pfDynamicAnchorNames:
		command = exec.Command("/bin/sh", "-c", `exec /sbin/pfctl -a "$SYSWARDEN_PF_ANCHOR" -s Anchors`)
	case pfDynamicAnchorValidate:
		command = exec.Command("/bin/sh", "-c", `exec /sbin/pfctl -n -a "$SYSWARDEN_PF_ANCHOR" -f -`)
	case pfDynamicAnchorLoad:
		command = exec.Command("/bin/sh", "-c", `exec /sbin/pfctl -a "$SYSWARDEN_PF_ANCHOR" -f -`)
	default:
		return nil, fmt.Errorf("unsupported dynamic PF operation %q", operation)
	}
	command.Env = append(
		os.Environ(),
		"SYSWARDEN_PF_ANCHOR="+anchor,
		"SYSWARDEN_PF_TABLE="+table,
	)
	stdout := &boundedBuffer{limit: maxPFViewBytes}
	stderr := &boundedBuffer{limit: 4096}
	command.Stdin = bytes.NewReader(input)
	command.Stdout = stdout
	command.Stderr = stderr
	if err := command.Run(); err != nil {
		return nil, fmt.Errorf("dynamic PF operation %s: %s: %w", operation, strings.TrimSpace(stderr.buffer.String()), err)
	}
	if stdout.overflow || stderr.overflow {
		return nil, fmt.Errorf("dynamic PF operation %s output exceeds its bound", operation)
	}
	return stdout.buffer.Bytes(), nil
}

func parsePFNames(view string, allowSlash bool) ([]string, error) {
	names := make([]string, 0)
	seen := make(map[string]struct{})
	for _, line := range strings.Split(view, "\n") {
		name := strings.TrimSpace(line)
		if name == "" {
			continue
		}
		if !validPFObjectName(name, allowSlash) {
			return nil, fmt.Errorf("invalid PF object name %q", name)
		}
		if _, duplicate := seen[name]; duplicate {
			return nil, fmt.Errorf("duplicate PF object name %q", name)
		}
		seen[name] = struct{}{}
		names = append(names, name)
	}
	sort.Strings(names)
	return names, nil
}

func capturePFTableEntries(anchor, tablesView string) ([]pfTableSnapshot, error) {
	names, err := parsePFNames(tablesView, false)
	if err != nil {
		return nil, err
	}
	tables := make([]pfTableSnapshot, 0, len(names))
	for _, name := range names {
		entries, err := runDynamicPFCommand(pfDynamicTableShow, anchor, name, nil)
		if err != nil {
			return nil, fmt.Errorf("capture entries for PF table %s: %w", name, err)
		}
		tables = append(tables, pfTableSnapshot{Name: name, Entries: string(entries)})
	}
	return tables, nil
}

func capturePFAnchor(anchor string) (pfAnchorSnapshot, error) {
	filterRules, err := runDynamicPFCommand(pfDynamicAnchorRules, anchor, "", nil)
	if err != nil {
		return pfAnchorSnapshot{}, err
	}
	natRules, err := runDynamicPFCommand(pfDynamicAnchorNAT, anchor, "", nil)
	if err != nil {
		return pfAnchorSnapshot{}, err
	}
	tables, err := runDynamicPFCommand(pfDynamicAnchorTables, anchor, "", nil)
	if err != nil {
		return pfAnchorSnapshot{}, err
	}
	anchorNames, err := runDynamicPFCommand(pfDynamicAnchorNames, anchor, "", nil)
	if err != nil {
		return pfAnchorSnapshot{}, err
	}
	tableEntries, err := capturePFTableEntries(anchor, string(tables))
	if err != nil {
		return pfAnchorSnapshot{}, err
	}
	return pfAnchorSnapshot{
		Name:         anchor,
		FilterRules:  string(filterRules),
		NATRules:     string(natRules),
		Tables:       string(tables),
		AnchorNames:  string(anchorNames),
		TableEntries: tableEntries,
	}, nil
}

func capturePFAnchors(rootView string) ([]pfAnchorSnapshot, error) {
	rootNames, err := parsePFNames(rootView, true)
	if err != nil {
		return nil, err
	}
	queue := append([]string(nil), rootNames...)
	seen := make(map[string]struct{})
	anchors := make([]pfAnchorSnapshot, 0, len(queue))
	for len(queue) > 0 {
		name := queue[0]
		queue = queue[1:]
		if _, exists := seen[name]; exists {
			continue
		}
		if len(seen) >= maxPFAnchors {
			return nil, fmt.Errorf("PF anchor count exceeds %d", maxPFAnchors)
		}
		seen[name] = struct{}{}
		anchor, err := capturePFAnchor(name)
		if err != nil {
			return nil, fmt.Errorf("capture PF anchor %s: %w", name, err)
		}
		anchors = append(anchors, anchor)
		children, err := parsePFNames(anchor.AnchorNames, true)
		if err != nil {
			return nil, err
		}
		for _, child := range children {
			if !strings.Contains(child, "/") {
				child = name + "/" + child
			}
			queue = append(queue, child)
		}
	}
	sort.Slice(anchors, func(left, right int) bool { return anchors[left].Name < anchors[right].Name })
	return anchors, nil
}

func currentPFLivePolicy() (pfLivePolicy, error) {
	filterRules, err := boundedCommandOutput(maxPFViewBytes, newPFCTLCommand("-sr"))
	if err != nil {
		return pfLivePolicy{}, fmt.Errorf("capture PF filter rules: %w", err)
	}
	natRules, err := boundedCommandOutput(maxPFViewBytes, newPFCTLCommand("-sn"))
	if err != nil {
		return pfLivePolicy{}, fmt.Errorf("capture PF NAT rules: %w", err)
	}
	tables, err := boundedCommandOutput(maxPFViewBytes, newPFCTLCommand("-s", "Tables"))
	if err != nil {
		return pfLivePolicy{}, fmt.Errorf("capture PF tables: %w", err)
	}
	anchorNames, err := boundedCommandOutput(maxPFViewBytes, newPFCTLCommand("-s", "Anchors"))
	if err != nil {
		return pfLivePolicy{}, fmt.Errorf("capture PF anchors: %w", err)
	}
	states, err := boundedCommandOutput(maxPFViewBytes, newPFCTLCommand("-ss"))
	if err != nil {
		return pfLivePolicy{}, fmt.Errorf("capture PF states: %w", err)
	}
	tableEntries, err := capturePFTableEntries("", string(tables))
	if err != nil {
		return pfLivePolicy{}, err
	}
	anchors, err := capturePFAnchors(string(anchorNames))
	if err != nil {
		return pfLivePolicy{}, err
	}
	policy := pfLivePolicy{
		FilterRules:  string(filterRules),
		NATRules:     string(natRules),
		Tables:       string(tables),
		AnchorNames:  string(anchorNames),
		States:       string(states),
		TableEntries: tableEntries,
		Anchors:      anchors,
	}
	if livePFPolicySize(policy) > maxPFLiveSnapshotBytes {
		return pfLivePolicy{}, fmt.Errorf("live PF policy snapshot exceeds its aggregate bound")
	}
	return policy, nil
}

func containsSysWardenPFState(values ...string) bool {
	for _, value := range values {
		for _, marker := range []string{
			"syswarden_whitelist", "syswarden_blacklist", "syswarden_blacklist6",
			"syswarden_zt_allowed", "syswarden_geoip", "syswarden_asn",
			"syswarden_asn6", "banned_ips",
		} {
			if strings.Contains(value, marker) {
				return true
			}
		}
	}
	return false
}

func livePFPolicySize(policy pfLivePolicy) int {
	total := len(policy.FilterRules) + len(policy.NATRules) + len(policy.Tables) +
		len(policy.AnchorNames) + len(policy.States)
	for _, table := range policy.TableEntries {
		total += len(table.Name) + len(table.Entries)
	}
	for _, anchor := range policy.Anchors {
		total += len(anchor.Name) + len(anchor.FilterRules) + len(anchor.NATRules) +
			len(anchor.Tables) + len(anchor.AnchorNames)
		for _, table := range anchor.TableEntries {
			total += len(table.Name) + len(table.Entries)
		}
	}
	return total
}

func containsSysWardenPFStateInLive(policy pfLivePolicy) bool {
	values := []string{policy.FilterRules, policy.NATRules, policy.Tables, policy.AnchorNames, policy.States}
	for _, table := range policy.TableEntries {
		values = append(values, table.Name, table.Entries)
	}
	for _, anchor := range policy.Anchors {
		values = append(values, anchor.Name, anchor.FilterRules, anchor.NATRules, anchor.Tables, anchor.AnchorNames)
		for _, table := range anchor.TableEntries {
			values = append(values, table.Name, table.Entries)
		}
	}
	return containsSysWardenPFState(values...)
}

func emptyPFLivePolicy(policy pfLivePolicy) bool {
	return policy.FilterRules == "" && policy.NATRules == "" && policy.Tables == "" &&
		policy.AnchorNames == "" && policy.States == "" && len(policy.TableEntries) == 0 &&
		len(policy.Anchors) == 0
}

func securePFSnapshotRoot() (*os.Root, error) {
	if err := os.MkdirAll(pfSnapshotDirectory, 0700); err != nil {
		return nil, fmt.Errorf("create PF snapshot directory: %w", err)
	}
	info, err := os.Lstat(pfSnapshotDirectory)
	if err != nil {
		return nil, fmt.Errorf("inspect PF snapshot directory: %w", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || !ok ||
		int(stat.Uid) != pfExpectedOwner() || info.Mode().Perm()&0022 != 0 {
		return nil, fmt.Errorf("PF snapshot directory is not a safe root-owned directory")
	}
	root, err := os.OpenRoot(pfSnapshotDirectory)
	if err != nil {
		return nil, fmt.Errorf("open PF snapshot directory: %w", err)
	}
	return root, nil
}

func validatePFTableSnapshots(tables []pfTableSnapshot) error {
	previous := ""
	for _, table := range tables {
		if !validPFObjectName(table.Name, false) || table.Name <= previous {
			return fmt.Errorf("PF table snapshot names are invalid or not strictly sorted")
		}
		previous = table.Name
	}
	return nil
}

func validatePFLivePolicy(policy pfLivePolicy) error {
	if livePFPolicySize(policy) > maxPFLiveSnapshotBytes || len(policy.Anchors) > maxPFAnchors {
		return fmt.Errorf("live PF policy exceeds its structural bounds")
	}
	if _, err := parsePFNames(policy.Tables, false); err != nil {
		return err
	}
	if _, err := parsePFNames(policy.AnchorNames, true); err != nil {
		return err
	}
	if err := validatePFTableSnapshots(policy.TableEntries); err != nil {
		return err
	}
	previousAnchor := ""
	for _, anchor := range policy.Anchors {
		if !validPFObjectName(anchor.Name, true) || anchor.Name <= previousAnchor {
			return fmt.Errorf("PF anchor snapshots are invalid or not strictly sorted")
		}
		previousAnchor = anchor.Name
		if _, err := parsePFNames(anchor.Tables, false); err != nil {
			return err
		}
		if _, err := parsePFNames(anchor.AnchorNames, true); err != nil {
			return err
		}
		if err := validatePFTableSnapshots(anchor.TableEntries); err != nil {
			return err
		}
	}
	return nil
}

func validatePFSnapshot(snapshot pfPolicySnapshot) error {
	if snapshot.SchemaVersion != pfSnapshotSchemaVersion {
		return fmt.Errorf("unsupported PF snapshot schema %d", snapshot.SchemaVersion)
	}
	if snapshot.Provenance != PFSnapshotExactLive && snapshot.Provenance != PFSnapshotLegacyDerived {
		return fmt.Errorf("invalid PF snapshot provenance %q", snapshot.Provenance)
	}
	if snapshot.InitialKernelState != PFInitialKernelAvailable &&
		snapshot.InitialKernelState != PFInitialKernelModuleAbsent {
		return fmt.Errorf("invalid initial PF kernel state %q", snapshot.InitialKernelState)
	}
	if snapshot.RuntimeStatus != "Enabled" && snapshot.RuntimeStatus != "Disabled" {
		return fmt.Errorf("invalid PF snapshot runtime status %q", snapshot.RuntimeStatus)
	}
	if snapshot.ConfiguredStatus != "Enabled" && snapshot.ConfiguredStatus != "Disabled" {
		return fmt.Errorf("invalid PF snapshot configured status %q", snapshot.ConfiguredStatus)
	}
	if snapshot.InitialKernelState == PFInitialKernelModuleAbsent &&
		snapshot.ConfiguredStatus != "Disabled" {
		return fmt.Errorf("an absent PF kernel requires disabled configured status")
	}
	if snapshot.Provenance == PFSnapshotLegacyDerived {
		if snapshot.ConfiguredStatus != snapshot.RuntimeStatus ||
			!emptyPFLivePolicy(snapshot.LivePolicy) {
			return fmt.Errorf("legacy-derived PF snapshot overstates unavailable live evidence")
		}
	} else {
		if snapshot.RuntimeStatus != "Disabled" || !emptyPFLivePolicy(snapshot.LivePolicy) {
			return fmt.Errorf("fresh exact-live PF is supported only for a disabled empty host policy and state table")
		}
	}
	if snapshot.Source.Path == "" || snapshot.Source.Size != int64(len(snapshot.SourceContent)) {
		return fmt.Errorf("PF snapshot source identity is invalid")
	}
	if snapshot.Source.Exists &&
		(snapshot.Source.Mode&0022 != 0 || int(snapshot.Source.UID) != pfExpectedOwner()) {
		return fmt.Errorf("PF snapshot source identity is unsafe")
	}
	if !snapshot.Source.Exists &&
		(snapshot.Source.Mode != 0 || snapshot.Source.UID != 0 || snapshot.Source.GID != 0 ||
			snapshot.Source.Size != 0 || len(snapshot.SourceContent) != 0) {
		return fmt.Errorf("missing PF snapshot source carries invented identity or content")
	}
	digest := sha256.Sum256(snapshot.SourceContent)
	if snapshot.Source.SHA256 != hex.EncodeToString(digest[:]) {
		return fmt.Errorf("PF snapshot source hash is invalid")
	}
	if containsSysWardenPFState(string(snapshot.SourceContent)) {
		return fmt.Errorf("PF snapshot source contains reserved SysWarden state")
	}
	if snapshot.Provenance == PFSnapshotExactLive && containsSysWardenPFStateInLive(snapshot.LivePolicy) {
		return fmt.Errorf("exact-live PF snapshot already contains SysWarden state")
	}
	if err := validatePFLivePolicy(snapshot.LivePolicy); err != nil {
		return err
	}
	if snapshot.Provenance == PFSnapshotLegacyDerived && !snapshot.Source.Exists &&
		snapshot.ConfiguredStatus != "Disabled" {
		return fmt.Errorf("an enabled legacy-derived PF policy requires a source file")
	}
	return nil
}

func readPFSnapshot() (pfPolicySnapshot, error) {
	root, err := securePFSnapshotRoot()
	if err != nil {
		return pfPolicySnapshot{}, err
	}
	defer func() { _ = root.Close() }()
	info, err := root.Lstat(pfSnapshotName)
	if err != nil {
		return pfPolicySnapshot{}, fmt.Errorf("inspect PF snapshot: %w", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || !ok ||
		int(stat.Uid) != pfExpectedOwner() || info.Size() > maxPFSnapshotBytes {
		return pfPolicySnapshot{}, fmt.Errorf("PF snapshot is not a bounded private root-owned file")
	}
	file, err := root.OpenFile(pfSnapshotName, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return pfPolicySnapshot{}, fmt.Errorf("open PF snapshot: %w", err)
	}
	defer func() { _ = file.Close() }()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return pfPolicySnapshot{}, fmt.Errorf("PF snapshot changed while opening")
	}
	decoder := json.NewDecoder(io.LimitReader(file, maxPFSnapshotBytes+1))
	decoder.DisallowUnknownFields()
	var snapshot pfPolicySnapshot
	if err := decoder.Decode(&snapshot); err != nil {
		return pfPolicySnapshot{}, fmt.Errorf("decode PF snapshot: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return pfPolicySnapshot{}, fmt.Errorf("PF snapshot contains trailing data")
	}
	if err := validatePFSnapshot(snapshot); err != nil {
		return pfPolicySnapshot{}, err
	}
	return snapshot, nil
}

func writePFSnapshot(snapshot pfPolicySnapshot, replace bool) error {
	if err := validatePFSnapshot(snapshot); err != nil {
		return err
	}
	encoded, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return fmt.Errorf("encode PF snapshot: %w", err)
	}
	encoded = append(encoded, '\n')
	if len(encoded) > maxPFSnapshotBytes {
		return fmt.Errorf("encoded PF snapshot exceeds its bound")
	}
	root, err := securePFSnapshotRoot()
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	existing, existingErr := root.Lstat(pfSnapshotName)
	if !replace && existingErr == nil {
		return fmt.Errorf("PF snapshot already exists")
	}
	if replace && existingErr != nil {
		return fmt.Errorf("inspect PF snapshot before replacement: %w", existingErr)
	}
	if replace {
		stat, ok := existing.Sys().(*syscall.Stat_t)
		if !existing.Mode().IsRegular() || existing.Mode().Perm() != 0600 || !ok ||
			int(stat.Uid) != pfExpectedOwner() || existing.Size() > maxPFSnapshotBytes {
			return fmt.Errorf("PF snapshot is unsafe to replace")
		}
	} else if !errors.Is(existingErr, fs.ErrNotExist) {
		return fmt.Errorf("inspect existing PF snapshot: %w", existingErr)
	}
	file, err := root.OpenFile(pfSnapshotTemporaryName, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("create temporary PF snapshot: %w", err)
	}
	temporaryExists := true
	defer func() {
		_ = file.Close()
		if temporaryExists {
			_ = root.Remove(pfSnapshotTemporaryName)
		}
	}()
	if _, err := file.Write(encoded); err != nil {
		return fmt.Errorf("write temporary PF snapshot: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync temporary PF snapshot: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close temporary PF snapshot: %w", err)
	}
	if err := root.Rename(pfSnapshotTemporaryName, pfSnapshotName); err != nil {
		return fmt.Errorf("publish PF snapshot: %w", err)
	}
	temporaryExists = false
	if err := syncPFSnapshotRoot(root); err != nil {
		return fmt.Errorf("sync published PF snapshot directory: %w", err)
	}
	return nil
}

func syncPFSnapshotRoot(root *os.Root) error {
	directory, err := root.Open(".")
	if err != nil {
		return err
	}
	defer func() { _ = directory.Close() }()
	return directory.Sync()
}

func savePFSnapshot(snapshot pfPolicySnapshot) error {
	return writePFSnapshot(snapshot, false)
}

func replacePFSnapshot(snapshot pfPolicySnapshot) error {
	return writePFSnapshot(snapshot, true)
}

func samePFSource(left safePFSource, right safePFSource) bool {
	return left.identity == right.identity && bytes.Equal(left.content, right.content)
}

func requireDisabledEmptyPFLiveState() (pfLivePolicy, error) {
	status, err := currentPFStatus()
	if err != nil {
		return pfLivePolicy{}, err
	}
	policy, err := currentPFLivePolicy()
	if err != nil {
		return pfLivePolicy{}, err
	}
	if status != "Disabled" || !emptyPFLivePolicy(policy) {
		return pfLivePolicy{}, fmt.Errorf("PF is not a disabled empty host policy and state table")
	}
	return policy, nil
}

func capturePFPolicySnapshotLocked(provenance PFSnapshotProvenance) error {
	if _, err := readPFSnapshot(); err == nil {
		return nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	path, err := configuredPFRulesPath()
	if err != nil {
		return err
	}
	source, err := readSafePFSource(path)
	if err != nil {
		return err
	}
	configuredStatus, err := normalizedPFConfiguredStatus()
	if err != nil {
		return err
	}
	initialKernelState, err := inspectPFKernelState()
	if err != nil {
		return err
	}
	if initialKernelState == PFInitialKernelModuleAbsent && configuredStatus != "Disabled" {
		return fmt.Errorf("PF kernel module is absent while configured PF is enabled")
	}
	snapshot := pfPolicySnapshot{
		SchemaVersion:      pfSnapshotSchemaVersion,
		Provenance:         provenance,
		InitialKernelState: initialKernelState,
		ConfiguredStatus:   configuredStatus,
		Source:             source.identity,
		SourceContent:      source.content,
	}
	switch provenance {
	case PFSnapshotExactLive:
		snapshot.RuntimeStatus = "Disabled"
		if initialKernelState == PFInitialKernelAvailable {
			snapshot.LivePolicy, err = requireDisabledEmptyPFLiveState()
		}
	case PFSnapshotLegacyDerived:
		snapshot.RuntimeStatus = snapshot.ConfiguredStatus
	default:
		return fmt.Errorf("unsupported PF snapshot provenance %q", provenance)
	}
	if err != nil {
		return err
	}
	revalidated, err := readSafePFSource(path)
	if err != nil {
		return err
	}
	if !samePFSource(source, revalidated) {
		return fmt.Errorf("PF source changed during snapshot capture")
	}
	revalidatedConfiguredStatus, err := normalizedPFConfiguredStatus()
	if err != nil {
		return err
	}
	if revalidatedConfiguredStatus != configuredStatus {
		return fmt.Errorf("configured PF status changed during snapshot capture")
	}
	revalidatedKernelState, err := inspectPFKernelState()
	if err != nil {
		return err
	}
	if revalidatedKernelState != initialKernelState {
		return fmt.Errorf("PF kernel state changed during snapshot capture")
	}
	if provenance == PFSnapshotExactLive && initialKernelState == PFInitialKernelAvailable {
		if _, err := requireDisabledEmptyPFLiveState(); err != nil {
			return fmt.Errorf("revalidate exact live PF state: %w", err)
		}
	}
	return savePFSnapshot(snapshot)
}

func ensurePFKernelReadyForMutationLocked() error {
	snapshot, err := readPFSnapshot()
	if err != nil {
		return err
	}
	state, err := inspectPFKernelState()
	if err != nil {
		return err
	}
	if !snapshot.MutationStarted && state != snapshot.InitialKernelState {
		return fmt.Errorf(
			"PF kernel state changed before the first policy mutation: snapshot=%s current=%s",
			snapshot.InitialKernelState,
			state,
		)
	}
	loadedNow := false
	if state == PFInitialKernelModuleAbsent {
		if err := loadPFKernelModule(); err != nil {
			return err
		}
		loadedNow = true
	}
	if loadedNow || (!snapshot.MutationStarted && snapshot.Provenance == PFSnapshotExactLive) {
		if _, err := requireDisabledEmptyPFLiveState(); err != nil {
			return fmt.Errorf("verify PF before first policy mutation: %w", err)
		}
	}
	return nil
}

func markPFMutationStartedLocked() error {
	snapshot, err := readPFSnapshot()
	if err != nil {
		return err
	}
	if snapshot.MutationStarted {
		return nil
	}
	if err := requireUnchangedPFSnapshotInputs(snapshot); err != nil {
		return fmt.Errorf("revalidate PF snapshot inputs before mutation: %w", err)
	}
	if err := requirePFKernelState(PFInitialKernelAvailable); err != nil {
		return fmt.Errorf("revalidate PF kernel before mutation: %w", err)
	}
	if snapshot.Provenance == PFSnapshotExactLive {
		if _, err := requireDisabledEmptyPFLiveState(); err != nil {
			return fmt.Errorf("revalidate exact live PF state before mutation: %w", err)
		}
	}
	snapshot.MutationStarted = true
	if err := replacePFSnapshot(snapshot); err != nil {
		return fmt.Errorf("record PF mutation boundary: %w", err)
	}
	return nil
}

// CapturePFPolicySnapshot records the operator PF policy under the same lock
// used by policy application and restoration.
func CapturePFPolicySnapshot(provenance PFSnapshotProvenance) error {
	lock, err := acquirePFRuntimeLock()
	if err != nil {
		return fmt.Errorf("acquire shared PF runtime lock: %w", err)
	}
	defer releasePFRuntimeLock(lock)
	return capturePFPolicySnapshotLocked(provenance)
}

func requireUnchangedPFSource(snapshot pfPolicySnapshot) error {
	current, err := readSafePFSource(snapshot.Source.Path)
	if err != nil {
		return err
	}
	expected := safePFSource{identity: snapshot.Source, content: snapshot.SourceContent}
	if !samePFSource(current, expected) {
		return fmt.Errorf("configured PF source changed after snapshot capture")
	}
	return nil
}

func validatePFSourceForRestore(snapshot pfPolicySnapshot) error {
	if err := requireUnchangedPFSource(snapshot); err != nil {
		return err
	}
	if !snapshot.Source.Exists {
		return nil
	}
	if err := boundedPFInput(snapshot.SourceContent, newPFCTLCommand("-nf", "-")); err != nil {
		return fmt.Errorf("validate snapshotted PF source: %w", err)
	}
	// The source is already byte- and identity-equivalent to the snapshot.
	// Replacing it would unnecessarily discard ACLs, flags, xattrs or hardlinks
	// that are outside this bounded snapshot contract.
	return nil
}

func requireUnchangedPFSnapshotInputs(snapshot pfPolicySnapshot) error {
	if err := requireUnchangedPFSource(snapshot); err != nil {
		return err
	}
	configuredStatus, err := normalizedPFConfiguredStatus()
	if err != nil {
		return err
	}
	if configuredStatus != snapshot.ConfiguredStatus {
		return fmt.Errorf("configured PF status changed after snapshot capture")
	}
	return nil
}

func buildRestoredPFConfig(filterRules, natRules string, tables []pfTableSnapshot) []byte {
	var configuration strings.Builder
	for _, table := range tables {
		_, _ = fmt.Fprintf(&configuration, "table <%s> persist\n", table.Name)
	}
	if natRules != "" {
		configuration.WriteString(natRules)
		if !strings.HasSuffix(natRules, "\n") {
			configuration.WriteByte('\n')
		}
	}
	if filterRules != "" {
		configuration.WriteString(filterRules)
		if !strings.HasSuffix(filterRules, "\n") {
			configuration.WriteByte('\n')
		}
	}
	return []byte(configuration.String())
}

func restorePFTableEntries(anchor string, tables []pfTableSnapshot) error {
	for _, table := range tables {
		if _, err := runDynamicPFCommand(
			pfDynamicTableReplace,
			anchor,
			table.Name,
			[]byte(table.Entries),
		); err != nil {
			return fmt.Errorf("restore PF table %s entries: %w", table.Name, err)
		}
	}
	return nil
}

func restoreExactLivePFPolicy(pfLivePolicy) error {
	if _, err := boundedCommandOutput(4096, newPFCTLCommand("-F", "all")); err != nil {
		return fmt.Errorf("restore fresh empty PF policy: %w", err)
	}
	return nil
}

func restoreLegacyDerivedPFPolicy(snapshot pfPolicySnapshot) error {
	if snapshot.RuntimeStatus == "Enabled" {
		if !snapshot.Source.Exists {
			return fmt.Errorf("enabled legacy-derived PF policy has no source file")
		}
		if err := boundedPFInput(snapshot.SourceContent, newPFCTLCommand("-nf", "-")); err != nil {
			return fmt.Errorf("validate legacy-derived PF source: %w", err)
		}
		if err := boundedPFInput(snapshot.SourceContent, newPFCTLCommand("-f", "-")); err != nil {
			return fmt.Errorf("load legacy-derived PF source: %w", err)
		}
		return nil
	}
	if _, err := boundedCommandOutput(4096, newPFCTLCommand("-F", "all")); err != nil {
		return fmt.Errorf("flush legacy-derived empty PF policy: %w", err)
	}
	return nil
}

func setPFStatus(expected string) error {
	current, err := currentPFStatus()
	if err != nil {
		return err
	}
	if current != expected {
		var command *exec.Cmd
		if expected == "Disabled" {
			command = newPFCTLCommand("-d")
		} else {
			command = newPFCTLCommand("-e")
		}
		if output, err := boundedCommandOutput(4096, command); err != nil {
			return fmt.Errorf("set PF status to %s: %s: %w", expected, strings.TrimSpace(string(output)), err)
		}
	}
	actual, err := currentPFStatus()
	if err != nil {
		return err
	}
	if actual != expected {
		return fmt.Errorf("PF status is %s after restoring %s", actual, expected)
	}
	return nil
}

func removePFSnapshot() error {
	root, err := securePFSnapshotRoot()
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	if err := root.Remove(pfSnapshotName); err != nil {
		return fmt.Errorf("remove consumed PF snapshot: %w", err)
	}
	if err := syncPFSnapshotRoot(root); err != nil {
		return fmt.Errorf("sync consumed PF snapshot directory: %w", err)
	}
	return nil
}

func restorePFPolicyLocked() error {
	snapshot, err := readPFSnapshot()
	if err != nil {
		return err
	}
	if err := requireUnchangedPFSnapshotInputs(snapshot); err != nil {
		return err
	}
	kernelState, err := inspectPFKernelState()
	if err != nil {
		return err
	}
	if kernelState == PFInitialKernelModuleAbsent {
		if snapshot.InitialKernelState == PFInitialKernelModuleAbsent {
			if snapshot.MutationStarted {
				return fmt.Errorf("PF kernel module disappeared after policy mutation started")
			}
			if err := requireUnchangedPFSnapshotInputs(snapshot); err != nil {
				return err
			}
			if err := requirePFKernelState(PFInitialKernelModuleAbsent); err != nil {
				return err
			}
			return removePFSnapshot()
		}
		return fmt.Errorf("PF kernel module disappeared after an available baseline was captured")
	}
	if err := validatePFSourceForRestore(snapshot); err != nil {
		return err
	}
	if !snapshot.MutationStarted && snapshot.Provenance == PFSnapshotExactLive {
		if _, err := requireDisabledEmptyPFLiveState(); err != nil {
			return fmt.Errorf("verify unmodified exact PF snapshot: %w", err)
		}
		if snapshot.InitialKernelState == PFInitialKernelModuleAbsent {
			if err := unloadPFKernelModule(); err != nil {
				return err
			}
		}
		if err := requireUnchangedPFSnapshotInputs(snapshot); err != nil {
			return err
		}
		if err := requirePFKernelState(snapshot.InitialKernelState); err != nil {
			return err
		}
		return removePFSnapshot()
	}
	if snapshot.Provenance == PFSnapshotExactLive {
		if err := restoreExactLivePFPolicy(snapshot.LivePolicy); err != nil {
			return err
		}
	} else if err := restoreLegacyDerivedPFPolicy(snapshot); err != nil {
		return err
	}
	if err := setPFStatus(snapshot.RuntimeStatus); err != nil {
		return err
	}
	livePolicy, err := currentPFLivePolicy()
	if err != nil {
		return err
	}
	if containsSysWardenPFStateInLive(livePolicy) {
		return fmt.Errorf("SysWarden PF state remains after restore")
	}
	if snapshot.Provenance == PFSnapshotExactLive && !emptyPFLivePolicy(livePolicy) {
		return fmt.Errorf("fresh empty PF policy was not restored exactly")
	}
	if snapshot.InitialKernelState == PFInitialKernelModuleAbsent {
		if snapshot.RuntimeStatus != "Disabled" || !emptyPFLivePolicy(livePolicy) {
			return fmt.Errorf("PF module cannot be unloaded before its disabled empty policy and state table are restored")
		}
		if _, err := requireDisabledEmptyPFLiveState(); err != nil {
			return fmt.Errorf("revalidate disabled empty PF state before module unload: %w", err)
		}
		if err := unloadPFKernelModule(); err != nil {
			return err
		}
	}
	if err := requireUnchangedPFSnapshotInputs(snapshot); err != nil {
		return err
	}
	if err := requirePFKernelState(snapshot.InitialKernelState); err != nil {
		return err
	}
	return removePFSnapshot()
}

// RestorePersistedPFPolicy restores the captured operator policy while holding
// the same cross-process lock used by ApplyPolicies.
func RestorePersistedPFPolicy() error {
	lock, err := acquirePFRuntimeLock()
	if err != nil {
		return fmt.Errorf("acquire shared PF runtime lock: %w", err)
	}
	defer releasePFRuntimeLock(lock)
	return restorePFPolicyLocked()
}
