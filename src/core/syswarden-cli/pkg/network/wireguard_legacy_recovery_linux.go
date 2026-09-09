//go:build linux

package network

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"syswarden-cli/pkg/wireguardstate"
	"unicode/utf8"
)

const (
	legacyWireGuardRecoverySchema           = "syswarden-legacy-wireguard-recovery-v1"
	legacyWireGuardGenerationWG0            = "pre-v3.75.7-wg0"
	legacyWireGuardGenerationWGSysWarden    = "v3.75.7-v4.03.0-wg-syswarden"
	maximumLegacyWireGuardConfigurationSize = 64 << 10
)

// LegacyWireGuardRecoveryPlan is a deterministic, secret-redacted description
// of the exact historical runtime state eligible for explicit recovery. It is
// deliberately insufficient to authorize mutation without its SHA-256 digest.
type LegacyWireGuardRecoveryPlan struct {
	Schema              string                               `json:"schema"`
	Generation          string                               `json:"generation"`
	ServiceManager      string                               `json:"service_manager"`
	HistoricalInterface string                               `json:"historical_interface"`
	Table               LegacyWireGuardTableEvidence         `json:"table"`
	ForwardRules        []LegacyWireGuardForwardRuleEvidence `json:"shared_forward_rules"`
	Configuration       LegacyWireGuardFileEvidence          `json:"configuration"`
	Ownership           LegacyWireGuardOwnershipEvidence     `json:"current_ownership"`
	Service             LegacyWireGuardServiceEvidence       `json:"historical_service"`
	InterfacePresent    bool                                 `json:"interface_present"`
	SafeToApply         bool                                 `json:"safe_to_apply"`
	Blockers            []string                             `json:"blockers"`
}

// LegacyWireGuardTableEvidence binds every handle in the historical two-chain
// table, not only its user-visible name.
type LegacyWireGuardTableEvidence struct {
	Family                 string `json:"family"`
	Name                   string `json:"name"`
	Handle                 uint64 `json:"handle"`
	PreroutingChainHandle  uint64 `json:"prerouting_chain_handle"`
	PostroutingChainHandle uint64 `json:"postrouting_chain_handle"`
	MasqueradeRuleHandle   uint64 `json:"masquerade_rule_handle"`
	EgressInterface        string `json:"egress_interface"`
}

// LegacyWireGuardForwardRuleEvidence identifies one exact rule in the shared
// inet filter forward chain. Other operator rules are never included or removed.
type LegacyWireGuardForwardRuleEvidence struct {
	Direction string `json:"direction"`
	Handle    uint64 `json:"handle"`
}

// LegacyWireGuardFileEvidence contains only metadata and a digest. Private and
// preshared WireGuard key bytes never leave the bounded file attestation.
type LegacyWireGuardFileEvidence struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Mode   uint32 `json:"mode"`
	UID    uint32 `json:"uid"`
	GID    uint32 `json:"gid"`
	NLink  uint64 `json:"nlink"`
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
	Size   int64  `json:"size"`
	Source string `json:"source"`
}

type LegacyWireGuardOwnershipEvidence struct {
	State  string `json:"state"`
	SHA256 string `json:"sha256"`
}

type LegacyWireGuardServiceEvidence struct {
	LoadState    string `json:"load_state"`
	Name         string `json:"name"`
	ActiveState  string `json:"active_state"`
	EnabledState string `json:"enabled_state"`
}

type legacyWireGuardConfiguration struct {
	evidence LegacyWireGuardFileEvidence
	content  []byte
}

type legacyWireGuardOwnership struct {
	evidence       LegacyWireGuardOwnershipEvidence
	modernIdentity *wireguardstate.ServerConfigurationIdentity
	modernServer   []byte
}

type legacyWireGuardGenerationCandidate struct {
	generation    string
	interfaceName string
	configuration legacyWireGuardConfiguration
}

type legacyWireGuardRecoveryHost struct {
	filesystemRoot string
	expectedUID    uint32
	expectedGID    uint32
	effectiveUID   func() int
	managerState   func() (string, error)
	isAlpine       func() bool
	commandOutput  wireGuardServiceOutputRunner
	nftRunner      wireGuardNFTCommandRunner
	nftBatch       func(context.Context, string) ([]byte, error)
	guard          func() (func() error, error)
}

func productionLegacyWireGuardRecoveryHost() legacyWireGuardRecoveryHost {
	return legacyWireGuardRecoveryHost{
		filesystemRoot: wireGuardFilesystemRoot,
		expectedUID:    wireGuardExpectedOwnerUID,
		expectedGID:    wireGuardExpectedOwnerGID,
		effectiveUID:   os.Geteuid,
		managerState:   wireGuardManagerRuntimeState,
		isAlpine:       wireGuardIsAlpine,
		commandOutput:  runWireGuardServiceOutput,
		nftRunner:      execWireGuardNFTCommandRunner{},
		nftBatch: func(ctx context.Context, script string) ([]byte, error) {
			return runBoundedWireGuardCommandContext(
				ctx, "nft", []string{"-f", "-"}, script,
				maximumWireGuardCommandOutput,
			)
		},
		guard: wireGuardNFTActivationGuard,
	}
}

func (host legacyWireGuardRecoveryHost) validate() error {
	if host.filesystemRoot == "" || host.effectiveUID == nil || host.managerState == nil ||
		host.isAlpine == nil || host.commandOutput == nil || host.nftRunner == nil ||
		host.nftBatch == nil || host.guard == nil {
		return fmt.Errorf("legacy WireGuard recovery dependencies are incomplete")
	}
	if host.effectiveUID() != 0 {
		return fmt.Errorf("legacy WireGuard recovery must be executed as root")
	}
	return nil
}

func sameLegacyWireGuardFileIdentity(left, right os.FileInfo) bool {
	if left == nil || right == nil || !os.SameFile(left, right) ||
		left.Mode() != right.Mode() || left.Size() != right.Size() {
		return false
	}
	leftStat, leftOK := left.Sys().(*syscall.Stat_t)
	rightStat, rightOK := right.Sys().(*syscall.Stat_t)
	return leftOK && rightOK && leftStat.Uid == rightStat.Uid &&
		leftStat.Gid == rightStat.Gid && leftStat.Nlink == rightStat.Nlink &&
		leftStat.Dev == rightStat.Dev && leftStat.Ino == rightStat.Ino
}

func legacyWireGuardLogicalName(path string) (string, error) {
	clean := filepath.Clean(path)
	if !filepath.IsAbs(clean) || clean != path || clean == "/" {
		return "", fmt.Errorf("legacy WireGuard configuration path is not canonical")
	}
	return strings.TrimPrefix(clean, "/"), nil
}

func captureLegacyWireGuardConfiguration(
	rootPath, path string,
	expectedUID, expectedGID uint32,
) (legacyWireGuardConfiguration, error) {
	logical, err := legacyWireGuardLogicalName(path)
	if err != nil {
		return legacyWireGuardConfiguration{}, err
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return legacyWireGuardConfiguration{}, fmt.Errorf("pin filesystem root for %s: %w", path, err)
	}
	defer func() { _ = root.Close() }()

	parents := []string{"etc", "etc/wireguard"}
	parentIdentities := make([]os.FileInfo, 0, len(parents))
	for _, parent := range parents {
		info, err := root.Lstat(parent)
		if err != nil {
			return legacyWireGuardConfiguration{}, fmt.Errorf("attest protected parent %s: %w", parent, err)
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
			info.Mode().Perm()&0022 != 0 || stat.Uid != expectedUID || stat.Gid != expectedGID {
			return legacyWireGuardConfiguration{}, fmt.Errorf("refusing unsafe protected parent %s", parent)
		}
		parentIdentities = append(parentIdentities, info)
	}

	before, err := root.Lstat(logical)
	if err != nil {
		return legacyWireGuardConfiguration{}, fmt.Errorf("inspect historical WireGuard configuration %s: %w", path, err)
	}
	stat, ok := before.Sys().(*syscall.Stat_t)
	if !ok || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 ||
		before.Mode().Perm() != 0600 || stat.Uid != expectedUID || stat.Gid != expectedGID ||
		stat.Nlink != 1 || before.Size() < 1 || before.Size() > maximumLegacyWireGuardConfigurationSize {
		return legacyWireGuardConfiguration{}, fmt.Errorf(
			"historical WireGuard configuration %s is not an exact owner-only regular file", path,
		)
	}
	file, err := root.Open(logical)
	if err != nil {
		return legacyWireGuardConfiguration{}, fmt.Errorf("open historical WireGuard configuration %s: %w", path, err)
	}
	opened, statErr := file.Stat()
	content, readErr := io.ReadAll(io.LimitReader(file, maximumLegacyWireGuardConfigurationSize+1))
	closeErr := file.Close()
	if statErr != nil || readErr != nil || closeErr != nil ||
		!sameLegacyWireGuardFileIdentity(before, opened) ||
		len(content) > maximumLegacyWireGuardConfigurationSize {
		return legacyWireGuardConfiguration{}, fmt.Errorf("historical WireGuard configuration %s changed while reading", path)
	}
	after, err := root.Lstat(logical)
	if err != nil || !sameLegacyWireGuardFileIdentity(opened, after) {
		return legacyWireGuardConfiguration{}, fmt.Errorf("historical WireGuard configuration %s changed during attestation", path)
	}
	for index, parent := range parents {
		current, err := root.Lstat(parent)
		if err != nil || !sameLegacyWireGuardFileIdentity(parentIdentities[index], current) {
			return legacyWireGuardConfiguration{}, fmt.Errorf("protected parent %s changed during attestation", parent)
		}
	}
	digest := sha256.Sum256(content)
	return legacyWireGuardConfiguration{
		evidence: LegacyWireGuardFileEvidence{
			Path: path, SHA256: hex.EncodeToString(digest[:]), Mode: uint32(after.Mode().Perm()),
			UID: stat.Uid, GID: stat.Gid, NLink: uint64(stat.Nlink), Device: uint64(stat.Dev),
			Inode: stat.Ino, Size: after.Size(),
		},
		content: content,
	}, nil
}

func exactLegacyWireGuardConfigurationValue(line, key string) (string, error) {
	prefix := key + " = "
	value, ok := strings.CutPrefix(line, prefix)
	if !ok || value == "" || strings.TrimSpace(value) != value {
		return "", fmt.Errorf("historical WireGuard configuration has an invalid %s entry", key)
	}
	return value, nil
}

func legacyWireGuardPostUp(interfaceName, egress string, addFilterTable bool) string {
	filterTable := ""
	if addFilterTable {
		filterTable = "nft 'add table inet filter' 2>/dev/null || true; "
	}
	return fmt.Sprintf(
		`nft 'add table inet syswarden_wg'; nft 'add chain inet syswarden_wg prerouting { type nat hook prerouting priority dstnat; }'; nft 'add chain inet syswarden_wg postrouting { type nat hook postrouting priority srcnat; }'; nft 'add rule inet syswarden_wg postrouting oifname "%s" masquerade'; %snft 'add chain inet filter forward { type filter hook forward priority 0; }' 2>/dev/null || true; nft 'insert rule inet filter forward iifname "%s" accept'; nft 'insert rule inet filter forward oifname "%s" accept'`,
		egress, filterTable, interfaceName, interfaceName,
	)
}

func legacyWireGuardPostDown(interfaceName string) string {
	return fmt.Sprintf(
		`nft delete table inet syswarden_wg 2>/dev/null || true; nft delete rule inet filter forward iifname "%s" accept 2>/dev/null || true; nft delete rule inet filter forward oifname "%s" accept 2>/dev/null || true`,
		interfaceName, interfaceName,
	)
}

func validateHistoricalWireGuardConfiguration(
	content []byte,
	interfaceName, egress string,
) error {
	if !utf8.Valid(content) || bytes.IndexByte(content, 0) >= 0 || bytes.Contains(content, []byte{'\r'}) ||
		len(content) == 0 || content[len(content)-1] != '\n' {
		return fmt.Errorf("historical WireGuard configuration is not canonical UTF-8 text")
	}
	lines := strings.Split(strings.TrimSuffix(string(content), "\n"), "\n")
	if len(lines) != 11 || lines[0] != "[Interface]" || lines[6] != "" || lines[7] != "[Peer]" {
		return fmt.Errorf("historical WireGuard configuration structure is not exact")
	}
	addressRaw, err := exactLegacyWireGuardConfigurationValue(lines[1], "Address")
	if err != nil {
		return err
	}
	address, err := netip.ParsePrefix(addressRaw)
	if err != nil || !address.Addr().Is4() || address.Addr().Is4In6() || address.String() != addressRaw ||
		address.Bits() > 30 || address.Addr() != address.Masked().Addr().Next() {
		return fmt.Errorf("historical WireGuard Address is not an exact generated host prefix")
	}
	if interfaceName == "wg0" && address.Bits() != 24 {
		return fmt.Errorf("pre-v3.75.7 WireGuard configuration requires the historical /24 prefix")
	}
	portRaw, err := exactLegacyWireGuardConfigurationValue(lines[2], "ListenPort")
	if err != nil {
		return err
	}
	port, err := strconv.Atoi(portRaw)
	if err != nil || port < 1 || port > 65535 || strconv.Itoa(port) != portRaw {
		return fmt.Errorf("historical WireGuard ListenPort is not canonical")
	}
	for index, key := range []string{"PrivateKey", "PublicKey", "PresharedKey"} {
		lineIndex := []int{3, 8, 9}[index]
		value, err := exactLegacyWireGuardConfigurationValue(lines[lineIndex], key)
		if err != nil {
			return err
		}
		canonical, err := canonicalWireGuardKey(value)
		if err != nil || canonical != value {
			return fmt.Errorf("historical WireGuard %s is not a canonical key", key)
		}
	}
	postUp, err := exactLegacyWireGuardConfigurationValue(lines[4], "PostUp")
	if err != nil {
		return err
	}
	validPostUp := postUp == legacyWireGuardPostUp(interfaceName, egress, false)
	if interfaceName == "wg-syswarden" {
		validPostUp = validPostUp || postUp == legacyWireGuardPostUp(interfaceName, egress, true)
	}
	if !validPostUp {
		return fmt.Errorf("historical WireGuard PostUp does not match a supported SysWarden generation")
	}
	postDown, err := exactLegacyWireGuardConfigurationValue(lines[5], "PostDown")
	if err != nil || postDown != legacyWireGuardPostDown(interfaceName) {
		return fmt.Errorf("historical WireGuard PostDown does not match a supported SysWarden generation")
	}
	allowedRaw, err := exactLegacyWireGuardConfigurationValue(lines[10], "AllowedIPs")
	if err != nil {
		return err
	}
	allowed, err := netip.ParsePrefix(allowedRaw)
	if err != nil || !allowed.Addr().Is4() || allowed.Addr().Is4In6() || allowed.Bits() != 32 ||
		allowed.String() != allowedRaw || allowed.Addr() != address.Addr().Next() ||
		!address.Masked().Contains(allowed.Addr()) {
		return fmt.Errorf("historical WireGuard AllowedIPs is not the exact generated peer address")
	}
	return nil
}

func validateLegacyWireGuardNFTTable(wire []byte, inventoryHandle uint64) (LegacyWireGuardTableEvidence, error) {
	var envelope struct {
		NFTables []map[string]json.RawMessage `json:"nftables"`
	}
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil {
		return LegacyWireGuardTableEvidence{}, fmt.Errorf("decode historical WireGuard nftables table: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return LegacyWireGuardTableEvidence{}, fmt.Errorf("historical WireGuard nftables table has trailing data")
	}
	evidence := LegacyWireGuardTableEvidence{Family: "inet", Name: "syswarden_wg"}
	tableCount := 0
	chainHandles := make(map[uint64]struct{})
	ruleHandles := make(map[uint64]struct{})
	chains := make(map[string]string)
	ruleCount := 0
	for _, element := range envelope.NFTables {
		if len(element) != 1 {
			return LegacyWireGuardTableEvidence{}, fmt.Errorf("historical WireGuard nftables table contains an ambiguous element")
		}
		for kind, raw := range element {
			switch kind {
			case "metainfo":
				continue
			case "table":
				var table struct {
					Family string `json:"family"`
					Name   string `json:"name"`
					Handle uint64 `json:"handle"`
				}
				if err := decodeStrictWireGuardNFTObject(raw, &table, "historical table"); err != nil ||
					table.Family != evidence.Family || table.Name != evidence.Name || table.Handle == 0 {
					return LegacyWireGuardTableEvidence{}, fmt.Errorf("historical WireGuard nftables table identity is not exact")
				}
				tableCount++
				evidence.Handle = table.Handle
			case "chain":
				var chain struct {
					Family string `json:"family"`
					Table  string `json:"table"`
					Name   string `json:"name"`
					Type   string `json:"type"`
					Hook   string `json:"hook"`
					Prio   int    `json:"prio"`
					Policy string `json:"policy"`
					Handle uint64 `json:"handle"`
				}
				if err := decodeStrictWireGuardNFTObject(raw, &chain, "historical chain"); err != nil ||
					chain.Family != evidence.Family || chain.Table != evidence.Name || chain.Handle == 0 {
					return LegacyWireGuardTableEvidence{}, fmt.Errorf("historical WireGuard nftables chain identity is not exact")
				}
				if _, duplicate := chainHandles[chain.Handle]; duplicate {
					return LegacyWireGuardTableEvidence{}, fmt.Errorf("historical WireGuard nftables chain handle is duplicated")
				}
				chainHandles[chain.Handle] = struct{}{}
				if _, duplicate := chains[chain.Name]; duplicate {
					return LegacyWireGuardTableEvidence{}, fmt.Errorf("historical WireGuard nftables chain %s is duplicated", chain.Name)
				}
				chains[chain.Name] = fmt.Sprintf("%s:%s:%d:%s", chain.Type, chain.Hook, chain.Prio, chain.Policy)
				switch chain.Name {
				case "prerouting":
					evidence.PreroutingChainHandle = chain.Handle
				case "postrouting":
					evidence.PostroutingChainHandle = chain.Handle
				}
			case "rule":
				var rule struct {
					Family string                       `json:"family"`
					Table  string                       `json:"table"`
					Chain  string                       `json:"chain"`
					Expr   []map[string]json.RawMessage `json:"expr"`
					Handle uint64                       `json:"handle"`
				}
				if err := decodeStrictWireGuardNFTObject(raw, &rule, "historical rule"); err != nil ||
					rule.Family != evidence.Family || rule.Table != evidence.Name ||
					rule.Chain != "postrouting" || rule.Handle == 0 {
					return LegacyWireGuardTableEvidence{}, fmt.Errorf("historical WireGuard nftables rule identity is not exact")
				}
				if _, duplicate := ruleHandles[rule.Handle]; duplicate {
					return LegacyWireGuardTableEvidence{}, fmt.Errorf("historical WireGuard nftables rule handle is duplicated")
				}
				ruleHandles[rule.Handle] = struct{}{}
				signature, err := wireGuardNFTExpressionSignature(rule.Expr)
				const prefix = "oifname="
				const suffix = ":masquerade"
				if err != nil || !strings.HasPrefix(signature, prefix) || !strings.HasSuffix(signature, suffix) {
					return LegacyWireGuardTableEvidence{}, fmt.Errorf("historical WireGuard masquerade rule is not exact")
				}
				egress := strings.TrimSuffix(strings.TrimPrefix(signature, prefix), suffix)
				if !wireGuardInterfaceName.MatchString(egress) {
					return LegacyWireGuardTableEvidence{}, fmt.Errorf("historical WireGuard egress interface is invalid")
				}
				evidence.EgressInterface = egress
				evidence.MasqueradeRuleHandle = rule.Handle
				ruleCount++
			default:
				return LegacyWireGuardTableEvidence{}, fmt.Errorf("historical WireGuard nftables table contains unexpected %s state", kind)
			}
		}
	}
	if tableCount != 1 || evidence.Handle == 0 || evidence.Handle != inventoryHandle {
		return LegacyWireGuardTableEvidence{}, fmt.Errorf("historical WireGuard nftables table handle is not stable")
	}
	wantChains := map[string]string{
		"prerouting":  "nat:prerouting:-100:accept",
		"postrouting": "nat:postrouting:100:accept",
	}
	if !reflectStringMap(chains, wantChains) || evidence.PreroutingChainHandle == 0 ||
		evidence.PostroutingChainHandle == 0 || ruleCount != 1 ||
		evidence.MasqueradeRuleHandle == 0 || evidence.EgressInterface == "" {
		return LegacyWireGuardTableEvidence{}, fmt.Errorf("historical WireGuard nftables table is not the exact two-chain generated topology")
	}
	return evidence, nil
}

func matchingLegacyWireGuardForwardRules(
	wire []byte,
) (map[string][]LegacyWireGuardForwardRuleEvidence, error) {
	var envelope struct {
		NFTables []map[string]json.RawMessage `json:"nftables"`
	}
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil {
		return nil, fmt.Errorf("decode shared nftables forward chain: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("shared nftables forward chain has trailing data")
	}
	matches := map[string][]LegacyWireGuardForwardRuleEvidence{
		"wg0":          {},
		"wg-syswarden": {},
	}
	seenHandles := make(map[uint64]struct{})
	for _, element := range envelope.NFTables {
		if len(element) != 1 {
			return nil, fmt.Errorf("shared nftables forward chain contains an ambiguous element")
		}
		raw, isRule := element["rule"]
		if !isRule {
			continue
		}
		var loose struct {
			Family string                       `json:"family"`
			Table  string                       `json:"table"`
			Chain  string                       `json:"chain"`
			Expr   []map[string]json.RawMessage `json:"expr"`
			Handle uint64                       `json:"handle"`
		}
		if err := json.Unmarshal(raw, &loose); err != nil {
			return nil, fmt.Errorf("decode shared nftables rule: %w", err)
		}
		signature, err := wireGuardNFTExpressionSignature(loose.Expr)
		if err != nil {
			continue
		}
		for _, interfaceName := range []string{"wg0", "wg-syswarden"} {
			for _, direction := range []string{"iifname", "oifname"} {
				if signature != direction+"="+interfaceName+":accept" {
					continue
				}
				var exact struct {
					Family string                       `json:"family"`
					Table  string                       `json:"table"`
					Chain  string                       `json:"chain"`
					Expr   []map[string]json.RawMessage `json:"expr"`
					Handle uint64                       `json:"handle"`
				}
				if err := decodeStrictWireGuardNFTObject(raw, &exact, "historical shared forward rule"); err != nil ||
					exact.Family != "inet" || exact.Table != "filter" || exact.Chain != "forward" || exact.Handle == 0 {
					return nil, fmt.Errorf("historical shared forward rule is not exact")
				}
				if _, duplicate := seenHandles[exact.Handle]; duplicate {
					return nil, fmt.Errorf("historical shared forward rule handle is duplicated")
				}
				seenHandles[exact.Handle] = struct{}{}
				matches[interfaceName] = append(matches[interfaceName], LegacyWireGuardForwardRuleEvidence{
					Direction: direction, Handle: exact.Handle,
				})
			}
		}
	}
	for interfaceName := range matches {
		sort.Slice(matches[interfaceName], func(left, right int) bool {
			return matches[interfaceName][left].Direction < matches[interfaceName][right].Direction
		})
	}
	return matches, nil
}

func selectLegacyWireGuardForwardRules(
	matches map[string][]LegacyWireGuardForwardRuleEvidence,
	selectedInterface string,
) ([]LegacyWireGuardForwardRuleEvidence, error) {
	if selectedInterface != "wg0" && selectedInterface != "wg-syswarden" {
		return nil, fmt.Errorf("unsupported historical WireGuard interface %q", selectedInterface)
	}
	otherInterface := "wg0"
	if selectedInterface == otherInterface {
		otherInterface = "wg-syswarden"
	}
	if len(matches[otherInterface]) != 0 {
		return nil, fmt.Errorf(
			"shared forward rules for conflicting historical interface %s remain",
			otherInterface,
		)
	}
	rules := matches[selectedInterface]
	if len(rules) > 2 {
		return nil, fmt.Errorf("historical shared forward rules for %s are duplicated", selectedInterface)
	}
	seenDirections := make(map[string]struct{}, len(rules))
	for _, rule := range rules {
		if rule.Direction != "iifname" && rule.Direction != "oifname" {
			return nil, fmt.Errorf("historical shared forward rule direction is invalid")
		}
		if _, duplicate := seenDirections[rule.Direction]; duplicate {
			return nil, fmt.Errorf(
				"historical shared forward rule direction %s for %s is duplicated",
				rule.Direction, selectedInterface,
			)
		}
		seenDirections[rule.Direction] = struct{}{}
	}
	selected := make([]LegacyWireGuardForwardRuleEvidence, len(rules))
	copy(selected, rules)
	return selected, nil
}

func inspectLegacyWireGuardOwnership(
	root string,
	expectedUID, expectedGID uint32,
) (legacyWireGuardOwnership, error) {
	inventory, err := wireguardstate.Inspect(root)
	if err != nil {
		return legacyWireGuardOwnership{}, fmt.Errorf("inspect current WireGuard ownership state: %w", err)
	}
	if inventory.Transaction {
		return legacyWireGuardOwnership{}, fmt.Errorf("a WireGuard ownership transaction is pending")
	}
	if !inventory.Manifest {
		preimage := "no-manifest\n" + strings.Join(inventory.Artifacts, "\n") + "\n"
		digest := sha256.Sum256([]byte(preimage))
		return legacyWireGuardOwnership{evidence: LegacyWireGuardOwnershipEvidence{
			State: "no-manifest", SHA256: hex.EncodeToString(digest[:]),
		}}, nil
	}
	manifest, err := wireguardstate.ReadAndVerify(root, expectedUID, expectedGID)
	if err != nil {
		return legacyWireGuardOwnership{}, fmt.Errorf("verify current WireGuard ownership manifest: %w", err)
	}
	manifestWire, err := json.Marshal(manifest)
	if err != nil {
		return legacyWireGuardOwnership{}, fmt.Errorf("encode current WireGuard ownership evidence: %w", err)
	}
	digest := sha256.Sum256(manifestWire)
	server, err := wireguardstate.ReadVerifiedArtifact(
		root, manifest, wireguardstate.ServerConfigurationPath, expectedUID, expectedGID,
	)
	if err != nil {
		return legacyWireGuardOwnership{}, fmt.Errorf("verify current WireGuard server configuration: %w", err)
	}
	identity, err := wireguardstate.ParseServerConfiguration(server)
	if err != nil {
		return legacyWireGuardOwnership{}, fmt.Errorf("parse current manifest-bound WireGuard identity: %w", err)
	}
	return legacyWireGuardOwnership{
		evidence: LegacyWireGuardOwnershipEvidence{
			State: "verified-manifest", SHA256: hex.EncodeToString(digest[:]),
		},
		modernIdentity: &identity,
		modernServer:   server,
	}, nil
}

func selectLegacyWireGuardConfiguration(
	host legacyWireGuardRecoveryHost,
	table LegacyWireGuardTableEvidence,
	ownership legacyWireGuardOwnership,
) (legacyWireGuardGenerationCandidate, error) {
	candidates := []legacyWireGuardGenerationCandidate{
		{generation: legacyWireGuardGenerationWG0, interfaceName: "wg0"},
		{generation: legacyWireGuardGenerationWGSysWarden, interfaceName: "wg-syswarden"},
	}
	eligible := make([]legacyWireGuardGenerationCandidate, 0, 1)
	for _, candidate := range candidates {
		path := "/etc/wireguard/" + candidate.interfaceName + ".conf"
		configuration, err := captureLegacyWireGuardConfiguration(
			host.filesystemRoot, path, host.expectedUID, host.expectedGID,
		)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return legacyWireGuardGenerationCandidate{}, err
		}

		historicalErr := validateHistoricalWireGuardConfiguration(
			configuration.content, candidate.interfaceName, table.EgressInterface,
		)
		switch {
		case historicalErr == nil:
			configuration.evidence.Source = "exact-historical-config"
		case candidate.interfaceName == "wg-syswarden" && ownership.modernIdentity != nil:
			serverDigest := sha256.Sum256(ownership.modernServer)
			if configuration.evidence.SHA256 != hex.EncodeToString(serverDigest[:]) ||
				ownership.modernIdentity.ActiveInterface != table.EgressInterface {
				return legacyWireGuardGenerationCandidate{}, fmt.Errorf(
					"current manifest does not bind the unmarked historical table egress and configuration",
				)
			}
			configuration.evidence.Source = "verified-current-manifest"
		default:
			return legacyWireGuardGenerationCandidate{}, fmt.Errorf(
				"configuration %s does not prove a supported historical WireGuard generation: %w",
				path, historicalErr,
			)
		}
		candidate.configuration = configuration
		eligible = append(eligible, candidate)
	}
	if len(eligible) == 0 {
		return legacyWireGuardGenerationCandidate{}, fmt.Errorf(
			"no exact supported historical WireGuard configuration proves the unmarked table lineage",
		)
	}
	if len(eligible) != 1 {
		return legacyWireGuardGenerationCandidate{}, fmt.Errorf(
			"multiple historical WireGuard configurations make the unmarked table lineage ambiguous",
		)
	}
	return eligible[0], nil
}

func legacyWireGuardCommandExitedWith(err error, expected int) bool {
	var exitErr *exec.ExitError
	return errors.As(err, &exitErr) && exitErr.ExitCode() == expected
}

func (host legacyWireGuardRecoveryHost) exactSystemdProperty(
	unit, property string,
	allowed ...string,
) (string, error) {
	output, err := host.commandOutput("systemctl", "show", unit, "--property="+property, "--value")
	if err != nil {
		return "", fmt.Errorf("read systemd %s for %s: %w", property, unit, err)
	}
	value := strings.TrimSpace(string(output))
	for _, expected := range allowed {
		if value == expected {
			return value, nil
		}
	}
	return "", fmt.Errorf("systemd %s for %s has ambiguous state %q", property, unit, value)
}

func (host legacyWireGuardRecoveryHost) inspectHistoricalService(
	interfaceName string,
) (string, LegacyWireGuardServiceEvidence, bool, error) {
	if host.isAlpine() {
		name := "wg-quick." + interfaceName
		servicePath := filepath.Join(host.filesystemRoot, "etc", "init.d", name)
		_, serviceErr := os.Lstat(servicePath)
		servicePresent := serviceErr == nil
		if serviceErr != nil && !errors.Is(serviceErr, os.ErrNotExist) {
			return "", LegacyWireGuardServiceEvidence{}, false,
				fmt.Errorf("inspect OpenRC historical WireGuard service %s: %w", servicePath, serviceErr)
		}

		runlevels, err := host.commandOutput("rc-update", "show")
		if err != nil {
			return "", LegacyWireGuardServiceEvidence{}, false, fmt.Errorf("inspect OpenRC runlevels: %w", err)
		}
		enabledState := "disabled"
		matches := 0
		for _, line := range strings.Split(string(runlevels), "\n") {
			fields := strings.Fields(line)
			if len(fields) == 0 || fields[0] != name {
				continue
			}
			matches++
			if len(fields) != 3 || fields[1] != "|" || fields[2] != "default" {
				return "", LegacyWireGuardServiceEvidence{}, false, fmt.Errorf("historical OpenRC service has an unexpected runlevel")
			}
			enabledState = "enabled"
		}
		if matches > 1 {
			return "", LegacyWireGuardServiceEvidence{}, false, fmt.Errorf("historical OpenRC service has duplicate enablement")
		}
		if !servicePresent {
			if matches != 0 {
				return "", LegacyWireGuardServiceEvidence{}, false,
					fmt.Errorf("absent historical OpenRC service still has runlevel enablement")
			}
			interfacePresent, err := host.inspectHistoricalInterface(interfaceName)
			return "openrc", LegacyWireGuardServiceEvidence{
				LoadState: "not-found", Name: name, ActiveState: "not-found", EnabledState: "not-found",
			}, interfacePresent, err
		}

		status, statusErr := host.commandOutput("rc-service", name, "status")
		trimmed := strings.TrimSpace(string(status))
		activeState := ""
		switch {
		case trimmed == "* status: started" && statusErr == nil:
			activeState = "active"
		case trimmed == "* status: stopped" && legacyWireGuardCommandExitedWith(statusErr, 3):
			activeState = "inactive"
		default:
			return "", LegacyWireGuardServiceEvidence{}, false,
				errors.Join(fmt.Errorf("ambiguous OpenRC historical WireGuard state %q", trimmed), statusErr)
		}
		interfacePresent, err := host.inspectHistoricalInterface(interfaceName)
		return "openrc", LegacyWireGuardServiceEvidence{
			LoadState: "loaded", Name: name, ActiveState: activeState, EnabledState: enabledState,
		}, interfacePresent, err
	}

	name := "wg-quick@" + interfaceName + ".service"
	loadState, err := host.exactSystemdProperty(name, "LoadState", "loaded", "not-found")
	if err != nil {
		return "", LegacyWireGuardServiceEvidence{}, false, err
	}
	activeState := "not-found"
	enabledState := "not-found"
	if loadState == "loaded" {
		activeState, err = host.exactSystemdProperty(name, "ActiveState", "active", "inactive", "failed")
		if err != nil {
			return "", LegacyWireGuardServiceEvidence{}, false, err
		}
		enabledState, err = host.exactSystemdProperty(name, "UnitFileState", "enabled", "disabled")
		if err != nil {
			return "", LegacyWireGuardServiceEvidence{}, false, err
		}
	}
	interfacePresent, err := host.inspectHistoricalInterface(interfaceName)
	return "systemd", LegacyWireGuardServiceEvidence{
		LoadState: loadState, Name: name, ActiveState: activeState, EnabledState: enabledState,
	}, interfacePresent, err
}

func (host legacyWireGuardRecoveryHost) inspectHistoricalInterface(interfaceName string) (bool, error) {
	interfaces, err := host.commandOutput("wg", "show", "interfaces")
	if err != nil {
		return false, fmt.Errorf("inspect historical WireGuard interfaces: %w", err)
	}
	matches := 0
	for _, candidate := range strings.Fields(string(interfaces)) {
		if candidate == interfaceName {
			matches++
		}
	}
	if matches > 1 {
		return false, fmt.Errorf("historical WireGuard interface %s is duplicated", interfaceName)
	}
	return matches == 1, nil
}

func (host legacyWireGuardRecoveryHost) inspect() (LegacyWireGuardRecoveryPlan, error) {
	if err := host.validate(); err != nil {
		return LegacyWireGuardRecoveryPlan{}, err
	}
	managerState, err := host.managerState()
	if err != nil {
		return LegacyWireGuardRecoveryPlan{}, fmt.Errorf("classify service-manager runtime: %w", err)
	}
	if managerState != "ACTIVE" {
		return LegacyWireGuardRecoveryPlan{}, fmt.Errorf("legacy WireGuard recovery requires an active service manager; state is %s", managerState)
	}
	ownership, err := inspectLegacyWireGuardOwnership(host.filesystemRoot, host.expectedUID, host.expectedGID)
	if err != nil {
		return LegacyWireGuardRecoveryPlan{}, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), wireGuardCommandTimeout)
	defer cancel()
	present, inventoryHandle, err := wireGuardReservedNFTTableIdentity(ctx, host.nftRunner)
	if err != nil {
		return LegacyWireGuardRecoveryPlan{}, err
	}
	if !present {
		return LegacyWireGuardRecoveryPlan{}, fmt.Errorf("no reserved inet syswarden_wg table requires legacy recovery")
	}
	tableWire, err := host.nftRunner.Run(ctx, "-a", "-j", "list", "table", "inet", "syswarden_wg")
	if err != nil {
		return LegacyWireGuardRecoveryPlan{}, fmt.Errorf("inspect historical reserved WireGuard table: %w", err)
	}
	table, err := validateLegacyWireGuardNFTTable(tableWire, inventoryHandle)
	if err != nil {
		return LegacyWireGuardRecoveryPlan{}, fmt.Errorf("refuse unknown unmarked WireGuard table: %w", err)
	}
	forwardWire, err := host.nftRunner.Run(ctx, "-a", "-j", "list", "chain", "inet", "filter", "forward")
	if err != nil {
		return LegacyWireGuardRecoveryPlan{}, fmt.Errorf("inspect historical shared WireGuard forward rules: %w", err)
	}
	matches, err := matchingLegacyWireGuardForwardRules(forwardWire)
	if err != nil {
		return LegacyWireGuardRecoveryPlan{}, err
	}
	candidate, err := selectLegacyWireGuardConfiguration(host, table, ownership)
	if err != nil {
		return LegacyWireGuardRecoveryPlan{}, err
	}
	forwardRules, err := selectLegacyWireGuardForwardRules(matches, candidate.interfaceName)
	if err != nil {
		return LegacyWireGuardRecoveryPlan{}, err
	}

	serviceManager, service, interfacePresent, err := host.inspectHistoricalService(candidate.interfaceName)
	if err != nil {
		return LegacyWireGuardRecoveryPlan{}, err
	}
	blockers := make([]string, 0, 3)
	if service.LoadState == "loaded" {
		if service.ActiveState != "inactive" {
			blockers = append(blockers, "historical service is not inactive")
		}
		if service.EnabledState != "disabled" {
			blockers = append(blockers, "historical service is not disabled")
		}
	} else if service.LoadState != "not-found" {
		blockers = append(blockers, "historical service load state is not proven safe")
	}
	if interfacePresent {
		blockers = append(blockers, "historical interface is present")
	}
	plan := LegacyWireGuardRecoveryPlan{
		Schema: legacyWireGuardRecoverySchema, Generation: candidate.generation,
		ServiceManager: serviceManager, HistoricalInterface: candidate.interfaceName,
		Table: table, ForwardRules: forwardRules, Configuration: candidate.configuration.evidence,
		Ownership: ownership.evidence, Service: service, InterfacePresent: interfacePresent,
		SafeToApply: len(blockers) == 0, Blockers: blockers,
	}
	return plan, nil
}

func canonicalLegacyWireGuardRecoveryPlan(plan LegacyWireGuardRecoveryPlan) ([]byte, error) {
	if plan.Schema != legacyWireGuardRecoverySchema || plan.Blockers == nil ||
		plan.ForwardRules == nil || len(plan.ForwardRules) > 2 {
		return nil, fmt.Errorf("legacy WireGuard recovery plan is incomplete")
	}
	expectedInterface := ""
	switch plan.Generation {
	case legacyWireGuardGenerationWG0:
		expectedInterface = "wg0"
	case legacyWireGuardGenerationWGSysWarden:
		expectedInterface = "wg-syswarden"
	default:
		return nil, fmt.Errorf("legacy WireGuard recovery plan generation is invalid")
	}
	if plan.HistoricalInterface != expectedInterface ||
		plan.Table.Family != "inet" || plan.Table.Name != "syswarden_wg" ||
		plan.Table.Handle == 0 || plan.Table.PreroutingChainHandle == 0 ||
		plan.Table.PostroutingChainHandle == 0 || plan.Table.MasqueradeRuleHandle == 0 ||
		!wireGuardInterfaceName.MatchString(plan.Table.EgressInterface) {
		return nil, fmt.Errorf("legacy WireGuard recovery plan table identity is invalid")
	}
	expectedPath := "/etc/wireguard/" + expectedInterface + ".conf"
	if plan.Configuration.Path != expectedPath ||
		!wireGuardOwnershipTokenName.MatchString(plan.Configuration.SHA256) ||
		plan.Configuration.Mode != 0600 || plan.Configuration.NLink != 1 ||
		plan.Configuration.Device == 0 || plan.Configuration.Inode == 0 ||
		plan.Configuration.Size < 1 || plan.Configuration.Size > maximumLegacyWireGuardConfigurationSize {
		return nil, fmt.Errorf("legacy WireGuard recovery plan configuration evidence is invalid")
	}
	if plan.Configuration.Source != "exact-historical-config" &&
		(plan.Configuration.Source != "verified-current-manifest" || expectedInterface != "wg-syswarden") {
		return nil, fmt.Errorf("legacy WireGuard recovery plan configuration source is invalid")
	}
	if (plan.Ownership.State != "no-manifest" && plan.Ownership.State != "verified-manifest") ||
		!wireGuardOwnershipTokenName.MatchString(plan.Ownership.SHA256) {
		return nil, fmt.Errorf("legacy WireGuard recovery plan ownership evidence is invalid")
	}
	if plan.Configuration.Source == "verified-current-manifest" && plan.Ownership.State != "verified-manifest" {
		return nil, fmt.Errorf("legacy WireGuard recovery plan manifest evidence is incoherent")
	}
	expectedServiceName := ""
	switch plan.ServiceManager {
	case "systemd":
		expectedServiceName = "wg-quick@" + expectedInterface + ".service"
		if plan.Service.LoadState == "not-found" {
			if plan.Service.ActiveState != "not-found" || plan.Service.EnabledState != "not-found" {
				return nil, fmt.Errorf("legacy WireGuard recovery plan absent systemd state is incoherent")
			}
		} else if plan.Service.LoadState != "loaded" ||
			(plan.Service.ActiveState != "active" && plan.Service.ActiveState != "inactive" && plan.Service.ActiveState != "failed") ||
			(plan.Service.EnabledState != "enabled" && plan.Service.EnabledState != "disabled") {
			return nil, fmt.Errorf("legacy WireGuard recovery plan systemd state is invalid")
		}
	case "openrc":
		expectedServiceName = "wg-quick." + expectedInterface
		if plan.Service.LoadState == "not-found" {
			if plan.Service.ActiveState != "not-found" || plan.Service.EnabledState != "not-found" {
				return nil, fmt.Errorf("legacy WireGuard recovery plan absent OpenRC state is incoherent")
			}
		} else if plan.Service.LoadState != "loaded" ||
			(plan.Service.ActiveState != "active" && plan.Service.ActiveState != "inactive") ||
			(plan.Service.EnabledState != "enabled" && plan.Service.EnabledState != "disabled") {
			return nil, fmt.Errorf("legacy WireGuard recovery plan OpenRC state is invalid")
		}
	default:
		return nil, fmt.Errorf("legacy WireGuard recovery plan service manager is invalid")
	}
	if plan.Service.Name != expectedServiceName {
		return nil, fmt.Errorf("legacy WireGuard recovery plan service identity is invalid")
	}
	seenDirections := make(map[string]struct{}, len(plan.ForwardRules))
	previousDirection := ""
	for _, rule := range plan.ForwardRules {
		if rule.Handle == 0 || (rule.Direction != "iifname" && rule.Direction != "oifname") ||
			(previousDirection != "" && rule.Direction <= previousDirection) {
			return nil, fmt.Errorf("legacy WireGuard recovery plan forward rules are not canonical")
		}
		if _, duplicate := seenDirections[rule.Direction]; duplicate {
			return nil, fmt.Errorf("legacy WireGuard recovery plan forward rules are duplicated")
		}
		seenDirections[rule.Direction] = struct{}{}
		previousDirection = rule.Direction
	}
	expectedBlockers := make([]string, 0, 3)
	if plan.Service.LoadState == "loaded" {
		if plan.Service.ActiveState != "inactive" {
			expectedBlockers = append(expectedBlockers, "historical service is not inactive")
		}
		if plan.Service.EnabledState != "disabled" {
			expectedBlockers = append(expectedBlockers, "historical service is not disabled")
		}
	} else if plan.Service.LoadState != "not-found" {
		expectedBlockers = append(expectedBlockers, "historical service load state is not proven safe")
	}
	if plan.InterfacePresent {
		expectedBlockers = append(expectedBlockers, "historical interface is present")
	}
	if !reflect.DeepEqual(plan.Blockers, expectedBlockers) || plan.SafeToApply != (len(expectedBlockers) == 0) {
		return nil, fmt.Errorf("legacy WireGuard recovery plan safety decision is not canonical")
	}
	return json.Marshal(plan)
}

// LegacyWireGuardRecoveryPlanSHA256 returns the authorization digest for the
// exact redacted plan. Any observed metadata, state, or handle drift changes it.
func LegacyWireGuardRecoveryPlanSHA256(plan LegacyWireGuardRecoveryPlan) (string, error) {
	wire, err := canonicalLegacyWireGuardRecoveryPlan(plan)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(wire)
	return hex.EncodeToString(digest[:]), nil
}

// RenderLegacyWireGuardRecoveryPlan returns stable, indented JSON and contains
// no private or preshared key material.
func RenderLegacyWireGuardRecoveryPlan(plan LegacyWireGuardRecoveryPlan) ([]byte, error) {
	if _, err := canonicalLegacyWireGuardRecoveryPlan(plan); err != nil {
		return nil, err
	}
	return json.MarshalIndent(plan, "", "  ")
}

// InspectLegacyWireGuardRecovery performs exact read-only classification. It
// never obtains the mutation guard and never invokes nft with a mutating verb.
func InspectLegacyWireGuardRecovery() (LegacyWireGuardRecoveryPlan, error) {
	return productionLegacyWireGuardRecoveryHost().inspect()
}

func legacyWireGuardRecoveryBatch(plan LegacyWireGuardRecoveryPlan) string {
	var builder strings.Builder
	for _, rule := range plan.ForwardRules {
		fmt.Fprintf(&builder, "delete rule inet filter forward handle %d\n", rule.Handle)
	}
	fmt.Fprintf(&builder, "delete table inet handle %d\n", plan.Table.Handle)
	return builder.String()
}

func (host legacyWireGuardRecoveryHost) verifyRemoved(plan LegacyWireGuardRecoveryPlan) error {
	ctx, cancel := context.WithTimeout(context.Background(), wireGuardCommandTimeout)
	defer cancel()
	present, handle, err := wireGuardReservedNFTTableIdentity(ctx, host.nftRunner)
	if err != nil {
		return fmt.Errorf("verify historical WireGuard table removal: %w", err)
	}
	if present {
		if handle == plan.Table.Handle {
			return fmt.Errorf("exact historical WireGuard table handle %d remains", handle)
		}
		return fmt.Errorf("a replacement inet syswarden_wg table appeared after recovery")
	}
	forwardWire, err := host.nftRunner.Run(ctx, "-a", "-j", "list", "chain", "inet", "filter", "forward")
	if err != nil {
		return fmt.Errorf("verify historical shared forward rule removal: %w", err)
	}
	matches, err := matchingLegacyWireGuardForwardRules(forwardWire)
	if err != nil {
		return err
	}
	if len(matches["wg0"]) != 0 || len(matches["wg-syswarden"]) != 0 {
		return fmt.Errorf("historical shared forward rules were replaced or remain after recovery")
	}
	return nil
}

func (host legacyWireGuardRecoveryHost) apply(expectedDigest string) (result LegacyWireGuardRecoveryPlan, resultErr error) {
	if !wireGuardOwnershipTokenName.MatchString(expectedDigest) {
		return LegacyWireGuardRecoveryPlan{}, fmt.Errorf("plan SHA-256 must be exactly 64 lowercase hexadecimal characters")
	}
	before, err := host.inspect()
	if err != nil {
		return LegacyWireGuardRecoveryPlan{}, err
	}
	digest, err := LegacyWireGuardRecoveryPlanSHA256(before)
	if err != nil || digest != expectedDigest {
		return LegacyWireGuardRecoveryPlan{}, errors.Join(fmt.Errorf("legacy WireGuard recovery plan digest mismatch"), err)
	}
	if !before.SafeToApply {
		return LegacyWireGuardRecoveryPlan{}, fmt.Errorf(
			"legacy WireGuard recovery is not safe to apply: %s",
			strings.Join(before.Blockers, "; "),
		)
	}
	release, err := host.guard()
	if err != nil {
		return LegacyWireGuardRecoveryPlan{}, fmt.Errorf("acquire WireGuard recovery guard: %w", err)
	}
	defer func() {
		if err := release(); err != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("release WireGuard recovery guard: %w", err))
		}
	}()

	guarded, err := host.inspect()
	if err != nil || !reflect.DeepEqual(guarded, before) {
		return LegacyWireGuardRecoveryPlan{}, errors.Join(fmt.Errorf("legacy WireGuard recovery state changed before guarded attestation"), err)
	}
	guardedDigest, err := LegacyWireGuardRecoveryPlanSHA256(guarded)
	if err != nil || guardedDigest != expectedDigest {
		return LegacyWireGuardRecoveryPlan{}, errors.Join(fmt.Errorf("guarded legacy WireGuard recovery plan digest mismatch"), err)
	}
	finalPlan, err := host.inspect()
	if err != nil || !reflect.DeepEqual(finalPlan, guarded) {
		return LegacyWireGuardRecoveryPlan{}, errors.Join(fmt.Errorf("legacy WireGuard recovery state changed immediately before apply"), err)
	}
	finalDigest, err := LegacyWireGuardRecoveryPlanSHA256(finalPlan)
	if err != nil || finalDigest != expectedDigest || !finalPlan.SafeToApply {
		return LegacyWireGuardRecoveryPlan{}, errors.Join(fmt.Errorf("final legacy WireGuard recovery plan is not authorized"), err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), wireGuardCommandTimeout)
	defer cancel()
	output, err := host.nftBatch(ctx, legacyWireGuardRecoveryBatch(finalPlan))
	if err != nil {
		return LegacyWireGuardRecoveryPlan{}, fmt.Errorf(
			"apply exact historical WireGuard nftables recovery atomically: %w: %s",
			err, strings.TrimSpace(string(output)),
		)
	}
	if err := host.verifyRemoved(finalPlan); err != nil {
		return LegacyWireGuardRecoveryPlan{}, err
	}
	return finalPlan, nil
}

// ApplyLegacyWireGuardRecovery recomputes and reattests the exact plan three
// times, including twice under the existing WireGuard/firewall activation guard,
// before one atomic handle-bound nft batch is allowed to run.
func ApplyLegacyWireGuardRecovery(expectedDigest string) (LegacyWireGuardRecoveryPlan, error) {
	return productionLegacyWireGuardRecoveryHost().apply(expectedDigest)
}

// legacyWireGuardRecoveryDryRunHint is kept in one place so every preflight
// failure sends an operator to the same non-mutating first step.
func legacyWireGuardRecoveryDryRunHint() string {
	return "inspect supported historical state with 'sudo syswarden recover-wireguard' before any explicit recovery"
}
