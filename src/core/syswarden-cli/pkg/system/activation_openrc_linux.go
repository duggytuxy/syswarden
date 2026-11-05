//go:build linux

package system

import (
	"context"
	"crypto/sha1" // #nosec G505 -- native installed-file consistency, not release authenticity
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

type activationOpenRCState struct {
	Services    []activationHostService
	Scheduler   CronDProviderEvidence
	ProofSHA256 string
}

// These exact service definitions are from Alpine aports 3.20 through 3.24:
// community/cronie/cronie.initd and main/nftables/nftables.initd. Their installed
// APK file checksums are verified independently. No shell text is evaluated.
const activationCronieDefinitionSHA256 = "d94de130fa0e24d365434c72e34ed5ed2b007c7e7619c5daf8c3b95892119324"

var activationNFTDefinitionSHA256 = [...]string{
	"06445d9301c2303812914d235f18f41a0be20d4f6a7d4982d7b6d4d6524092c1",
	"ffc3bba3fc17d93c251711529331321d53e2e67c52485afbf00911468aad86c2",
}

func observeActivationOpenRC(ctx context.Context, backend string) (activationOpenRCState, error) {
	if err := nativeOpenRCEnvironment(); err != nil {
		return activationOpenRCState{}, err
	}
	return observeActivationOpenRCWith(ctx, backend, nativeOpenRCObserver{root: "/", uid: 0, gid: 0}, observeNativeOpenRCCore, observeActivationCronie)
}

func observeActivationOpenRCWith(ctx context.Context, backend string, host nativeOpenRCObserver, core, cronie nativeOpenRCCoreObserver) (activationOpenRCState, error) {
	if ctx == nil || (backend != "keep" && backend != "nftables") || core == nil || cronie == nil {
		return activationOpenRCState{}, errors.New("unsupported OpenRC activation observation")
	}
	first, proofs, err := captureActivationOpenRC(ctx, backend, host, core, cronie)
	if err != nil {
		return activationOpenRCState{}, err
	}
	second, confirmed, err := captureActivationOpenRC(ctx, backend, host, core, cronie)
	if err != nil {
		return activationOpenRCState{}, err
	}
	if !reflect.DeepEqual(first, second) || !sameNativeOpenRCProofs(proofs, confirmed) {
		return activationOpenRCState{}, errors.New("OpenRC activation prerequisites changed during observation")
	}
	second.ProofSHA256, err = activationOpenRCProofDigest(confirmed)
	return second, errors.Join(err, ctx.Err())
}

func captureActivationOpenRC(ctx context.Context, backend string, host nativeOpenRCObserver, core, cronie nativeOpenRCCoreObserver) (activationOpenRCState, map[string]nativeOpenRCProof, error) {
	var state activationOpenRCState
	if err := ctx.Err(); err != nil {
		return state, nil, err
	}
	pair, proofs, err := captureNativeOpenRCServices(host, core)
	if err != nil {
		return state, nil, err
	}
	root, err := os.OpenRoot(host.root)
	if err != nil {
		return state, nil, err
	}
	defer func() { _ = root.Close() }()
	r := &nativeOpenRCRead{host: host, root: root, proofs: proofs}
	for _, service := range pair {
		if service.load == "unsupported" || service.active == "unknown" {
			return state, nil, errors.New("OpenRC product service definition requires administrator review")
		}
		state.Services = append(state.Services, activationHostService{Name: service.name, Load: service.load, Active: service.active, Enabled: service.enabled, Runlevels: service.runlevels})
	}
	levels, err := r.entries("etc/runlevels")
	if err != nil {
		return state, nil, err
	}
	// Compatibility frontends cannot be classified through their executable
	// status functions. The bounded supported setup requires complete absence.
	for _, service := range []string{"iptables", "ip6tables", "netfilter-persistent", "firewalld", "ufw", "dcron", "crond"} {
		observed, err := r.service(service, levels)
		if err != nil {
			return state, nil, err
		}
		if observed.load != "not-found" || observed.active != "inactive" || observed.enabled != "disabled" {
			return state, nil, fmt.Errorf("OpenRC activation requires separate review of service %s", service)
		}
	}
	for _, service := range []string{"cronie", "nftables"} {
		if err := activationOpenRCOverrides(r, service); err != nil {
			return state, nil, err
		}
	}
	required := map[string]string{"usr/sbin/crond": "cronie", "etc/init.d/cronie": "cronie-openrc", "usr/sbin/nft": "nftables"}
	nft, err := r.service("nftables", levels)
	if err != nil {
		return state, nil, err
	}
	if nft.load != "not-found" {
		if !activationOpenRCHashAllowed(r.proofs["etc/init.d/nftables"].content, activationNFTDefinitionSHA256[:]) {
			return state, nil, errors.New("unsupported OpenRC nftables service definition")
		}
		nft.load = "loaded"
		if nft.active == "unknown" {
			nft.active = "active"
		}
		required["etc/init.d/nftables"] = "nftables-openrc"
		if err := activationOpenRCEmptyBookkeeping(r, "nftables"); err != nil {
			return state, nil, err
		}
	}
	if backend == "nftables" && (nft.load != "loaded" || nft.active != "active" || nft.enabled != "enabled") {
		return state, nil, errors.New("selected nftables backend must already be active and enabled")
	}
	state.Services = append(state.Services, activationHostService{Name: nft.name, Load: nft.load, Active: nft.active, Enabled: nft.enabled, Runlevels: nft.runlevels})
	cron, err := r.service("cronie", levels)
	if err != nil {
		return state, nil, err
	}
	if !activationOpenRCHashAllowed(r.proofs["etc/init.d/cronie"].content, []string{activationCronieDefinitionSHA256}) || cron.active != "unknown" || cron.runlevels != "default" {
		return state, nil, errors.New("Cronie requires the supported started service in the default runlevel only")
	}
	versions, err := activationOpenRCPackageFiles(r, required)
	if err != nil {
		return state, nil, err
	}
	if versions["cronie"] != versions["cronie-openrc"] || versions["cronie"] == "" {
		return state, nil, errors.New("Cronie daemon and service provenance disagree")
	}
	if versions["nftables-openrc"] != "" && versions["nftables"] != versions["nftables-openrc"] {
		return state, nil, errors.New("nftables executable and service provenance disagree")
	}
	if err := activationCronieBookkeeping(r); err != nil {
		return state, nil, err
	}
	process, err := cronie(r)
	if err != nil || process == "" {
		return state, nil, errors.Join(errors.New("Cronie live process observation failed"), err)
	}
	r.proofs["cronie-process"] = nativeOpenRCProof{content: process}
	state.Scheduler = CronDProviderEvidence{Mode: CronDProviderRuntime, Manager: "openrc", Unit: "cronie", Daemon: "/usr/sbin/crond", Fragment: "/etc/init.d/cronie", Packages: []string{"cronie", "cronie-openrc"}, DefaultRunlevel: true}
	return state, r.proofs, ctx.Err()
}

func activationOpenRCHashAllowed(content string, allowed []string) bool {
	digest := sha256.Sum256([]byte(content))
	for _, value := range allowed {
		if hex.EncodeToString(digest[:]) == value {
			return true
		}
	}
	return false
}

func activationOpenRCOverrides(r *nativeOpenRCRead, service string) error {
	if err := r.absent("usr/local/etc/init.d/" + service); err != nil {
		return err
	}
	entries, err := r.entries("etc/conf.d")
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), service+".") {
			return errors.New("OpenRC service variant configuration requires review")
		}
	}
	content, err := r.file("etc/conf.d/"+service, 64<<10)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, raw := range strings.Split(string(content), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || seen[key] {
			return errors.New("nonliteral OpenRC service configuration")
		}
		seen[key] = true
		if len(value) >= 2 && (value[0] == '"' || value[0] == '\'') && value[len(value)-1] == value[0] {
			value = value[1 : len(value)-1]
		}
		valid := service == "cronie" && key == "CRON_OPTS" && value == ""
		if service == "nftables" {
			switch key {
			case "rules_file":
				valid = value == "/etc/nftables.nft"
			case "save_objects":
				valid = value == "counters limits quotas" || value == "ruleset"
			case "save_on_stop", "enable_forwarding":
				valid = value == "no"
			case "save_options", "netns", "vrf":
				valid = value == ""
			}
		}
		if !valid {
			return errors.New("OpenRC service configuration requires explicit review")
		}
	}
	return nil
}

func activationOpenRCEmptyBookkeeping(r *nativeOpenRCRead, service string) error {
	for _, kind := range []string{"daemons", "options"} {
		entries, err := r.entries("run/openrc/" + kind + "/" + service)
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		if len(entries) != 0 {
			return errors.New("OpenRC oneshot service has unexpected daemon bookkeeping")
		}
	}
	return nil
}

func activationCronieBookkeeping(r *nativeOpenRCRead) error {
	expected := map[string]string{"command": "/usr/sbin/crond", "pidfile": "/run/cronie.pid", "chroot": "", "procname": ""}
	entries, err := r.entries("run/openrc/options/cronie")
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	for _, entry := range entries {
		value, known := expected[entry.Name()]
		if !known {
			return errors.New("unsupported Cronie saved daemon option")
		}
		wire, err := r.file("run/openrc/options/cronie/"+entry.Name(), 256)
		if err != nil || string(wire) != value {
			return errors.New("Cronie saved daemon parameters disagree")
		}
	}
	entries, err = r.entries("run/openrc/daemons/cronie")
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if len(entries) == 0 {
		return nil
	}
	if len(entries) != 1 || entries[0].Name() != "001" {
		return errors.New("unsupported Cronie daemon inventory")
	}
	wire, err := r.file("run/openrc/daemons/cronie/001", 1024)
	expectedWire := "exec=/usr/sbin/crond\nargv_0=/usr/sbin/crond\nargv_1=-n\npidfile=/run/cronie.pid\n"
	if err != nil || string(wire) != expectedWire {
		return errors.New("Cronie saved daemon record disagrees")
	}
	return nil
}

// APK's protected installed database is local package provenance. Q1 is checked
// only for native file consistency; it is not signature or release acceptance.
func activationOpenRCPackageFiles(r *nativeOpenRCRead, required map[string]string) (map[string]string, error) {
	database, err := r.file("lib/apk/db/installed", 4<<20)
	if err != nil {
		return nil, err
	}
	if strings.ContainsAny(string(database), "\x00\r") {
		return nil, errors.New("unsupported APK database framing")
	}
	versions := map[string]string{}
	found := map[string]bool{}
	seenPaths := map[string]bool{}
	for _, record := range strings.Split(string(database), "\n\n") {
		if strings.TrimSpace(record) == "" {
			continue
		}
		owner, version, directory, filename := "", "", "", ""
		checksums := map[string]string{}
		for _, line := range strings.Split(record, "\n") {
			if line == "" {
				continue
			}
			if len(line) < 2 || line[1] != ':' {
				return nil, errors.New("malformed APK installed record")
			}
			value := line[2:]
			switch line[0] {
			case 'P':
				if owner != "" {
					return nil, errors.New("duplicate APK package identity")
				}
				owner = value
			case 'V':
				if version != "" {
					return nil, errors.New("duplicate APK package version")
				}
				version = value
			case 'F':
				directory = value
				filename = ""
			case 'R':
				filename = path.Join(directory, value)
				if path.Base(value) != value || value == "." || path.Clean(directory) != directory || strings.HasPrefix(directory, "/") || strings.HasPrefix(directory, "..") {
					return nil, errors.New("noncanonical APK installed path")
				}
				if _, needed := required[filename]; needed {
					if seenPaths[filename] {
						return nil, errors.New("duplicate APK installed provider path")
					}
					seenPaths[filename] = true
				}
			case 'Z':
				if filename == "" {
					return nil, errors.New("APK file checksum lacks a filename")
				}
				if _, needed := required[filename]; needed {
					if _, duplicate := checksums[filename]; duplicate {
						return nil, errors.New("duplicate APK file checksum")
					}
					checksums[filename] = value
				}
			}
		}
		for name, checksum := range checksums {
			if found[name] || required[name] != owner || !safePackageVersion(version) {
				return nil, errors.New("APK file provenance is ambiguous")
			}
			if previous := versions[owner]; previous != "" && previous != version {
				return nil, errors.New("APK package version is ambiguous")
			}
			wire, err := r.file(name, 4<<20)
			if err != nil {
				return nil, err
			}
			if r.proofs[name].identity.Mode().Perm() != 0755 {
				return nil, errors.New("APK provider executable mode is unsupported")
			}
			sum := sha1.Sum(wire) // #nosec G401 -- checks protected native file metadata only
			if checksum != "Q1"+base64.StdEncoding.EncodeToString(sum[:]) {
				return nil, errors.New("APK provider bytes differ from installed provenance")
			}
			versions[owner] = version
			found[name] = true
		}
	}
	if len(found) != len(required) {
		return nil, errors.New("APK provider lacks complete installed file provenance")
	}
	return versions, nil
}

func activationOpenRCProofDigest(proofs map[string]nativeOpenRCProof) (string, error) {
	type witness struct {
		Path, ContentSHA256                                  string
		Device, Inode                                        uint64
		Mode                                                 uint32
		UID, GID                                             uint32
		Links                                                uint64
		Size, ModifiedSec, ModifiedNS, ChangedSec, ChangedNS int64
	}
	names := make([]string, 0, len(proofs))
	for name := range proofs {
		names = append(names, name)
	}
	sort.Strings(names)
	rows := make([]witness, 0, len(names))
	for _, name := range names {
		proof := proofs[name]
		sum := sha256.Sum256([]byte(proof.content))
		row := witness{Path: name, ContentSHA256: hex.EncodeToString(sum[:])}
		if proof.identity != nil {
			status, ok := proof.identity.Sys().(*syscall.Stat_t)
			if !ok {
				return "", errors.New("OpenRC proof metadata unavailable")
			}
			row.Device, row.Inode, row.Mode, row.UID, row.GID = status.Dev, status.Ino, status.Mode, status.Uid, status.Gid
			if !proof.identity.IsDir() {
				row.Links, row.Size, row.ModifiedSec, row.ModifiedNS, row.ChangedSec, row.ChangedNS = status.Nlink, status.Size, status.Mtim.Sec, status.Mtim.Nsec, status.Ctim.Sec, status.Ctim.Nsec
			}
		}
		rows = append(rows, row)
	}
	raw, err := json.Marshal(rows)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

func observeActivationCronie(r *nativeOpenRCRead) (string, error) {
	before, err := os.Lstat("/proc")
	if err != nil || !before.IsDir() || before.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("Cronie procfs is unavailable")
	}
	proc, err := os.OpenRoot("/proc")
	if err != nil {
		return "", err
	}
	defer func() { _ = proc.Close() }()
	file, err := proc.Open(".")
	if err != nil {
		return "", err
	}
	var stat unix.Statfs_t
	fsErr := unix.Fstatfs(int(file.Fd()), &stat)
	closeErr := file.Close()
	if fsErr != nil || closeErr != nil || stat.Type != unix.PROC_SUPER_MAGIC {
		return "", errors.New("Cronie observation requires kernel procfs")
	}
	proof, err := observeActivationCronieAt(r, proc, "/usr/sbin/crond")
	after, pathErr := os.Lstat("/proc")
	if pathErr != nil || !os.SameFile(before, after) || after.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("Cronie procfs changed during observation")
	}
	return proof, err
}

func observeActivationCronieAt(r *nativeOpenRCRead, proc *os.Root, expectedPath string) (string, error) {
	wire, err := r.file("run/cronie.pid", 32)
	if err != nil {
		return "", err
	}
	pid := strings.TrimSuffix(string(wire), "\n")
	number, err := strconv.ParseInt(pid, 10, 32)
	if err != nil || number <= 1 || strconv.FormatInt(number, 10) != pid {
		return "", errors.New("Cronie PID is not canonical")
	}
	before, err := proc.Lstat(pid)
	if err != nil || !r.trusted(before, true, false) {
		return "", errors.New("Cronie process is absent or foreign")
	}
	process, err := proc.OpenRoot(pid)
	if err != nil {
		return "", err
	}
	defer func() { _ = process.Close() }()
	opened, err := process.Stat(".")
	if err != nil || !os.SameFile(before, opened) {
		return "", errors.New("Cronie process changed while opening")
	}
	status, err := readBoundedFirewallRemovalProcFile(process, "status", 64<<10)
	if err != nil {
		return "", err
	}
	uidLine := ""
	for _, line := range strings.Split(string(status), "\n") {
		if strings.HasPrefix(line, "Uid:") {
			if uidLine != "" {
				return "", errors.New("Cronie process credentials are ambiguous")
			}
			uidLine = line
		}
	}
	fields := strings.Fields(uidLine)
	if len(fields) != 5 {
		return "", errors.New("Cronie process credentials are unavailable")
	}
	for _, uid := range fields[1:] {
		if uid != strconv.FormatUint(uint64(r.host.uid), 10) {
			return "", errors.New("Cronie process credentials differ from provider ownership")
		}
	}
	identity, err := nativeOpenRCCoreIdentity(process, pid, expectedPath)
	if err != nil || strings.HasSuffix(identity, " (deleted)") {
		return "", errors.New("Cronie process executable identity is unsupported")
	}
	cmdline, err := readBoundedFirewallRemovalProcFile(process, "cmdline", 4096)
	if err != nil || string(cmdline) != expectedPath+"\x00-n\x00" {
		return "", errors.New("Cronie process arguments differ from approved provider contract")
	}
	directory, err := process.Open(".")
	if err != nil {
		return "", err
	}
	var executable unix.Stat_t
	statErr := unix.Fstatat(int(directory.Fd()), "exe", &executable, 0)
	closeErr := directory.Close()
	disk := r.proofs["usr/sbin/crond"].identity
	if disk == nil {
		return "", errors.New("Cronie package executable proof is absent")
	}
	expected, ok := disk.Sys().(*syscall.Stat_t)
	if statErr != nil || closeErr != nil || !ok || executable.Dev != expected.Dev || executable.Ino != expected.Ino || executable.Uid != r.host.uid || executable.Mode != expected.Mode {
		return "", errors.New("Cronie process does not execute the attested installed inode")
	}
	confirmed, err := nativeOpenRCCoreIdentity(process, pid, expectedPath)
	after, pathErr := proc.Lstat(pid)
	if err != nil || pathErr != nil || identity != confirmed || !os.SameFile(before, after) || !r.trusted(after, true, false) {
		return "", errors.New("Cronie process generation changed")
	}
	return identity + ":" + hex.EncodeToString(cmdline), nil
}
