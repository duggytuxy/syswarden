//go:build linux

package system

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"slices"
	"strings"
	"syscall"
)

const nativeOpenRCInventoryLimit = 4096

type nativeOpenRCObserver struct {
	root     string
	uid, gid uint32
}

type nativeOpenRCProof struct {
	identity os.FileInfo
	content  string
}

type nativeOpenRCRead struct {
	host   nativeOpenRCObserver
	root   *os.Root
	proofs map[string]nativeOpenRCProof
	bytes  int64
}

type nativeOpenRCCoreObserver func(*nativeOpenRCRead) (string, error)

// No OpenRC executable is a read-only primitive: status can execute init
// scripts, and even lookup/report commands may create state or dependency data.
// Inspect two stable filesystem views instead. This is not a manager lock.
func inspectNativeOpenRCServices(host nativeOpenRCObserver, core nativeOpenRCCoreObserver) (installationServiceSnapshot, error) {
	first, proofs, err := captureNativeOpenRCServices(host, core)
	if err != nil {
		return first, err
	}
	second, confirmed, err := captureNativeOpenRCServices(host, core)
	if err != nil {
		return second, err
	}
	if first != second || !sameNativeOpenRCProofs(proofs, confirmed) {
		return installationServiceSnapshot{}, errors.New("OpenRC service evidence changed during observation")
	}
	return second, nil
}

func sameNativeOpenRCProofs(a, b map[string]nativeOpenRCProof) bool {
	if len(a) != len(b) {
		return false
	}
	for key, first := range a {
		second, exists := b[key]
		if !exists || first.content != second.content {
			return false
		}
		if first.identity == nil || second.identity == nil {
			if first.identity != nil || second.identity != nil {
				return false
			}
		} else if first.identity.IsDir() {
			// Unrelated daemon activity may change directory timestamps. Relevant
			// membership is independently inventoried in each observation.
			if !os.SameFile(first.identity, second.identity) || first.identity.Mode() != second.identity.Mode() {
				return false
			}
		} else if !sameWireGuardDefinitionIdentity(first.identity, second.identity) {
			return false
		}
	}
	return true
}

func (r *nativeOpenRCRead) trusted(info os.FileInfo, directory, runtime bool) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != r.host.uid || stat.Gid != r.host.gid ||
		info.Mode()&(os.ModeSymlink|os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return false
	}
	if directory {
		return info.IsDir() && (info.Mode().Perm()&0022 == 0 || runtime && info.Mode().Perm() == 0775)
	}
	return info.Mode().IsRegular() && info.Mode().Perm()&0022 == 0 && stat.Nlink == 1
}

// Every component is pinned independently; no path alias is followed, and no
// directory is created. Root is fixed to / in production, injectable in tests.
func (r *nativeOpenRCRead) directory(relative string) (*os.Root, error) {
	if relative != "." && (path.Clean(relative) != relative || strings.HasPrefix(relative, "/") || strings.HasPrefix(relative, "..")) {
		return nil, errors.New("invalid OpenRC observation path")
	}
	current, err := r.root.OpenRoot(".")
	if err != nil {
		return nil, err
	}
	if relative == "." {
		return current, nil
	}
	prefix := ""
	for _, part := range strings.Split(relative, "/") {
		prefix = path.Join(prefix, part)
		before, err := current.Lstat(part)
		if err != nil {
			_ = current.Close()
			return nil, err
		}
		runtime := prefix == "run/openrc" || strings.HasPrefix(prefix, "run/openrc/")
		if !r.trusted(before, true, runtime) {
			_ = current.Close()
			return nil, errors.New("unsafe OpenRC observation directory")
		}
		next, err := current.OpenRoot(part)
		if err != nil {
			_ = current.Close()
			return nil, err
		}
		opened, openErr := next.Stat(".")
		after, afterErr := current.Lstat(part)
		_ = current.Close()
		if openErr != nil || afterErr != nil || !sameWireGuardDefinitionIdentity(before, opened) || !sameWireGuardDefinitionIdentity(before, after) {
			_ = next.Close()
			return nil, errors.New("OpenRC directory changed while opening")
		}
		r.proofs[prefix+"/"] = nativeOpenRCProof{identity: after}
		current = next
	}
	return current, nil
}

func (r *nativeOpenRCRead) entries(relative string) ([]os.DirEntry, error) {
	directory, err := r.directory(relative)
	if err != nil {
		return nil, err
	}
	defer func() { _ = directory.Close() }()
	file, err := directory.Open(".")
	if err != nil {
		return nil, err
	}
	entries, readErr := file.ReadDir(nativeOpenRCInventoryLimit + 1)
	_ = file.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) || len(entries) > nativeOpenRCInventoryLimit {
		return nil, errors.New("OpenRC inventory is unreadable or exceeds its limit")
	}
	slices.SortFunc(entries, func(a, b os.DirEntry) int { return strings.Compare(a.Name(), b.Name()) })
	return entries, nil
}

func (r *nativeOpenRCRead) entry(relative string) (os.FileInfo, *os.Root, error) {
	directory, err := r.directory(path.Dir(relative))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			r.proofs[relative] = nativeOpenRCProof{}
		}
		return nil, nil, err
	}
	info, err := directory.Lstat(path.Base(relative))
	if err != nil {
		_ = directory.Close()
		if errors.Is(err, fs.ErrNotExist) {
			r.proofs[relative] = nativeOpenRCProof{}
		}
		return nil, nil, err
	}
	return info, directory, nil
}

func (r *nativeOpenRCRead) absent(relative string) error {
	_, directory, err := r.entry(relative)
	if directory != nil {
		_ = directory.Close()
	}
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return errors.New("OpenRC contains pending or unsupported service state")
}

func (r *nativeOpenRCRead) file(relative string, limit int64) ([]byte, error) {
	before, directory, err := r.entry(relative)
	if err != nil {
		return nil, err
	}
	defer func() { _ = directory.Close() }()
	if !r.trusted(before, false, false) || before.Size() > limit {
		return nil, errors.New("unsafe or oversized OpenRC observation file")
	}
	file, err := directory.OpenFile(path.Base(relative), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	opened, statErr := file.Stat()
	content, readErr := io.ReadAll(io.LimitReader(file, limit+1))
	after, afterErr := file.Stat()
	_ = file.Close()
	named, nameErr := directory.Lstat(path.Base(relative))
	if statErr != nil || readErr != nil || afterErr != nil || nameErr != nil || int64(len(content)) > limit ||
		!sameWireGuardDefinitionIdentity(before, opened) || !sameWireGuardDefinitionIdentity(before, after) || !sameWireGuardDefinitionIdentity(before, named) {
		return nil, errors.New("OpenRC file changed during observation")
	}
	r.bytes += int64(len(content))
	if r.bytes > 4<<20 {
		return nil, errors.New("OpenRC observation exceeds its total byte limit")
	}
	r.proofs[relative] = nativeOpenRCProof{identity: named, content: string(content)}
	return content, nil
}

func (r *nativeOpenRCRead) link(relative string, targets ...string) (bool, error) {
	before, directory, err := r.entry(relative)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer func() { _ = directory.Close() }()
	stat, ok := before.Sys().(*syscall.Stat_t)
	if !ok || before.Mode()&os.ModeSymlink == 0 || stat.Uid != r.host.uid || stat.Gid != r.host.gid || stat.Nlink != 1 {
		return false, errors.New("unsafe OpenRC service link")
	}
	target, err := directory.Readlink(path.Base(relative))
	after, afterErr := directory.Lstat(path.Base(relative))
	if err != nil || afterErr != nil || !slices.Contains(targets, target) || !sameWireGuardDefinitionIdentity(before, after) {
		return false, errors.New("OpenRC service link changed or has an unsupported target")
	}
	r.proofs[relative] = nativeOpenRCProof{identity: after, content: target}
	return true, nil
}

func captureNativeOpenRCServices(host nativeOpenRCObserver, core nativeOpenRCCoreObserver) (installationServiceSnapshot, map[string]nativeOpenRCProof, error) {
	var snapshot installationServiceSnapshot
	root, err := os.OpenRoot(host.root)
	if err != nil {
		return snapshot, nil, err
	}
	defer func() { _ = root.Close() }()
	r := &nativeOpenRCRead{host: host, root: root, proofs: make(map[string]nativeOpenRCProof)}
	info, err := root.Stat(".")
	if err != nil || !r.trusted(info, true, false) {
		return snapshot, nil, errors.New("unsafe OpenRC observation root")
	}
	r.proofs["/"] = nativeOpenRCProof{identity: info}
	if err := r.configuration(); err != nil {
		return snapshot, nil, err
	}
	for _, marker := range []string{"rc.starting", "rc.stopping", "openrc-run.sh"} {
		if err := r.absent("run/openrc/" + marker); err != nil {
			return snapshot, nil, err
		}
	}
	level, err := r.file("run/openrc/softlevel", 64)
	name := strings.TrimSuffix(string(level), "\n")
	if err != nil || name == "" || name == "shutdown" || name == "reboot" || strings.Trim(name, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-") != "" {
		return snapshot, nil, errors.New("OpenRC is not in a stable supported runlevel")
	}
	levels, err := r.entries("etc/runlevels")
	if err != nil {
		return snapshot, nil, err
	}
	for _, level := range levels {
		if !level.IsDir() || strings.HasPrefix(level.Name(), ".") || strings.Trim(level.Name(), "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-") != "" {
			return snapshot, nil, errors.New("OpenRC runlevel aliases require administrator review")
		}
	}
	for index, service := range []string{"syswarden-firewall", "syswarden-core"} {
		state, err := r.service(service, levels)
		if err != nil {
			return snapshot, nil, err
		}
		if service == "syswarden-firewall" && state.active == "active" {
			for _, directory := range []string{"run/openrc/daemons/syswarden-firewall", "run/openrc/options/syswarden-firewall"} {
				entries, err := r.entries(directory)
				if err != nil && !errors.Is(err, fs.ErrNotExist) {
					return snapshot, nil, err
				}
				if len(entries) != 0 {
					return snapshot, nil, errors.New("OpenRC oneshot firewall retains unexpected daemon bookkeeping")
				}
			}
		}
		if service == "syswarden-core" && state.active == "active" {
			if err := r.coreBookkeeping(); err != nil {
				return snapshot, nil, err
			}
			if core == nil {
				return snapshot, nil, errors.New("missing OpenRC core observer")
			}
			identity, err := core(r)
			if err != nil {
				return snapshot, nil, err
			}
			r.proofs["core-process"] = nativeOpenRCProof{content: identity}
		}
		snapshot[index] = state
	}
	return snapshot, r.proofs, nil
}

func (r *nativeOpenRCRead) service(service string, levels []os.DirEntry) (installationServiceState, error) {
	state := installationServiceState{name: service, load: "not-found", active: "inactive", enabled: "disabled"}
	definition, err := r.file("etc/init.d/"+service, 64<<10)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return state, err
	}
	if err == nil {
		state.load = "loaded"
		definitions := []string{openRCCoreService, historicalV4104OpenRCCoreService, historicalV4028OpenRCCoreService}
		if service == "syswarden-firewall" {
			definitions = []string{openRCFirewallService, historicalV4104OpenRCFirewallService, historicalV4028OpenRCFirewallService}
		}
		if !slices.Contains(definitions, string(definition)) || r.proofs["etc/init.d/"+service].identity.Mode().Perm() != 0755 {
			state.load = "unsupported"
		}
	}
	for _, marker := range []string{"stopped", "starting", "stopping", "inactive", "wasinactive", "failed", "crashed", "hotplugged", "exclusive"} {
		if err := r.absent("run/openrc/" + marker + "/" + service); err != nil {
			return state, err
		}
	}
	scheduled, err := r.entries("run/openrc/scheduled")
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return state, err
	}
	for _, dependency := range scheduled {
		if !dependency.IsDir() {
			return state, errors.New("unsupported OpenRC scheduled entry")
		}
		if err := r.absent("run/openrc/scheduled/" + dependency.Name() + "/" + service); err != nil {
			return state, err
		}
	}
	started, err := r.link("run/openrc/started/"+service, "/etc/init.d/"+service)
	if err != nil {
		return state, err
	}
	if started {
		state.active = "active"
		if state.load == "unsupported" {
			state.active = "unknown"
		}
	}
	var membership []string
	for _, level := range levels {
		linked, err := r.link("etc/runlevels/"+level.Name()+"/"+service, "/etc/init.d/"+service, "../../init.d/"+service)
		if err != nil {
			return state, err
		}
		if linked && level.Name() == "single" {
			return state, errors.New("OpenRC ignores service membership in the single runlevel")
		}
		if linked {
			membership = append(membership, level.Name())
		}
	}
	slices.Sort(membership)
	state.runlevels = strings.Join(membership, " ")
	if len(membership) > 0 {
		state.enabled = "enabled"
	}
	if state.load == "not-found" {
		for _, retained := range []string{"run/openrc/daemons/" + service, "run/openrc/options/" + service} {
			if err := r.absent(retained); err != nil {
				return state, err
			}
		}
		if service == "syswarden-core" {
			if err := r.absent("run/syswarden-core.pid"); err != nil {
				return state, err
			}
		}
	}
	if state.load == "not-found" && (started || len(membership) > 0) {
		return state, errors.New("OpenRC retains state for a missing service definition")
	}
	return state, nil
}
