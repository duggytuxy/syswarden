//go:build linux

package system

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"runtime"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

type nativeInactiveHostState struct {
	Schema       string
	OpenRCSHA256 string
	NFTSHA256    string
	Kernel       nativeInactiveKernelState
}

type nativeInactiveKernelState struct {
	Boot          string
	NetworkDevice uint64
	NetworkInode  uint64
	LegacyTables  map[string]string
}

// ObserveNativeInactiveHost collects admission evidence for the supported
// NFT-only inactive source. It does not prove package provenance or hold
// publication exclusion. The
// native coordinator must bind those independently before mutation. Loaded
// legacy ipset support and nonempty legacy table inventories remain refused.
func ObserveNativeInactiveHost(ctx context.Context, nft func(context.Context) (string, error)) (string, error) {
	if ctx == nil || nft == nil || os.Geteuid() != 0 || runtime.GOARCH != "amd64" || !IsAlpine() {
		return "", errors.New("inactive native observation requires a root Linux AMD64 Alpine host")
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if err := nativeOpenRCEnvironment(); err != nil {
		return "", err
	}
	if err := requireActivationServiceManager(true, classifyServiceManagerRuntime); err != nil {
		return "", err
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	first, err := captureNativeInactiveHost(ctx, nft)
	if err != nil {
		return "", err
	}
	second, err := captureNativeInactiveHost(ctx, nft)
	if err != nil {
		return "", err
	}
	if !reflect.DeepEqual(first, second) {
		return "", errors.New("inactive native host changed during admission")
	}
	raw, err := json.Marshal(second)
	if err != nil {
		return "", err
	}
	return apkTransitionDigest(raw), ctx.Err()
}

func captureNativeInactiveHost(ctx context.Context, nft func(context.Context) (string, error)) (nativeInactiveHostState, error) {
	state := nativeInactiveHostState{Schema: "syswarden-native-inactive-host-v1"}
	before, err := captureNativeInactiveKernel(ctx)
	if err != nil {
		return state, err
	}
	state.OpenRCSHA256, err = observeNativeInactiveOpenRCWith(ctx, nativeOpenRCObserver{root: "/", uid: 0, gid: 0})
	if err != nil {
		return state, err
	}
	scanner := productionFirewallRemovalProcessScanner()
	scanner.rejectCore = true
	// Inactivity also excludes exact product processes under service accounts.
	// Inaccessible process evidence remains a refusal, never an empty inventory.
	scanner.inspectAllUsers = true
	if err := scanner.scan(); err != nil {
		return state, err
	}
	state.NFTSHA256, err = nft(ctx)
	if err != nil {
		return state, err
	}
	if !validSHA256(state.NFTSHA256) {
		return state, errors.New("inactive native firewall observation is incomplete")
	}
	if err := scanner.scan(); err != nil {
		return state, err
	}
	after, err := captureNativeInactiveKernel(ctx)
	if err != nil {
		return state, err
	}
	if !reflect.DeepEqual(before, after) {
		return state, errors.New("inactive native kernel context changed during observation")
	}
	state.Kernel = after
	return state, ctx.Err()
}

func captureNativeInactiveKernel(ctx context.Context) (_ nativeInactiveKernelState, result error) {
	state := nativeInactiveKernelState{LegacyTables: map[string]string{}}
	if err := ctx.Err(); err != nil {
		return state, err
	}
	proc, err := os.OpenRoot("/proc")
	if err != nil {
		return state, err
	}
	defer func() { result = errors.Join(result, proc.Close()) }()
	file, err := proc.Open(".")
	if err != nil {
		return state, err
	}
	defer func() { result = errors.Join(result, file.Close()) }()
	var filesystem unix.Statfs_t
	if err := unix.Fstatfs(int(file.Fd()), &filesystem); err != nil || filesystem.Type != unix.PROC_SUPER_MAGIC {
		return state, errors.New("inactive native observation requires real procfs")
	}
	// This fixed kernel magic link is followed intentionally while the goroutine
	// is pinned to its OS thread. No namespace is entered or changed.
	network, err := os.Open("/proc/thread-self/ns/net")
	if err != nil {
		return state, err
	}
	defer func() { result = errors.Join(result, network.Close()) }()
	info, err := network.Stat()
	if err != nil {
		return state, err
	}
	identity, ok := info.Sys().(*syscall.Stat_t)
	if !ok || identity.Ino == 0 {
		return state, errors.New("inactive native network namespace identity unavailable")
	}
	state.NetworkDevice, state.NetworkInode = identity.Dev, identity.Ino
	boot, err := readBoundedFirewallRemovalProcFile(proc, "sys/kernel/random/boot_id", 64)
	if err != nil || len(boot) != 37 || boot[36] != '\n' {
		return state, errors.New("inactive native boot identity unavailable")
	}
	state.Boot = string(boot[:36])
	for i, c := range state.Boot {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return state, errors.New("invalid inactive native boot identity")
			}
		} else if !strings.ContainsRune("0123456789abcdef", c) {
			return state, errors.New("invalid inactive native boot identity")
		}
	}
	for _, name := range []string{"ip_tables_names", "ip6_tables_names", "arp_tables_names", "eb_tables_names"} {
		raw, err := readBoundedFirewallRemovalProcFile(proc, "thread-self/net/"+name, 4096)
		if errors.Is(err, os.ErrNotExist) {
			state.LegacyTables[name] = "absent"
			continue
		}
		if err != nil {
			return state, err
		}
		if len(strings.TrimSpace(string(raw))) != 0 {
			return state, errors.New("legacy firewall tables require a separate preservation path")
		}
		state.LegacyTables[name] = "empty"
	}
	// Refuse loaded ipset support rather than interpreting a missing procfs
	// listing as proof that no legacy set exists, or loading modules to inspect it.
	sys, err := os.OpenRoot("/sys")
	if err != nil {
		return state, err
	}
	defer func() { result = errors.Join(result, sys.Close()) }()
	sysFile, err := sys.Open(".")
	if err != nil {
		return state, err
	}
	defer func() { result = errors.Join(result, sysFile.Close()) }()
	if err := unix.Fstatfs(int(sysFile.Fd()), &filesystem); err != nil || filesystem.Type != unix.SYSFS_MAGIC {
		return state, errors.New("inactive native observation requires real sysfs")
	}
	if _, err := sys.Lstat("module/ip_set"); !errors.Is(err, os.ErrNotExist) {
		return state, errors.New("legacy ipset support requires separate native preservation qualification")
	}
	current, err := os.Stat("/proc/thread-self/ns/net")
	if err != nil || !os.SameFile(info, current) {
		return state, errors.New("inactive native network namespace changed")
	}
	// Confirm procfs remains named by the same directory before accepting absence.
	named, err := os.Lstat("/proc")
	opened, statErr := file.Stat()
	if err != nil || statErr != nil || !os.SameFile(named, opened) {
		return state, errors.New("inactive native procfs changed")
	}
	return state, ctx.Err()
}
