//go:build linux

package system

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"syscall"
)

const apkTransitionGateName = "syswarden-transition-v1"
const apkTransitionGateDirectory = "etc/apk/commit_hooks.d"
const apkRecoveryHookSHA256 = "c38eb138669360b3d664cc97c390ef5852964be64bc55991b5f664e586084522"

// This inventory is included in the execution proposal before approval. Neither
// a familiar filename nor an executable hook grants transaction authority.
type apkNativeHookProposal struct {
	Entries []apkTransitionHostEntry `json:"entries"`
}

func captureAPKNativeHooks(ctx context.Context, host string) (_ *apkNativeHookProposal, result error) {
	if ctx == nil || !filepath.IsAbs(host) || filepath.Clean(host) != host {
		return nil, errors.New("APK hook capture requires a context and canonical host root")
	}
	return captureAPKNativeHooksWithGate(ctx, host, nil)
}

func captureAPKNativeHooksWithGate(ctx context.Context, host string, gate *apkTransitionHostEntry) (*apkNativeHookProposal, error) {
	return captureAPKNativeHooksWithTerminalQuarantine(ctx, host, gate, nil)
}

// Ordinary capture always passes nil. Only the independently reconstructed
// terminal authority supplies its exact already-recorded moved gate observation.
func captureAPKNativeHooksWithTerminalQuarantine(ctx context.Context, host string, gate *apkTransitionHostEntry, quarantine *apkTerminalGateQuarantine) (_ *apkNativeHookProposal, result error) {
	if quarantine != nil && (gate != nil || quarantine.host != host) {
		return nil, errors.New("APK terminal quarantine observation conflicts with hook capture")
	}
	quarantineSeen := false
	if ctx == nil {
		return nil, errors.New("APK hook context is unavailable")
	}
	root, err := os.OpenRoot(host)
	if err != nil {
		return nil, err
	}
	defer func() { result = errors.Join(result, root.Close()) }()
	proposal := &apkNativeHookProposal{}
	for _, path := range []string{".", "etc", "etc/apk", "lib", "lib/apk", apkTransitionGateDirectory, "lib/apk/commit_hooks.d"} {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		info, err := root.Lstat(path)
		optional := path == apkTransitionGateDirectory || path == "lib/apk/commit_hooks.d"
		if optional && errors.Is(err, os.ErrNotExist) {
			proposal.Entries = append(proposal.Entries, apkTransitionHostEntry{Path: path, Absent: true})
			continue
		}
		if err != nil {
			return nil, err
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.IsDir() || info.Mode().Perm()&0022 != 0 || int64(st.Uid) != int64(os.Geteuid()) || int64(st.Gid) != int64(os.Getegid()) {
			return nil, errors.New("APK hook ancestry is not a protected real directory")
		}
		proposal.Entries = append(proposal.Entries, apkTransitionHostEntry{Path: path, Identity: apkTransitionStat(st)})
		if !optional {
			continue
		}
		dir, err := root.Open(path)
		if err != nil {
			return nil, err
		}
		names, readErr := dir.Readdirnames(4)
		closeErr := dir.Close()
		if readErr != nil && !errors.Is(readErr, io.EOF) || closeErr != nil || len(names) > 2 {
			return nil, errors.New("APK commit hooks require a bounded recognized inventory")
		}
		for _, name := range names {
			if path == apkTransitionGateDirectory && quarantine != nil && name == quarantine.entry.Path {
				if err := quarantine.requireNamedAbsence(root); err != nil {
					return nil, err
				}
				observed, err := readAPKNativeHook(root, filepath.Join(path, name))
				if err != nil {
					return nil, err
				}
				actualPath := observed.Path
				observed.Path = name
				if !reflect.DeepEqual(observed, quarantine.entry) {
					return nil, errors.New("APK terminal gate quarantine changed during inventory capture")
				}
				observed.Path = actualPath
				proposal.Entries = append(proposal.Entries, observed)
				quarantineSeen = true
				continue
			}
			if path == apkTransitionGateDirectory && name == apkTransitionGateName && gate != nil {
				observed, err := readAPKNativeHook(root, filepath.Join(path, name))
				if err != nil {
					return nil, err
				}
				observed.Path = gate.Path
				if !reflect.DeepEqual(observed, *gate) {
					return nil, errors.New("APK transition gate identity changed")
				}
				proposal.Entries = append(proposal.Entries, observed)
				continue
			}
			if path != apkTransitionGateDirectory || name != "syswarden-recovery" {
				return nil, errors.New("APK commit hook is unknown or an unresolved transition already exists")
			}
			hook, err := readAPKNativeHook(root, filepath.Join(path, name))
			if err != nil {
				return nil, err
			}
			if apkTransitionDigest(hook.Content) != apkRecoveryHookSHA256 && apkTransitionDigest(hook.Content) != APKRecoveryHookSHA256() {
				return nil, errors.New("installed APK recovery hook is not an independently recognized implementation")
			}
			proposal.Entries = append(proposal.Entries, hook)
		}
		after, err := root.Lstat(path)
		if err != nil || apkTransitionStat(after.Sys().(*syscall.Stat_t)) != apkTransitionStat(st) {
			return nil, errors.New("APK hook directory changed during capture")
		}
	}
	if quarantine != nil {
		if !quarantineSeen {
			return nil, errors.New("APK terminal gate quarantine disappeared during inventory capture")
		}
		if err := quarantine.requireNamedAbsence(root); err != nil {
			return nil, err
		}
	}
	sort.Slice(proposal.Entries, func(i, j int) bool { return proposal.Entries[i].Path < proposal.Entries[j].Path })
	return proposal, ctx.Err()
}

func readAPKNativeHook(root *os.Root, path string) (apkTransitionHostEntry, error) {
	return readAPKNativeHookMode(root, path, 0755)
}

func readAPKNativeHookMode(root *os.Root, path string, mode os.FileMode) (apkTransitionHostEntry, error) {
	var empty apkTransitionHostEntry
	file, err := root.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return empty, err
	}
	before, statErr := file.Stat()
	if statErr != nil {
		_ = file.Close()
		return empty, statErr
	}
	st, ok := before.Sys().(*syscall.Stat_t)
	if !ok || !before.Mode().IsRegular() || before.Mode().Perm() != mode || st.Nlink != 1 || st.Size <= 0 || st.Size > 8192 || int64(st.Uid) != int64(os.Geteuid()) || int64(st.Gid) != int64(os.Getegid()) {
		_ = file.Close()
		return empty, errors.New("APK hook metadata is not protected")
	}
	data, readErr := io.ReadAll(io.LimitReader(file, 8193))
	after, afterErr := file.Stat()
	closeErr := file.Close()
	named, nameErr := root.Lstat(path)
	if readErr != nil || afterErr != nil || closeErr != nil || nameErr != nil || int64(len(data)) != st.Size || apkTransitionStat(after.Sys().(*syscall.Stat_t)) != apkTransitionStat(st) || apkTransitionStat(named.Sys().(*syscall.Stat_t)) != apkTransitionStat(st) {
		return empty, errors.New("APK hook changed during bounded capture")
	}
	return apkTransitionHostEntry{Path: path, Identity: apkTransitionStat(st), Content: data}, nil
}

func revalidateAPKNativeHookProposal(ctx context.Context, host string, want *apkNativeHookProposal) error {
	got, err := captureAPKNativeHooks(ctx, host)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(got, want) {
		return errors.New("APK commit hook inventory changed after execution review")
	}
	return nil
}
