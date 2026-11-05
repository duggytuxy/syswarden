//go:build linux

package system

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
)

// Only independent terminal reconstruction can mint this observation. It does
// not authorize deletion, native replay, restoration or a pretransaction hook.
type apkTerminalGateQuarantine struct {
	host  string
	entry apkTransitionHostEntry
}

func (authority *apkTerminalAuthority) inspectGateQuarantine(ctx context.Context) (_ *apkTerminalGateQuarantine, result error) {
	if ctx == nil || authority == nil || authority.closed || authority.database == nil || !authority.database.held || authority.prepared == nil {
		return nil, errors.New("APK terminal quarantine requires retained terminal authority")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	intended, err := authority.retirementBytes()
	if err != nil {
		return nil, err
	}
	retain := func(name string, limit int64) ([]byte, error) {
		raw, err := readAPKTransitionBytes(authority.directory, name, limit)
		if err != nil {
			return nil, err
		}
		if previous, exists := authority.records[name]; exists && !bytes.Equal(previous, raw) {
			return nil, errors.New("APK terminal quarantine evidence changed")
		}
		authority.records[name] = bytes.Clone(raw)
		return raw, nil
	}
	for _, name := range []string{"terminal-finalizing.json", "terminal-retirement-intent.json"} {
		raw, err := retain(name, 4096)
		if err != nil || !bytes.Equal(raw, intended) {
			return nil, errors.Join(errors.New("APK terminal quarantine lacks exact finalization intent"), err)
		}
	}
	raw, err := retain("terminal-retire-gate.json", 16384)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var record apkTerminalGateRetirement
	if decodeAPKTransitionJSON(raw, &record) != nil || record.Schema != apkExecutionSchema || record.Name != apkTransitionGateName || !reflect.DeepEqual(record.Original, authority.handoff.Hook) || !safeAssetName(record.Quarantine) || !strings.HasPrefix(record.Quarantine, ".syswarden-apk-retired-") || len(record.Quarantine) != len(".syswarden-apk-retired-")+32 {
		return nil, errors.New("APK terminal gate quarantine intent is inconsistent")
	}
	approvedParent := false
	if authority.plan.NativeHooks != nil {
		for _, parent := range authority.plan.NativeHooks.Entries {
			if parent.Path == apkTransitionGateDirectory && !parent.Absent && len(parent.Content) == 0 && apkLauncherSameParent(parent.Identity, record.Parent) {
				approvedParent = true
			}
		}
	}
	if !approvedParent {
		return nil, errors.New("APK terminal quarantine ancestry differs from execution approval")
	}
	path := filepath.Join(authority.host, apkTransitionGateDirectory)
	directory, err := openExistingPinnedServiceDirectory(path)
	if err != nil {
		return nil, err
	}
	defer func() { result = errors.Join(result, closeAPKExecutionDirectory(directory)) }()
	info, err := directory.file.Stat()
	identity, identityErr := apkLauncherIdentity(info)
	if err != nil || identityErr != nil || !apkLauncherSameParent(record.Parent, identity) {
		return nil, errors.New("APK terminal quarantine parent changed")
	}
	if err := attestRetainedDirectoryParent(path, directory, false); err != nil {
		return nil, err
	}
	observed, err := readAPKNativeHook(directory.root, record.Quarantine)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if _, err := directory.root.Lstat(apkTransitionGateName); !errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("APK terminal quarantine conflicts with a live named gate")
	}
	if observed.Absent || observed.LinkTarget != "" || !sameAPKLauncherMovedIdentity(record.Original.Identity, observed.Identity) || !bytes.Equal(observed.Content, record.Original.Content) {
		return nil, errors.New("APK terminal quarantine is not the exact moved gate")
	}
	if err := errors.Join(ctx.Err(), attestRetainedDirectoryParent(path, directory, false)); err != nil {
		return nil, err
	}
	return &apkTerminalGateQuarantine{host: authority.host, entry: observed}, nil
}

func (quarantine *apkTerminalGateQuarantine) requireNamedAbsence(root *os.Root) error {
	if quarantine == nil || quarantine.entry.Path == "" {
		return errors.New("APK terminal quarantine observation is unavailable")
	}
	if _, err := root.Lstat(filepath.Join(apkTransitionGateDirectory, apkTransitionGateName)); !errors.Is(err, os.ErrNotExist) {
		return errors.New("APK terminal gate name reappeared beside its recorded quarantine")
	}
	return nil
}
