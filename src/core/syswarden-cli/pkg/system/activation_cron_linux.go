//go:build linux

package system

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"golang.org/x/sys/unix"
	"syswarden-cli/pkg/cronstate"
)

type activationCronDirectory struct {
	Path     string
	Identity LegacyLogRetentionIdentity
}

type activationRootCron struct {
	Directories []activationCronDirectory
	Present     bool
	File        LegacyLogRetentionFile
	content     []byte
}

func activationCronSpoolForProvider(provider CronDProviderEvidence) (string, error) {
	if spool, err := legacyCronSpoolForProvider(provider); err == nil {
		return spool, nil
	}
	// Upstream Cronie RPM packaging creates /var/spool/cron with mode 0700
	// and installs crond.service. This mapping does not authorize retirement.
	// https://github.com/cronie-crond/cronie/blob/master/cronie.spec
	if provider.Mode == CronDProviderRuntime && provider.Manager == "systemd" &&
		provider.Unit == "crond.service" && provider.Daemon == "/usr/sbin/crond" &&
		provider.Fragment == "/usr/lib/systemd/system/crond.service" &&
		strings.Join(provider.Packages, ",") == "cronie" {
		return "/var/spool/cron", nil
	}
	return "", fmt.Errorf("activation root crontab requires a verified supported runtime provider")
}

// The production trust anchor is /. Tests supply an existing private root.
// Every component is opened without following links. Only the final Debian
// spool may be group-writable; root-owned private crontab files remain required.
func activationCronDirectoryEvidence(rootPath, spool string, uid uint32) ([]activationCronDirectory, error) {
	if !filepath.IsAbs(rootPath) || filepath.Clean(rootPath) != rootPath || !filepath.IsAbs(spool) || filepath.Clean(spool) != spool {
		return nil, fmt.Errorf("activation cron paths must be clean and absolute")
	}
	fd, err := unix.Open(rootPath, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = unix.Close(fd) }()
	components := append([]string{""}, strings.Split(strings.TrimPrefix(spool, "/"), "/")...)
	var evidence []activationCronDirectory
	path := "/"
	for index, component := range components {
		if component != "" {
			next, err := unix.Openat(fd, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			if err != nil {
				return nil, fmt.Errorf("open activation cron ancestry %s: %w", component, err)
			}
			_ = unix.Close(fd)
			fd = next
			path = filepath.Join(path, component)
		}
		var stat unix.Stat_t
		if err := unix.Fstat(fd, &stat); err != nil {
			return nil, err
		}
		allowedGroupWrite := spool == legacyCronSpool && index == len(components)-1
		if stat.Uid != uid || stat.Mode&0002 != 0 || (!allowedGroupWrite && stat.Mode&0020 != 0) {
			return nil, fmt.Errorf("activation cron ancestry %s has unsafe ownership or permissions", path)
		}
		evidence = append(evidence, activationCronDirectory{path, LegacyLogRetentionIdentity{Device: uint64(stat.Dev), Inode: stat.Ino, Mode: stat.Mode, UID: stat.Uid, GID: stat.Gid}})
	}
	return evidence, nil
}

func readActivationRootCron(rootPath, spool string, uid uint32) (activationRootCron, error) {
	var snapshot activationRootCron
	before, err := activationCronDirectoryEvidence(rootPath, spool, uid)
	if err != nil {
		return snapshot, err
	}
	directory, err := openPinnedSharedRemovalParent(filepath.Join(rootPath, spool), uid)
	if err != nil {
		return snapshot, err
	}
	defer directory.close()
	info, err := directory.file.Stat()
	identity, identityErr := exactRemovalArtifactIdentity(info)
	if err != nil || identityErr != nil || legacyLogPlanIdentity(identity) != before[len(before)-1].Identity {
		return snapshot, fmt.Errorf("activation cron spool changed while pinning")
	}
	file, content, err := readLegacyCronFile(directory, "root", uid)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return snapshot, err
	}
	snapshot.Present = err == nil
	if snapshot.Present {
		snapshot.File = LegacyLogRetentionFile{Path: spool + "/root", Identity: legacyLogPlanIdentity(file), Size: file.size, Modified: file.mtime, Changed: file.ctime, SHA256: fmt.Sprintf("%x", sha256.Sum256(content))}
		snapshot.content = content
	}
	after, err := activationCronDirectoryEvidence(rootPath, spool, uid)
	if err != nil {
		return activationRootCron{}, err
	}
	if !reflect.DeepEqual(before, after) {
		return activationRootCron{}, fmt.Errorf("activation cron spool ancestry changed during inspection")
	}
	snapshot.Directories = after
	return snapshot, nil
}

// preflightActivationCron reads crontab evidence without commands or writes.
// The provider callback independently revalidates captured provider evidence:
// fixed bounded read-only native queries are allowed for systemd; OpenRC uses
// no commands. Neither callback may mutate state. Missing or unsafe spool
// directories are errors; only an absent root file means no root crontab.
func preflightActivationCron(ctx context.Context, provider CronDProviderEvidence, ha bool, revalidateProvider func() error) (cronstate.Inspection, string, error) {
	return preflightActivationCronAt(ctx, provider, ha, revalidateProvider, "/", 0, 0)
}

func preflightActivationCronAt(ctx context.Context, provider CronDProviderEvidence, ha bool, revalidateProvider func() error, rootPath string, uid, gid uint32) (cronstate.Inspection, string, error) {
	if ctx == nil || revalidateProvider == nil {
		return cronstate.Inspection{}, "", fmt.Errorf("activation cron context and provider revalidation are required")
	}
	if err := ctx.Err(); err != nil {
		return cronstate.Inspection{}, "", err
	}
	spool, err := activationCronSpoolForProvider(provider)
	if err != nil {
		return cronstate.Inspection{}, "", err
	}
	if err := revalidateProvider(); err != nil {
		return cronstate.Inspection{}, "", err
	}
	before, err := readActivationRootCron(rootPath, spool, uid)
	if err != nil {
		return cronstate.Inspection{}, "", err
	}
	read := func() (string, bool, error) {
		if err := ctx.Err(); err != nil {
			return "", false, err
		}
		current, err := readActivationRootCron(rootPath, spool, uid)
		if err != nil {
			return "", false, err
		}
		if !reflect.DeepEqual(before.Directories, current.Directories) || before.Present != current.Present || before.File != current.File || !bytes.Equal(before.content, current.content) {
			return "", false, fmt.Errorf("activation root crontab evidence changed")
		}
		return string(current.content), current.Present, nil
	}
	options := cronstate.DefaultOptions(read)
	options.RootPath = rootPath
	options.DirectoryOwnerUID, options.FileOwnerUID = int(uid), int(uid)
	options.DirectoryOwnerGID, options.FileOwnerGID = int(gid), int(gid)
	options.AttestCronDProvider = func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return revalidateProvider()
	}
	inspection, ownedDigest, err := cronstate.PreflightForActivation(options, ha)
	if err != nil {
		return cronstate.Inspection{}, "", err
	}
	if _, _, err := read(); err != nil {
		return cronstate.Inspection{}, "", err
	}
	if err := options.AttestCronDProvider(); err != nil {
		return cronstate.Inspection{}, "", err
	}
	wire, err := json.Marshal(struct {
		Schema      string
		Provider    CronDProviderEvidence
		RootCron    activationRootCron
		OwnedSHA256 string
	}{"syswarden-activation-cron-v1", provider, before, ownedDigest})
	if err != nil {
		return cronstate.Inspection{}, "", err
	}
	return inspection, fmt.Sprintf("%x", sha256.Sum256(wire)), nil
}
