//go:build linux

package firewall

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"reflect"
	"sort"
	"strings"
)

type nftOpenRCObservation struct {
	profile   map[string]string
	configs   []string
	runtime   nftOpenRCRuntime
	processes nftOpenRCProcessObserver
}

type nftOpenRCProcessObserver func(nftPersistenceFilesystem) (nftPersistenceRead, error)

var nftOpenRCAbsentPaths = []string{
	"/var/cache/rc/openrc-run.sh", "/sbin/livecd-functions.sh", "/usr/local/etc/init.d/nftables", "/etc/profile.env", "/etc/conf.d/rc",
	"/bin/nft", "/sbin/nft", "/usr/bin/nft",
	"/usr/libexec/rc/sbin/nft", "/usr/libexec/rc/bin/nft",
	"/usr/local/sbin/nft", "/usr/local/bin/nft",
}

func checkNFTOpenRCImports(host nftPersistenceFilesystem) ([]string, error) {
	for _, path := range nftOpenRCAbsentPaths {
		// Use Lstat on the pinned parent so dangling links also refuse.
		if err := requireNFTOpenRCPathAbsent(host, path); err != nil {
			return nil, err
		}
	}
	for _, pattern := range []string{"/etc/conf.d/nftables.*", "/etc/rc.conf.d/.*", "/usr/lib/rc/plugins/*", "/usr/libexec/rc/plugins/*", "/usr/lib/rc/plugins/.*", "/usr/libexec/rc/plugins/.*"} {
		paths, err := host.expand(pattern)
		if err != nil || len(paths) != 0 {
			return nil, fmt.Errorf("OpenRC nftables observation refuses alternate runlevel configuration or plugins: %s", pattern)
		}
	}
	return host.expand("/etc/rc.conf.d/*.conf")
}

func requireNFTOpenRCPathAbsent(host nftPersistenceFilesystem, path string) error {
	if _, err := host.snapshot(path); !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("OpenRC nftables observation requires an absent optional override: %s", path)
	}
	return nil
}

func captureNFTOpenRCLoader(ctx context.Context, host nftPersistenceFilesystem, profiles []map[string]string, processes nftOpenRCProcessObserver) (*nftPersistenceLoaderInspection, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	configs, err := checkNFTOpenRCImports(host)
	if err != nil {
		return nil, err
	}
	inspection := &nftPersistenceLoaderInspection{host: host, files: make(map[string]nftPersistenceRead), xattrs: make(map[string]string)}
	if len(profiles) == 0 {
		return nil, fmt.Errorf("OpenRC nftables observation lacks a reviewed definition profile")
	}
	paths := []string{"/etc/alpine-release", "/usr/sbin/nft", "/etc/rc.conf", "/etc/conf.d/nftables"}
	paths = append(paths, configs...)
	for path := range profiles[0] {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	var evidence []nftPersistenceGraphSourceRecord
	for _, path := range paths {
		if _, duplicate := inspection.files[path]; duplicate {
			return nil, fmt.Errorf("OpenRC nftables definition has duplicate sources")
		}
		snapshot, attrs, err := snapshotNFTPersistenceMetadata(host, path)
		if err != nil {
			return nil, err
		}
		if (path == "/sbin/openrc-run" || path == "/usr/sbin/nft" || path == "/etc/init.d/nftables") && snapshot.identity.Mode().Perm()&0111 == 0 {
			return nil, fmt.Errorf("OpenRC nftables loader executable is not executable")
		}
		bound, err := bindNFTPersistenceGraphSource(path, snapshot, attrs, snapshot.content)
		if err != nil {
			return nil, err
		}
		evidence = append(evidence, bound)
		inspection.files[path], inspection.xattrs[path] = snapshot, bound.Xattrs
	}
	var matched map[string]string
	for _, profile := range profiles {
		valid := len(profile) == len(profiles[0])
		for path, digest := range profile {
			snapshot, exists := inspection.files[path]
			valid = valid && exists && nftSHA256Hex(snapshot.content) == digest
		}
		if valid {
			matched = profile
			break
		}
	}
	if matched == nil {
		return nil, fmt.Errorf("OpenRC nftables executable or shell definitions differ from the reviewed Alpine profiles; preserve them for separate recovery")
	}
	release := strings.TrimSuffix(string(inspection.files["/etc/alpine-release"].content), "\n")
	if !strings.HasPrefix(release, "3.22.") && !strings.HasPrefix(release, "3.24.") || len(release) > 32 || strings.ContainsAny(release, "\n\r\x00 ") {
		return nil, fmt.Errorf("OpenRC nftables observation requires a supported Alpine release")
	}
	configPaths := append([]string{"/etc/rc.conf"}, configs...)
	configPaths = append(configPaths, "/etc/conf.d/nftables")
	values := make(map[string]string)
	for _, path := range configPaths {
		if err := parseNFTOpenRCConfig(inspection.files[path].content, values); err != nil {
			return nil, err
		}
	}
	runtime, err := captureNFTOpenRCRuntime(host, processes)
	if err != nil {
		return nil, err
	}
	inspection.status = nftPersistenceLoaderStatus{values: values, entries: []string{nftOpenRCRulesFile(values)}, binary: "/usr/sbin/nft", fragments: []string{"/etc/init.d/nftables"}}
	inspection.resolvedBinary = inspection.status.binary
	inspection.manager = inspection.files["/sbin/openrc-run"]
	inspection.openrc = &nftOpenRCObservation{matched, configs, runtime, processes}
	content, err := json.Marshal(struct {
		Schema  string                            `json:"schema"`
		Values  map[string]string                 `json:"values"`
		Files   []nftPersistenceGraphSourceRecord `json:"files"`
		Configs []string                          `json:"configs"`
	}{"syswarden-nftables-openrc-observation-v1", values, evidence, configs})
	if err != nil {
		return nil, err
	}
	inspection.digest = nftSHA256Hex(content)
	return inspection, nil
}

func inspectNFTOpenRCLoader(ctx context.Context, host nftPersistenceFilesystem, profiles []map[string]string) (*nftPersistenceLoaderInspection, error) {
	return inspectNFTOpenRCLoaderUsing(ctx, host, profiles, captureNFTOpenRCProcesses)
}

func inspectNFTOpenRCLoaderUsing(ctx context.Context, host nftPersistenceFilesystem, profiles []map[string]string, processes nftOpenRCProcessObserver) (*nftPersistenceLoaderInspection, error) {
	inspection, err := captureNFTOpenRCLoader(ctx, host, profiles, processes)
	if err != nil {
		return nil, err
	}
	return inspection, inspection.verifyOpenRC(ctx)
}

func (inspection *nftPersistenceLoaderInspection) verifyOpenRC(ctx context.Context) error {
	if inspection == nil || inspection.openrc == nil {
		return fmt.Errorf("OpenRC nftables observation is incomplete")
	}
	next, err := captureNFTOpenRCLoader(ctx, inspection.host, []map[string]string{inspection.openrc.profile}, inspection.openrc.processes)
	if err != nil {
		return err
	}
	if next.digest != inspection.digest || !reflect.DeepEqual(next.status, inspection.status) ||
		!sameNFTOpenRCRuntime(inspection.openrc.runtime, next.openrc.runtime) {
		return fmt.Errorf("OpenRC nftables loader configuration or runtime changed after observation")
	}
	for path, expected := range inspection.files {
		if !sameLegacyFail2banSource(expected, next.files[path]) || inspection.xattrs[path] != next.xattrs[path] {
			return fmt.Errorf("OpenRC nftables evidence identity changed after observation")
		}
	}
	return nil
}
