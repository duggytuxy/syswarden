//go:build linux

package firewall

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"reflect"
	"slices"
	"sort"
	"syswarden-cli/pkg/cronstate"
	"syswarden-cli/pkg/system"
)

type nftRemovalProducerInspection struct {
	entries []string
	absent  []string
	digest  string
	verify  func(context.Context) error
}

// Runtime timestamps are verified within one operation, but are not persisted
// as producer identity. A reboot can change them without changing an attested
// loader executable, configuration, entry point or quiescent product state.
func nftRemovalLoaderDigest(inspection *nftPersistenceLoaderInspection, entries, absent []string) (string, error) {
	if inspection == nil || len(inspection.files) < 3 || len(inspection.status.entries) == 0 {
		return "", fmt.Errorf("removal producer inspection lacks its loader evidence")
	}
	binary, alias, err := resolveNFTPersistenceLoaderBinary(inspection.host, inspection.status.binary)
	if err != nil || binary != inspection.resolvedBinary || !reflect.DeepEqual(alias, inspection.alias) {
		return "", fmt.Errorf("removal loader executable alias changed before binding")
	}
	paths := make([]string, 0, len(inspection.files))
	for path := range inspection.files {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	var files []nftPersistenceGraphSourceRecord
	for _, path := range paths {
		snapshot, attrs, err := snapshotNFTPersistenceMetadata(inspection.host, path)
		if err != nil || !sameLegacyFail2banSource(inspection.files[path], snapshot) || nftPersistenceXattrDigest(attrs) != inspection.xattrs[path] {
			return "", fmt.Errorf("removal loader evidence changed before binding")
		}
		bound, err := bindNFTPersistenceGraphSource(path, snapshot, attrs, snapshot.content)
		if err != nil {
			return "", err
		}
		files = append(files, bound)
	}
	content, err := json.Marshal(struct {
		Schema        string                            `json:"schema"`
		Binary        string                            `json:"binary"`
		LoaderEntries []string                          `json:"loader_entries"`
		Entries       []string                          `json:"all_entries"`
		Absent        []string                          `json:"absent_entries"`
		Files         []nftPersistenceGraphSourceRecord `json:"loader_files"`
		Alias         *nftPersistenceLoaderAlias        `json:"executable_alias,omitempty"`
	}{"syswarden-removal-producers-v1", inspection.status.binary, inspection.status.entries, entries, absent, files, inspection.alias})
	if err != nil {
		return "", err
	}
	return nftSHA256Hex(content), nil
}

func attestNFTRemovalProductProducers() error {
	if err := system.RequireRemovalTombstone(); err != nil {
		return err
	}
	if err := system.ReattestFirewallStatePreparedForRemoval(); err != nil {
		return err
	}
	if err := system.PreflightHistoricalHostRemoval(); err != nil {
		return err
	}
	if err := PreflightHistoricalFail2banRemoval(); err != nil {
		return err
	}
	options := cronstate.DefaultOptions(system.ReadOnlyRootCrontabEvidence)
	options.AttestCronDProvider = system.AttestRuntimeCronDProvider
	state, err := cronstate.Inspect(options)
	if err != nil {
		return fmt.Errorf("inspect retired firewall schedules: %w", err)
	}
	if state.OwnedFeed || state.OwnedHA || state.LegacyFeedCount != 0 || state.LegacyHACount != 0 {
		return fmt.Errorf("firewall scheduling producers remain active or persistent")
	}
	return system.RequireRemovalTombstone()
}

func inspectNFTRemovalProducers(ctx context.Context, host nftPersistenceFilesystem) (nftRemovalProducerInspection, error) {
	return inspectNFTRemovalProducersUsing(ctx, host, inspectNFTPersistenceLoader, attestNFTRemovalProductProducers)
}

// The production dependencies observe the actual service manager and the
// stopped product services, processes, historical integrations and schedules.
// Shared nftables is only observed, never stopped, restarted or disabled.
func inspectNFTRemovalProducersUsing(ctx context.Context, host nftPersistenceFilesystem,
	inspect func(context.Context, nftPersistenceFilesystem) (*nftPersistenceLoaderInspection, error), productGuard func() error,
) (nftRemovalProducerInspection, error) {
	var empty nftRemovalProducerInspection
	if inspect == nil || productGuard == nil {
		return empty, fmt.Errorf("removal requires complete producer inspection")
	}
	if err := productGuard(); err != nil {
		return empty, err
	}
	loader, err := inspect(ctx, host)
	if err != nil {
		return empty, err
	}
	if loader == nil {
		return empty, fmt.Errorf("removal loader inspection is missing")
	}
	entries := append([]string(nil), loader.status.entries...)
	var absent []string
	for _, path := range knownNFTPersistenceEntryPoints {
		_, err := host.snapshot(path)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			absent = append(absent, path)
		case err != nil:
			return empty, err
		default:
			if !slices.Contains(entries, path) {
				entries = append(entries, path)
			}
		}
	}
	sort.Strings(entries)
	sort.Strings(absent)
	if slices.Contains(entries, legacyNFTIncludePath) {
		return empty, fmt.Errorf("shared nftables loader directly consumes the product source; preserve it for bounded recovery")
	}
	digest, err := nftRemovalLoaderDigest(loader, entries, absent)
	if err != nil {
		return empty, err
	}
	inspection := nftRemovalProducerInspection{entries: entries, absent: absent, digest: digest}
	inspection.verify = func(ctx context.Context) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := productGuard(); err != nil {
			return err
		}
		if err := loader.verify(ctx); err != nil {
			return err
		}
		for _, path := range absent {
			if _, err := host.snapshot(path); !errors.Is(err, fs.ErrNotExist) {
				return fmt.Errorf("a previously absent firewall entry point appeared or became unsafe")
			}
		}
		return nil
	}
	return inspection, inspection.verify(ctx)
}
