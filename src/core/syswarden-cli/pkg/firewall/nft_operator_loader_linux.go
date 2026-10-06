//go:build linux

package firewall

import (
	"context"
	"fmt"
	"strings"
)

const nftOperatorBootProperties = "Id,LoadState,ActiveState,SubState,UnitFileState,NeedDaemonReload"

// Stable enablement is separate from the existing loader observation schema.
// Extending that schema would change old canonical retirement journal digests.
func verifyNFTOperatorBootProperties(content []byte) error {
	expected := map[string]string{"Id": "nftables.service", "LoadState": "loaded", "ActiveState": "active", "SubState": "exited", "UnitFileState": "enabled", "NeedDaemonReload": "no"}
	if len(content) == 0 || len(content) > 4096 || content[len(content)-1] != '\n' || strings.ContainsAny(string(content), "\x00\r") {
		return fmt.Errorf("operator receiver lacks an enabled active boot loader")
	}
	for _, line := range strings.Split(strings.TrimSuffix(string(content), "\n"), "\n") {
		key, value, found := strings.Cut(line, "=")
		wanted, present := expected[key]
		if !found || !present || value != wanted {
			return fmt.Errorf("operator receiver boot loader is disabled, changing or unsupported")
		}
		delete(expected, key)
	}
	if len(expected) != 0 {
		return fmt.Errorf("operator receiver boot-loader observation is incomplete")
	}
	return nil
}

type nftOperatorBootLoader struct {
	loader *nftPersistenceLoaderInspection
	digest string
}

func inspectNFTOperatorBootLoader(ctx context.Context, host nftPersistenceFilesystem) (*nftOperatorBootLoader, error) {
	loader, err := inspectNFTPersistenceLoader(ctx, host)
	if err != nil {
		return nil, err
	}
	digest, err := nftRemovalLoaderDigest(loader, loader.status.entries, nil)
	if err != nil {
		return nil, err
	}
	result := &nftOperatorBootLoader{loader, digest}
	return result, result.verify(ctx)
}

func (inspection *nftOperatorBootLoader) verify(ctx context.Context) error {
	if inspection == nil || inspection.loader == nil || !validLegacyRetirementDigest(inspection.digest) {
		return fmt.Errorf("operator boot loader inspection is missing")
	}
	if err := inspection.loader.verify(ctx); err != nil {
		return err
	}
	observed, err := queryNFTPersistenceLoaderProperties(ctx, inspection.loader.host, inspection.loader.manager, nftOperatorBootProperties)
	if err != nil {
		return err
	}
	if err := verifyNFTOperatorBootProperties(observed); err != nil {
		return err
	}
	return inspection.loader.verify(ctx)
}
