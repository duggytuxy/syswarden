//go:build linux

package system

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
)

type historicalRemovalServiceTemplate struct {
	content string
	length  int
	sha256  string
}

func historicalSystemdCoreRemovalTemplates() []historicalRemovalServiceTemplate {
	return []historicalRemovalServiceTemplate{
		{historicalV4028SystemdCoreService, historicalV4028SystemdCoreServiceLength, historicalV4028SystemdCoreServiceSHA256},
		{historicalV4043SystemdCoreService, historicalV4043SystemdCoreServiceLength, historicalV4043SystemdCoreServiceSHA256},
	}
}

func historicalSystemdFirewallRemovalTemplates() []historicalRemovalServiceTemplate {
	return []historicalRemovalServiceTemplate{
		{historicalV4028SystemdFirewallService, historicalV4028SystemdFirewallServiceLength, historicalV4028SystemdFirewallServiceSHA256},
	}
}

// Selection is read-only and grants no authority to start or rewrite a service.
// Removal callers retain their independent directory, loaded-unit, process,
// enablement, race and exact-content checks before stopping or deleting it.
func selectExactSystemdRemovalContent(
	path string,
	current string,
	historical []historicalRemovalServiceTemplate,
	expectedUID uint32,
	expectedGID uint32,
) (string, error) {
	if current == "" {
		return "", fmt.Errorf("current systemd removal template is empty")
	}
	for _, template := range historical {
		digest := sha256.Sum256([]byte(template.content))
		if template.length <= 0 || len(template.content) != template.length ||
			hex.EncodeToString(digest[:]) != template.sha256 {
			return "", fmt.Errorf("historical systemd removal template anchor is inconsistent")
		}
	}
	snapshot, err := readFirewallRemovalFileWithOwnerModes(
		path, []os.FileMode{sourceSystemdUnitMode, historicalSourceSystemdUnitMode},
		expectedUID, expectedGID,
	)
	if errors.Is(err, os.ErrNotExist) {
		// A prior verified removal may already have deleted this artifact.
		// Presence and loaded-unit checks still run at their normal boundaries.
		return current, nil
	}
	if err != nil {
		return "", err
	}
	if string(snapshot.content) == current {
		return current, nil
	}
	for _, template := range historical {
		if string(snapshot.content) == template.content {
			return template.content, nil
		}
	}
	return "", fmt.Errorf("refusing modified systemd removal service file %s; no exact current or historical template matches", path)
}
