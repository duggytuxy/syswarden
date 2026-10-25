//go:build linux

package network

import (
	"fmt"
	"syswarden-cli/pkg/wireguardstate"
)

func renderWireGuardMigrationConfigurations(input wireGuardRenderInput, snapshot wireguardstate.LegacyMigrationSnapshot) (string, string, error) {
	input.LegacyPolicy = false
	server, client, err := renderWireGuardConfigurations(input)
	if err != nil {
		return "", "", err
	}
	if snapshot.Journal == nil || snapshot.MatchesTargetServer([]byte(server)) {
		return server, client, nil
	}
	// Only a preexisting journal's exact target permits historical rendering.
	// Do not rewrite its sealed hash, keys, original files, or recovery copies.
	input.LegacyPolicy = true
	server, client, err = renderWireGuardConfigurations(input)
	if err != nil || !snapshot.MatchesTargetServer([]byte(server)) {
		return "", "", fmt.Errorf("legacy migration target differs from both exact generated policy versions")
	}
	return server, client, nil
}
