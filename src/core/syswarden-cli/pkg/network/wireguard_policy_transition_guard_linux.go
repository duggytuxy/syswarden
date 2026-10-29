//go:build linux

package network

import "syswarden-cli/pkg/wireguardstate"

// RefusePendingWireGuardPolicyTransition prevents other lifecycle operations
// from mutating a policy whose file transaction still requires host acceptance.
// It never recovers, deletes or accepts policy transition evidence.
func RefusePendingWireGuardPolicyTransition() error {
	return wireguardstate.RefusePendingPolicyTransition(wireGuardFilesystemRoot)
}
