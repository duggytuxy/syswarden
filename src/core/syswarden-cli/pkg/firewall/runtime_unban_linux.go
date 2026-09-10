//go:build linux

package firewall

import (
	"fmt"
	"syswarden-cli/pkg/network"
)

func preflightRuntimeUnban(entry string) error { return network.PreflightRuntimeUnban(entry) }
func unbanRuntime(entry string) error          { return network.UnbanRuntime(entry) }

func applyPoliciesWithAuthoritativeUnban(entry string, preflight func(string) error, apply func() error, unban func(string) error) error {
	if err := preflight(entry); err != nil {
		return err
	}
	// Keep all dynamic native claims during the persistent policy transaction.
	// Only the core may remove the target and commit its durable lifecycle.
	if err := apply(); err != nil {
		return err
	}
	if err := unban(entry); err != nil {
		return markCommittedFirewallPolicyError(fmt.Errorf("persistent policy is committed; authoritative runtime unban is incomplete: %w", err))
	}
	return nil
}
