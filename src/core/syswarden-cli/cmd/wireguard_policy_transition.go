package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
	"syswarden-cli/pkg/network"
)

// Check before configuration repair, service preparation or other recovery.
var preflightWireGuardPolicyTransition = network.RefusePendingWireGuardPolicyTransition

func enforceWireGuardPolicyTransition(cmd *cobra.Command) error {
	if cmd == configCmd || cmd == configEditRecoveryCmd {
		if err := preflightWireGuardPolicyTransition(); err != nil {
			return fmt.Errorf("WireGuard policy transition requires recovery before configuration editor preparation: %w", err)
		}
		return nil
	}
	top := topLevelCommand(cmd)
	if top == nil {
		return nil
	}
	if top.Name() == "recover-removal" {
		apply, err := cmd.Flags().GetBool("apply")
		if err != nil {
			return err
		}
		if apply {
			return preflightWireGuardPolicyTransition()
		}
		return nil
	}
	switch top.Name() {
	case "install", "reload", "update", "uninstall", "prepare-package-removal":
		if err := preflightWireGuardPolicyTransition(); err != nil {
			return fmt.Errorf("WireGuard policy transition requires recovery before lifecycle command preparation: %w", err)
		}
	}
	return nil
}
