//go:build linux

package cmd

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"
)

// These phases describe one command invocation, not durable runtime acceptance.
// Recovery is already a possible host effect. Once it begins, the original host
// observation cannot be reused as evidence that intentional changes did not occur.
type configurationActivationPhase uint8

const (
	activationPrepared configurationActivationPhase = iota
	activationRecovering
	activationReady
	activationApplying
	activationFailed
	activationFinished
)

func recoverConfigurationActivation(cmd *cobra.Command, recoverHost func() error) (result error) {
	execution := configurationActivationExecution(cmd)
	if execution == nil {
		return errors.New("activation recovery requires consumed approval")
	}
	defer func() { recordConfigurationActivationFailure(cmd, result) }()
	if execution.phase != activationPrepared || execution.command != cmd || recoverHost == nil {
		return errors.New("activation recovery cannot reuse or change its prepared operation")
	}
	if err := revalidateConfigurationActivation(cmd); err != nil {
		return err
	}
	if execution.reviewedHost != nil {
		if err := execution.reviewedHost(cmd.Context()); err != nil {
			return fmt.Errorf("reviewed activation host changed before the first recovery effect: %w", err)
		}
	}
	if err := revalidateConfigurationActivation(cmd); err != nil {
		return err
	}
	execution.phase = activationRecovering
	execution.reviewedHost = nil
	if err := recoverHost(); err != nil {
		return err
	}
	if err := revalidateConfigurationActivation(cmd); err != nil {
		return fmt.Errorf("activation authority changed during recovery: %w", err)
	}
	execution.phase = activationReady
	return nil
}

func beginConfigurationActivationApplication(cmd *cobra.Command) error {
	execution := configurationActivationExecution(cmd)
	if execution == nil || execution.phase != activationReady || execution.command != cmd {
		return errors.New("activation application requires this command's completed guarded recovery phase")
	}
	if err := revalidateConfigurationActivation(cmd); err != nil {
		execution.phase = activationFailed
		return err
	}
	execution.phase = activationApplying
	return nil
}

func recordConfigurationActivationFailure(cmd *cobra.Command, failure error) {
	if failure == nil {
		return
	}
	if execution := configurationActivationExecution(cmd); execution != nil {
		execution.phase = activationFailed
	}
}
