package firewall

import (
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// A pending record proves only that an operation was attempted. Retirement
// removes no firewall permission and requires fresh absence in both firewalld
// scopes. An inactive daemon, unknown zone or query failure is not absence.
func requireAbsentPendingFirewalldPort(path string, rule linuxWrapperRule) error {
	if path == "" || rule.backend != "firewalld" || rule.kind != "port" || !rule.pending {
		return fmt.Errorf("pending wrapper absence requires an active firewalld port record")
	}
	for _, permanent := range linuxWrapperRuleScopes(rule) {
		arguments, err := linuxWrapperRuleArguments(rule, "query", permanent)
		if err != nil {
			return err
		}
		output, err := runLinuxFirewallCommand(path, arguments...)
		if err == nil {
			return fmt.Errorf("pending wrapper ownership %s remains present (permanent=%t); preserve the rule and receipt for verified attribution", rule.key(), permanent)
		}
		var exit *exec.ExitError
		if !errors.As(err, &exit) || exit.ExitCode() != 1 || strings.TrimSpace(string(output)) != "no" {
			return fmt.Errorf("pending wrapper %s has no verified absence response (permanent=%t): %w", rule.key(), permanent, err)
		}
	}
	return nil
}

// Called at the existing precommit, pre-mutation and final verification gates.
// The pending record is retained until reconciliation succeeds in full. Any
// changed receipt or reappearing rule prevents retirement; no pending rule is removed.
func reattestAbsentPendingFirewalldPorts(plan *linuxWrapperReconciliationPlan) error {
	if len(plan.absentPending) == 0 {
		return nil
	}
	if err := requirePendingFirewalldReceipt(plan); err != nil {
		return err
	}
	for key, rule := range plan.absentPending {
		if _, desired := plan.desired[key]; desired {
			return fmt.Errorf("pending firewalld port retirement conflicts with the active plan")
		}
		if err := requireAbsentPendingFirewalldPort(plan.paths["firewalld"], rule); err != nil {
			return err
		}
	}
	return requirePendingFirewalldReceipt(plan)
}

func requirePendingFirewalldReceipt(plan *linuxWrapperReconciliationPlan) error {
	current, exists, migration, err := readLinuxWrapperState(linuxWrapperStateFile)
	if err != nil {
		return err
	}
	if !exists || migration || !sameLinuxWrapperRules(current, plan.expectedState) {
		return fmt.Errorf("wrapper ownership state changed during pending firewalld port recovery")
	}
	return nil
}
