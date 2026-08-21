package cmd

import (
	"errors"
	"fmt"
	"strings"

	"syswarden-cli/pkg/firewall"

	"github.com/spf13/cobra"
)

type whitelistEntryOperation func(string, string) error

type whitelistPortFlag struct {
	value       string
	occurrences int
}

func (flag *whitelistPortFlag) Set(value string) error {
	flag.value = value
	flag.occurrences++
	return nil
}

func (flag *whitelistPortFlag) String() string {
	return flag.value
}

func (*whitelistPortFlag) Type() string {
	return "string"
}

func isDecimalWhitelistArgument(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func resolveWhitelistArguments(args []string, flagPort string, flagOccurrences int) ([]string, string, error) {
	addresses := append([]string(nil), args...)
	positionedPorts := make([]int, 0, 1)
	for index, argument := range args {
		if isDecimalWhitelistArgument(argument) {
			positionedPorts = append(positionedPorts, index)
		}
	}

	if flagOccurrences > 1 {
		return nil, "", fmt.Errorf("multiple --port flags are not allowed")
	}
	if flagOccurrences == 1 {
		if strings.TrimSpace(flagPort) == "" {
			return nil, "", fmt.Errorf("--port requires a decimal port in 1..65535")
		}
		if len(positionedPorts) > 0 {
			return nil, "", fmt.Errorf("--port cannot be combined with the legacy positional [PORT]")
		}
		return addresses, flagPort, nil
	}

	if len(positionedPorts) > 1 {
		return nil, "", fmt.Errorf("multiple legacy positional ports are not allowed; use --port once")
	}
	if len(positionedPorts) == 1 {
		portIndex := positionedPorts[0]
		if portIndex != len(args)-1 {
			return nil, "", fmt.Errorf("the legacy positional [PORT] must be the final argument")
		}
		if portIndex == 0 {
			return nil, "", fmt.Errorf("at least one IP address or CIDR is required before the legacy positional [PORT]")
		}
		return addresses[:portIndex], args[portIndex], nil
	}
	return addresses, "", nil
}

func newWhitelistCommand(validate, add whitelistEntryOperation) *cobra.Command {
	var flagPort whitelistPortFlag
	command := &cobra.Command{
		Use:   "whitelist <IP|CIDR>... [PORT]",
		Short: "Add addresses or CIDRs to the persistent whitelist",
		Long: "Records each entry in the persistent whitelist and reapplies firewall policy. " +
			"Use --port for a TCP service-scoped entry. A single final positional [PORT] remains temporarily accepted for compatibility. " +
			"Verify the resulting kernel rule before relying on the entry.",
		Args: cobra.MinimumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			addresses, port, err := resolveWhitelistArguments(args, flagPort.value, flagPort.occurrences)
			if err != nil {
				return err
			}

			validationErrors := make([]error, 0)
			for _, address := range addresses {
				if err := validate(address, port); err != nil {
					validationErrors = append(validationErrors, fmt.Errorf("validate whitelist %s: %w", address, err))
				}
			}
			if err := errors.Join(validationErrors...); err != nil {
				return err
			}

			failures := make([]error, 0)
			for _, address := range addresses {
				if err := add(address, port); err != nil {
					failures = append(failures, fmt.Errorf("whitelist %s: %w", address, err))
				}
			}
			return errors.Join(failures...)
		},
	}
	command.Flags().Var(&flagPort, "port", "Scope every whitelist entry to this TCP destination port")
	return command
}

var whitelistCmd = newWhitelistCommand(firewall.ValidateWhitelistEntry, firewall.AddToWhitelist)

func init() { rootCmd.AddCommand(whitelistCmd) }
