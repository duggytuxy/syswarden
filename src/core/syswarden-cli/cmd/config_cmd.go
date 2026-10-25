package cmd

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"syswarden-cli/config"

	"github.com/spf13/cobra"
)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Open the interactive configuration editor",
	RunE: func(cmd *cobra.Command, args []string) error {
		configRoot := configEditorRoot
		configDir := filepath.Join(configRoot, "modules")
		info, err := os.Lstat(configDir)
		if err != nil {
			return fmt.Errorf("[ERROR] modular configuration is unavailable: %w; run 'syswarden migrate-config' first", err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("[ERROR] modular configuration path %s is not a real directory", configDir)
		}
		reader := bufio.NewReader(cmd.InOrStdin())
		output := cmd.OutOrStdout()

		for {
			_, _ = fmt.Fprint(output, "\033[H\033[2J")
			_, _ = fmt.Fprintln(output, "\n==========================================")
			_, _ = fmt.Fprintln(output, "[SysWarden] Modular Configuration Editor")
			_, _ = fmt.Fprintln(output, "==========================================")
			_, _ = fmt.Fprintln(output, "Please select the module you want to edit:")
			_, _ = fmt.Fprintln(output, "1) Core System & Backend   (00-core.toml)")
			_, _ = fmt.Fprintln(output, "2) Network & Threat Intel  (10-network.toml)")
			_, _ = fmt.Fprintln(output, "3) Security & Hardening    (20-security.toml)")
			_, _ = fmt.Fprintln(output, "4) WAAP Engine             (30-waap.toml)")
			_, _ = fmt.Fprintln(output, "5) Integrations, HA & BunkerWeb (40-integrations.toml)")
			_, _ = fmt.Fprintln(output, "6) Custom User Overrides   (99-user.toml)")
			_, _ = fmt.Fprintln(output, "7) Set Profile Name")
			_, _ = fmt.Fprintln(output, "8) Import Configuration File")
			_, _ = fmt.Fprintln(output, "9) Master Configuration    (config.toml)")
			_, _ = fmt.Fprintln(output, "0) Exit")
			_, _ = fmt.Fprint(output, "\nSelect [0-9]: ")

			line, err := reader.ReadString('\n')
			if err != nil && len(line) == 0 {
				return fmt.Errorf("[ERROR] read configuration menu input: %w", err)
			}
			choice, parseErr := strconv.Atoi(strings.TrimSpace(line))
			if parseErr != nil {
				_, _ = fmt.Fprintln(output, "[ERROR] Invalid input. Please enter a number between 0 and 9.")
				continue
			}

			if choice == 0 {
				_, _ = fmt.Fprintln(output, "\n[*] Exiting Configuration Editor.")
				_, _ = fmt.Fprintln(output, "Run 'sudo syswarden config validate' and review the selected policy before activation.")
				_, _ = fmt.Fprintln(output, "An explicit 'sudo syswarden install' for a fresh setup, or 'sudo syswarden reload' for an existing setup, changes host policy and services.")
				return nil
			}

			if choice < 1 || choice > 9 {
				_, _ = fmt.Fprintln(output, "[ERROR] Invalid choice. Please try again.")
				continue
			}

			if choice == 7 {
				if err := setProfileName(cmd, reader, output, configRoot); err != nil {
					return fmt.Errorf("[ERROR] set profile name: %w", err)
				}
				continue
			}

			if choice == 8 {
				if err := importConfiguration(cmd, reader, output, configRoot); err != nil {
					return fmt.Errorf("[ERROR] import configuration: %w", err)
				}
				continue
			}

			targetFile := configEditorTarget(choice)

			targetPath := filepath.Join(configDir, targetFile)

			// Detect editor
			editor := os.Getenv("EDITOR")
			if editor == "" {
				if _, err := exec.LookPath("nano"); err == nil {
					editor = "nano"
				} else if _, err := exec.LookPath("vi"); err == nil {
					editor = "vi"
				} else {
					return fmt.Errorf("[ERROR] no suitable editor found (nano/vi); set EDITOR")
				}
			}

			if choice == 6 {
				edit, err := config.BeginUserModuleEdit(cmd.Context(), configRoot)
				if err != nil {
					return err
				}
				proposal, err := edit.PrepareWithEditor(cmd.Context(), func(path string) error {
					_, _ = fmt.Fprintln(output, "Opening a private working copy of 99-user.toml.")
					return launchConfigEditor(editor, path, cmd.InOrStdin(), output, cmd.ErrOrStderr())
				})
				if err != nil {
					return err
				}
				if err := reviewUserModuleProposal(cmd, reader, output, proposal); err != nil {
					return err
				}
				continue
			}

			_, _ = fmt.Fprintf(output, "\n[*] Opening %s with %s...\n", targetPath, editor)
			if err := launchConfigEditor(editor, targetPath, cmd.InOrStdin(), output, cmd.ErrOrStderr()); err != nil {
				return fmt.Errorf("[ERROR] editor execution failed: %w", err)
			}
			_, _ = fmt.Fprintln(output, "[*] Editor closed. Changes have not been validated or activated; run 'syswarden config validate' before activation.")
		}
	},
}

var configValidateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Validate modular configuration without modifying it",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		path, err := cmd.Flags().GetString("path")
		if err != nil {
			return err
		}
		report, err := config.ValidateModularConfig(path)
		if err != nil {
			return fmt.Errorf("configuration validation failed: %w", err)
		}
		schema := strconv.Itoa(report.SchemaVersion)
		if report.Historical {
			schema = "historical"
		}
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Configuration is valid (schema: %s).\n", schema)
		for _, line := range report.ModulePlan {
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), line)
		}
		for _, key := range report.DeprecatedKeys {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Deprecated key: %s\n", key)
		}
		for _, key := range report.UnknownKeys {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Unknown key: %s\n", key)
		}
		return nil
	},
}

var configEditorRoot = "/etc/syswarden/config"

var launchConfigEditor = func(editor, targetPath string, stdin io.Reader, stdout, stderr io.Writer) error {
	execCmd := exec.Command(editor, targetPath) // #nosec G204 -- editor is explicitly selected by the local operator
	execCmd.Stdin = stdin
	execCmd.Stdout = stdout
	execCmd.Stderr = stderr
	return execCmd.Run()
}

func configEditorTarget(choice int) string {
	switch choice {
	case 1:
		return "00-core.toml"
	case 2:
		return "10-network.toml"
	case 3:
		return "20-security.toml"
	case 4:
		return "30-waap.toml"
	case 5:
		return "40-integrations.toml"
	case 6:
		return "99-user.toml"
	case 9:
		return "../config.toml"
	default:
		return ""
	}
}

func setProfileName(cmd *cobra.Command, reader *bufio.Reader, output io.Writer, configRoot string) error {
	edit, err := config.BeginUserModuleEdit(cmd.Context(), configRoot)
	if err != nil {
		return err
	}
	_, _ = fmt.Fprint(output, "\nEnter Profile Name (max 15 ASCII characters): ")
	input, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("read profile name: %w", err)
	}
	proposal, err := edit.PrepareProfileName(cmd.Context(), strings.TrimSpace(input))
	if err != nil {
		return err
	}
	return reviewUserModuleProposal(cmd, reader, output, proposal)
}

func importConfiguration(cmd *cobra.Command, reader *bufio.Reader, output io.Writer, configRoot string) error {
	edit, err := config.BeginUserModuleEdit(cmd.Context(), configRoot)
	if err != nil {
		return err
	}
	_, _ = fmt.Fprint(output, "\nEnter the absolute path to the TOML configuration file to import: ")
	input, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("read import path: %w", err)
	}
	proposal, err := edit.PrepareImport(cmd.Context(), strings.TrimSpace(input))
	if err != nil {
		return err
	}
	return reviewUserModuleProposal(cmd, reader, output, proposal)
}

func reviewUserModuleProposal(cmd *cobra.Command, reader *bufio.Reader, output io.Writer, proposal *config.UserModuleProposal) error {
	review := proposal.Review()
	_, _ = fmt.Fprintf(output, "\nValidated candidate for %s.\n", review.Target)
	for _, line := range review.ModulePlan {
		_, _ = fmt.Fprintln(output, line)
	}
	_, _ = fmt.Fprintf(output, "Unknown keys: %d. Deprecated entries: %d.\n", review.UnknownKeyCount, review.DeprecatedKeyCount)
	_, _ = fmt.Fprintln(output, "Configuration values are private and are not printed in this summary. Review the edited or imported TOML before approving.")
	_, _ = fmt.Fprintln(output, "Publishing replaces only the user TOML. Host policy and services are not activated.")
	_, _ = fmt.Fprintf(output, "Approval expires at %s.\n", review.ExpiresAt.Format("15:04:05 MST"))
	expected := "publish " + review.ApprovalID
	_, _ = fmt.Fprintf(output, "Type '%s' to publish, or press Enter to cancel: ", expected)
	input, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("read publication approval; configuration was not published: %w", err)
	}
	if strings.TrimSpace(input) != expected {
		_, _ = fmt.Fprintln(output, "Publication cancelled. Live configuration was preserved.")
		return nil
	}
	if err := proposal.Publish(cmd.Context(), review.ApprovalID, func() error {
		if err := preflightWireGuardPolicyTransition(); err != nil {
			return err
		}
		if err := enforceRemovalState(cmd); err != nil {
			return err
		}
		return refusePendingFirewallTransactionHook()
	}); err != nil {
		return fmt.Errorf("configuration publication refused: %w", err)
	}
	_, _ = fmt.Fprintln(output, "Validated user configuration published. Host activation remains a separate explicit operation.")
	return nil
}

func init() {
	rootCmd.AddCommand(configCmd)
	configCmd.AddCommand(configValidateCmd)
	configValidateCmd.Flags().String("path", configEditorRoot, "Modular configuration root")
}
