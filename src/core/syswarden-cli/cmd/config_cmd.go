package cmd

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
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
			_, _ = fmt.Fprintln(output, "0) Save & Exit")
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
				_, _ = fmt.Fprintln(output, "Remember to run 'sudo syswarden reload' to apply changes.")
				_, _ = fmt.Fprintln(output, "(If this is a fresh setup, run 'sudo syswarden install' instead).")
				return nil
			}

			if choice < 1 || choice > 9 {
				_, _ = fmt.Fprintln(output, "[ERROR] Invalid choice. Please try again.")
				continue
			}

			if choice == 7 {
				if err := setProfileName(reader, output, configRoot); err != nil {
					return fmt.Errorf("[ERROR] set profile name: %w", err)
				}
				continue
			}

			if choice == 8 {
				if err := importConfiguration(reader, output, configRoot); err != nil {
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

			_, _ = fmt.Fprintf(output, "\n[*] Opening %s with %s...\n", targetPath, editor)
			if err := launchConfigEditor(editor, targetPath, cmd.InOrStdin(), output, cmd.ErrOrStderr()); err != nil {
				return fmt.Errorf("[ERROR] editor execution failed: %w", err)
			}
			_, _ = fmt.Fprintln(output, "[*] Configuration updated successfully.")
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

func setProfileName(reader *bufio.Reader, output io.Writer, configRoot string) error {
	_, _ = fmt.Fprint(output, "\nEnter Profile Name (max 15 chars, no accents): ")
	input, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("read profile name: %w", err)
	}
	profileName := strings.TrimSpace(input)
	if len(profileName) == 0 {
		return fmt.Errorf("profile name cannot be empty")
	}
	if len(profileName) > 15 {
		return fmt.Errorf("profile name exceeds 15 characters")
	}
	validRegex := regexp.MustCompile(`^[a-zA-Z0-9_\-\s]+$`)
	if !validRegex.MatchString(profileName) {
		return fmt.Errorf("profile name contains invalid characters")
	}
	if err := config.SetValidatedProfileName(configRoot, profileName); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(output, "[SUCCESS] Profile name set to '%s'.\n", profileName)
	return nil
}

func importConfiguration(reader *bufio.Reader, output io.Writer, configRoot string) error {
	_, _ = fmt.Fprint(output, "\nEnter the absolute path to the TOML configuration file to import: ")
	input, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("read import path: %w", err)
	}
	sourcePath := strings.TrimSpace(input)
	if !filepath.IsAbs(sourcePath) {
		return fmt.Errorf("import path must be absolute")
	}
	if err := config.ImportValidatedUserModule(configRoot, sourcePath); err != nil {
		return err
	}
	_, _ = fmt.Fprintln(output, "[SUCCESS] Configuration successfully imported to User Overrides.")
	return nil
}

func init() {
	rootCmd.AddCommand(configCmd)
	configCmd.AddCommand(configValidateCmd)
	configValidateCmd.Flags().String("path", configEditorRoot, "Modular configuration root")
}
