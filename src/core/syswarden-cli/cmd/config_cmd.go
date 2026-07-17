package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"regexp"

	"syswarden-cli/config"

	"github.com/spf13/cobra"
)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Open the interactive configuration editor",
	Run: func(cmd *cobra.Command, args []string) {
		configPath := "/opt/syswarden/syswarden-auto.conf"

		// Create default config if it doesn't exist
		if _, err := os.Stat(configPath); os.IsNotExist(err) {
			fmt.Println("[*] Configuration file not found. Generating default...")
			err := os.MkdirAll("/opt/syswarden", 0750)
			if err == nil {
				_ = os.WriteFile(configPath, []byte(config.DefaultConfig), 0600)
			}
		}

		// Detect editor
		editor := os.Getenv("EDITOR")
		if editor == "" {
			if _, err := exec.LookPath("nano"); err == nil {
				editor = "nano"
			} else if _, err := exec.LookPath("vi"); err == nil {
				editor = "vi"
			} else {
				fmt.Println("[ERROR] No suitable editor found (nano/vi). Please set EDITOR environment variable.")
				return
			}
		}

		fmt.Printf("[*] Opening configuration with %s...\n", editor)

		// Launch interactive editor
		execCmd := exec.Command(editor, configPath) // #nosec
		execCmd.Stdin = os.Stdin
		execCmd.Stdout = os.Stdout
		execCmd.Stderr = os.Stderr
		if err := execCmd.Run(); err != nil {
			fmt.Printf("[ERROR] Editor execution failed: %v\n", err)
			return
		}

		// Validate configuration
		fmt.Println("[*] Validating configuration...")
		if err := config.ParseConfig(configPath); err != nil {
			fmt.Printf("[ERROR] Configuration parsing failed: %v\n", err)
			return
		}

		// Security constraint: AbuseIPDB API Key must be exactly 80 lowercase hex chars
		if config.GlobalConfig.EnableAbuse {
			matched, _ := regexp.MatchString("^[a-f0-9]{80}$", config.GlobalConfig.AbuseAPIKey)
			if !matched {
				fmt.Println("\n[CRITICAL ERROR] Invalid AbuseIPDB API Key!")
				fmt.Println("The API key must be exactly 80 lowercase alphanumeric characters to prevent data poisoning.")
				fmt.Println("Please run 'syswarden config' again to fix this issue.")
				return
			}
		}

		fmt.Println("[SUCCESS] Configuration is valid.")
		fmt.Println("[INFO] To apply the new configuration, please run: sudo syswarden install")

	},
}

func init() {
	rootCmd.AddCommand(configCmd)
}
