package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/spf13/cobra"
)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Open the interactive configuration editor",
	Run: func(cmd *cobra.Command, args []string) {
		configDir := "/etc/syswarden/config/modules"

		// Ensure directory exists
		if _, err := os.Stat(configDir); os.IsNotExist(err) {
			fmt.Println("[ERROR] Modular configuration not found.")
			fmt.Println("Please run 'syswarden migrate-config' first to initialize the configuration.")
			return
		}

		for {
			fmt.Print("\033[H\033[2J") // Clear screen
			fmt.Println("\n==========================================")
			fmt.Println("[SysWarden] Modular Configuration Editor")
			fmt.Println("==========================================")
			fmt.Println("Please select the module you want to edit:")
			fmt.Println("1) Core System & Backend   (00-core.toml)")
			fmt.Println("2) Network & Threat Intel  (10-network.toml)")
			fmt.Println("3) Security & Hardening    (20-security.toml)")
			fmt.Println("4) WAAP Engine             (30-waap.toml)")
			fmt.Println("5) Integrations & HA       (40-integrations.toml)")
			fmt.Println("6) Custom User Overrides   (99-user.toml)")
			fmt.Println("0) Save & Exit")
			fmt.Print("\nSelect [0-6]: ")

			var choice int
			_, err := fmt.Scanf("%d", &choice)
			if err != nil {
				// Clear the stdin buffer if non-integer is provided
				var discard string
				_, _ = fmt.Scanln(&discard)
				fmt.Println("[ERROR] Invalid input. Please enter a number between 0 and 6.")
				continue
			}

			if choice == 0 {
				fmt.Println("\n[*] Exiting Configuration Editor.")
				fmt.Println("Remember to run 'sudo syswarden reload' to apply changes.")
				fmt.Println("(If this is a fresh setup, run 'sudo syswarden install' instead).")
				break
			}

			if choice < 1 || choice > 6 {
				fmt.Println("[ERROR] Invalid choice. Please try again.")
				continue
			}

			var targetFile string
			switch choice {
			case 1:
				targetFile = "00-core.toml"
			case 2:
				targetFile = "10-network.toml"
			case 3:
				targetFile = "20-security.toml"
			case 4:
				targetFile = "30-waap.toml"
			case 5:
				targetFile = "40-integrations.toml"
			case 6:
				targetFile = "99-user.toml"
			}

			targetPath := filepath.Join(configDir, targetFile)

			// Detect editor
			editor := os.Getenv("EDITOR")
			if editor == "" {
				if _, err := exec.LookPath("nano"); err == nil {
					editor = "nano"
				} else if _, err := exec.LookPath("vi"); err == nil {
					editor = "vi"
				} else {
					fmt.Println("[ERROR] No suitable editor found (nano/vi). Please set EDITOR environment variable.")
					break
				}
			}

			fmt.Printf("\n[*] Opening %s with %s...\n", targetPath, editor)

			execCmd := exec.Command(editor, targetPath) // #nosec
			execCmd.Stdin = os.Stdin
			execCmd.Stdout = os.Stdout
			execCmd.Stderr = os.Stderr
			if err := execCmd.Run(); err != nil {
				fmt.Printf("[ERROR] Editor execution failed: %v\n", err)
			}

			fmt.Println("[*] Configuration updated successfully.")
		}
	},
}

func init() {
	rootCmd.AddCommand(configCmd)
}
