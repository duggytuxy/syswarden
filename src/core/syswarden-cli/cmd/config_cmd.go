package cmd

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

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
			fmt.Println("7) Set Profile Name")
			fmt.Println("8) Import Configuration File")
			fmt.Println("9) Master Configuration    (config.toml)")
			fmt.Println("0) Save & Exit")
			fmt.Print("\nSelect [0-9]: ")

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

			if choice < 1 || choice > 9 {
				fmt.Println("[ERROR] Invalid choice. Please try again.")
				continue
			}

			if choice == 7 {
				setProfileName(filepath.Join(configDir, "99-user.toml"))
				continue
			}

			if choice == 8 {
				importConfiguration(filepath.Join(configDir, "99-user.toml"))
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
			case 9:
				targetFile = "../config.toml"
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

func setProfileName(userTomlPath string) {
	fmt.Print("\nEnter Profile Name (max 15 chars, no accents): ")
	reader := bufio.NewReader(os.Stdin)
	input, err := reader.ReadString('\n')
	if err != nil {
		fmt.Println("[ERROR] Failed to read input.")
		return
	}
	profileName := strings.TrimSpace(input)
	if len(profileName) == 0 {
		fmt.Println("[WARNING] Profile name cannot be empty.")
		return
	}
	if len(profileName) > 15 {
		fmt.Println("[ERROR] Profile name exceeds 15 characters.")
		return
	}
	validRegex := regexp.MustCompile(`^[a-zA-Z0-9_\-\s]+$`)
	if !validRegex.MatchString(profileName) {
		fmt.Println("[ERROR] Profile name contains invalid characters (accents/special).")
		return
	}

	content, err := os.ReadFile(userTomlPath) // #nosec
	var newContent []string
	if err == nil {
		lines := strings.Split(string(content), "\n")
		inUserBlock := false
		profileSet := false
		for _, line := range lines {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
				if trimmed == "[user]" {
					inUserBlock = true
				} else {
					if inUserBlock && !profileSet {
						newContent = append(newContent, fmt.Sprintf("profile_name = \"%s\"", profileName))
						profileSet = true
					}
					inUserBlock = false
				}
			}
			if inUserBlock && strings.HasPrefix(trimmed, "profile_name") {
				newContent = append(newContent, fmt.Sprintf("profile_name = \"%s\"", profileName))
				profileSet = true
				continue
			}
			newContent = append(newContent, line)
		}
		if inUserBlock && !profileSet {
			newContent = append(newContent, fmt.Sprintf("profile_name = \"%s\"", profileName))
			profileSet = true
		}
		if !profileSet {
			newContent = append(newContent, "\n[user]")
			newContent = append(newContent, fmt.Sprintf("profile_name = \"%s\"", profileName))
		}
	} else {
		newContent = []string{"[user]", fmt.Sprintf("profile_name = \"%s\"", profileName)}
	}

	err = os.WriteFile(userTomlPath, []byte(strings.Join(newContent, "\n")), 0640) // #nosec
	if err != nil {
		fmt.Println("[ERROR] Failed to save profile name:", err)
		return
	}
	fmt.Printf("[SUCCESS] Profile name set to '%s'.\n", profileName)
	fmt.Println("Press ENTER to continue...")
	_, _ = reader.ReadString('\n')
}

func importConfiguration(userTomlPath string) {
	fmt.Print("\nEnter the absolute path to the TOML configuration file to import: ")
	reader := bufio.NewReader(os.Stdin)
	input, err := reader.ReadString('\n')
	if err != nil {
		fmt.Println("[ERROR] Failed to read input.")
		return
	}
	sourcePath := strings.TrimSpace(input)
	if _, err := os.Stat(sourcePath); os.IsNotExist(err) {
		fmt.Println("[ERROR] File not found:", sourcePath)
		return
	}

	sourceFile, err := os.Open(sourcePath) // #nosec
	if err != nil {
		fmt.Println("[ERROR] Failed to open source file:", err)
		return
	}
	defer func() {
		_ = sourceFile.Close()
	}()

	destFile, err := os.OpenFile(userTomlPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0640) // #nosec
	if err != nil {
		fmt.Println("[ERROR] Failed to open destination file:", err)
		return
	}
	defer func() {
		_ = destFile.Close()
	}()

	_, err = io.Copy(destFile, sourceFile)
	if err != nil {
		fmt.Println("[ERROR] Failed to copy configuration:", err)
		return
	}
	fmt.Println("[SUCCESS] Configuration successfully imported to User Overrides.")
	fmt.Println("Press ENTER to continue...")
	_, _ = reader.ReadString('\n')
}

func init() {
	rootCmd.AddCommand(configCmd)
}
