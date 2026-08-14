package cmd

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"

	"syswarden-cli/config"

	"github.com/spf13/cobra"
)

var rotateToken bool
var webtuiPort = "62027" // Default port

func generateSecureToken(length int) string {
	b := make([]byte, length/2)
	if _, err := rand.Read(b); err != nil {
		log.Fatalf("[ERROR] Failed to generate random token: %v", err)
	}
	return hex.EncodeToString(b)
}

func getPublicIP() string {
	// Minimal best effort to find a global unicast IP
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "127.0.0.1"
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil && ipnet.IP.IsGlobalUnicast() {
				return ipnet.IP.String()
			}
		}
	}
	return "127.0.0.1" // Fallback
}

func updateConfigToken(newToken string) error {
	tomlPath := "/etc/syswarden/config/modules/99-user.toml"

	// Legacy fallback if TOML doesn't exist at all (though unlikely here)
	if _, err := os.Stat(tomlPath); os.IsNotExist(err) {
		// Just ensure directory exists
		_ = os.MkdirAll("/etc/syswarden/config/modules", 0750)
	}

	content, err := os.ReadFile(tomlPath) // #nosec
	if err != nil {
		content = []byte("# [99] USER CUSTOM OVERRIDES\n\n[user]\n")
	}

	lines := strings.Split(string(content), "\n")
	foundUserBlock := false
	foundToken := false
	var newLines []string

	for i := 0; i < len(lines); i++ {
		line := lines[i]
		trimmed := strings.TrimSpace(line)

		if strings.HasPrefix(trimmed, "[user]") {
			foundUserBlock = true
		}

		if foundUserBlock && strings.HasPrefix(trimmed, "webtui_password") {
			newLines = append(newLines, fmt.Sprintf(`webtui_password = "%s"`, newToken))
			foundToken = true
			continue
		}

		newLines = append(newLines, line)
	}

	if !foundToken {
		if !foundUserBlock {
			newLines = append(newLines, "\n[user]")
		}
		newLines = append(newLines, fmt.Sprintf(`webtui_password = "%s"`, newToken))
	}

	return os.WriteFile(tomlPath, []byte(strings.Join(newLines, "\n")), 0640) // #nosec G703
}

func readConfigToken() string {
	if config.GlobalConfig != nil && config.GlobalConfig.WebTUIPassword != "" {
		return config.GlobalConfig.WebTUIPassword
	}
	return ""
}

var webTokenCmd = &cobra.Command{
	Use:   "web-token",
	Short: "Display or rotate the Web-TUI access token",
	Long: "Displays the configured Web-TUI access token. If no token exists, an invocation " +
		"without --rotate generates and persists one, then attempts to restart " +
		"syswarden-webtui.service. --rotate always replaces the persisted token and makes the same " +
		"restart attempt. If that attempt fails, a running Web-TUI process may continue accepting " +
		"its previous token.",
	Run: func(cmd *cobra.Command, args []string) {
		token := readConfigToken()

		if rotateToken || token == "" {
			fmt.Println("[SYSWARDEN] Generating a new secure Web-TUI token...")
			token = generateSecureToken(32)
			if err := updateConfigToken(token); err != nil {
				log.Fatalf("[ERROR] Failed to save token to syswarden-auto.conf: %v", err)
			}
			fmt.Println("[SYSWARDEN] Token updated successfully.")

			// Restart the daemon to apply changes immediately
			_ = exec.Command("systemctl", "restart", "syswarden-webtui.service").Run() // #nosec
		}

		ip := getPublicIP()
		fmt.Printf("\n[+] Web-TUI Client Access URL: https://%s:%s/\n", ip, webtuiPort)
		fmt.Printf("    Username: admin\n")
		fmt.Printf("    Password: %s\n\n", token)
	},
}

func init() {
	webTokenCmd.Flags().BoolVarP(&rotateToken, "rotate", "r", false, "Persist a replacement token and request a Web-TUI service restart")
	rootCmd.AddCommand(webTokenCmd)
}
