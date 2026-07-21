package cmd

import (
	"bufio"
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
	confPath := "/opt/syswarden/syswarden-auto.conf"
	content, err := os.ReadFile(confPath) // #nosec
	if err != nil || len(strings.TrimSpace(string(content))) == 0 {
		content = []byte(config.DefaultConfig)
	}

	lines := strings.Split(string(content), "\n")

	found := false
	var newLines []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "SYSWARDEN_WEB_TOKEN=") {
			newLines = append(newLines, fmt.Sprintf("SYSWARDEN_WEB_TOKEN=\"%s\"", newToken))
			found = true
		} else {
			newLines = append(newLines, line)
		}
	}
	if !found {
		newLines = append(newLines, fmt.Sprintf("SYSWARDEN_WEB_TOKEN=\"%s\"", newToken))
	}

	return os.WriteFile(confPath, []byte(strings.Join(newLines, "\n")), 0600) // #nosec G703
}

func readConfigToken() string {
	confPath := "/opt/syswarden/syswarden-auto.conf"
	file, err := os.Open(confPath) // #nosec
	if err != nil {
		return ""
	}
	defer func() { _ = file.Close() }()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "SYSWARDEN_WEB_TOKEN=") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(strings.Trim(strings.TrimSpace(parts[1]), "\"'"))
			}
		}
	}
	return ""
}

var webTokenCmd = &cobra.Command{
	Use:   "web-token",
	Short: "Manage the Web-TUI secure access token",
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
		fmt.Printf("\n[+] Web-TUI Client Access URL: https://%s:%s/?token=%s\n\n", ip, webtuiPort, token)
	},
}

func init() {
	webTokenCmd.Flags().BoolVarP(&rotateToken, "rotate", "r", false, "Generate a new token and invalidate the old one")
	rootCmd.AddCommand(webTokenCmd)
}
