package cmd

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
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
	return updateConfigTokenInDirectory("/etc/syswarden/config/modules", newToken)
}

func updateConfigTokenInDirectory(directory, newToken string) error {
	if err := os.MkdirAll(directory, 0750); err != nil {
		return fmt.Errorf("create Web-TUI configuration directory: %w", err)
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return fmt.Errorf("open Web-TUI configuration directory: %w", err)
	}
	defer func() { _ = root.Close() }()

	content := []byte("# [99] USER CUSTOM OVERRIDES\n\n[user]\n")
	pathInfo, err := root.Lstat("99-user.toml")
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect Web-TUI token file: %w", err)
	}
	if err == nil {
		if !pathInfo.Mode().IsRegular() {
			return fmt.Errorf("Web-TUI token file must be a regular file")
		}
		file, err := root.Open("99-user.toml")
		if err != nil {
			return fmt.Errorf("open Web-TUI token file: %w", err)
		}
		openedInfo, statErr := file.Stat()
		if statErr != nil || !openedInfo.Mode().IsRegular() || !os.SameFile(pathInfo, openedInfo) {
			_ = file.Close()
			return fmt.Errorf("Web-TUI token file changed while opening")
		}
		content, err = io.ReadAll(file)
		closeErr := file.Close()
		if err != nil {
			return fmt.Errorf("read Web-TUI token file: %w", err)
		}
		if closeErr != nil {
			return fmt.Errorf("close Web-TUI token file: %w", closeErr)
		}
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

	return writeWebTokenFileAtomically(root, []byte(strings.Join(newLines, "\n")))
}

func writeWebTokenFileAtomically(root *os.Root, content []byte) error {
	randomSuffix := make([]byte, 16)
	if _, err := rand.Read(randomSuffix); err != nil {
		return fmt.Errorf("generate Web-TUI token temporary filename: %w", err)
	}
	temporaryName := ".99-user.toml.tmp-" + hex.EncodeToString(randomSuffix)
	temporary, err := root.OpenFile(temporaryName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("create temporary Web-TUI token file: %w", err)
	}
	temporaryOpen := true
	defer func() {
		if temporaryOpen {
			_ = temporary.Close()
		}
		_ = root.Remove(temporaryName)
	}()

	if _, err := temporary.Write(content); err != nil {
		return fmt.Errorf("write temporary Web-TUI token file: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("sync temporary Web-TUI token file: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary Web-TUI token file: %w", err)
	}
	temporaryOpen = false
	if err := root.Rename(temporaryName, "99-user.toml"); err != nil {
		return fmt.Errorf("replace Web-TUI token file atomically: %w", err)
	}

	directoryFile, err := root.Open(".")
	if err != nil {
		return fmt.Errorf("open Web-TUI configuration directory for sync: %w", err)
	}
	defer func() { _ = directoryFile.Close() }()
	if err := directoryFile.Sync(); err != nil {
		return fmt.Errorf("sync Web-TUI configuration directory: %w", err)
	}
	return nil
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
		webTUIServiceDisplay + ". --rotate always replaces the persisted token and makes the same " +
		"restart attempt. If that attempt fails, a running Web-TUI process may continue accepting " +
		"its previous token.",
	RunE: func(cmd *cobra.Command, args []string) error {
		token := readConfigToken()

		if rotateToken || token == "" {
			fmt.Println("[SYSWARDEN] Generating a new secure Web-TUI token...")
			token = generateSecureToken(32)
			if err := updateConfigToken(token); err != nil {
				return fmt.Errorf("save Web-TUI token: %w", err)
			}
			fmt.Println("[SYSWARDEN] Token updated successfully.")

			if err := restartWebTUIService(); err != nil {
				return fmt.Errorf("Web-TUI token was persisted but the running service was not verified with it: %w", err)
			}
		}

		ip := getPublicIP()
		fmt.Printf("\n[+] Web-TUI Client Access URL: https://%s:%s/\n", ip, webtuiPort)
		fmt.Printf("    Username: admin\n")
		fmt.Printf("    Password: %s\n\n", token)
		return nil
	},
}

func init() {
	webTokenCmd.Flags().BoolVarP(&rotateToken, "rotate", "r", false, "Persist a replacement token and request a Web-TUI service restart")
	rootCmd.AddCommand(webTokenCmd)
}
