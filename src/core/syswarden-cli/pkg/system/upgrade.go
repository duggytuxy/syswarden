package system

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
)

var Version = "v2.00.3"

// UpgradeSystem checks for updates natively via GitHub API and installs them
func UpgradeSystem() error {
	fmt.Println("[INFO] Checking for SysWarden updates via GitHub API...")

	apiURL := "https://api.github.com/repos/duggytuxy/syswarden/releases/latest"
	resp, err := http.Get(apiURL)
	if err != nil {
		return fmt.Errorf("failed to connect to GitHub API: %v", err)
	}
 defer func() { _ = resp.Body.Close()
 }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return err
	}

	latestVersion, ok := result["tag_name"].(string)
	if !ok {
		return fmt.Errorf("could not parse latest version from API")
	}

	fmt.Printf("Current Version : %s\n", Version)
	fmt.Printf("Latest Version  : %s\n", latestVersion)

	if Version == latestVersion {
		fmt.Println("[SUCCESS] You are already using the latest version of SysWarden!")
		return nil
	}

	fmt.Println("[+] A new Enterprise version is available!")
	
	// Check if installed via DEB/RPM package manager
	if _, err := os.Stat("/etc/apt/sources.list.d/syswarden.list"); err == nil {
		fmt.Println("[INFO] SysWarden is installed via APT repository. Upgrading via apt-get...")
  _ = exec.Command("apt-get", "update").Run()
		return exec.Command("apt-get", "install", "--only-upgrade", "-y", "syswarden").Run()
	}

	// Manual upgrade via direct script
	fmt.Println("[INFO] Manual deployment detected. Initiating in-place upgrade...")
	fmt.Println("Please run: curl -sSL https://raw.githubusercontent.com/duggytuxy/syswarden/main/install.sh | bash")
	
	return nil
}
