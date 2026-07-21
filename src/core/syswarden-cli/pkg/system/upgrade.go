package system

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
)

var Version = "v3.74.4"

func isRHEL() bool {
	_, errDnf := exec.LookPath("dnf")
	_, errYum := exec.LookPath("yum")
	return errDnf == nil || errYum == nil
}

func isAlpine() bool {
	_, errApk := exec.LookPath("apk")
	return errApk == nil
}

// downloadFile securely downloads a file to the destination path
func downloadFile(url, dest string) error {
	out, err := os.Create(dest) // #nosec
	if err != nil {
		return fmt.Errorf("failed to create destination file: %w", err)
	}
	defer func() { _ = out.Close() }()

	resp, err := http.Get(url) // #nosec
	if err != nil {
		return fmt.Errorf("failed to download file: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad status: %s", resp.Status)
	}

	if _, err := io.Copy(out, resp.Body); err != nil {
		return fmt.Errorf("failed to write file content: %w", err)
	}

	return nil
}

// UpgradeSystem checks for updates natively via GitHub API and installs them
func UpgradeSystem() error {
	fmt.Println("[INFO] Checking for SYSWARDEN updates via GitHub API...")

	apiURL := "https://api.github.com/repos/duggytuxy/syswarden/releases/latest"
	resp, err := http.Get(apiURL) // #nosec
	if err != nil {
		return fmt.Errorf("failed to connect to GitHub API: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusForbidden {
		return fmt.Errorf("GitHub API rate limit exceeded. Please try again later or authenticate")
	} else if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GitHub API returned unexpected status: %s", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return fmt.Errorf("failed to unmarshal JSON: %w", err)
	}

	latestVersion, ok := result["tag_name"].(string)
	if !ok {
		return fmt.Errorf("could not parse latest version from API")
	}

	fmt.Printf("Current Version : %s\n", Version)
	fmt.Printf("Latest Version  : %s\n", latestVersion)

	if Version == latestVersion {
		fmt.Println("[SUCCESS] You are already using the latest version of SYSWARDEN!")
		return nil
	}

	fmt.Println("[+] A new Enterprise version is available!")

	// 1. Check if it's an APT repository deployment (highly unlikely now, but keeping for compatibility)
	if _, err := os.Stat("/etc/apt/sources.list.d/syswarden.list"); err == nil {
		fmt.Println("[INFO] SYSWARDEN is installed via APT repository. Upgrading via apt-get...")
		_ = exec.Command("apt-get", "update").Run()                                                           // #nosec
		if err := exec.Command("apt-get", "install", "--only-upgrade", "-y", "syswarden").Run(); err != nil { // #nosec
			return fmt.Errorf("failed to upgrade via apt-get: %w", err)
		}
		fmt.Println("[+] Upgrade completed via APT.")
		return nil
	}

	// 2. Native In-Place Upgrade for offline/manual packages
	fmt.Println("[INFO] In-place upgrade detected. Determining OS architecture...")

	var pkgURL, pkgFile string
	cleanVersion := strings.TrimPrefix(latestVersion, "v")

	if _, err := exec.LookPath("apt-get"); err == nil {
		// Debian / Ubuntu (.deb)
		fmt.Println(" -> Detected Debian-based OS")
		pkgFile = "/tmp/syswarden.deb"
		pkgURL = fmt.Sprintf("https://github.com/duggytuxy/syswarden/releases/download/%s/syswarden_%s_amd64.deb", latestVersion, cleanVersion)

		fmt.Printf("[INFO] Downloading %s...\n", pkgURL)
		if err := downloadFile(pkgURL, pkgFile); err != nil {
			return fmt.Errorf("failed to download DEB package: %w", err)
		}

		// [FIX] CIS Level 2 / ANSSI Hardening Compatibility
		// Ensure the _apt sandbox user can read the file in the sticky /tmp directory
		_ = os.Chmod(pkgFile, 0600)
		_ = exec.Command("chown", "_apt", pkgFile).Run() // #nosec

		fmt.Println("[INFO] Installing new version via apt-get...")
		cmd := exec.Command("apt-get", "install", "-y", pkgFile) // #nosec
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to install DEB package: %w", err)
		}

	} else if isRHEL() {
		// RHEL / Alma / Fedora (.rpm)
		fmt.Println(" -> Detected RHEL-based OS")
		pkgFile = "/tmp/syswarden.rpm"
		pkgURL = fmt.Sprintf("https://github.com/duggytuxy/syswarden/releases/download/%s/syswarden-%s-1.x86_64.rpm", latestVersion, cleanVersion)

		fmt.Printf("[INFO] Downloading %s...\n", pkgURL)
		if err := downloadFile(pkgURL, pkgFile); err != nil {
			return fmt.Errorf("failed to download RPM package: %w", err)
		}

		fmt.Println("[INFO] Installing new version via DNF...")
		installer := "dnf"
		if _, err := exec.LookPath("dnf"); err != nil {
			installer = "yum"
		}

		cmd := exec.Command(installer, "install", "-y", pkgFile) // #nosec
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to install RPM package: %w", err)
		}
	} else if isAlpine() {
		// Alpine Linux (.apk)
		fmt.Println(" -> Detected Alpine-based OS")
		pkgFile = "/tmp/syswarden.apk"
		pkgURL = fmt.Sprintf("https://github.com/duggytuxy/syswarden/releases/download/%s/syswarden-%s-r0.apk", latestVersion, cleanVersion)

		fmt.Printf("[INFO] Downloading %s...\n", pkgURL)
		if err := downloadFile(pkgURL, pkgFile); err != nil {
			return fmt.Errorf("failed to download APK package: %w", err)
		}

		fmt.Println("[INFO] Installing new version via apk...")
		cmd := exec.Command("apk", "add", "--allow-untrusted", pkgFile) // #nosec
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to install APK package: %w", err)
		}
	} else {
		return fmt.Errorf("no supported package manager found (apt-get/dnf/yum/apk)")
	}

	// Clean up
	_ = os.Remove(pkgFile)

	// Ensure Web-TUI is initialized and display URL if upgrading to a version supporting it
	configPath := "/opt/syswarden/syswarden-auto.conf"
	out, err := os.ReadFile(configPath) // #nosec G304
	if err == nil && !strings.Contains(string(out), "SYSWARDEN_WEB_TOKEN=") {
		fmt.Println("\n[INFO] Upgrading SysWarden: Initializing Web-TUI...")
		cmdWT := exec.Command("/opt/syswarden/bin/syswarden-cli", "web-token", "--rotate") // #nosec
		cmdWT.Stdout = os.Stdout
		cmdWT.Stderr = os.Stderr
		_ = cmdWT.Run()
	} else if err == nil && strings.Contains(string(out), "SYSWARDEN_WEB_TOKEN=") {
		fmt.Println("\n[INFO] Web-TUI is available at:")
		cmdWT := exec.Command("/opt/syswarden/bin/syswarden-cli", "web-token") // #nosec
		cmdWT.Stdout = os.Stdout
		cmdWT.Stderr = os.Stderr
		_ = cmdWT.Run()
	}

	fmt.Println("\n[+] In-place upgrade completed successfully!")
	fmt.Println("[INFO] Please restart your terminal session to use the new version.")
	return nil
}
