package integration

import (
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"syswarden-cli/config"
	"syswarden-cli/pkg/system"
)

const (
	wazuhConfigDirectory = "/var/ossec/etc"
	wazuhConfigName      = "ossec.conf"
)

// SetupWazuh registers the node with Wazuh natively and injects SYSWARDEN log parsing
func SetupWazuh() error {
	fmt.Println("[INFO] Configuring Wazuh Agent Integration...")

	if !config.GlobalConfig.EnableWazuh {
		fmt.Println("[INFO] Wazuh integration disabled.")
		return nil
	}

	ip := config.GlobalConfig.WazuhIP
	if ip == "" {
		return fmt.Errorf("wazuh IP is missing in configuration")
	}

	wazuhConf := wazuhConfigDirectory + "/" + wazuhConfigName
	if _, err := os.Stat(wazuhConf); os.IsNotExist(err) {
		fmt.Println("[WARNING] Wazuh agent is enabled but ossec.conf was not found. Please install the Wazuh agent first.")
		return nil
	}

	root, err := os.OpenRoot(wazuhConfigDirectory)
	if err != nil {
		return fmt.Errorf("failed to open wazuh config directory: %w", err)
	}
	defer func() { _ = root.Close() }()
	info, err := root.Lstat(wazuhConfigName)
	if err != nil {
		return fmt.Errorf("failed to inspect wazuh config: %w", err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("wazuh config must be a regular file")
	}
	configFile, err := openRegularWazuhConfig(root, os.O_RDONLY)
	if err != nil {
		return fmt.Errorf("failed to read wazuh config: %w", err)
	}
	content, err := io.ReadAll(configFile)
	closeErr := configFile.Close()
	if err != nil {
		return fmt.Errorf("failed to read wazuh config: %w", err)
	}
	if closeErr != nil {
		return fmt.Errorf("failed to close wazuh config: %w", closeErr)
	}
	confStr := string(content)

	var modified bool

	// Inject waf.json telemetry parsing
	if !strings.Contains(confStr, "/var/log/syswarden/waf.json") {
		localfileBlock := `
  <localfile>
    <log_format>json</log_format>
    <location>/var/log/syswarden/waf.json</location>
  </localfile>
`
		// Insert before the closing </ossec_config>
		if idx := strings.LastIndex(confStr, "</ossec_config>"); idx != -1 {
			confStr = confStr[:idx] + localfileBlock + confStr[idx:]
			modified = true
		}
	}

	// Inject core.log tracing
	if !strings.Contains(confStr, "/var/log/syswarden/core.log") {
		localfileBlock := `
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/syswarden/core.log</location>
  </localfile>
`
		if idx := strings.LastIndex(confStr, "</ossec_config>"); idx != -1 {
			confStr = confStr[:idx] + localfileBlock + confStr[idx:]
			modified = true
		}
	}

	if modified {
		if err := writeWazuhConfigFromSnapshot(root, []byte(confStr), content); err != nil {
			return fmt.Errorf("failed to write wazuh config: %w", err)
		}
		fmt.Println("[INFO] SYSWARDEN logs successfully injected into Wazuh agent.")

		// Restart Wazuh Agent
		fmt.Println("[INFO] Restarting wazuh-agent service...")
		if system.IsAlpine() {
			_ = exec.Command("rc-service", "wazuh-agent", "restart").Run() // #nosec
		} else {
			cmd := exec.Command("systemctl", "restart", "wazuh-agent") // #nosec
			if err := cmd.Run(); err != nil {
				// Fallback for FreeBSD or non-systemd
				_ = exec.Command("service", "wazuh-agent", "restart").Run() // #nosec
			}
		}
	}

	fmt.Printf("[SUCCESS] Wazuh Agent integration active (Manager: %s)\n", ip)
	return nil
}

func openRegularWazuhConfig(root *os.Root, flags int) (*os.File, error) {
	pathInfo, err := root.Lstat(wazuhConfigName)
	if err != nil {
		return nil, err
	}
	if !pathInfo.Mode().IsRegular() {
		return nil, fmt.Errorf("wazuh config must be a regular file")
	}
	file, err := root.OpenFile(wazuhConfigName, flags, 0)
	if err != nil {
		return nil, err
	}
	openedInfo, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	if !openedInfo.Mode().IsRegular() || !os.SameFile(pathInfo, openedInfo) {
		_ = file.Close()
		return nil, fmt.Errorf("wazuh config changed while opening")
	}
	return file, nil
}

type wazuhConfigIdentity struct {
	info       fs.FileInfo
	digest     [sha256.Size]byte
	mode       fs.FileMode
	uid        int
	gid        int
	ownerKnown bool
}

func snapshotWazuhConfig(file *os.File) (fs.FileInfo, [sha256.Size]byte, error) {
	var digest [sha256.Size]byte
	before, err := file.Stat()
	if err != nil {
		return nil, digest, err
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return nil, digest, err
	}
	after, err := file.Stat()
	if err != nil {
		return nil, digest, err
	}
	if !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return nil, digest, fmt.Errorf("wazuh config changed while snapshotting")
	}
	copy(digest[:], hash.Sum(nil))
	return after, digest, nil
}

func sameWazuhConfigState(expected wazuhConfigIdentity, actualInfo fs.FileInfo, actualDigest [sha256.Size]byte) bool {
	if !os.SameFile(expected.info, actualInfo) || expected.info.Size() != actualInfo.Size() ||
		!expected.info.ModTime().Equal(actualInfo.ModTime()) || expected.info.Mode() != actualInfo.Mode() ||
		expected.digest != actualDigest {
		return false
	}
	if expected.ownerKnown {
		stat, ok := actualInfo.Sys().(*syscall.Stat_t)
		return ok && int(stat.Uid) == expected.uid && int(stat.Gid) == expected.gid
	}
	return true
}

func inspectWazuhConfig(root *os.Root) (wazuhConfigIdentity, error) {
	file, err := openRegularWazuhConfig(root, os.O_RDONLY)
	if err != nil {
		return wazuhConfigIdentity{}, err
	}
	info, digest, statErr := snapshotWazuhConfig(file)
	closeErr := file.Close()
	if statErr != nil {
		return wazuhConfigIdentity{}, statErr
	}
	if closeErr != nil {
		return wazuhConfigIdentity{}, closeErr
	}
	identity := wazuhConfigIdentity{info: info, digest: digest, mode: info.Mode().Perm()}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		identity.uid = int(stat.Uid)
		identity.gid = int(stat.Gid)
		identity.ownerKnown = true
	}
	return identity, nil
}

func createWazuhStagingFile(root *os.Root) (*os.File, string, error) {
	for range 128 {
		var random [16]byte
		if _, err := cryptorand.Read(random[:]); err != nil {
			return nil, "", fmt.Errorf("generate wazuh staging name: %w", err)
		}
		name := "." + wazuhConfigName + ".syswarden-" + hex.EncodeToString(random[:]) + ".tmp"
		file, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if errors.Is(err, fs.ErrExist) {
			continue
		}
		if err != nil {
			return nil, "", fmt.Errorf("create wazuh staging file: %w", err)
		}
		return file, name, nil
	}
	return nil, "", fmt.Errorf("create wazuh staging file: too many name collisions")
}

func verifyWazuhDestination(root *os.Root, identity wazuhConfigIdentity) error {
	current, err := root.Lstat(wazuhConfigName)
	if err != nil {
		return fmt.Errorf("reinspect wazuh config: %w", err)
	}
	if !current.Mode().IsRegular() || !os.SameFile(identity.info, current) {
		return fmt.Errorf("wazuh config changed before publication")
	}
	file, err := openRegularWazuhConfig(root, os.O_RDONLY)
	if err != nil {
		return fmt.Errorf("reopen wazuh config before publication: %w", err)
	}
	actualInfo, actualDigest, snapshotErr := snapshotWazuhConfig(file)
	closeErr := file.Close()
	if snapshotErr != nil {
		return fmt.Errorf("resnapshot wazuh config: %w", snapshotErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close wazuh config after resnapshot: %w", closeErr)
	}
	if !sameWazuhConfigState(identity, actualInfo, actualDigest) {
		return fmt.Errorf("wazuh config content or metadata changed before publication")
	}
	return nil
}

func syncWazuhDirectory(root *os.Root) error {
	directoryFile, err := root.Open(".")
	if err != nil {
		return fmt.Errorf("open wazuh directory for sync: %w", err)
	}
	if err := directoryFile.Sync(); err != nil {
		_ = directoryFile.Close()
		return fmt.Errorf("sync wazuh directory: %w", err)
	}
	if err := directoryFile.Close(); err != nil {
		return fmt.Errorf("close wazuh directory: %w", err)
	}
	return nil
}

func writeWazuhConfig(root *os.Root, content []byte) error {
	return writeWazuhConfigBeforeRename(root, content, nil)
}

func writeWazuhConfigBeforeRename(root *os.Root, content []byte, beforeRename func() error) error {
	return writeWazuhConfigExpected(root, content, nil, beforeRename)
}

func writeWazuhConfigFromSnapshot(root *os.Root, content, snapshot []byte) error {
	digest := sha256.Sum256(snapshot)
	return writeWazuhConfigExpected(root, content, &digest, nil)
}

func writeWazuhConfigExpected(root *os.Root, content []byte, expectedDigest *[sha256.Size]byte, beforeRename func() error) error {
	identity, err := inspectWazuhConfig(root)
	if err != nil {
		return err
	}
	if expectedDigest != nil && identity.digest != *expectedDigest {
		return fmt.Errorf("wazuh config changed after it was read")
	}
	file, stagingName, err := createWazuhStagingFile(root)
	if err != nil {
		return err
	}
	defer func() {
		if file != nil {
			_ = file.Close()
		}
		if stagingName != "" {
			_ = root.Remove(stagingName)
		}
	}()
	if identity.ownerKnown {
		if err := file.Chown(identity.uid, identity.gid); err != nil {
			return fmt.Errorf("preserve wazuh config owner: %w", err)
		}
	}
	if err := file.Chmod(identity.mode); err != nil {
		return fmt.Errorf("preserve wazuh config mode: %w", err)
	}
	if written, err := file.Write(content); err != nil {
		return fmt.Errorf("write wazuh staging file: %w", err)
	} else if written != len(content) {
		return fmt.Errorf("write wazuh staging file: %w", io.ErrShortWrite)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync wazuh staging file: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close wazuh staging file: %w", err)
	}
	file = nil
	if beforeRename != nil {
		if err := beforeRename(); err != nil {
			return err
		}
	}
	if err := verifyWazuhDestination(root, identity); err != nil {
		return err
	}
	if err := root.Rename(stagingName, wazuhConfigName); err != nil {
		return fmt.Errorf("publish wazuh config: %w", err)
	}
	stagingName = ""
	return syncWazuhDirectory(root)
}
