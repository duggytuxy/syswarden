package runtimepaths

import (
	"os"
	"path/filepath"
	"runtime"
)

const (
	linuxInstallRoot   = "/opt/syswarden"
	freeBSDInstallRoot = "/usr/local/syswarden"
)

// InstallRootFor returns the native package prefix for a target operating system.
func InstallRootFor(goos string) string {
	if goos == "freebsd" {
		return freeBSDInstallRoot
	}
	return linuxInstallRoot
}

// InstallRoot returns the package prefix for the running binary.
func InstallRoot() string {
	return InstallRootFor(runtime.GOOS)
}

// Signatures returns the native packaged signature database path.
func Signatures() string {
	return filepath.Join(InstallRoot(), "signatures.json")
}

// LegacyConfig returns the legacy flat configuration path for compatibility checks.
func LegacyConfig() string {
	return filepath.Join(InstallRoot(), "syswarden-auto.conf")
}

// ReadSignatures reads the fixed packaged database through a rooted directory handle.
func ReadSignatures() ([]byte, error) {
	return readFileAtRoot(InstallRoot(), "signatures.json")
}

func readFileAtRoot(rootPath, name string) ([]byte, error) {
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	return root.ReadFile(name)
}
