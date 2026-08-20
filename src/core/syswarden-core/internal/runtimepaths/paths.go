package runtimepaths

import (
	"os"
	"path/filepath"
)

const linuxInstallRoot = "/opt/syswarden"

// InstallRoot returns the Linux package prefix for the running binary.
func InstallRoot() string {
	return linuxInstallRoot
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
