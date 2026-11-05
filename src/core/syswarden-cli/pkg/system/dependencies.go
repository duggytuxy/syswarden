package system

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
)

var offlineQualificationDependencyLookPath = exec.LookPath

// InstallDependencies installs only base prerequisites for a manual install.
// Native package scripts never launch a nested package transaction. Selected
// optional modules are checked separately and require administrator-installed
// prerequisites from operator-approved repositories.
func InstallDependencies() error {
	fmt.Println("[INFO] Checking base system prerequisites...")
	if os.Getenv("SYSWARDEN_PKG_INSTALL") == "1" {
		if OfflineQualificationOperation() {
			if err := attestOfflineQualificationDependencies(); err != nil {
				return fmt.Errorf("attest offline package dependencies: %w", err)
			}
		}
		fmt.Println("[INFO] Package manager install detected. Skipping manual dependency resolution.")
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	return installBaseDependenciesWith(ctx, exec.LookPath, func(path string) error {
		if err := validateOfflineQualificationDependency(path, 0); err != nil {
			return err
		}
		canonical, err := filepath.EvalSymlinks(path)
		if err != nil {
			return err
		}
		return attestCronProviderDirectoryChain(filepath.Dir(canonical))
	}, runBaseDependencyCommand)
}

// baseDependencyArguments contains no optional module, repository setup,
// removal or trust override. An existing module selection does not authorize
// changing its prerequisites as a side effect of installing the base product.
func baseDependencyArguments(manager string, refresh bool) ([]string, error) {
	switch manager {
	case "/usr/bin/apt-get":
		if refresh {
			return []string{"update"}, nil
		}
		return []string{"install", "-y", "--no-install-recommends", "--no-remove",
			"bash-completion", "cron", "curl", "jq", "nftables", "procps", "wget"}, nil
	case "/usr/bin/dnf", "/usr/bin/yum":
		if !refresh {
			return []string{"install", "-y", "--setopt=install_weak_deps=False",
				"--setopt=clean_requirements_on_remove=False", "--setopt=obsoletes=False",
				"bash-completion", "cronie", "curl", "jq", "nftables", "procps-ng", "wget"}, nil
		}
	case "/sbin/apk", "/usr/sbin/apk":
		if !refresh {
			// OpenRC, the cron.d-capable provider and lifecycle account tools
			// are required on Alpine even with every optional module disabled.
			return []string{"add", "--no-cache", "bash-completion", "cronie", "cronie-openrc",
				"curl", "jq", "nftables", "openrc", "procps-ng", "shadow", "wget"}, nil
		}
	}
	return nil, errors.New("unsupported base dependency operation")
}

func installBaseDependenciesWith(ctx context.Context, look func(string) (string, error), validate func(string) error, run func(context.Context, string, bool) error) error {
	if ctx == nil || look == nil || validate == nil || run == nil {
		return errors.New("base dependency resolution is unavailable")
	}
	for _, name := range []string{"apt-get", "dnf", "yum", "apk"} {
		if err := ctx.Err(); err != nil {
			return err
		}
		path, err := look(name)
		if errors.Is(err, exec.ErrNotFound) {
			continue
		}
		if err != nil {
			return fmt.Errorf("resolve base dependency package manager %s: %w", name, err)
		}
		if !trustedPackageManagerPath(name, path) {
			return fmt.Errorf("package manager %q resolved to untrusted path %q", name, path)
		}
		if err := validate(path); err != nil {
			return fmt.Errorf("package manager %q is untrusted: %w", name, err)
		}
		if name == "apt-get" {
			if err := run(ctx, path, true); err != nil {
				return fmt.Errorf("refresh base dependency package metadata: %w", err)
			}
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := validate(path); err != nil {
			return fmt.Errorf("revalidate package manager %q before installation: %w", name, err)
		}
		if err := run(ctx, path, false); err != nil {
			return fmt.Errorf("install base dependencies with %s: %w", name, err)
		}
		return nil
	}
	return errors.New("no supported package manager found; install the required base prerequisites before retrying")
}

func runBaseDependencyCommand(ctx context.Context, manager string, refresh bool) error {
	if ctx == nil {
		return errors.New("base dependency context is unavailable")
	}
	command, err := baseDependencyCommand(manager, refresh)
	if err != nil {
		return err
	}
	return runQualificationProcessGroup(ctx, command)
}

// Build only the fixed base operation. Ambient package roots, configuration,
// loader/interpreter settings and working directories cannot redirect this
// transaction away from the system inspected by the installer.
func baseDependencyCommand(manager string, refresh bool) (*exec.Cmd, error) {
	args, err := baseDependencyArguments(manager, refresh)
	if err != nil {
		return nil, err
	}
	var cmd *exec.Cmd
	switch manager {
	case "/usr/bin/apt-get":
		cmd = exec.Command("/usr/bin/apt-get")
	case "/usr/bin/dnf":
		cmd = exec.Command("/usr/bin/dnf")
	case "/usr/bin/yum":
		cmd = exec.Command("/usr/bin/yum")
	case "/sbin/apk":
		cmd = exec.Command("/sbin/apk")
	case "/usr/sbin/apk":
		cmd = exec.Command("/usr/sbin/apk")
	default:
		return nil, errors.New("untrusted base dependency package manager")
	}
	cmd.Args = append([]string{cmd.Path}, args...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	cmd.Env = productionNativeCommandEnvironment()
	cmd.Dir = "/"
	return cmd, nil
}

func attestOfflineQualificationDependencies() error {
	return attestOfflineQualificationDependenciesWith(
		offlineQualificationDependencyLookPath,
		func(path string) error {
			return validateOfflineQualificationDependency(path, os.Geteuid())
		},
	)
}

func attestOfflineQualificationDependenciesWith(
	lookPath func(string) (string, error),
	validate func(string) error,
) error {
	if lookPath == nil || validate == nil {
		return errors.New("offline dependency attestation is unavailable")
	}
	type dependencyProfile struct {
		manager string
		paths   []string
	}
	profiles := []dependencyProfile{
		{
			manager: "apt-get",
			paths:   []string{"chattr", "cron", "curl", "ipset", "jq", "nft", "ps", "qrencode", "rsyslogd", "wg", "wget"},
		},
		{
			manager: "dnf",
			paths:   []string{"chattr", "checkpolicy", "crond", "curl", "ipset", "jq", "nft", "ps", "rsyslogd", "semanage", "wg", "wget"},
		},
		{
			manager: "yum",
			paths:   []string{"chattr", "checkpolicy", "crond", "curl", "ipset", "jq", "nft", "ps", "rsyslogd", "semanage", "wg", "wget"},
		},
		{
			manager: "apk",
			paths:   []string{"chattr", "crond", "curl", "jq", "nft", "ps", "qrencode", "rsyslogd", "wg", "wget"},
		},
	}
	for _, profile := range profiles {
		managerPath, err := lookPath(profile.manager)
		if err != nil {
			continue
		}
		if !trustedPackageManagerPath(profile.manager, managerPath) {
			return fmt.Errorf("package manager %q resolved to untrusted path %q", profile.manager, managerPath)
		}
		for _, dependency := range profile.paths {
			resolved, err := lookPath(dependency)
			if err != nil {
				return fmt.Errorf("required dependency %q is unavailable: %w", dependency, err)
			}
			if err := validate(resolved); err != nil {
				return fmt.Errorf("required dependency %q is untrusted: %w", dependency, err)
			}
		}
		return nil
	}
	return errors.New("no supported package manager is available for offline dependency attestation")
}

func validateOfflineQualificationDependency(path string, expectedUID int) error {
	return validateDependencyWithParentAttestation(path, expectedUID, attestCronProviderDirectoryChain)
}

// A protected executable alone is insufficient when an enclosing directory
// permits replacement. Optional-module and offline prerequisite checks share
// the same parent attestation used by native retention and base installation.
// This read-only observation is not a retained execution lease.
func validateDependencyWithParentAttestation(path string, expectedUID int, attestParents func(string) error) error {
	if expectedUID < 0 || attestParents == nil {
		return errors.New("dependency attestation is unavailable")
	}
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("dependency path is not canonical and absolute: %q", path)
	}
	if !nativeDependencySystemPath(path) {
		return errors.New("dependency lookup is outside trusted system directories")
	}
	canonical, err := resolveDependencyExecutableAt("/", path, expectedUID)
	if err != nil {
		return err
	}
	if !nativeDependencySystemPath(canonical) {
		return fmt.Errorf("dependency resolves outside trusted system directories: %q", canonical)
	}
	info, err := os.Stat(canonical)
	if err != nil {
		return err
	}
	status, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 || info.Mode().Perm()&0022 != 0 ||
		int(status.Uid) != expectedUID {
		return errors.New("dependency is not an owner-controlled regular executable")
	}
	return attestParents(filepath.Dir(canonical))
}

func nativeDependencySystemPath(path string) bool {
	switch filepath.Dir(path) {
	case "/bin", "/sbin", "/usr/bin", "/usr/sbin":
		return true
	}
	return false
}
