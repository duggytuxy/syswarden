//go:build linux

package security

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"syswarden-cli/config"

	"golang.org/x/sys/unix"
)

var cisSSHDaemonSignalPaths = []string{
	"/usr/sbin/sshd", "/usr/local/sbin/sshd", "/sbin/sshd", "/usr/lib/ssh/sshd",
	"/usr/libexec/openssh/sshd", "/usr/libexec/sshd", "/etc/ssh/sshd_config.d",
	"/etc/default/ssh", "/etc/sysconfig/sshd", "/etc/pam.d/sshd", "/etc/init.d/ssh",
	"/etc/init.d/sshd", "/etc/rc.d/init.d/ssh", "/etc/rc.d/init.d/sshd",
	"/etc/systemd/system/ssh.service", "/etc/systemd/system/sshd.service",
	"/etc/systemd/system/ssh.socket", "/etc/systemd/system/sshd.socket",
	"/run/systemd/system/ssh.service", "/run/systemd/system/sshd.service",
	"/run/systemd/system/ssh.socket", "/run/systemd/system/sshd.socket",
	"/lib/systemd/system/ssh.service", "/lib/systemd/system/sshd.service",
	"/lib/systemd/system/ssh.socket", "/lib/systemd/system/sshd.socket",
	"/usr/lib/systemd/system/ssh.service", "/usr/lib/systemd/system/sshd.service",
	"/usr/lib/systemd/system/ssh.socket", "/usr/lib/systemd/system/sshd.socket",
	"/usr/local/lib/systemd/system/ssh.service", "/usr/local/lib/systemd/system/sshd.service",
	"/usr/local/lib/systemd/system/ssh.socket", "/usr/local/lib/systemd/system/sshd.socket",
	"/etc/systemd/system/ssh.service.d", "/etc/systemd/system/sshd.service.d",
	"/etc/systemd/system/ssh.socket.d", "/etc/systemd/system/sshd.socket.d",
	"/run/systemd/system/ssh.service.d", "/run/systemd/system/sshd.service.d",
	"/run/systemd/system/ssh.socket.d", "/run/systemd/system/sshd.socket.d",
	"/etc/systemd/system/multi-user.target.wants/ssh.service",
	"/etc/systemd/system/multi-user.target.wants/sshd.service",
	"/etc/systemd/system/sockets.target.wants/ssh.socket",
	"/etc/systemd/system/sockets.target.wants/sshd.socket",
}

type hardeningStage struct {
	name string
	run  func() error
}

func runHardeningStages(stages []hardeningStage) error {
	var failures []error
	for _, stage := range stages {
		if err := stage.run(); err != nil {
			failures = append(failures, fmt.Errorf("%s: %w", stage.name, err))
		}
	}
	return errors.Join(failures...)
}

// ApplyCISHardening applies CIS Level 2 controls natively.
func ApplyCISHardening() error {
	if !config.GlobalConfig.CISL2Hardening {
		return nil
	}

	fmt.Println("[INFO] Applying CIS Level 2 System Hardening...")
	host := productionHardeningHost()
	return runHardeningStages([]hardeningStage{
		{name: "disable obscure filesystems", run: func() error { return disableObscureFilesystemsOn(host) }},
		{name: "disable uncommon protocols", run: func() error { return disableUncommonProtocolsOn(host) }},
		{name: "apply sysctl parameters", run: func() error { return applySysctlOn(host) }},
		{name: "restrict core dumps", run: func() error { return restrictCoreDumpsOn(host) }},
		{name: "apply CIS SSH hardening", run: func() error { return applySSHHardeningOn(host) }},
		{name: "secure cron permissions", run: func() error { return secureCronPermissionsOn(host) }},
		{name: "configure automatic security updates", run: func() error { return enableAutomaticSecurityUpdatesOn(host) }},
	})
}

func disableObscureFilesystemsOn(host hardeningHost) error {
	fmt.Println(" -> Disabling obscure filesystems (CIS 1.1.1.1 - 1.1.1.8)")
	content := `# --- SYSWARDEN: CIS Level 2 Filesystem Hardening ---
install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install squashfs /bin/true
install udf /bin/true
`
	if err := host.write("/etc/modprobe.d/syswarden-cis-fs.conf", []byte(content), 0600); err != nil {
		return err
	}
	active, reason, err := hardeningKernelRuntimeApplicable(host, "kernel module removal")
	if err != nil {
		return err
	}
	if !active {
		reportHardeningRuntimeNotApplicable("kernel module removal", reason)
		return nil
	}
	return removeLoadedModules(host, []string{"cramfs", "freevxfs", "jffs2", "hfs", "hfsplus", "squashfs", "udf"})
}

func disableUncommonProtocolsOn(host hardeningHost) error {
	fmt.Println(" -> Disabling uncommon network protocols (CIS 3.3.1 - 3.3.4)")
	content := `# --- SYSWARDEN: CIS Level 2 Network Protocol Hardening ---
install dccp /bin/true
install sctp /bin/true
install rds /bin/true
install tipc /bin/true
`
	if err := host.write("/etc/modprobe.d/syswarden-cis-net.conf", []byte(content), 0600); err != nil {
		return err
	}
	active, reason, err := hardeningKernelRuntimeApplicable(host, "kernel protocol module removal")
	if err != nil {
		return err
	}
	if !active {
		reportHardeningRuntimeNotApplicable("kernel protocol module removal", reason)
		return nil
	}
	return removeLoadedModules(host, []string{"dccp", "sctp", "rds", "tipc"})
}

func loadedKernelModules(host hardeningHost) (map[string]struct{}, error) {
	snapshot, err := host.snapshot("/proc/modules")
	if err != nil {
		return nil, err
	}
	loaded := make(map[string]struct{})
	if !snapshot.existed {
		return loaded, nil
	}
	for _, line := range strings.Split(string(snapshot.content), "\n") {
		fields := strings.Fields(line)
		if len(fields) > 0 {
			loaded[fields[0]] = struct{}{}
		}
	}
	return loaded, nil
}

func removeLoadedModules(host hardeningHost, modules []string) error {
	loaded, err := loadedKernelModules(host)
	if err != nil {
		return fmt.Errorf("inspect loaded modules: %w", err)
	}
	for _, module := range modules {
		if _, present := loaded[module]; !present {
			continue
		}
		if err := host.executor.run("rmmod", module); err != nil {
			return fmt.Errorf("remove loaded module %s: %w", module, err)
		}
	}
	remaining, err := loadedKernelModules(host)
	if err != nil {
		return fmt.Errorf("reinspect loaded modules: %w", err)
	}
	for _, module := range modules {
		if _, present := remaining[module]; present {
			return fmt.Errorf("module remains loaded after removal: %s", module)
		}
	}
	return nil
}

func applySysctlOn(host hardeningHost) error {
	fmt.Println(" -> Applying strict kernel parameters (CIS 1.5, 3.2)")
	content := `# --- SYSWARDEN: CIS Level 2 Kernel Hardening ---
fs.suid_dumpable = 0
kernel.randomize_va_space = 2
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
kernel.yama.ptrace_scope = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.tcp_syncookies = 1
`
	logical := "/etc/sysctl.d/99-syswarden-cis-level2.conf"
	physical, err := host.path(logical)
	if err != nil {
		return err
	}
	expected := map[string]string{
		"fs.suid_dumpable": "0", "kernel.randomize_va_space": "2", "kernel.unprivileged_bpf_disabled": "1",
		"net.core.bpf_jit_harden": "2", "kernel.dmesg_restrict": "1", "kernel.kptr_restrict": "2",
		"kernel.yama.ptrace_scope": "1", "net.ipv4.conf.all.accept_source_route": "0",
		"net.ipv4.conf.default.accept_source_route": "0", "net.ipv4.conf.all.accept_redirects": "0",
		"net.ipv4.conf.default.accept_redirects": "0", "net.ipv4.conf.all.secure_redirects": "0",
		"net.ipv4.conf.default.secure_redirects": "0", "net.ipv4.conf.all.log_martians": "1",
		"net.ipv4.conf.default.log_martians": "1", "net.ipv4.conf.all.rp_filter": "1",
		"net.ipv4.conf.default.rp_filter": "1", "net.ipv4.tcp_syncookies": "1",
	}
	bpfJITHardeningAvailable, err := host.regularFileExists("/proc/sys/net/core/bpf_jit_harden")
	if err != nil {
		return fmt.Errorf("inspect BPF JIT hardening control: %w", err)
	}
	if !bpfJITHardeningAvailable {
		delete(expected, "net.core.bpf_jit_harden")
		content = strings.Replace(content, "net.core.bpf_jit_harden = 2\n", "", 1)
		fmt.Println(" -> BPF JIT hardening sysctl is unavailable; the kernel control is not applicable.")
	}
	runtimeActive, reason, err := hardeningKernelRuntimeApplicable(host, "kernel sysctl")
	if err != nil {
		return err
	}
	if !runtimeActive {
		for _, key := range []string{"kernel.unprivileged_bpf_disabled", "kernel.yama.ptrace_scope"} {
			value, present, err := readKernelControlOn(host, key)
			if err != nil {
				return fmt.Errorf("read persistent-policy baseline %s: %w", key, err)
			}
			if !present {
				continue
			}
			switch {
			case key == "kernel.unprivileged_bpf_disabled" && value == "2":
				expected[key] = value
				content = strings.Replace(content, "kernel.unprivileged_bpf_disabled = 1", "kernel.unprivileged_bpf_disabled = 2", 1)
			case key == "kernel.yama.ptrace_scope" && (value == "2" || value == "3"):
				expected[key] = value
				content = strings.Replace(content, "kernel.yama.ptrace_scope = 1", "kernel.yama.ptrace_scope = "+value, 1)
			}
		}
		if err := host.applyManagedFile(logical, []byte(content), nil, nil); err != nil {
			return err
		}
		reportHardeningRuntimeNotApplicable("kernel sysctl", reason)
		return nil
	}
	previous := make(map[string]string, len(expected))
	for key := range expected {
		output, err := host.executor.output("sysctl", "-n", key)
		if err != nil {
			return fmt.Errorf("snapshot effective sysctl %s: %w", key, err)
		}
		previous[key] = strings.TrimSpace(string(output))
	}
	if previous["kernel.unprivileged_bpf_disabled"] == "2" {
		expected["kernel.unprivileged_bpf_disabled"] = "2"
		content = strings.Replace(content, "kernel.unprivileged_bpf_disabled = 1", "kernel.unprivileged_bpf_disabled = 2", 1)
	}
	if previous["kernel.yama.ptrace_scope"] == "2" || previous["kernel.yama.ptrace_scope"] == "3" {
		expected["kernel.yama.ptrace_scope"] = previous["kernel.yama.ptrace_scope"]
		content = strings.Replace(content, "kernel.yama.ptrace_scope = 1", "kernel.yama.ptrace_scope = "+previous["kernel.yama.ptrace_scope"], 1)
	}
	activating := true
	reload := func() error {
		if activating {
			activating = false
			if err := host.executor.run("sysctl", "-p", physical); err != nil {
				return fmt.Errorf("apply sysctl policy: %w", err)
			}
			return attestSysctlValues(host, expected)
		}
		var failures []error
		for key, value := range previous {
			if err := host.executor.run("sysctl", "-w", key+"="+value); err != nil {
				failures = append(failures, fmt.Errorf("restore sysctl %s: %w", key, err))
			}
		}
		failures = append(failures, attestSysctlValues(host, previous))
		return errors.Join(failures...)
	}
	return host.applyManagedFile(logical, []byte(content), nil, reload)
}

func readKernelControlOn(host hardeningHost, key string) (string, bool, error) {
	logical := "/proc/sys/" + strings.ReplaceAll(key, ".", "/")
	snapshot, err := host.snapshot(logical)
	if errors.Is(err, fs.ErrNotExist) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	if !snapshot.existed {
		return "", false, nil
	}
	value := strings.TrimSpace(string(snapshot.content))
	if value == "" || len(strings.Fields(value)) != 1 {
		return "", false, fmt.Errorf("kernel control %s has invalid value %q", key, value)
	}
	return value, true, nil
}

func attestSysctlValues(host hardeningHost, expected map[string]string) error {
	for key, want := range expected {
		output, err := host.executor.output("sysctl", "-n", key)
		if err != nil {
			return fmt.Errorf("read effective sysctl %s: %w", key, err)
		}
		if got := strings.TrimSpace(string(output)); got != want {
			return fmt.Errorf("effective sysctl %s=%q, want %q", key, got, want)
		}
	}
	return nil
}

func restrictCoreDumpsOn(host hardeningHost) error {
	fmt.Println(" -> Enforcing hard limits on core dumps (CIS 1.5.1)")
	limitsContent := "# --- SYSWARDEN: CIS Level 2 Limits ---\n* hard core 0\n"
	if err := host.write("/etc/security/limits.d/99-syswarden-cis.conf", []byte(limitsContent), 0600); err != nil {
		return err
	}
	decision, err := host.executionDecision()
	if err != nil {
		return fmt.Errorf("classify systemd coredump execution context: %w", err)
	}
	if decision.state == hardeningExecutionDeferred {
		return fmt.Errorf("systemd coredump policy cannot be deferred without a verified offline context")
	}
	installed, runtimeActive, err := host.systemdCoredumpPolicyRuntime(decision)
	if err != nil {
		return fmt.Errorf("classify systemd coredump policy surface: %w", err)
	}
	if !installed {
		fmt.Println(" -> Systemd coredump policy is not applicable because no complete trusted coredump consumer is installed. The limits policy remains attested; no systemd coredump policy was claimed.")
		return nil
	}
	content := []byte("[Coredump]\nStorage=none\nProcessSizeMax=0\n")
	validate := func() error {
		output, err := host.executor.output("systemd-analyze", "cat-config", "systemd/coredump.conf")
		if err != nil {
			return err
		}
		values := lastAssignments(string(output), "Storage", "ProcessSizeMax")
		if values["storage"] != "none" || values["processsizemax"] != "0" {
			return fmt.Errorf("effective coredump settings are not Storage=none and ProcessSizeMax=0")
		}
		return nil
	}
	logical := "/etc/systemd/coredump.conf.d/99-syswarden.conf"
	if !runtimeActive {
		if err := host.applyManagedFile(logical, content, validate, nil); err != nil {
			return err
		}
		fmt.Println(" -> Systemd coredump policy was written, validated, and attested for the installed consumer. No current runtime activation is claimed.")
		return nil
	}
	return host.applyManagedFile(logical, content, validate, func() error {
		return host.executor.run("systemctl", "daemon-reload")
	})
}

func lastAssignments(content string, keys ...string) map[string]string {
	wanted := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		wanted[strings.ToLower(key)] = struct{}{}
	}
	values := make(map[string]string, len(keys))
	for _, raw := range strings.Split(content, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(parts[0]))
		if _, ok := wanted[key]; ok {
			values[key] = strings.TrimSpace(parts[1])
		}
	}
	return values
}

func applySSHHardeningOn(host hardeningHost) error {
	fmt.Println(" -> Applying CIS Level 2 SSH Hardening (CIS 5.2)")
	sshdConfig, err := host.snapshot("/etc/ssh/sshd_config")
	if errors.Is(err, fs.ErrNotExist) {
		sshdConfig = hardeningFileSnapshot{}
		err = nil
	}
	if err != nil {
		return err
	}
	if !sshdConfig.existed {
		for _, signal := range cisSSHDaemonSignalPaths {
			present, err := cisSSHSignalPresent(host, signal)
			if err != nil {
				return fmt.Errorf("inspect SSH daemon component %s: %w", signal, err)
			}
			if present {
				return fmt.Errorf("SSH daemon component %s exists but /etc/ssh/sshd_config is absent", signal)
			}
		}
		fmt.Println(" -> SSH server configuration absent; CIS SSH controls are not applicable.")
		return nil
	}
	decision, err := host.executionDecision()
	if err != nil {
		return fmt.Errorf("classify SSH service execution context: %w", err)
	}
	if decision.state == hardeningExecutionDeferred {
		return fmt.Errorf("SSH service activation cannot be deferred without a verified offline policy path")
	}
	offline := decision.state == hardeningExecutionNotApplicable && decision.packageInstall && decision.manager == ""
	if decision.state == hardeningExecutionNotApplicable && !offline {
		return fmt.Errorf("SSH service is inactive outside a verified package-hook context")
	}
	if offline {
		running, err := host.processNamedRunning("sshd")
		if err != nil {
			return fmt.Errorf("prove sshd is stopped before offline configuration: %w", err)
		}
		if running {
			return fmt.Errorf("sshd is running without an active service manager; refusing unactivated SSH policy")
		}
	}
	normalized, err := normalizeCISSSHConfiguration(string(sshdConfig.content))
	if err != nil {
		return err
	}
	content := []byte(normalized)
	validate := func() error {
		if err := host.executor.run("sshd", "-t"); err != nil {
			return err
		}
		output, err := host.executor.output("sshd", "-T")
		if err != nil {
			return err
		}
		values := sshdEffectiveValues(output)
		expected := map[string]string{"x11forwarding": "no", "maxauthtries": "4", "clientaliveinterval": "300", "clientalivecountmax": "3"}
		for key, want := range expected {
			if got := values[key]; got != want {
				return fmt.Errorf("effective sshd %s=%q, want %q", key, got, want)
			}
		}
		return nil
	}
	reload := func() error { return restartSSHDaemon(host) }
	if offline {
		reload = func() error {
			running, err := host.processNamedRunning("sshd")
			if err != nil {
				return fmt.Errorf("prove sshd remains stopped after offline configuration: %w", err)
			}
			if running {
				return fmt.Errorf("sshd started during offline SSH policy publication")
			}
			return nil
		}
	}
	if err := host.applyManagedFileFromSnapshot("/etc/ssh/sshd_config", sshdConfig, content, validate, reload); err != nil {
		return err
	}
	if offline {
		fmt.Println(" -> SSH policy was written, validated, and attested while sshd was stopped. No manager command or current runtime activation is claimed.")
	}
	return nil
}

func cisSSHSignalPresent(host hardeningHost, logical string) (bool, error) {
	if logical != "/etc/ssh/sshd_config.d" {
		return host.pathEntryExists(logical)
	}
	physical, err := host.path(logical)
	if err != nil {
		return false, err
	}
	info, err := os.Lstat(physical)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 {
		return true, nil
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false, fmt.Errorf("SSH drop-in directory ownership is unavailable")
	}
	if int(stat.Uid) != host.expectedRootUID {
		return true, nil
	}
	fd, err := syscall.Open(physical, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return false, err
	}
	directory := os.NewFile(uintptr(fd), physical)
	if directory == nil {
		_ = syscall.Close(fd)
		return false, fmt.Errorf("open SSH drop-in directory")
	}
	defer func() { _ = directory.Close() }()
	opened, err := directory.Stat()
	if err != nil {
		return false, err
	}
	if !opened.IsDir() || !os.SameFile(info, opened) || opened.Mode() != info.Mode() ||
		opened.Size() != info.Size() || !opened.ModTime().Equal(info.ModTime()) {
		return false, fmt.Errorf("SSH drop-in directory changed while opening")
	}
	names, err := directory.Readdirnames(1)
	if err != nil && !errors.Is(err, io.EOF) {
		return false, err
	}
	after, err := directory.Stat()
	if err != nil {
		return false, err
	}
	if !os.SameFile(opened, after) || opened.Mode() != after.Mode() ||
		opened.Size() != after.Size() || !opened.ModTime().Equal(after.ModTime()) {
		return false, fmt.Errorf("SSH drop-in directory changed while inspecting")
	}
	return len(names) != 0, nil
}

func normalizeCISSSHConfiguration(content string) (string, error) {
	directives := map[string]string{
		"x11forwarding":       "X11Forwarding no",
		"maxauthtries":        "MaxAuthTries 4",
		"clientaliveinterval": "ClientAliveInterval 300",
		"clientalivecountmax": "ClientAliveCountMax 3",
	}
	lines := strings.Split(content, "\n")
	filtered := make([]string, 0, len(lines)+6)
	insertAt := -1
	inManagedBlock := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "# --- SYSWARDEN CIS SSH HARDENING ---" {
			if inManagedBlock {
				return "", fmt.Errorf("nested SYSWARDEN CIS SSH managed block")
			}
			inManagedBlock = true
			continue
		}
		if trimmed == "# ------------------------------------" && !inManagedBlock {
			return "", fmt.Errorf("orphan SYSWARDEN CIS SSH managed-block terminator")
		}
		if inManagedBlock {
			if trimmed == "# ------------------------------------" {
				inManagedBlock = false
			}
			continue
		}
		fields := strings.Fields(strings.Replace(trimmed, "=", " ", 1))
		if len(fields) > 0 && !strings.HasPrefix(trimmed, "#") {
			key := strings.ToLower(fields[0])
			if _, managed := directives[key]; managed {
				filtered = append(filtered, "# SYSWARDEN OVERRIDE: "+line)
				continue
			}
			if insertAt < 0 && (key == "include" || key == "match") {
				insertAt = len(filtered)
			}
		}
		filtered = append(filtered, line)
	}
	if inManagedBlock {
		return "", fmt.Errorf("unterminated SYSWARDEN CIS SSH managed block")
	}
	block := []string{
		"# --- SYSWARDEN CIS SSH HARDENING ---",
		directives["x11forwarding"], directives["maxauthtries"],
		directives["clientaliveinterval"], directives["clientalivecountmax"],
		"# ------------------------------------",
	}
	if insertAt < 0 {
		insertAt = len(filtered)
	}
	result := make([]string, 0, len(filtered)+len(block))
	result = append(result, filtered[:insertAt]...)
	result = append(result, block...)
	result = append(result, filtered[insertAt:]...)
	return strings.Join(result, "\n"), nil
}

func sshdEffectiveValues(output []byte) map[string]string {
	values := make(map[string]string)
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			values[strings.ToLower(fields[0])] = strings.Join(fields[1:], " ")
		}
	}
	return values
}

func restartSSHDaemon(host hardeningHost) error {
	alpine, err := host.markerExists("/etc/alpine-release")
	if err != nil {
		return err
	}
	if alpine {
		return host.executor.run("rc-service", "sshd", "restart")
	}
	var diagnostics []error
	for _, unit := range []string{"ssh.service", "sshd.service"} {
		output, err := host.executor.output("systemctl", "show", "--property=LoadState", "--value", unit)
		if err != nil {
			diagnostics = append(diagnostics, err)
			continue
		}
		if strings.TrimSpace(string(output)) != "loaded" {
			continue
		}
		return host.executor.run("systemctl", "restart", unit)
	}
	return errors.Join(append([]error{fmt.Errorf("no loaded SSH systemd unit found")}, diagnostics...)...)
}

func secureCronPermissionsOn(host hardeningHost) error {
	fmt.Println(" -> Securing cron directories permissions (CIS 5.1)")
	cronDirs := []string{"/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly", "/etc/cron.weekly", "/etc/cron.monthly"}
	for _, dir := range cronDirs {
		if _, err := host.securePathPermissions(dir, true, 0700, 0, 0); err != nil {
			return err
		}
	}
	_, err := host.securePathPermissions("/etc/crontab", false, 0600, 0, 0)
	return err
}

func enableAutomaticSecurityUpdatesOn(host hardeningHost) error {
	fmt.Println(" -> Configuring automatic security updates (Zero-Day defense)")
	decision, err := host.executionDecision()
	if err != nil {
		return fmt.Errorf("classify automatic-update execution context: %w", err)
	}
	if decision.state == hardeningExecutionDeferred {
		return fmt.Errorf("automatic security updates cannot be deferred without an attested convergence path")
	}
	if decision.state != hardeningExecutionActive && decision.state != hardeningExecutionNotApplicable {
		return fmt.Errorf("automatic security-update execution context has unknown state %d", decision.state)
	}
	distributionID, family, err := linuxDistributionIdentityOn(host)
	if err != nil {
		return err
	}
	switch family {
	case "debian":
		if decision.packageInstall {
			for _, dependency := range []string{"/usr/bin/unattended-upgrade", "/usr/bin/apt-listchanges"} {
				available, err := host.regularFileExists(dependency)
				if errors.Is(err, fs.ErrNotExist) {
					available = false
					err = nil
				}
				if err != nil {
					return fmt.Errorf("inspect automatic-update package payload %s: %w", dependency, err)
				}
				if !available {
					return fmt.Errorf("%s is not preinstalled; refusing recursive APT from a package hook", dependency)
				}
			}
		} else if err := host.executor.run("apt-get", "install", "-y", "-q", "unattended-upgrades", "apt-listchanges"); err != nil {
			return err
		}
		content := []byte("APT::Periodic::Update-Package-Lists \"1\";\nAPT::Periodic::Unattended-Upgrade \"1\";\n")
		logical := "/etc/apt/apt.conf.d/20auto-upgrades"
		snapshot, err := host.snapshot(logical)
		if err != nil {
			return err
		}
		return applyAutomaticUpdatePolicy(host, logical, snapshot, content, decision, "apt-daily.timer", "apt-daily-upgrade.timer")
	case "redhat":
		packageName := "dnf-automatic"
		timer := "dnf-automatic.timer"
		if distributionID == "fedora" {
			packageName = "dnf5-plugin-automatic"
			timer = "dnf5-automatic.timer"
		}
		if !decision.packageInstall {
			if err := host.executor.run("dnf", "install", "-y", "-q", packageName); err != nil {
				return err
			}
		}
		logical := "/etc/dnf/automatic.conf"
		snapshot, err := host.snapshot(logical)
		if errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("inspect dnf automatic-update configuration: %w", err)
		}
		if err != nil {
			return err
		}
		input := snapshot.content
		if !snapshot.existed {
			if distributionID != "fedora" {
				if decision.packageInstall {
					return fmt.Errorf("dnf-automatic is not preinstalled; refusing recursive DNF from a package hook")
				}
				return fmt.Errorf("dnf-automatic configuration is absent after installation")
			}
			templateLogical := "/usr/share/dnf5/dnf5-plugins/automatic.conf"
			template, present, err := offlineAutomaticUpdateUnitAt(host, templateLogical)
			if err != nil {
				return fmt.Errorf("inspect Fedora automatic-update template: %w", err)
			}
			if !present {
				if decision.packageInstall {
					return fmt.Errorf("dnf5-plugin-automatic is not preinstalled; refusing recursive DNF from a package hook")
				}
				return fmt.Errorf("Fedora automatic-update template is absent after installation")
			}
			unitLogical := "/usr/lib/systemd/system/" + timer
			if _, present, err := offlineAutomaticUpdateUnitAt(host, unitLogical); err != nil {
				return fmt.Errorf("inspect Fedora automatic-update timer payload: %w", err)
			} else if !present {
				if decision.packageInstall {
					return fmt.Errorf("dnf5-plugin-automatic timer is not preinstalled; refusing recursive DNF from a package hook")
				}
				return fmt.Errorf("Fedora automatic-update timer is absent after installation")
			}
			input = template.content
		}
		content, err := renderDNFAutomaticConfiguration(input)
		if err != nil {
			return err
		}
		return applyAutomaticUpdatePolicy(host, logical, snapshot, content, decision, timer)
	case "alpine":
		fmt.Println(" -> Alpine automatic-update scheduling is intentionally left to the package/operator policy.")
		return nil
	default:
		return fmt.Errorf("automatic security updates are unsupported on this Linux distribution")
	}
}

type automaticUpdateTimerSnapshot struct {
	name    string
	enabled bool
	active  bool
}

func applyAutomaticUpdatePolicy(
	host hardeningHost,
	logical string,
	configSnapshot hardeningFileSnapshot,
	content []byte,
	decision hardeningExecutionDecision,
	timers ...string,
) error {
	if len(timers) == 0 {
		return fmt.Errorf("automatic-update timer list is empty")
	}
	runtimeActive := decision.state == hardeningExecutionActive
	if decision.packageInstall && decision.manager == "" {
		runtimeActive = false
	}
	if !runtimeActive {
		return applyOfflineAutomaticUpdatePolicy(host, logical, configSnapshot, content, timers...)
	}
	snapshots := make([]automaticUpdateTimerSnapshot, 0, len(timers))
	for _, timer := range timers {
		if timer == "" || strings.ContainsAny(timer, "/\x00\r\n \t") {
			return fmt.Errorf("automatic-update timer name is invalid")
		}
		enabled, err := automaticUpdateTimerEnabled(host, timer)
		if err != nil {
			return fmt.Errorf("snapshot automatic-update timer enablement %s: %w", timer, err)
		}
		active, err := automaticUpdateTimerActive(host, timer)
		if err != nil {
			return fmt.Errorf("snapshot automatic-update timer activation %s: %w", timer, err)
		}
		snapshots = append(snapshots, automaticUpdateTimerSnapshot{name: timer, enabled: enabled, active: active})
	}
	if err := host.applyManagedFileFromSnapshot(logical, configSnapshot, content, nil, nil); err != nil {
		return err
	}
	rollback := func(cause error) error {
		var failures []error
		for index := len(snapshots) - 1; index >= 0; index-- {
			if err := restoreAutomaticUpdateTimer(host, snapshots[index], runtimeActive); err != nil {
				failures = append(failures, err)
			}
		}
		if err := host.restore(logical, configSnapshot, content); err != nil {
			failures = append(failures, fmt.Errorf("restore automatic-update configuration: %w", err))
		}
		return errors.Join(append([]error{cause}, failures...)...)
	}
	for _, snapshot := range snapshots {
		if !snapshot.enabled {
			if err := host.executor.run("systemctl", "enable", snapshot.name); err != nil {
				return rollback(fmt.Errorf("enable automatic-update timer %s: %w", snapshot.name, err))
			}
		}
		enabled, err := automaticUpdateTimerEnabled(host, snapshot.name)
		if err != nil || !enabled {
			if err == nil {
				err = fmt.Errorf("timer remains disabled")
			}
			return rollback(fmt.Errorf("attest automatic-update timer enablement %s: %w", snapshot.name, err))
		}
	}
	for _, snapshot := range snapshots {
		if !snapshot.active {
			if err := host.executor.run("systemctl", "start", snapshot.name); err != nil {
				return rollback(fmt.Errorf("start automatic-update timer %s: %w", snapshot.name, err))
			}
		}
		active, err := automaticUpdateTimerActive(host, snapshot.name)
		if err != nil || !active {
			if err == nil {
				err = fmt.Errorf("timer remains inactive")
			}
			return rollback(fmt.Errorf("attest automatic-update timer activation %s: %w", snapshot.name, err))
		}
	}
	return nil
}

type offlineAutomaticUpdateTimerSnapshot struct {
	name           string
	sourceLogical  string
	sourceSnapshot hardeningFileSnapshot
	linkLogical    string
	linkTarget     string
	linkExisted    bool
	linkCreated    bool
	publishedLink  fs.FileInfo
}

func offlineAutomaticUpdateUnitAt(host hardeningHost, logical string) (hardeningFileSnapshot, bool, error) {
	exists, err := host.trustedStructuralRegularFile(logical, false)
	if err != nil || !exists {
		return hardeningFileSnapshot{}, exists, err
	}
	snapshot, err := host.snapshot(logical)
	if err != nil {
		return hardeningFileSnapshot{}, false, err
	}
	if !snapshot.existed {
		return hardeningFileSnapshot{}, false, fmt.Errorf("automatic-update unit disappeared after structural attestation: %s", logical)
	}
	return snapshot, true, nil
}

func trustedLibAliasToUsr(host hardeningHost) (bool, bool, error) {
	physical, err := host.path("/lib")
	if err != nil {
		return false, false, err
	}
	if err := host.verifyHardeningDirectoryChain(filepath.Dir(physical)); err != nil {
		return false, false, err
	}
	info, err := os.Lstat(physical)
	if errors.Is(err, fs.ErrNotExist) {
		return false, false, nil
	}
	if err != nil {
		return false, false, err
	}
	if info.IsDir() && info.Mode()&os.ModeSymlink == 0 {
		return true, false, nil
	}
	if info.Mode()&os.ModeSymlink == 0 {
		return false, false, fmt.Errorf("/lib is neither a real directory nor the trusted usr/lib alias")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 || int(stat.Uid) != host.expectedRootUID || int(stat.Gid) != host.expectedRootGID {
		return false, false, fmt.Errorf("/lib alias has unsafe ownership or links")
	}
	target, err := os.Readlink(physical)
	if err != nil || (target != "usr/lib" && target != "/usr/lib") {
		return false, false, fmt.Errorf("/lib has an untrusted symlink target %q", target)
	}
	after, err := os.Lstat(physical)
	if err != nil || !os.SameFile(info, after) || after.Mode() != info.Mode() {
		return false, false, fmt.Errorf("/lib alias changed during attestation")
	}
	afterTarget, err := os.Readlink(physical)
	if err != nil || afterTarget != target {
		return false, false, fmt.Errorf("/lib alias target changed during attestation")
	}
	return false, true, nil
}

func resolveOfflineAutomaticUpdateTimer(host hardeningHost, timer string) (offlineAutomaticUpdateTimerSnapshot, error) {
	if timer == "" || strings.ContainsAny(timer, "/\x00\r\n \t") {
		return offlineAutomaticUpdateTimerSnapshot{}, fmt.Errorf("automatic-update timer name is invalid")
	}
	usrLogical := "/usr/lib/systemd/system/" + timer
	usrSnapshot, usrExists, err := offlineAutomaticUpdateUnitAt(host, usrLogical)
	if err != nil {
		return offlineAutomaticUpdateTimerSnapshot{}, err
	}
	libReal, libAlias, err := trustedLibAliasToUsr(host)
	if err != nil {
		return offlineAutomaticUpdateTimerSnapshot{}, err
	}
	libLogical := "/lib/systemd/system/" + timer
	var libSnapshot hardeningFileSnapshot
	libExists := false
	if libReal {
		libSnapshot, libExists, err = offlineAutomaticUpdateUnitAt(host, libLogical)
		if err != nil {
			return offlineAutomaticUpdateTimerSnapshot{}, err
		}
	}
	if libAlias && !usrExists {
		return offlineAutomaticUpdateTimerSnapshot{}, fmt.Errorf("automatic-update timer source is absent through the trusted /lib alias: %s", timer)
	}
	if usrExists && libExists && !os.SameFile(usrSnapshot.identity.info, libSnapshot.identity.info) {
		return offlineAutomaticUpdateTimerSnapshot{}, fmt.Errorf("automatic-update timer has multiple distinct source units: %s", timer)
	}
	sourceLogical := usrLogical
	sourceSnapshot := usrSnapshot
	if !usrExists && libExists {
		sourceLogical = libLogical
		sourceSnapshot = libSnapshot
	}
	if !usrExists && !libExists {
		return offlineAutomaticUpdateTimerSnapshot{}, fmt.Errorf("automatic-update timer source unit is absent: %s", timer)
	}
	return offlineAutomaticUpdateTimerSnapshot{
		name:           timer,
		sourceLogical:  sourceLogical,
		sourceSnapshot: sourceSnapshot,
		linkLogical:    "/etc/systemd/system/timers.target.wants/" + timer,
		linkTarget:     sourceLogical,
	}, nil
}

func attestOfflineAutomaticUpdateSource(host hardeningHost, snapshot offlineAutomaticUpdateTimerSnapshot) error {
	exists, err := host.trustedStructuralRegularFile(snapshot.sourceLogical, false)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("automatic-update source unit disappeared: %s", snapshot.sourceLogical)
	}
	current, err := host.snapshot(snapshot.sourceLogical)
	if err != nil {
		return err
	}
	if !current.existed || !sameSecurityFileState(snapshot.sourceSnapshot.identity, current.identity.info, current.identity.digest) {
		return fmt.Errorf("automatic-update source unit changed during transaction: %s", snapshot.sourceLogical)
	}
	return nil
}

type offlineAutomaticUpdateCreatedDirectory struct {
	parentPhysical string
	name           string
	identity       fs.FileInfo
}

func prepareOfflineAutomaticUpdateLinkParent(host hardeningHost, logical string) ([]offlineAutomaticUpdateCreatedDirectory, error) {
	physical, err := host.path(logical)
	if err != nil {
		return nil, err
	}
	directory := filepath.Dir(physical)
	rootPath := filepath.Clean(host.root)
	relative, err := filepath.Rel(rootPath, directory)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return nil, fmt.Errorf("automatic-update link parent escapes root")
	}
	rootInfo, err := os.Lstat(rootPath)
	if err != nil {
		return nil, fmt.Errorf("inspect automatic-update policy root: %w", err)
	}
	if err := validateHardeningDirectoryInfo(rootPath, rootInfo, host.expectedRootUID, host.expectedRootGID); err != nil {
		return nil, err
	}
	current, err := os.OpenRoot(rootPath)
	if err != nil {
		return nil, err
	}
	openedRoot, err := current.Stat(".")
	if err != nil || !os.SameFile(rootInfo, openedRoot) || openedRoot.Mode() != rootInfo.Mode() {
		_ = current.Close()
		return nil, fmt.Errorf("automatic-update policy root changed while opening")
	}
	currentPath := rootPath
	var created []offlineAutomaticUpdateCreatedDirectory
	fail := func(cause error) ([]offlineAutomaticUpdateCreatedDirectory, error) {
		_ = current.Close()
		return nil, errors.Join(cause, removeCreatedAutomaticUpdateDirectories(host, created))
	}
	for _, component := range strings.Split(relative, string(filepath.Separator)) {
		if component == "" || component == "." {
			continue
		}
		componentPath := filepath.Join(currentPath, component)
		info, inspectErr := current.Lstat(component)
		createdNow := false
		if errors.Is(inspectErr, fs.ErrNotExist) {
			if err := current.Mkdir(component, 0750); err != nil {
				if !errors.Is(err, fs.ErrExist) {
					return fail(fmt.Errorf("create automatic-update directory %s: %w", componentPath, err))
				}
			} else {
				createdNow = true
			}
			info, inspectErr = current.Lstat(component)
		}
		if inspectErr != nil {
			return fail(fmt.Errorf("inspect automatic-update directory %s: %w", componentPath, inspectErr))
		}
		if err := validateHardeningDirectoryInfo(componentPath, info, host.expectedRootUID, host.expectedRootGID); err != nil {
			return fail(err)
		}
		next, err := current.OpenRoot(component)
		if err != nil {
			return fail(fmt.Errorf("open automatic-update directory %s: %w", componentPath, err))
		}
		opened, statErr := next.Stat(".")
		if statErr != nil || !os.SameFile(info, opened) || opened.Mode() != info.Mode() {
			_ = next.Close()
			return fail(fmt.Errorf("automatic-update directory changed while opening: %s", componentPath))
		}
		if createdNow {
			if host.directorySync == nil {
				_ = next.Close()
				return fail(fmt.Errorf("directory sync operation is unavailable"))
			}
			if err := host.directorySync(current); err != nil {
				_ = next.Close()
				created = append(created, offlineAutomaticUpdateCreatedDirectory{parentPhysical: currentPath, name: component, identity: info})
				return fail(fmt.Errorf("sync created automatic-update directory %s: %w", componentPath, err))
			}
			created = append(created, offlineAutomaticUpdateCreatedDirectory{parentPhysical: currentPath, name: component, identity: info})
		}
		_ = current.Close()
		current = next
		currentPath = componentPath
	}
	if err := current.Close(); err != nil {
		return nil, errors.Join(err, removeCreatedAutomaticUpdateDirectories(host, created))
	}
	return created, nil
}

func removeCreatedAutomaticUpdateDirectories(host hardeningHost, created []offlineAutomaticUpdateCreatedDirectory) error {
	var failures []error
	for index := len(created) - 1; index >= 0; index-- {
		record := created[index]
		if err := host.verifyHardeningDirectoryChain(record.parentPhysical); err != nil {
			failures = append(failures, fmt.Errorf("attest automatic-update directory parent %s: %w", record.parentPhysical, err))
			continue
		}
		root, err := os.OpenRoot(record.parentPhysical)
		if err != nil {
			failures = append(failures, fmt.Errorf("open automatic-update directory parent %s: %w", record.parentPhysical, err))
			continue
		}
		info, inspectErr := root.Lstat(record.name)
		if errors.Is(inspectErr, fs.ErrNotExist) {
			_ = root.Close()
			continue
		}
		if inspectErr != nil || !os.SameFile(record.identity, info) || !info.IsDir() {
			failures = append(failures, errors.Join(fmt.Errorf("created automatic-update directory identity changed: %s", filepath.Join(record.parentPhysical, record.name)), inspectErr))
			_ = root.Close()
			continue
		}
		if err := root.Remove(record.name); err != nil {
			failures = append(failures, fmt.Errorf("remove automatic-update directory %s: %w", filepath.Join(record.parentPhysical, record.name), err))
			_ = root.Close()
			continue
		}
		if host.directorySync == nil {
			err = fmt.Errorf("directory sync operation is unavailable")
		} else {
			err = host.directorySync(root)
		}
		closeErr := root.Close()
		if err != nil || closeErr != nil {
			failures = append(failures, errors.Join(err, closeErr))
		}
	}
	return errors.Join(failures...)
}

func inspectOfflineAutomaticUpdateLink(host hardeningHost, snapshot offlineAutomaticUpdateTimerSnapshot) (bool, error) {
	if err := host.verifyHardeningPolicyParent(snapshot.linkLogical); err != nil {
		return false, err
	}
	target, err := host.target(snapshot.linkLogical, false)
	if err != nil {
		return false, err
	}
	root, err := openSecurityDirectory(target)
	if err != nil {
		return false, err
	}
	defer func() { _ = root.Close() }()
	info, err := root.Lstat(target.name)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if info.Mode()&os.ModeSymlink == 0 || !ok || stat.Nlink != 1 ||
		int(stat.Uid) != host.expectedRootUID || int(stat.Gid) != host.expectedRootGID {
		return false, fmt.Errorf("automatic-update enablement link has unsafe metadata: %s", snapshot.linkLogical)
	}
	linkTarget, err := root.Readlink(target.name)
	if err != nil || linkTarget != snapshot.linkTarget {
		return false, fmt.Errorf("automatic-update enablement link has unexpected target %q: %s", linkTarget, snapshot.linkLogical)
	}
	after, err := root.Lstat(target.name)
	if err != nil || !os.SameFile(info, after) || after.Mode() != info.Mode() {
		return false, fmt.Errorf("automatic-update enablement link changed during attestation: %s", snapshot.linkLogical)
	}
	afterTarget, err := root.Readlink(target.name)
	if err != nil || afterTarget != linkTarget {
		return false, fmt.Errorf("automatic-update enablement link target changed during attestation: %s", snapshot.linkLogical)
	}
	return true, nil
}

func publishOfflineAutomaticUpdateLink(host hardeningHost, snapshot *offlineAutomaticUpdateTimerSnapshot) error {
	if snapshot.linkExisted {
		exists, err := inspectOfflineAutomaticUpdateLink(host, *snapshot)
		if err != nil || !exists {
			return errors.Join(fmt.Errorf("preexisting automatic-update enablement link disappeared: %s", snapshot.linkLogical), err)
		}
		return attestOfflineAutomaticUpdateSource(host, *snapshot)
	}
	if err := attestOfflineAutomaticUpdateSource(host, *snapshot); err != nil {
		return err
	}
	target, err := host.target(snapshot.linkLogical, false)
	if err != nil {
		return err
	}
	root, err := openSecurityDirectory(target)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	if _, err := root.Lstat(target.name); !errors.Is(err, fs.ErrNotExist) {
		if err == nil {
			return fmt.Errorf("automatic-update enablement link appeared before publication: %s", snapshot.linkLogical)
		}
		return err
	}
	directory, err := root.Open(".")
	if err != nil {
		return err
	}
	if err := attestOfflineAutomaticUpdateSource(host, *snapshot); err != nil {
		_ = directory.Close()
		return err
	}
	if err := unix.Symlinkat(snapshot.linkTarget, int(directory.Fd()), target.name); err != nil {
		_ = directory.Close()
		if errors.Is(err, fs.ErrExist) || errors.Is(err, unix.EEXIST) {
			return fmt.Errorf("automatic-update enablement link appeared before publication: %s", snapshot.linkLogical)
		}
		return fmt.Errorf("publish automatic-update enablement link without replacement: %w", err)
	}
	snapshot.linkCreated = true
	published, err := root.Lstat(target.name)
	if err == nil {
		snapshot.publishedLink = published
	}
	closeErr := directory.Close()
	if err != nil {
		return errors.Join(fmt.Errorf("snapshot published automatic-update link: %w", err), closeErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close automatic-update enablement directory: %w", closeErr)
	}
	if host.directorySync == nil {
		return fmt.Errorf("directory sync operation is unavailable")
	}
	if err := host.directorySync(root); err != nil {
		return fmt.Errorf("sync published automatic-update enablement link: %w", err)
	}
	exists, err := inspectOfflineAutomaticUpdateLink(host, *snapshot)
	if err != nil || !exists {
		return errors.Join(fmt.Errorf("automatic-update enablement link attestation failed: %s", snapshot.linkLogical), err)
	}
	return attestOfflineAutomaticUpdateSource(host, *snapshot)
}

func restoreOfflineAutomaticUpdateLink(host hardeningHost, snapshot offlineAutomaticUpdateTimerSnapshot) error {
	exists, err := inspectOfflineAutomaticUpdateLink(host, snapshot)
	if err != nil {
		return err
	}
	if snapshot.linkExisted {
		if !exists {
			return fmt.Errorf("preexisting automatic-update enablement link is absent during rollback: %s", snapshot.linkLogical)
		}
		return nil
	}
	if !snapshot.linkCreated {
		return nil
	}
	if !exists {
		return nil
	}
	target, err := host.target(snapshot.linkLogical, false)
	if err != nil {
		return err
	}
	root, err := openSecurityDirectory(target)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	current, err := root.Lstat(target.name)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil || (snapshot.publishedLink != nil && !os.SameFile(snapshot.publishedLink, current)) {
		return errors.Join(fmt.Errorf("automatic-update enablement link identity changed before rollback: %s", snapshot.linkLogical), err)
	}
	if err := root.Remove(target.name); err != nil {
		return fmt.Errorf("remove automatic-update enablement link: %w", err)
	}
	if host.directorySync == nil {
		return fmt.Errorf("directory sync operation is unavailable")
	}
	if err := host.directorySync(root); err != nil {
		return fmt.Errorf("sync automatic-update enablement rollback: %w", err)
	}
	exists, err = inspectOfflineAutomaticUpdateLink(host, snapshot)
	if err != nil || exists {
		return errors.Join(fmt.Errorf("automatic-update enablement rollback attestation failed: %s", snapshot.linkLogical), err)
	}
	return nil
}

func applyOfflineAutomaticUpdatePolicy(host hardeningHost, logical string, configSnapshot hardeningFileSnapshot, content []byte, timers ...string) error {
	if len(timers) == 0 {
		return fmt.Errorf("automatic-update timer list is empty")
	}
	snapshots := make([]offlineAutomaticUpdateTimerSnapshot, 0, len(timers))
	for _, timer := range timers {
		snapshot, err := resolveOfflineAutomaticUpdateTimer(host, timer)
		if err != nil {
			return err
		}
		snapshots = append(snapshots, snapshot)
	}
	created, err := prepareOfflineAutomaticUpdateLinkParent(host, snapshots[0].linkLogical)
	if err != nil {
		return err
	}
	cleanupBeforeConfig := func(cause error) error {
		return errors.Join(cause, removeCreatedAutomaticUpdateDirectories(host, created))
	}
	for index := range snapshots {
		exists, err := inspectOfflineAutomaticUpdateLink(host, snapshots[index])
		if err != nil {
			return cleanupBeforeConfig(err)
		}
		snapshots[index].linkExisted = exists
	}
	if err := host.applyManagedFileFromSnapshot(logical, configSnapshot, content, nil, nil); err != nil {
		return cleanupBeforeConfig(err)
	}
	rollback := func(cause error) error {
		var failures []error
		for index := len(snapshots) - 1; index >= 0; index-- {
			if err := restoreOfflineAutomaticUpdateLink(host, snapshots[index]); err != nil {
				failures = append(failures, err)
			}
		}
		if err := removeCreatedAutomaticUpdateDirectories(host, created); err != nil {
			failures = append(failures, err)
		}
		if err := host.restore(logical, configSnapshot, content); err != nil {
			failures = append(failures, fmt.Errorf("restore automatic-update configuration: %w", err))
		}
		return errors.Join(append([]error{cause}, failures...)...)
	}
	for index := range snapshots {
		if err := publishOfflineAutomaticUpdateLink(host, &snapshots[index]); err != nil {
			return rollback(fmt.Errorf("publish offline automatic-update timer %s: %w", snapshots[index].name, err))
		}
	}
	for _, snapshot := range snapshots {
		exists, err := inspectOfflineAutomaticUpdateLink(host, snapshot)
		if err != nil || !exists {
			return rollback(errors.Join(fmt.Errorf("attest offline automatic-update timer %s", snapshot.name), err))
		}
		if err := attestOfflineAutomaticUpdateSource(host, snapshot); err != nil {
			return rollback(err)
		}
	}
	fmt.Println(" -> Automatic-update timer links were published and attested offline for boot. No manager command or current runtime activation is claimed.")
	return nil
}

func automaticUpdateTimerEnabled(host hardeningHost, timer string) (bool, error) {
	output, status, err := host.executor.status("systemctl", "is-enabled", timer)
	if err != nil {
		return false, err
	}
	value := strings.TrimSpace(string(output))
	switch {
	case status == 0 && value == "enabled":
		return true, nil
	case status == 1 && value == "disabled":
		return false, nil
	default:
		return false, fmt.Errorf("unexpected systemctl is-enabled result status=%d value=%q", status, value)
	}
}

func automaticUpdateTimerActive(host hardeningHost, timer string) (bool, error) {
	output, status, err := host.executor.status("systemctl", "is-active", timer)
	if err != nil {
		return false, err
	}
	value := strings.TrimSpace(string(output))
	switch {
	case status == 0 && value == "active":
		return true, nil
	case status == 3 && value == "inactive":
		return false, nil
	default:
		return false, fmt.Errorf("unexpected systemctl is-active result status=%d value=%q", status, value)
	}
}

func restoreAutomaticUpdateTimer(host hardeningHost, snapshot automaticUpdateTimerSnapshot, runtimeActive bool) error {
	var failures []error
	if snapshot.enabled {
		if err := host.executor.run("systemctl", "enable", snapshot.name); err != nil {
			failures = append(failures, fmt.Errorf("restore enabled timer %s: %w", snapshot.name, err))
		}
	}
	if runtimeActive {
		action := "stop"
		if snapshot.active {
			action = "start"
		}
		if err := host.executor.run("systemctl", action, snapshot.name); err != nil {
			failures = append(failures, fmt.Errorf("restore timer activation %s: %w", snapshot.name, err))
		}
		active, err := automaticUpdateTimerActive(host, snapshot.name)
		if err != nil || active != snapshot.active {
			if err == nil {
				err = fmt.Errorf("active=%t, want %t", active, snapshot.active)
			}
			failures = append(failures, fmt.Errorf("attest restored timer activation %s: %w", snapshot.name, err))
		}
	}
	if !snapshot.enabled {
		if err := host.executor.run("systemctl", "disable", snapshot.name); err != nil {
			failures = append(failures, fmt.Errorf("restore disabled timer %s: %w", snapshot.name, err))
		}
	}
	enabled, err := automaticUpdateTimerEnabled(host, snapshot.name)
	if err != nil || enabled != snapshot.enabled {
		if err == nil {
			err = fmt.Errorf("enabled=%t, want %t", enabled, snapshot.enabled)
		}
		failures = append(failures, fmt.Errorf("attest restored timer enablement %s: %w", snapshot.name, err))
	}
	return errors.Join(failures...)
}

func linuxDistributionFamilyOn(host hardeningHost) (string, error) {
	_, family, err := linuxDistributionIdentityOn(host)
	return family, err
}

func linuxDistributionIdentityOn(host hardeningHost) (string, string, error) {
	content, err := secureOSReleaseOn(host)
	if err != nil {
		return "", "", err
	}
	id, err := parseOSReleaseID(content)
	if err != nil {
		return "", "", err
	}
	switch id {
	case "debian", "ubuntu":
		return id, "debian", nil
	case "fedora", "almalinux", "rocky", "rhel", "ol", "centos":
		return id, "redhat", nil
	case "alpine":
		return id, "alpine", nil
	default:
		return "", "", fmt.Errorf("automatic security updates are unsupported for Linux distribution ID %q", id)
	}
}

func secureOSReleaseOn(host hardeningHost) ([]byte, error) {
	usrSnapshot, err := host.snapshot("/usr/lib/os-release")
	if errors.Is(err, fs.ErrNotExist) {
		usrSnapshot = hardeningFileSnapshot{}
		err = nil
	}
	if err != nil {
		return nil, fmt.Errorf("inspect /usr/lib/os-release: %w", err)
	}
	if usrSnapshot.existed {
		if err := validateOSReleaseSnapshot("/usr/lib/os-release", usrSnapshot, host.expectedRootUID); err != nil {
			return nil, err
		}
	}

	etcPath, err := host.path("/etc/os-release")
	if err != nil {
		return nil, err
	}
	etcParent, err := host.directoryExists("/etc")
	if err != nil {
		return nil, fmt.Errorf("inspect /etc for os-release: %w", err)
	}
	if !etcParent {
		if usrSnapshot.existed {
			return usrSnapshot.content, nil
		}
		return nil, fmt.Errorf("Linux os-release metadata is absent")
	}
	info, err := os.Lstat(etcPath)
	if errors.Is(err, fs.ErrNotExist) {
		if usrSnapshot.existed {
			return usrSnapshot.content, nil
		}
		return nil, fmt.Errorf("Linux os-release metadata is absent")
	}
	if err != nil {
		return nil, fmt.Errorf("inspect /etc/os-release: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		target, err := os.Readlink(etcPath)
		if err != nil {
			return nil, fmt.Errorf("read /etc/os-release symlink: %w", err)
		}
		if target != "../usr/lib/os-release" && target != "/usr/lib/os-release" {
			return nil, fmt.Errorf("/etc/os-release has untrusted symlink target %q", target)
		}
		if !usrSnapshot.existed {
			return nil, fmt.Errorf("/etc/os-release target /usr/lib/os-release is absent")
		}
		return usrSnapshot.content, nil
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("/etc/os-release is not a regular file or approved symlink")
	}
	etcSnapshot, err := host.snapshot("/etc/os-release")
	if err != nil {
		return nil, fmt.Errorf("snapshot /etc/os-release: %w", err)
	}
	if err := validateOSReleaseSnapshot("/etc/os-release", etcSnapshot, host.expectedRootUID); err != nil {
		return nil, err
	}
	if usrSnapshot.existed {
		usrID, err := parseOSReleaseID(usrSnapshot.content)
		if err != nil {
			return nil, fmt.Errorf("parse /usr/lib/os-release: %w", err)
		}
		etcID, err := parseOSReleaseID(etcSnapshot.content)
		if err != nil {
			return nil, fmt.Errorf("parse /etc/os-release: %w", err)
		}
		if usrID != etcID {
			return nil, fmt.Errorf("conflicting os-release IDs %q and %q", usrID, etcID)
		}
	}
	return etcSnapshot.content, nil
}

func validateOSReleaseSnapshot(path string, snapshot hardeningFileSnapshot, expectedRootUID int) error {
	if !snapshot.existed || len(snapshot.content) == 0 || len(snapshot.content) > 64<<10 {
		return fmt.Errorf("%s has invalid size", path)
	}
	if !snapshot.identity.ownerKnown || snapshot.identity.uid != expectedRootUID {
		return fmt.Errorf("%s is not owned by root", path)
	}
	if snapshot.mode&0022 != 0 {
		return fmt.Errorf("%s is writable by group or other", path)
	}
	return nil
}

func parseOSReleaseID(content []byte) (string, error) {
	id := ""
	for lineNumber, raw := range strings.Split(string(content), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 || strings.TrimSpace(parts[0]) != parts[0] || parts[0] == "" {
			return "", fmt.Errorf("malformed os-release line %d", lineNumber+1)
		}
		for _, character := range parts[0] {
			if (character < 'A' || character > 'Z') && character != '_' && (character < '0' || character > '9') {
				return "", fmt.Errorf("invalid os-release key on line %d", lineNumber+1)
			}
		}
		if parts[0] != "ID" {
			continue
		}
		if id != "" {
			return "", fmt.Errorf("os-release contains duplicate ID assignments")
		}
		value := strings.TrimSpace(parts[1])
		if len(value) >= 2 && ((value[0] == '"' && value[len(value)-1] == '"') || (value[0] == '\'' && value[len(value)-1] == '\'')) {
			value = value[1 : len(value)-1]
		}
		if value == "" || strings.ContainsAny(value, "\\\"'`$ \t\r\n") {
			return "", fmt.Errorf("os-release ID has unsafe value")
		}
		id = value
	}
	if id == "" {
		return "", fmt.Errorf("os-release does not contain an ID")
	}
	return id, nil
}

func renderDNFAutomaticConfiguration(input []byte) ([]byte, error) {
	lines := strings.Split(string(input), "\n")
	section := ""
	foundCommands := false
	found := map[string]bool{"upgrade_type": false, "download_updates": false, "apply_updates": false, "reboot": false}
	want := map[string]string{"upgrade_type": "security", "download_updates": "yes", "apply_updates": "yes", "reboot": "never"}
	for index, raw := range lines {
		trimmed := strings.TrimSpace(raw)
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			section = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(trimmed, "["), "]")))
			if section == "commands" {
				foundCommands = true
			}
			continue
		}
		if section != "commands" || trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") {
			continue
		}
		parts := strings.SplitN(trimmed, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(parts[0]))
		value, ok := want[key]
		if !ok {
			continue
		}
		indent := raw[:len(raw)-len(strings.TrimLeft(raw, " \t"))]
		lines[index] = indent + key + " = " + value
		found[key] = true
	}
	if !foundCommands {
		return nil, fmt.Errorf("dnf-automatic configuration lacks [commands] section")
	}
	for key, present := range found {
		if !present {
			return nil, fmt.Errorf("dnf-automatic [commands] lacks %s", key)
		}
	}
	return []byte(strings.Join(lines, "\n")), nil
}
