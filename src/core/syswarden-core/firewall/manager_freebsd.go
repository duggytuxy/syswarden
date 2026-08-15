//go:build freebsd

package firewall

import (
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
)

type Manager interface {
	Ban(ip string) error
	Unban(ip string) error
	Name() string
}

var (
	firewallRuntimeLockPath = "/var/run/syswarden-firewall.lock"
	firewallRuntimeMu       sync.Mutex
)

type firewallRuntimeLock struct {
	file *os.File
}

func openRootedRuntimeFile(path string, flags int, permission fs.FileMode) (*os.File, error) {
	clean := filepath.Clean(path)
	if !filepath.IsAbs(clean) || clean != path {
		return nil, fmt.Errorf("firewall runtime lock path is not absolute and canonical: %q", path)
	}
	root, err := os.OpenRoot(filepath.Dir(clean))
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	return root.OpenFile(filepath.Base(clean), flags|syscall.O_NOFOLLOW, permission)
}

func acquireFirewallRuntimeLock() (*firewallRuntimeLock, error) {
	firewallRuntimeMu.Lock()
	file, err := openRootedRuntimeFile(firewallRuntimeLockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		firewallRuntimeMu.Unlock()
		return nil, err
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		_ = file.Close()
		firewallRuntimeMu.Unlock()
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("firewall runtime lock is not a regular file")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int64(stat.Uid) != int64(os.Geteuid()) {
		_ = file.Close()
		firewallRuntimeMu.Unlock()
		return nil, fmt.Errorf("firewall runtime lock is not owned by the effective user")
	}
	if err := file.Chmod(0600); err != nil {
		_ = file.Close()
		firewallRuntimeMu.Unlock()
		return nil, err
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX); err != nil {
		_ = file.Close()
		firewallRuntimeMu.Unlock()
		return nil, err
	}
	return &firewallRuntimeLock{file: file}, nil
}

func releaseFirewallRuntimeLock(lock *firewallRuntimeLock) {
	if lock != nil && lock.file != nil {
		_ = syscall.Flock(int(lock.file.Fd()), syscall.LOCK_UN)
		_ = lock.file.Close()
	}
	firewallRuntimeMu.Unlock()
}

type pfCommandRunner func(args ...string) ([]byte, error)

// PFManager implements FreeBSD Packet Filter dynamic banning.
type PFManager struct {
	run     pfCommandRunner
	health  HealthState
	lastErr error
	mu      sync.RWMutex
}

func (m *PFManager) Name() string {
	return "pf (Packet Filter)"
}

func (m *PFManager) Health() HealthState {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.health
}

func (m *PFManager) BanExpiryMode() BanExpiryMode {
	return BanExpiryExternal
}

func (m *PFManager) LastError() error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.lastErr
}

func (m *PFManager) Ban(ip string) error {
	entry, err := parseFirewallEntry(ip)
	if err != nil {
		return err
	}
	lock, err := acquireFirewallRuntimeLock()
	if err != nil {
		return fmt.Errorf("acquire shared firewall transaction lock: %w", err)
	}
	defer releaseFirewallRuntimeLock(lock)
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.mutateAndVerifyLocked(entry.text, true); err != nil {
		m.lastErr = err
		if m.health != HealthUnavailable {
			m.health = HealthDegraded
		}
		return fmt.Errorf("failed to inject IP natively into pf: %w", err)
	}
	m.health = HealthHealthy
	m.lastErr = nil
	log.Printf("[Firewall-PF] Successfully injected entry after kernel verification: %s into banned_ips table", entry.text)
	return nil
}

func (m *PFManager) BanPermanent(ip string) error {
	return m.Ban(ip)
}

func (m *PFManager) Unban(ip string) error {
	entry, err := parseFirewallEntry(ip)
	if err != nil {
		return err
	}
	lock, err := acquireFirewallRuntimeLock()
	if err != nil {
		return fmt.Errorf("acquire shared firewall transaction lock: %w", err)
	}
	defer releaseFirewallRuntimeLock(lock)
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.mutateAndVerifyLocked(entry.text, false); err != nil {
		m.lastErr = err
		if m.health != HealthUnavailable {
			m.health = HealthDegraded
		}
		return fmt.Errorf("failed to remove IP natively from pf: %w", err)
	}
	m.health = HealthHealthy
	m.lastErr = nil
	log.Printf("[Firewall-PF] Successfully unbanned entry after kernel verification: %s from banned_ips table", entry.text)
	return nil
}

func (m *PFManager) mutateAndVerifyLocked(ip string, add bool) error {
	firstErr := m.applyMutationLocked(ip, add)
	if firstErr == nil {
		return nil
	}
	refreshErr := m.refreshHealthLocked()
	if m.health == HealthUnavailable {
		return errors.Join(firstErr, refreshErr, fmt.Errorf("PF table banned_ips is unavailable"))
	}
	retryErr := m.applyMutationLocked(ip, add)
	if retryErr == nil {
		return nil
	}
	return errors.Join(firstErr, refreshErr, retryErr)
}

func (m *PFManager) applyMutationLocked(ip string, add bool) error {
	if m.health == HealthUnavailable {
		return fmt.Errorf("PF table banned_ips is unavailable")
	}
	present, err := m.elementPresentLocked(ip)
	if err != nil {
		return fmt.Errorf("preflight PF table element: %w", err)
	}
	if present == add {
		return nil
	}
	action := "add"
	if !add {
		action = "delete"
	}
	output, err := m.run("-t", "banned_ips", "-T", action, ip)
	if err != nil {
		return fmt.Errorf("pfctl %s: %w: %s", action, err, strings.TrimSpace(string(output)))
	}
	present, err = m.elementPresentLocked(ip)
	if err != nil {
		return fmt.Errorf("verify pf table element: %w", err)
	}
	if present != add {
		state := "absent"
		if add {
			state = "present"
		}
		return fmt.Errorf("PF verification failed: element is not %s", state)
	}
	return nil
}

func (m *PFManager) elementPresentLocked(ip string) (bool, error) {
	output, err := m.run("-t", "banned_ips", "-T", "show")
	if err != nil {
		return false, fmt.Errorf("pfctl show: %w: %s", err, strings.TrimSpace(string(output)))
	}
	for _, line := range strings.Split(string(output), "\n") {
		if strings.TrimSpace(line) == ip {
			return true, nil
		}
	}
	return false, nil
}

func (m *PFManager) refreshHealthLocked() error {
	statusOutput, statusErr := m.run("-s", "info")
	if statusErr != nil || !pfStatusEnabled(statusOutput) {
		m.health = HealthUnavailable
		m.lastErr = errors.Join(statusErr, fmt.Errorf("PF is not enabled: %s", strings.TrimSpace(string(statusOutput))))
		return m.lastErr
	}
	output, err := m.run("-s", "Tables")
	if err != nil {
		m.health = HealthUnavailable
		m.lastErr = fmt.Errorf("list PF tables: %w: %s", err, strings.TrimSpace(string(output)))
		return m.lastErr
	}
	for _, line := range strings.Split(string(output), "\n") {
		name := strings.Trim(strings.TrimSpace(line), "<>")
		if name == "banned_ips" {
			m.health = HealthHealthy
			m.lastErr = nil
			return nil
		}
	}
	m.health = HealthUnavailable
	m.lastErr = fmt.Errorf("required PF table banned_ips is missing")
	return m.lastErr
}

func pfStatusEnabled(output []byte) bool {
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && strings.TrimSuffix(fields[0], ":") == "Status" && fields[1] == "Enabled" {
			return true
		}
	}
	return false
}

func newPFManager(runner pfCommandRunner) (*PFManager, error) {
	manager := &PFManager{run: runner, health: HealthUnavailable}
	manager.mu.Lock()
	err := manager.refreshHealthLocked()
	manager.mu.Unlock()
	return manager, err
}

func runPFCommand(args ...string) ([]byte, error) {
	switch {
	case len(args) == 2 && args[0] == "-s" && args[1] == "info":
		return exec.Command("pfctl", "-s", "info").CombinedOutput()
	case len(args) == 2 && args[0] == "-s" && args[1] == "Tables":
		return exec.Command("pfctl", "-s", "Tables").CombinedOutput()
	case len(args) == 4 && args[0] == "-t" && args[1] == "banned_ips" && args[2] == "-T" && args[3] == "show":
		return exec.Command("pfctl", "-t", "banned_ips", "-T", "show").CombinedOutput()
	case len(args) == 5 && args[0] == "-t" && args[1] == "banned_ips" && args[2] == "-T":
		entry, err := parseFirewallEntry(args[4])
		if err != nil || entry.text != args[4] {
			return nil, fmt.Errorf("refuse non-canonical PF entry %q", args[4])
		}
		switch args[3] {
		case "add":
			command := exec.Command("pfctl", "-t", "banned_ips", "-T", "add", "-f", "-")
			command.Stdin = strings.NewReader(entry.text + "\n")
			return command.CombinedOutput()
		case "delete":
			command := exec.Command("pfctl", "-t", "banned_ips", "-T", "delete", "-f", "-")
			command.Stdin = strings.NewReader(entry.text + "\n")
			return command.CombinedOutput()
		}
	}
	return nil, fmt.Errorf("refuse unsupported pfctl operation")
}

func NewManager() (Manager, error) {
	_, err := exec.LookPath("pfctl")
	if err != nil {
		return nil, fmt.Errorf("no supported firewall backend found on the system (pfctl missing)")
	}
	manager, validationErr := newPFManager(runPFCommand)
	if validationErr != nil {
		log.Printf("[Firewall-PF] Backend initialized in %s state: %v", manager.Health(), validationErr)
	}
	return manager, nil
}
