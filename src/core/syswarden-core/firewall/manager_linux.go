//go:build linux

package firewall

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/nftables"
)

type Manager interface {
	Ban(ip string) error
	Unban(ip string) error
	Name() string
}

var (
	firewallRuntimeLockPath = "/run/syswarden-firewall.lock"
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

type FallbackManager struct {
	backend            string
	cmdPath            string
	mu                 sync.RWMutex
	health             HealthState
	firewalldRuleKinds map[string]firewalldRuleKind
}

type firewalldRuleKind uint8

const (
	firewalldRuleUnknown firewalldRuleKind = iota
	firewalldRuleTimed
	firewalldRulePermanent
)

var errUnsupportedFallbackBackend = errors.New("unsupported fallback backend")

func (m *FallbackManager) Name() string {
	return m.backend
}

func (m *FallbackManager) Health() HealthState {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.health
}

func (m *FallbackManager) BanExpiryMode() BanExpiryMode {
	return BanExpiryExternal
}

func (m *FallbackManager) setHealth(health HealthState) {
	m.mu.Lock()
	m.health = health
	m.mu.Unlock()
}

func (m *FallbackManager) firewalldRuleKind(entry string) firewalldRuleKind {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.firewalldRuleKinds[entry]
}

func (m *FallbackManager) rememberFirewalldRuleKind(entry string, kind firewalldRuleKind) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if kind == firewalldRuleUnknown {
		delete(m.firewalldRuleKinds, entry)
		return
	}
	if m.firewalldRuleKinds == nil {
		m.firewalldRuleKinds = make(map[string]firewalldRuleKind)
	}
	m.firewalldRuleKinds[entry] = kind
}

func fallbackIptablesPath(commandPath string, isIPv4 bool) string {
	if isIPv4 {
		return commandPath
	}
	base := strings.Replace(filepath.Base(commandPath), "iptables", "ip6tables", 1)
	return filepath.Join(filepath.Dir(commandPath), base)
}

func newFallbackCommand(path string, arguments ...string) *exec.Cmd {
	command := exec.Command(path, arguments...) // #nosec G204 -- path is resolved from the fixed backend allowlist and arguments are canonicalized below
	command.Env = append(os.Environ(), "LC_ALL=C", "LANG=C")
	return command
}

func buildFallbackCommandForState(backend, commandPath, value string, add, permanent bool) (*exec.Cmd, error) {
	entry, err := parseFirewallEntry(value)
	if err != nil {
		return nil, err
	}
	isIPv4 := len(entry.key) == net.IPv4len
	switch backend {
	case "ufw":
		if add {
			return newFallbackCommand(commandPath, "insert", "1", "deny", "from", entry.text), nil
		}
		return newFallbackCommand(commandPath, "--force", "delete", "deny", "from", entry.text), nil
	case "firewalld":
		family := "ipv4"
		if !isIPv4 {
			family = "ipv6"
		}
		rule := fmt.Sprintf("rule family=%s source address=%s drop", family, entry.text)
		if add {
			arguments := []string{"--add-rich-rule", rule}
			if !permanent {
				arguments = append(arguments, fmt.Sprintf("--timeout=%d", int64(MaximumBanTTL/time.Second)))
			}
			return newFallbackCommand(commandPath, arguments...), nil
		}
		return newFallbackCommand(commandPath, "--remove-rich-rule", rule), nil
	case "iptables":
		iptablesPath := fallbackIptablesPath(commandPath, isIPv4)
		if add {
			return newFallbackCommand(iptablesPath, "-I", "INPUT", "1", "-s", entry.text, "-j", "DROP"), nil
		}
		return newFallbackCommand(iptablesPath, "-D", "INPUT", "-s", entry.text, "-j", "DROP"), nil
	default:
		return nil, fmt.Errorf("%w: %s", errUnsupportedFallbackBackend, backend)
	}
}

func buildFallbackCommand(backend, commandPath, value string, add bool) (*exec.Cmd, error) {
	return buildFallbackCommandForState(backend, commandPath, value, add, true)
}

func fallbackRulePresent(backend, commandPath string, entry firewallEntry) (bool, error) {
	isIPv4 := len(entry.key) == net.IPv4len
	var command *exec.Cmd
	switch backend {
	case "iptables":
		command = newFallbackCommand(fallbackIptablesPath(commandPath, isIPv4), "-C", "INPUT", "-s", entry.text, "-j", "DROP")
	case "firewalld":
		family := "ipv4"
		if !isIPv4 {
			family = "ipv6"
		}
		rule := fmt.Sprintf("rule family=%s source address=%s drop", family, entry.text)
		command = newFallbackCommand(commandPath, "--query-rich-rule", rule)
	case "ufw":
		command = newFallbackCommand(commandPath, "status")
	default:
		return false, fmt.Errorf("%w: %s", errUnsupportedFallbackBackend, backend)
	}
	output, err := command.CombinedOutput()
	if backend == "ufw" {
		if err != nil {
			return false, fmt.Errorf("query ufw state: %w: %s", err, strings.TrimSpace(string(output)))
		}
		lines := strings.Split(string(output), "\n")
		if len(lines) == 0 || strings.TrimSpace(lines[0]) != "Status: active" {
			return false, fmt.Errorf("ufw is not active")
		}
		for _, line := range lines[1:] {
			fields := strings.Fields(line)
			hasEntry := false
			hasDeny := false
			for _, field := range fields {
				hasEntry = hasEntry || field == entry.text
				hasDeny = hasDeny || field == "DENY"
			}
			if hasEntry && hasDeny {
				return true, nil
			}
		}
		return false, nil
	}
	if err == nil {
		return true, nil
	}
	var exitError *exec.ExitError
	if errors.As(err, &exitError) && exitError.ExitCode() == 1 {
		return false, nil
	}
	return false, fmt.Errorf("query %s firewall rule: %w: %s", backend, err, strings.TrimSpace(string(output)))
}

func (m *FallbackManager) mutateAndVerify(value string, add, permanent bool) error {
	entry, err := parseFirewallEntry(value)
	if err != nil {
		return err
	}
	lock, err := acquireFirewallRuntimeLock()
	if err != nil {
		m.setHealth(HealthDegraded)
		return fmt.Errorf("acquire shared firewall transaction lock: %w", err)
	}
	defer releaseFirewallRuntimeLock(lock)

	const maximumDuplicateRemovals = 128
	for attempt := 0; attempt <= maximumDuplicateRemovals; attempt++ {
		present, queryErr := fallbackRulePresent(m.backend, m.cmdPath, entry)
		if queryErr != nil {
			if errors.Is(queryErr, errUnsupportedFallbackBackend) {
				m.setHealth(HealthUnavailable)
			} else {
				m.setHealth(HealthDegraded)
			}
			return queryErr
		}
		if add && present {
			if m.backend == "firewalld" && permanent && m.firewalldRuleKind(entry.text) != firewalldRulePermanent {
				command, buildErr := buildFallbackCommandForState(m.backend, m.cmdPath, entry.text, false, false)
				if buildErr != nil {
					m.setHealth(HealthDegraded)
					return buildErr
				}
				if output, runErr := command.CombinedOutput(); runErr != nil {
					m.setHealth(HealthDegraded)
					return fmt.Errorf("failed to replace timed or unknown firewalld rule with a permanent rule: %w: %s", runErr, strings.TrimSpace(string(output)))
				}
				removed, verifyErr := fallbackRulePresent(m.backend, m.cmdPath, entry)
				if verifyErr != nil || removed {
					m.setHealth(HealthDegraded)
					return errors.Join(verifyErr, fmt.Errorf("firewalld replacement pre-verification still found the prior rule"))
				}
				m.rememberFirewalldRuleKind(entry.text, firewalldRuleUnknown)
				continue
			}
			m.setHealth(HealthHealthy)
			return nil
		}
		if !add && !present {
			if m.backend == "firewalld" {
				m.rememberFirewalldRuleKind(entry.text, firewalldRuleUnknown)
			}
			m.setHealth(HealthHealthy)
			return nil
		}
		if attempt == maximumDuplicateRemovals {
			m.setHealth(HealthDegraded)
			return fmt.Errorf("fallback rule did not converge after %d verified mutations", maximumDuplicateRemovals)
		}
		command, buildErr := buildFallbackCommandForState(m.backend, m.cmdPath, entry.text, add, permanent)
		if buildErr != nil {
			m.setHealth(HealthDegraded)
			return buildErr
		}
		if output, runErr := command.CombinedOutput(); runErr != nil {
			m.setHealth(HealthDegraded)
			return fmt.Errorf("failed to mutate %s fallback rule: %w: %s", m.backend, runErr, strings.TrimSpace(string(output)))
		}
		if add {
			verified, verifyErr := fallbackRulePresent(m.backend, m.cmdPath, entry)
			if verifyErr != nil || !verified {
				m.setHealth(HealthDegraded)
				return errors.Join(verifyErr, fmt.Errorf("%s fallback post-verification did not find the requested rule", m.backend))
			}
			if m.backend == "firewalld" {
				kind := firewalldRuleTimed
				if permanent {
					kind = firewalldRulePermanent
				}
				m.rememberFirewalldRuleKind(entry.text, kind)
			}
			m.setHealth(HealthHealthy)
			return nil
		}
	}
	return fmt.Errorf("unreachable fallback reconciliation state")
}

func (m *FallbackManager) Ban(ip string) error {
	return m.mutateAndVerify(ip, true, false)
}

func (m *FallbackManager) BanPermanent(ip string) error {
	return m.mutateAndVerify(ip, true, true)
}

func (m *FallbackManager) Unban(ip string) error {
	return m.mutateAndVerify(ip, false, false)
}

type nftablesConnection interface {
	ListTables() ([]*nftables.Table, error)
	GetSets(table *nftables.Table) ([]*nftables.Set, error)
	SetAddElements(set *nftables.Set, elements []nftables.SetElement) error
	SetDeleteElements(set *nftables.Set, elements []nftables.SetElement) error
	GetSetElements(set *nftables.Set) ([]nftables.SetElement, error)
	Flush() error
}

type nftablesConnectionFactory func() nftablesConnection

type NftablesManager struct {
	conn       nftablesConnection
	newConn    nftablesConnectionFactory
	inetSet    *nftables.Set
	netdevSet  *nftables.Set
	inetSet6   *nftables.Set
	netdevSet6 *nftables.Set
	health     HealthState
	lastErr    error
	mu         sync.RWMutex
}

type nftablesLayer struct {
	name string
	set  *nftables.Set
}

func (m *NftablesManager) Name() string {
	return "nftables (Native Netlink)"
}

func (m *NftablesManager) Health() HealthState {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.health
}

func (m *NftablesManager) BanExpiryMode() BanExpiryMode {
	return BanExpiryNative
}

func (m *NftablesManager) LastError() error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.lastErr
}

func (m *NftablesManager) Ban(ip string) error {
	return m.BanWithTTL(ip, MaximumBanTTL)
}

func (m *NftablesManager) BanPermanent(ip string) error {
	entry, err := parseFirewallEntry(ip)
	if err != nil {
		return err
	}
	return m.applyRequestedState(entry, true, 0, true, false)
}

func (m *NftablesManager) BanWithTTL(ip string, ttl time.Duration) error {
	if err := validateBanTTL(ttl); err != nil {
		return err
	}
	entry, err := parseFirewallEntry(ip)
	if err != nil {
		return err
	}
	return m.applyRequestedState(entry, true, ttl, false, false)
}

func (m *NftablesManager) ReconcileBanTTL(ip string, ttl time.Duration) error {
	if err := validateBanTTL(ttl); err != nil {
		return err
	}
	entry, err := parseFirewallEntry(ip)
	if err != nil {
		return err
	}
	return m.applyRequestedState(entry, true, ttl, false, true)
}

func (m *NftablesManager) Unban(ip string) error {
	entry, err := parseFirewallEntry(ip)
	if err != nil {
		return err
	}

	return m.applyRequestedState(entry, false, 0, false, false)
}

func (m *NftablesManager) applyRequestedState(entry firewallEntry, add bool, ttl time.Duration, permanent, exactTTL bool) error {
	lock, err := acquireFirewallRuntimeLock()
	if err != nil {
		m.mu.Lock()
		m.markOperationFailureLocked(err)
		m.mu.Unlock()
		return fmt.Errorf("acquire shared firewall transaction lock: %w", err)
	}
	defer releaseFirewallRuntimeLock(lock)

	m.mu.Lock()
	defer m.mu.Unlock()
	err = m.mutateAndVerifyLocked(entry, add, ttl, permanent, exactTTL)
	if err != nil {
		m.markOperationFailureLocked(err)
		if add {
			return fmt.Errorf("failed to inject firewall entry natively: %w", err)
		}
		return fmt.Errorf("failed to remove firewall entry natively: %w", err)
	}
	m.lastErr = nil
	if !add {
		log.Printf("[Firewall-Netlink] Successfully unbanned entry after kernel verification: %s", entry.text)
	} else if permanent {
		log.Printf("[Firewall-Netlink] Successfully injected permanent entry after kernel verification: %s", entry.text)
	} else {
		log.Printf("[Firewall-Netlink] Successfully injected entry after kernel verification: %s with %s timeout", entry.text, ttl)
	}
	return nil
}

func (m *NftablesManager) mutateAndVerifyLocked(entry firewallEntry, add bool, ttl time.Duration, permanent, exactTTL bool) error {
	firstMutationRequested, firstErr := m.applyMutationLocked(entry, add, ttl, permanent, exactTTL, true)
	if firstErr == nil {
		return nil
	}

	refreshErr := m.refreshHandlesLocked()
	_, retryErr := m.applyMutationLocked(entry, add, ttl, permanent, exactTTL, !firstMutationRequested)
	if retryErr == nil {
		return nil
	}
	discardErr := m.refreshHandlesLocked()
	if discardErr != nil {
		discardErr = fmt.Errorf("reset netlink state after failed retry: %w", discardErr)
	}
	return errors.Join(firstErr, refreshErr, retryErr, discardErr)
}

func (m *NftablesManager) applyMutationLocked(entry firewallEntry, add bool, ttl time.Duration, permanent, exactTTL, acceptPreexistingPermanent bool) (bool, error) {
	layers := m.layersForKeyLocked(entry.key)
	available := 0
	queued := 0
	renewed := make(map[string]bool, len(layers))
	preexistingPermanent := make(map[string]bool, len(layers))
	var errs []error
	for _, layer := range layers {
		if layer.set == nil {
			continue
		}
		available++
		current, present, err := m.elementStateLocked(layer.set, entry)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s preflight: %w", layer.name, err))
			continue
		}

		element := nftables.SetElement{
			Key:    append([]byte(nil), entry.key...),
			KeyEnd: append([]byte(nil), entry.keyEnd...),
		}
		if add {
			alreadyDesired := present && permanent && current.Timeout == 0 && current.Expires == 0
			strongerPermanent := present && !permanent && !exactTTL && current.Timeout == 0 && current.Expires == 0
			longerTimedBan := present && !permanent && !exactTTL && current.Timeout > 0 && current.Expires >= ttl
			const reconcileTolerance = 1500 * time.Millisecond
			exactTimedBan := present && exactTTL && current.Timeout == ttl && current.Expires <= ttl && current.Expires >= ttl-reconcileTolerance
			if strongerPermanent {
				preexistingPermanent[layer.name] = true
			}
			if alreadyDesired || strongerPermanent || longerTimedBan || exactTimedBan {
				continue
			}
			if present {
				if err := m.conn.SetDeleteElements(layer.set, []nftables.SetElement{element}); err != nil {
					errs = append(errs, fmt.Errorf("%s queue ban replacement delete: %w", layer.name, err))
					continue
				}
				queued++
			}
			if !permanent {
				element.Timeout = ttl
			}
			if err := m.conn.SetAddElements(layer.set, []nftables.SetElement{element}); err != nil {
				errs = append(errs, fmt.Errorf("%s queue mutation: %w", layer.name, err))
				continue
			}
			renewed[layer.name] = true
		} else {
			if !present {
				continue
			}
			if err := m.conn.SetDeleteElements(layer.set, []nftables.SetElement{element}); err != nil {
				errs = append(errs, fmt.Errorf("%s queue mutation: %w", layer.name, err))
				continue
			}
		}
		queued++
	}
	if available == 0 {
		return queued > 0, fmt.Errorf("no nftables ban set is available for this address family")
	}
	if len(errs) > 0 {
		return queued > 0, errors.Join(errs...)
	}
	if queued > 0 {
		if err := m.conn.Flush(); err != nil {
			return true, fmt.Errorf("flush netlink transaction: %w", err)
		}
	}
	verifiedAt := time.Now()

	for _, layer := range layers {
		if layer.set == nil {
			continue
		}
		element, present, err := m.elementStateLocked(layer.set, entry)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s verify mutation: %w", layer.name, err))
			continue
		}
		if present != add {
			action := "absent"
			if add {
				action = "present"
			}
			errs = append(errs, fmt.Errorf("%s verification failed: element is not %s", layer.name, action))
			continue
		}
		if !add {
			continue
		}
		if permanent {
			if element.Timeout != 0 || element.Expires != 0 {
				errs = append(errs, fmt.Errorf("%s verification failed: permanent element has timeout %s and expiry %s", layer.name, element.Timeout, element.Expires))
			}
			continue
		}
		if element.Timeout == 0 && element.Expires == 0 {
			if acceptPreexistingPermanent && !exactTTL && !renewed[layer.name] && preexistingPermanent[layer.name] {
				continue
			}
			errs = append(errs, fmt.Errorf("%s verification failed: requested timed state resolved to an unverified permanent element", layer.name))
			continue
		}
		if element.Timeout == 0 || element.Expires <= 0 || element.Expires > element.Timeout {
			errs = append(errs, fmt.Errorf("%s verification failed: inconsistent timeout %s and expiry %s", layer.name, element.Timeout, element.Expires))
			continue
		}
		const expiryTolerance = 1500 * time.Millisecond
		minimum := ttl - time.Since(verifiedAt) - expiryTolerance
		if minimum < time.Millisecond {
			minimum = time.Millisecond
		}
		if element.Expires < minimum {
			errs = append(errs, fmt.Errorf("%s verification failed: remaining expiry is %s, shorter than requested %s", layer.name, element.Expires, ttl))
		}
		if renewed[layer.name] && element.Timeout != ttl {
			errs = append(errs, fmt.Errorf("%s verification failed: renewed timeout is %s, expected %s", layer.name, element.Timeout, ttl))
		}
		if renewed[layer.name] && element.Expires > ttl+expiryTolerance {
			errs = append(errs, fmt.Errorf("%s verification failed: renewed expiry is %s, expected at most %s", layer.name, element.Expires, ttl))
		}
	}
	return queued > 0, errors.Join(errs...)
}

func (m *NftablesManager) layersForKeyLocked(key []byte) []nftablesLayer {
	if len(key) == net.IPv4len {
		return []nftablesLayer{{name: "inet", set: m.inetSet}, {name: "netdev", set: m.netdevSet}}
	}
	return []nftablesLayer{{name: "inet6", set: m.inetSet6}, {name: "netdev6", set: m.netdevSet6}}
}

func (m *NftablesManager) elementStateLocked(set *nftables.Set, entry firewallEntry) (nftables.SetElement, bool, error) {
	elements, err := m.conn.GetSetElements(set)
	if err != nil {
		return nftables.SetElement{}, false, err
	}
	for _, element := range elements {
		if bytes.Equal(element.Key, entry.key) && bytes.Equal(element.KeyEnd, entry.keyEnd) {
			return element, true, nil
		}
	}
	return nftables.SetElement{}, false, nil
}

func (m *NftablesManager) refreshHandlesLocked() error {
	connection := m.newConn()
	if connection == nil {
		m.clearHandlesLocked()
		m.health = HealthUnavailable
		m.lastErr = fmt.Errorf("nftables connection factory returned nil")
		return m.lastErr
	}
	m.conn = connection
	m.clearHandlesLocked()

	tables, err := connection.ListTables()
	if err != nil {
		m.health = HealthUnavailable
		m.lastErr = fmt.Errorf("list nftables tables: %w", err)
		return m.lastErr
	}

	var validationErrs []error
	foundInet := false
	foundNetdev := false
	for _, table := range tables {
		var destinationV4, destinationV6 **nftables.Set
		switch {
		case table.Name == "syswarden" && table.Family == nftables.TableFamilyINet:
			foundInet = true
			destinationV4, destinationV6 = &m.inetSet, &m.inetSet6
		case table.Name == "syswarden_hw_drop" && table.Family == nftables.TableFamilyNetdev:
			foundNetdev = true
			destinationV4, destinationV6 = &m.netdevSet, &m.netdevSet6
		default:
			continue
		}
		sets, setErr := connection.GetSets(table)
		if setErr != nil {
			validationErrs = append(validationErrs, fmt.Errorf("list sets in %s: %w", table.Name, setErr))
			continue
		}
		for _, set := range sets {
			switch set.Name {
			case "banned_ips":
				*destinationV4 = set
			case "banned_ips6":
				*destinationV6 = set
			}
		}
	}
	if !foundInet {
		validationErrs = append(validationErrs, fmt.Errorf("required table inet syswarden is missing"))
	}
	if !foundNetdev {
		validationErrs = append(validationErrs, fmt.Errorf("required table netdev syswarden_hw_drop is missing"))
	}
	for name, set := range map[string]*nftables.Set{
		"inet banned_ips":    m.inetSet,
		"inet banned_ips6":   m.inetSet6,
		"netdev banned_ips":  m.netdevSet,
		"netdev banned_ips6": m.netdevSet6,
	} {
		if set == nil {
			validationErrs = append(validationErrs, fmt.Errorf("required set %s is missing", name))
		}
	}

	count := m.availableHandleCountLocked()
	switch count {
	case 0:
		m.health = HealthUnavailable
	case 4:
		m.health = HealthHealthy
	default:
		m.health = HealthDegraded
	}
	m.lastErr = errors.Join(validationErrs...)
	return m.lastErr
}

func (m *NftablesManager) clearHandlesLocked() {
	m.inetSet = nil
	m.netdevSet = nil
	m.inetSet6 = nil
	m.netdevSet6 = nil
}

func (m *NftablesManager) availableHandleCountLocked() int {
	count := 0
	for _, set := range []*nftables.Set{m.inetSet, m.netdevSet, m.inetSet6, m.netdevSet6} {
		if set != nil {
			count++
		}
	}
	return count
}

func (m *NftablesManager) markOperationFailureLocked(err error) {
	m.lastErr = err
	if m.availableHandleCountLocked() == 0 {
		m.health = HealthUnavailable
	} else {
		m.health = HealthDegraded
	}
}

func detectBackendWithLookup(lookup func(string) (string, error)) (string, string) {
	if path, err := lookup("nft"); err == nil {
		return "nftables", path
	}
	if path, err := lookup("ufw"); err == nil {
		return "ufw", path
	}
	if path, err := lookup("firewall-cmd"); err == nil {
		return "firewalld", path
	}
	if path, err := lookup("iptables"); err == nil {
		return "iptables", path
	}
	return "none", ""
}

func detectBackend() (string, string) {
	return detectBackendWithLookup(exec.LookPath)
}

func newNftablesManager(factory nftablesConnectionFactory) (*NftablesManager, error) {
	manager := &NftablesManager{newConn: factory, health: HealthUnavailable}
	manager.mu.Lock()
	err := manager.refreshHandlesLocked()
	manager.mu.Unlock()
	return manager, err
}

func newManagerForConfiguredBackend(backend string, factory nftablesConnectionFactory) (Manager, error) {
	switch backend {
	case "keep", "nftables":
		manager, validationErr := newNftablesManager(factory)
		if validationErr != nil {
			log.Printf("[Firewall-Netlink] Backend initialized in %s state: %v", manager.Health(), validationErr)
		}
		return manager, nil
	case "iptables":
		return nil, fmt.Errorf("iptables is accepted for configuration compatibility but refused for core firewall mutations")
	default:
		return nil, fmt.Errorf("unsupported core firewall backend %q", backend)
	}
}

// NewManager constructs only the authoritative nftables runtime manager for a
// backend already accepted by the validated core configuration.
func NewManager(backend string) (Manager, error) {
	return newManagerForConfiguredBackend(backend, func() nftablesConnection { return &nftables.Conn{} })
}
