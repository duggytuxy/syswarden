//go:build linux

package firewall

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/nftables"
)

func TestMain(m *testing.M) {
	directory, err := os.MkdirTemp("", "syswarden-core-firewall-tests-")
	if err != nil {
		panic(err)
	}
	firewallRuntimeLockPath = filepath.Join(directory, "firewall.lock")
	code := m.Run()
	_ = os.RemoveAll(directory)
	os.Exit(code)
}

type fakeNftMutation struct {
	set     *nftables.Set
	element nftables.SetElement
	add     bool
}

type fakeNftablesConnection struct {
	mu              sync.Mutex
	tables          []*nftables.Table
	sets            map[string][]*nftables.Set
	elements        map[string][]nftables.SetElement
	queued          []fakeNftMutation
	listErr         error
	getSetsErr      error
	queueErr        error
	flushErr        error
	getElementsErr  error
	timeoutOverride *time.Duration
	expiresOverride *time.Duration
	flushCalls      int
}

func newFakeNftablesConnection(layerNames ...string) *fakeNftablesConnection {
	connection := &fakeNftablesConnection{
		sets:     make(map[string][]*nftables.Set),
		elements: make(map[string][]nftables.SetElement),
	}
	requested := make(map[string]bool, len(layerNames))
	for _, name := range layerNames {
		requested[name] = true
	}
	inet := &nftables.Table{Name: "syswarden", Family: nftables.TableFamilyINet}
	netdev := &nftables.Table{Name: "syswarden_hw_drop", Family: nftables.TableFamilyNetdev}
	for _, table := range []*nftables.Table{inet, netdev} {
		prefix := "inet"
		if table.Family == nftables.TableFamilyNetdev {
			prefix = "netdev"
		}
		var sets []*nftables.Set
		for _, family := range []struct {
			name   string
			suffix string
		}{{name: "banned_ips"}, {name: "banned_ips6", suffix: "6"}} {
			if requested[prefix+family.suffix] {
				sets = append(sets, &nftables.Set{Table: table, Name: family.name})
			}
		}
		if len(sets) > 0 {
			connection.tables = append(connection.tables, table)
			connection.sets[fakeNftTableKey(table)] = sets
		}
	}
	return connection
}

func fullFakeNftablesConnection() *fakeNftablesConnection {
	return newFakeNftablesConnection("inet", "inet6", "netdev", "netdev6")
}

func (c *fakeNftablesConnection) ListTables() ([]*nftables.Table, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.listErr != nil {
		return nil, c.listErr
	}
	return append([]*nftables.Table(nil), c.tables...), nil
}

func (c *fakeNftablesConnection) GetSets(table *nftables.Table) ([]*nftables.Set, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.getSetsErr != nil {
		return nil, c.getSetsErr
	}
	return append([]*nftables.Set(nil), c.sets[fakeNftTableKey(table)]...), nil
}

func (c *fakeNftablesConnection) SetAddElements(set *nftables.Set, elements []nftables.SetElement) error {
	return c.queueMutation(set, elements, true)
}

func (c *fakeNftablesConnection) SetDeleteElements(set *nftables.Set, elements []nftables.SetElement) error {
	return c.queueMutation(set, elements, false)
}

func (c *fakeNftablesConnection) queueMutation(set *nftables.Set, elements []nftables.SetElement, add bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.queueErr != nil {
		return c.queueErr
	}
	for _, element := range elements {
		copyElement := nftables.SetElement{
			Key:     append([]byte(nil), element.Key...),
			KeyEnd:  append([]byte(nil), element.KeyEnd...),
			Timeout: element.Timeout,
			Expires: element.Expires,
		}
		c.queued = append(c.queued, fakeNftMutation{set: set, element: copyElement, add: add})
	}
	return nil
}

func (c *fakeNftablesConnection) Flush() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.flushCalls++
	if c.flushErr != nil {
		c.queued = nil
		return c.flushErr
	}
	for _, mutation := range c.queued {
		key := fakeNftSetKey(mutation.set)
		if mutation.add {
			if mutation.element.Timeout > 0 && mutation.element.Expires == 0 {
				mutation.element.Expires = mutation.element.Timeout
			}
			if !fakeElementPresent(c.elements[key], mutation.element) {
				c.elements[key] = append(c.elements[key], mutation.element)
			}
			continue
		}
		remaining := c.elements[key][:0]
		for _, existing := range c.elements[key] {
			if !sameFakeElement(existing, mutation.element) {
				remaining = append(remaining, existing)
			}
		}
		c.elements[key] = remaining
	}
	c.queued = nil
	return nil
}

func (c *fakeNftablesConnection) GetSetElements(set *nftables.Set) ([]nftables.SetElement, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.getElementsErr != nil {
		return nil, c.getElementsErr
	}
	elements := append([]nftables.SetElement(nil), c.elements[fakeNftSetKey(set)]...)
	if c.timeoutOverride != nil {
		for index := range elements {
			elements[index].Timeout = *c.timeoutOverride
		}
	}
	if c.expiresOverride != nil {
		for index := range elements {
			elements[index].Expires = *c.expiresOverride
		}
	}
	return elements, nil
}

func fakeNftTableKey(table *nftables.Table) string {
	return fmt.Sprintf("%d/%s", table.Family, table.Name)
}

func fakeNftSetKey(set *nftables.Set) string {
	return fakeNftTableKey(set.Table) + "/" + set.Name
}

func fakeElementPresent(elements []nftables.SetElement, wanted nftables.SetElement) bool {
	for _, element := range elements {
		if sameFakeElement(element, wanted) {
			return true
		}
	}
	return false
}

func sameFakeElement(left, right nftables.SetElement) bool {
	return bytes.Equal(left.Key, right.Key) && bytes.Equal(left.KeyEnd, right.KeyEnd)
}

type fakeNftablesFactory struct {
	mu          sync.Mutex
	connections []*fakeNftablesConnection
	calls       int
}

func (f *fakeNftablesFactory) New() nftablesConnection {
	f.mu.Lock()
	defer f.mu.Unlock()
	index := f.calls
	f.calls++
	if index >= len(f.connections) {
		index = len(f.connections) - 1
	}
	return f.connections[index]
}

func TestNftablesManagerUnavailableRefusesFalseSuccess_SW_FW_003(t *testing.T) {
	connection := newFakeNftablesConnection()
	manager, validationErr := newNftablesManager(func() nftablesConnection { return connection })
	if validationErr == nil {
		t.Fatal("initialization did not report missing mandatory tables and sets")
	}
	if manager.Health() != HealthUnavailable {
		t.Fatalf("health = %q, want %q", manager.Health(), HealthUnavailable)
	}

	logs := captureFirewallLogs(t)
	if err := manager.Ban("192.0.2.10"); err == nil {
		t.Fatal("Ban() reported success without any usable nftables layer")
	}
	if connection.flushCalls != 0 {
		t.Fatalf("Flush() called %d times without a usable set", connection.flushCalls)
	}
	if strings.Contains(logs.String(), "Successfully injected") {
		t.Fatalf("success was logged before verification: %s", logs.String())
	}
}

func TestNftablesManagerDegradedLayerIsVerified_SW_FW_003(t *testing.T) {
	connection := newFakeNftablesConnection("inet")
	manager, _ := newNftablesManager(func() nftablesConnection { return connection })
	if manager.Health() != HealthDegraded {
		t.Fatalf("health = %q, want %q", manager.Health(), HealthDegraded)
	}
	if err := manager.BanWithTTL("192.0.2.20", time.Hour); err != nil {
		t.Fatalf("BanWithTTL() with one available layer: %v", err)
	}
	if manager.Health() != HealthDegraded {
		t.Fatalf("successful partial enforcement changed health to %q", manager.Health())
	}
}

func TestNftablesManagerRefreshesStaleHandles_SW_FW_003(t *testing.T) {
	stale := fullFakeNftablesConnection()
	stale.flushErr = errors.New("stale netlink handle")
	refreshed := fullFakeNftablesConnection()
	factory := &fakeNftablesFactory{connections: []*fakeNftablesConnection{stale, refreshed}}
	manager, err := newNftablesManager(factory.New)
	if err != nil {
		t.Fatalf("initialize healthy manager: %v", err)
	}
	if err := manager.BanWithTTL("2001:db8::20", 2*time.Hour); err != nil {
		t.Fatalf("BanWithTTL() did not recover after handle refresh: %v", err)
	}
	if factory.calls != 2 {
		t.Fatalf("connection factory calls = %d, want 2", factory.calls)
	}
	if manager.Health() != HealthHealthy {
		t.Fatalf("health = %q after refresh, want %q", manager.Health(), HealthHealthy)
	}
}

func TestNftablesManagerVerificationFailureHasNoSuccessLog_SW_FW_003(t *testing.T) {
	first := fullFakeNftablesConnection()
	first.getElementsErr = errors.New("verification unavailable")
	second := fullFakeNftablesConnection()
	second.getElementsErr = errors.New("verification unavailable")
	factory := &fakeNftablesFactory{connections: []*fakeNftablesConnection{first, second}}
	manager, err := newNftablesManager(factory.New)
	if err != nil {
		t.Fatal(err)
	}
	logs := captureFirewallLogs(t)
	if err := manager.Ban("198.51.100.30"); err == nil {
		t.Fatal("Ban() succeeded although post-flush verification failed")
	}
	if strings.Contains(logs.String(), "Successfully injected") {
		t.Fatalf("success logged before verification: %s", logs.String())
	}
	if manager.Health() != HealthDegraded {
		t.Fatalf("health = %q, want %q", manager.Health(), HealthDegraded)
	}
}

func TestNftablesManagerCIDRIsAtomicAndIdempotent_SW_FW_003(t *testing.T) {
	connection := fullFakeNftablesConnection()
	manager, err := newNftablesManager(func() nftablesConnection { return connection })
	if err != nil {
		t.Fatal(err)
	}
	const network = "198.51.100.0/24"
	if err := manager.Ban(network); err != nil {
		t.Fatalf("Ban(CIDR): %v", err)
	}
	if err := manager.Ban(network); err != nil {
		t.Fatalf("second Ban(CIDR) must be idempotent: %v", err)
	}
	entry, err := parseFirewallEntry(network)
	if err != nil {
		t.Fatal(err)
	}
	if len(entry.keyEnd) != net.IPv4len {
		t.Fatalf("CIDR KeyEnd length = %d, want %d", len(entry.keyEnd), net.IPv4len)
	}
	if err := manager.Unban(network); err != nil {
		t.Fatalf("Unban(CIDR): %v", err)
	}
	if err := manager.Unban(network); err != nil {
		t.Fatalf("second Unban(CIDR) must be idempotent: %v", err)
	}
}

func TestNftablesManagerBanWithTTLBoundsAndExactVerification_SW_FW_003(t *testing.T) {
	connection := fullFakeNftablesConnection()
	manager, err := newNftablesManager(func() nftablesConnection { return connection })
	if err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []time.Duration{
		MinimumBanTTL - time.Second,
		MinimumBanTTL + time.Millisecond,
		MaximumBanTTL + time.Second,
	} {
		if err := manager.BanWithTTL("192.0.2.40", invalid); err == nil {
			t.Fatalf("BanWithTTL() accepted invalid TTL %s", invalid)
		}
	}
	if connection.flushCalls != 0 {
		t.Fatalf("invalid TTL reached the kernel: %d flushes", connection.flushCalls)
	}

	if err := manager.BanWithTTL("192.0.2.40", MinimumBanTTL); err != nil {
		t.Fatalf("minimum TTL rejected: %v", err)
	}
	if err := manager.BanWithTTL("192.0.2.40", MaximumBanTTL); err != nil {
		t.Fatalf("maximum TTL rejected: %v", err)
	}
	entry, _ := parseFirewallEntry("192.0.2.40")
	for _, set := range []*nftables.Set{manager.inetSet, manager.netdevSet} {
		elements := connection.elements[fakeNftSetKey(set)]
		if len(elements) != 1 || !sameFakeElement(elements[0], nftables.SetElement{Key: entry.key, KeyEnd: entry.keyEnd}) {
			t.Fatalf("renewed element missing from %s", set.Name)
		}
		if elements[0].Timeout != MaximumBanTTL {
			t.Fatalf("renewed timeout = %s, want %s", elements[0].Timeout, MaximumBanTTL)
		}
	}
}

func TestNftablesManagerBanWithTTLRenewsIPAndCIDRFamilies_SW_FW_003(t *testing.T) {
	connection := fullFakeNftablesConnection()
	manager, err := newNftablesManager(func() nftablesConnection { return connection })
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range []string{"198.51.100.0/24", "2001:db8::10", "2001:db8:1::/64"} {
		if err := manager.BanWithTTL(entry, time.Hour); err != nil {
			t.Fatalf("BanWithTTL(%s): %v", entry, err)
		}
		if err := manager.BanWithTTL(entry, 2*time.Hour); err != nil {
			t.Fatalf("renew BanWithTTL(%s): %v", entry, err)
		}
		parsed, _ := parseFirewallEntry(entry)
		for _, layer := range manager.layersForKeyLocked(parsed.key) {
			elements := connection.elements[fakeNftSetKey(layer.set)]
			found := false
			for _, element := range elements {
				if sameFakeElement(element, nftables.SetElement{Key: parsed.key, KeyEnd: parsed.keyEnd}) {
					found = true
					if element.Timeout != 2*time.Hour {
						t.Fatalf("%s timeout = %s, want 2h", entry, element.Timeout)
					}
				}
			}
			if !found {
				t.Fatalf("renewed %s missing from %s", entry, layer.name)
			}
		}
	}
}

func TestNftablesManagerPermanentBanDominatesTimedRecords_SW_FW_003(t *testing.T) {
	connection := fullFakeNftablesConnection()
	manager, err := newNftablesManager(func() nftablesConnection { return connection })
	if err != nil {
		t.Fatal(err)
	}
	const entryText = "198.51.100.0/24"
	if err := manager.BanWithTTL(entryText, 2*time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := manager.BanPermanent(entryText); err != nil {
		t.Fatal(err)
	}
	flushesAfterPermanent := connection.flushCalls
	if err := manager.BanWithTTL(entryText, time.Hour); err != nil {
		t.Fatalf("temporary replay must accept stronger permanent coverage: %v", err)
	}
	if connection.flushCalls != flushesAfterPermanent {
		t.Fatalf("temporary replay replaced a permanent element: flushes %d -> %d", flushesAfterPermanent, connection.flushCalls)
	}
	entry, _ := parseFirewallEntry(entryText)
	for _, layer := range manager.layersForKeyLocked(entry.key) {
		element, present, stateErr := manager.elementStateLocked(layer.set, entry)
		if stateErr != nil || !present {
			t.Fatalf("permanent element missing from %s: %v", layer.name, stateErr)
		}
		if element.Timeout != 0 || element.Expires != 0 {
			t.Fatalf("%s permanent element has timeout=%s expires=%s", layer.name, element.Timeout, element.Expires)
		}
	}
}

func TestNftablesManagerTimedReplayNeverShortensLongerExpiry_SW_FW_003(t *testing.T) {
	connection := fullFakeNftablesConnection()
	manager, err := newNftablesManager(func() nftablesConnection { return connection })
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.BanWithTTL("203.0.113.55", 2*time.Hour); err != nil {
		t.Fatal(err)
	}
	flushes := connection.flushCalls
	if err := manager.BanWithTTL("203.0.113.55", time.Hour); err != nil {
		t.Fatalf("shorter HA replay failed: %v", err)
	}
	if connection.flushCalls != flushes {
		t.Fatalf("shorter HA replay reached the kernel: flushes %d -> %d", flushes, connection.flushCalls)
	}
}

func TestNftablesManagerReconcilesRemovedMaximumTTLAtomically_SW_FW_003(t *testing.T) {
	connection := fullFakeNftablesConnection()
	manager, err := newNftablesManager(func() nftablesConnection { return connection })
	if err != nil {
		t.Fatal(err)
	}
	const value = "203.0.113.88"
	if err := manager.BanWithTTL(value, 2*time.Hour); err != nil {
		t.Fatal(err)
	}
	flushes := connection.flushCalls
	if err := manager.ReconcileBanTTL(value, time.Hour); err != nil {
		t.Fatalf("ReconcileBanTTL(2h -> 1h): %v", err)
	}
	if connection.flushCalls != flushes+1 {
		t.Fatalf("TTL replacement used %d flushes, want exactly one atomic flush", connection.flushCalls-flushes)
	}
	entry, _ := parseFirewallEntry(value)
	for _, layer := range manager.layersForKeyLocked(entry.key) {
		element, present, stateErr := manager.elementStateLocked(layer.set, entry)
		if stateErr != nil || !present {
			t.Fatalf("reconciled ban became absent in %s: %v", layer.name, stateErr)
		}
		if element.Timeout != time.Hour || element.Expires != time.Hour {
			t.Fatalf("%s reconciled timeout/expiry = %s/%s, want 1h/1h", layer.name, element.Timeout, element.Expires)
		}
	}
}

func TestNftablesManagerRejectsWrongKernelTTLWithoutSuccess_SW_FW_003(t *testing.T) {
	wrongTTL := 30 * time.Minute
	first := fullFakeNftablesConnection()
	first.timeoutOverride = &wrongTTL
	second := fullFakeNftablesConnection()
	second.timeoutOverride = &wrongTTL
	factory := &fakeNftablesFactory{connections: []*fakeNftablesConnection{first, second}}
	manager, err := newNftablesManager(factory.New)
	if err != nil {
		t.Fatal(err)
	}
	logs := captureFirewallLogs(t)
	if err := manager.BanWithTTL("203.0.113.44", time.Hour); err == nil {
		t.Fatal("BanWithTTL() succeeded with a mismatched kernel timeout")
	}
	if strings.Contains(logs.String(), "Successfully injected") {
		t.Fatalf("success logged before exact TTL verification: %s", logs.String())
	}
}

func TestNftablesManagerStrictPermanentVersusTTLVerification_SW_FW_003(t *testing.T) {
	t.Run("preexisting permanent is stronger for BanWithTTL", func(t *testing.T) {
		connection := fullFakeNftablesConnection()
		manager, err := newNftablesManager(func() nftablesConnection { return connection })
		if err != nil {
			t.Fatal(err)
		}
		if err := manager.BanPermanent("203.0.113.61"); err != nil {
			t.Fatal(err)
		}
		flushes := connection.flushCalls
		if err := manager.BanWithTTL("203.0.113.61", time.Hour); err != nil {
			t.Fatalf("preexisting permanent coverage was rejected: %v", err)
		}
		if connection.flushCalls != flushes {
			t.Fatalf("preexisting permanent coverage was mutated: %d -> %d flushes", flushes, connection.flushCalls)
		}
	})

	t.Run("mutation resolving to permanent is rejected", func(t *testing.T) {
		zero := time.Duration(0)
		first := fullFakeNftablesConnection()
		first.timeoutOverride = &zero
		first.expiresOverride = &zero
		second := fullFakeNftablesConnection()
		second.timeoutOverride = &zero
		second.expiresOverride = &zero
		factory := &fakeNftablesFactory{connections: []*fakeNftablesConnection{first, second}}
		manager, err := newNftablesManager(factory.New)
		if err != nil {
			t.Fatal(err)
		}
		if err := manager.BanWithTTL("203.0.113.62", time.Hour); err == nil {
			t.Fatal("BanWithTTL accepted a permanent result after requesting a timed mutation")
		}
	})

	t.Run("exact reconciliation resolving to permanent is rejected", func(t *testing.T) {
		connection := fullFakeNftablesConnection()
		manager, err := newNftablesManager(func() nftablesConnection { return connection })
		if err != nil {
			t.Fatal(err)
		}
		if err := manager.BanPermanent("203.0.113.63"); err != nil {
			t.Fatal(err)
		}
		zero := time.Duration(0)
		connection.timeoutOverride = &zero
		connection.expiresOverride = &zero
		if err := manager.ReconcileBanTTL("203.0.113.63", time.Hour); err == nil {
			t.Fatal("ReconcileBanTTL accepted a permanent kernel result")
		}
	})

	t.Run("correct timed result is accepted", func(t *testing.T) {
		connection := fullFakeNftablesConnection()
		manager, err := newNftablesManager(func() nftablesConnection { return connection })
		if err != nil {
			t.Fatal(err)
		}
		if err := manager.BanWithTTL("203.0.113.64", 2*time.Hour); err != nil {
			t.Fatalf("correct BanWithTTL result rejected: %v", err)
		}
		if err := manager.ReconcileBanTTL("203.0.113.64", time.Hour); err != nil {
			t.Fatalf("correct exact reconciliation rejected: %v", err)
		}
	})
}

func TestBanExpiryCoordinationCapabilities_SW_FW_003(t *testing.T) {
	connection := fullFakeNftablesConnection()
	manager, err := newNftablesManager(func() nftablesConnection { return connection })
	if err != nil {
		t.Fatal(err)
	}
	var historical Manager = manager
	if _, ok := historical.(BanWithTTLManager); !ok {
		t.Fatal("nftables manager does not expose BanWithTTL capability")
	}
	if _, ok := historical.(BanPermanentManager); !ok {
		t.Fatal("nftables manager does not expose BanPermanent capability")
	}
	if _, ok := historical.(BanTTLReconciler); !ok {
		t.Fatal("nftables manager does not expose exact TTL reconciliation capability")
	}
	if reporter, ok := historical.(BanExpiryReporter); !ok || reporter.BanExpiryMode() != BanExpiryNative {
		t.Fatalf("nftables expiry mode = %v, want native", reporter)
	}
	fallback := &FallbackManager{backend: "iptables", cmdPath: "/usr/sbin/iptables", health: HealthHealthy}
	if fallback.BanExpiryMode() != BanExpiryExternal {
		t.Fatalf("fallback expiry mode = %q, want external", fallback.BanExpiryMode())
	}
	if _, ok := any(fallback).(BanWithTTLManager); ok {
		t.Fatal("fallback manager falsely advertises native TTL enforcement")
	}
}

func TestFallbackManagerIptablesReplayAndRemovalAreIdempotent_SW_FW_003(t *testing.T) {
	directory := t.TempDir()
	statePath := filepath.Join(directory, "rules")
	commandPath := filepath.Join(directory, "iptables")
	script := `#!/bin/sh
state="$SYSWARDEN_FAKE_FIREWALL_STATE"
case "$1" in
  -C)
    target="-I INPUT 1 -s $4 -j DROP"
    if [ -f "$state" ] && grep -F -x -- "$target" "$state" >/dev/null; then exit 0; fi
    exit 1
    ;;
  -I)
    printf '%s\n' "$*" >> "$state"
    exit 0
    ;;
  -D)
    target="-I INPUT 1 -s $4 -j DROP"
    awk -v target="$target" 'BEGIN { removed=0 } { if (!removed && $0 == target) { removed=1; next } print }' "$state" > "$state.tmp"
    mv "$state.tmp" "$state"
    exit 0
    ;;
esac
exit 2
`
	writeRootedExecutableTestFile(t, commandPath, []byte(script))
	t.Setenv("SYSWARDEN_FAKE_FIREWALL_STATE", statePath)
	manager := &FallbackManager{backend: "iptables", cmdPath: commandPath, health: HealthHealthy}
	for range 2 {
		if err := manager.Ban("192.0.2.77"); err != nil {
			t.Fatalf("idempotent Ban(): %v", err)
		}
	}
	content := readRootedTestFile(t, statePath)
	if strings.Count(strings.TrimSpace(string(content)), "\n") != 0 {
		t.Fatalf("replayed Ban() duplicated iptables state: %q", content)
	}
	duplicate := "-I INPUT 1 -s 192.0.2.77 -j DROP\n-I INPUT 1 -s 192.0.2.77 -j DROP\n-I INPUT 1 -s 192.0.2.77 -j DROP\n"
	if err := os.WriteFile(statePath, []byte(duplicate), 0600); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := manager.Unban("192.0.2.77"); err != nil {
			t.Fatalf("idempotent Unban(): %v", err)
		}
	}
	content = readRootedTestFile(t, statePath)
	if strings.TrimSpace(string(content)) != "" {
		t.Fatalf("Unban() left duplicate rules active: %q", content)
	}
}

func TestFallbackManagerFirewalldHistoricalAndPermanentBans_SW_FW_003(t *testing.T) {
	directory := t.TempDir()
	statePath := filepath.Join(directory, "state")
	logPath := filepath.Join(directory, "commands")
	commandPath := filepath.Join(directory, "firewall-cmd")
	script := `#!/bin/sh
state="$SYSWARDEN_FAKE_FIREWALL_STATE"
log="$SYSWARDEN_FAKE_FIREWALL_LOG"
printf '%s\n' "$*" >> "$log"
operation="$1"
rule="$2"
case "$operation" in
  --query-rich-rule)
    if [ -s "$state" ]; then
      current="$(sed -n '1p' "$state")"
      [ "${current#*|}" = "$rule" ] && exit 0
    fi
    exit 1
    ;;
  --add-rich-rule)
    kind="permanent"
    [ "${3:-}" = "--timeout=2592000" ] && kind="timed"
    printf '%s|%s\n' "$kind" "$rule" > "$state"
    exit 0
    ;;
  --remove-rich-rule)
    : > "$state"
    exit 0
    ;;
esac
exit 2
`
	writeRootedExecutableTestFile(t, commandPath, []byte(script))
	t.Setenv("SYSWARDEN_FAKE_FIREWALL_STATE", statePath)
	t.Setenv("SYSWARDEN_FAKE_FIREWALL_LOG", logPath)
	manager := &FallbackManager{backend: "firewalld", cmdPath: commandPath, health: HealthHealthy}
	const value = "198.51.100.0/24"
	for range 2 {
		if err := manager.Ban(value); err != nil {
			t.Fatalf("idempotent historical Ban(): %v", err)
		}
	}
	for range 2 {
		if err := manager.BanPermanent(value); err != nil {
			t.Fatalf("idempotent BanPermanent(): %v", err)
		}
	}
	state := string(readRootedTestFile(t, statePath))
	if !strings.HasPrefix(state, "permanent|") {
		t.Fatalf("BanPermanent did not replace the timed firewalld rule: %q", state)
	}
	commands := strings.Split(strings.TrimSpace(string(readRootedTestFile(t, logPath))), "\n")
	timedAdds := 0
	permanentAdds := 0
	queries := 0
	for _, command := range commands {
		switch {
		case strings.HasPrefix(command, "--query-rich-rule "):
			queries++
		case strings.HasPrefix(command, "--add-rich-rule ") && strings.HasSuffix(command, " --timeout=2592000"):
			timedAdds++
		case strings.HasPrefix(command, "--add-rich-rule "):
			permanentAdds++
		}
	}
	if timedAdds != 1 || permanentAdds != 1 {
		t.Fatalf("firewalld additions timed/permanent = %d/%d, want 1/1; commands=%v", timedAdds, permanentAdds, commands)
	}
	if queries < 6 {
		t.Fatalf("firewalld reconciliation omitted pre/post queries: %v", commands)
	}
	for range 2 {
		if err := manager.Unban(value); err != nil {
			t.Fatalf("idempotent firewalld Unban(): %v", err)
		}
	}
	if state := strings.TrimSpace(string(readRootedTestFile(t, statePath))); state != "" {
		t.Fatalf("firewalld Unban left state active: %q", state)
	}
}

func TestDetectBackendUsesFirewallCommandClient_SW_FW_003(t *testing.T) {
	requested := []string{}
	backend, path := detectBackendWithLookup(func(name string) (string, error) {
		requested = append(requested, name)
		if name == "firewall-cmd" {
			return "/usr/bin/firewall-cmd", nil
		}
		return "", errors.New("missing")
	})
	if backend != "firewalld" || path != "/usr/bin/firewall-cmd" {
		t.Fatalf("detected backend = %q/%q", backend, path)
	}
	if strings.Contains(strings.Join(requested, ","), "firewalld") {
		t.Fatalf("backend detector queried the daemon binary: %v", requested)
	}
}

func TestConfiguredRuntimeManagerNeverSelectsCompatibilityFrontends_SW2_FWBACKEND_001(t *testing.T) {
	for _, backend := range []string{"keep", "nftables"} {
		t.Run(backend, func(t *testing.T) {
			factoryCalls := 0
			manager, err := newManagerForConfiguredBackend(backend, func() nftablesConnection {
				factoryCalls++
				return fullFakeNftablesConnection()
			})
			if err != nil {
				t.Fatalf("newManagerForConfiguredBackend(%q): %v", backend, err)
			}
			if factoryCalls != 1 {
				t.Fatalf("nftables factory calls = %d, want 1", factoryCalls)
			}
			if _, ok := manager.(*NftablesManager); !ok {
				t.Fatalf("configured backend %q selected %T", backend, manager)
			}
			if !strings.HasPrefix(manager.Name(), "nftables") {
				t.Fatalf("configured backend %q manager name = %q", backend, manager.Name())
			}
		})
	}

	factoryCalls := 0
	manager, err := newManagerForConfiguredBackend("iptables", func() nftablesConnection {
		factoryCalls++
		return fullFakeNftablesConnection()
	})
	if err == nil || !strings.Contains(err.Error(), "accepted for configuration compatibility but refused") {
		t.Fatalf("iptables manager error = %v", err)
	}
	if manager != nil || factoryCalls != 0 {
		t.Fatalf("iptables reached runtime manager construction: manager=%T calls=%d", manager, factoryCalls)
	}
}

func TestFirewallRuntimeLockRejectsSymlink_SW_FW_003(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "target")
	if err := os.WriteFile(target, nil, 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "firewall.lock")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	previous := firewallRuntimeLockPath
	firewallRuntimeLockPath = link
	t.Cleanup(func() { firewallRuntimeLockPath = previous })
	if lock, err := acquireFirewallRuntimeLock(); err == nil {
		releaseFirewallRuntimeLock(lock)
		t.Fatal("firewall runtime lock followed a symbolic link")
	}
}

func TestFirewallEntryRejectsIPv4MappedInputs_SW_FW_003(t *testing.T) {
	for _, value := range []string{"::ffff:192.0.2.1", "::ffff:192.0.2.1/120"} {
		if _, err := parseFirewallEntry(value); err == nil {
			t.Fatalf("parseFirewallEntry(%q) accepted an IPv4-mapped input", value)
		}
	}
}

func TestNftablesManagerConcurrentBans_SW_FW_003(t *testing.T) {
	connection := fullFakeNftablesConnection()
	manager, err := newNftablesManager(func() nftablesConnection { return connection })
	if err != nil {
		t.Fatal(err)
	}
	const workers = 32
	errorsChannel := make(chan error, workers)
	var wait sync.WaitGroup
	for index := 1; index <= workers; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			errorsChannel <- manager.Ban(fmt.Sprintf("192.0.2.%d", index))
		}(index)
	}
	wait.Wait()
	close(errorsChannel)
	for err := range errorsChannel {
		if err != nil {
			t.Fatal(err)
		}
	}
	if connection.flushCalls != workers {
		t.Fatalf("Flush() calls = %d, want %d", connection.flushCalls, workers)
	}
}

func TestFallbackManagerSelectsCIDRFamily_SW_FW_003(t *testing.T) {
	tests := []struct {
		name          string
		backend       string
		commandPath   string
		entry         string
		add           bool
		wantPath      string
		wantArguments string
	}{
		{
			name:          "iptables IPv4 prefix",
			backend:       "iptables",
			commandPath:   "/usr/sbin/iptables",
			entry:         "192.0.2.99/24",
			add:           true,
			wantPath:      "/usr/sbin/iptables",
			wantArguments: "-I INPUT 1 -s 192.0.2.0/24 -j DROP",
		},
		{
			name:          "iptables IPv6 prefix",
			backend:       "iptables",
			commandPath:   "/usr/sbin/iptables",
			entry:         "2001:db8::99/64",
			add:           false,
			wantPath:      "/usr/sbin/ip6tables",
			wantArguments: "-D INPUT -s 2001:db8::/64 -j DROP",
		},
		{
			name:          "firewalld IPv4 prefix",
			backend:       "firewalld",
			commandPath:   "/usr/bin/firewall-cmd",
			entry:         "198.51.100.255/24",
			add:           true,
			wantPath:      "/usr/bin/firewall-cmd",
			wantArguments: "--add-rich-rule rule family=ipv4 source address=198.51.100.0/24 drop",
		},
		{
			name:          "firewalld IPv6 prefix",
			backend:       "firewalld",
			commandPath:   "/usr/bin/firewall-cmd",
			entry:         "2001:db8:1::99/48",
			add:           false,
			wantPath:      "/usr/bin/firewall-cmd",
			wantArguments: "--remove-rich-rule rule family=ipv6 source address=2001:db8:1::/48 drop",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			command, err := buildFallbackCommand(test.backend, test.commandPath, test.entry, test.add)
			if err != nil {
				t.Fatalf("buildFallbackCommand(): %v", err)
			}
			if command.Path != test.wantPath {
				t.Fatalf("command path = %q, want %q", command.Path, test.wantPath)
			}
			if arguments := strings.Join(command.Args[1:], " "); arguments != test.wantArguments {
				t.Fatalf("command arguments = %q, want %q", arguments, test.wantArguments)
			}
		})
	}
}

func TestFallbackManagerRejectsInvalidEntry_SW_FW_003(t *testing.T) {
	if _, err := buildFallbackCommand("iptables", "/usr/sbin/iptables", "not-an-address", true); err == nil {
		t.Fatal("buildFallbackCommand() accepted an invalid firewall entry")
	}
}

func captureFirewallLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	previousWriter := log.Writer()
	previousFlags := log.Flags()
	var buffer bytes.Buffer
	log.SetOutput(&buffer)
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(previousWriter)
		log.SetFlags(previousFlags)
	})
	return &buffer
}

func writeRootedExecutableTestFile(t *testing.T, path string, content []byte) {
	t.Helper()
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	file, err := root.OpenFile(filepath.Base(path), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	if _, err := file.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := file.Chmod(0700); err != nil {
		t.Fatal(err)
	}
}

func readRootedTestFile(t *testing.T, path string) []byte {
	t.Helper()
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	file, err := root.Open(filepath.Base(path))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	content, err := io.ReadAll(file)
	if err != nil {
		t.Fatal(err)
	}
	return content
}
