//go:build linux

package firewall

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/nftables"
)

const nftablesManagerKernelLabMode = "isolated-rootless-netns-v1"

type kernelIntervalExpectation struct {
	value        string
	start        string
	exclusiveEnd string
	timeout      time.Duration
}

type kernelElementExpectation struct {
	interval kernelIntervalExpectation
	end      bool
}

// TestNftablesManagerKernelIntervals_SW_FW_004 is deliberately excluded from
// ordinary test runs. The nftables kernel laboratory compiles this package and
// runs the resulting test binary as root inside a rootless, network-disabled
// container with only CAP_NET_ADMIN.
func TestNftablesManagerKernelIntervals_SW_FW_004(t *testing.T) {
	if os.Getenv("SYSWARDEN_NFTABLES_KERNEL_LAB") != nftablesManagerKernelLabMode {
		t.Skip("requires the isolated rootless nftables kernel laboratory")
	}
	currentNetNS, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatalf("read laboratory network namespace: %v", err)
	}
	if expected := os.Getenv("SYSWARDEN_NFTABLES_KERNEL_LAB_NETNS"); expected == "" || expected != currentNetNS {
		t.Fatalf("laboratory network namespace mismatch: expected %q, found %q", expected, currentNetNS)
	}
	if os.Geteuid() != 0 {
		t.Fatalf("laboratory test must run as namespace root, found euid %d", os.Geteuid())
	}

	manager, err := newNftablesManager(func() nftablesConnection { return &nftables.Conn{} })
	if err != nil {
		t.Fatalf("initialize the real NftablesManager against the kernel: %v", err)
	}
	if manager.Health() != HealthHealthy {
		t.Fatalf("real NftablesManager health = %s, want %s", manager.Health(), HealthHealthy)
	}

	intervals := []kernelIntervalExpectation{
		// Preserve the reported reproduction order for two non-adjacent IPv4
		// singletons: 45.87.249.145 first, then 5.6.7.9.
		{value: "45.87.249.145", start: "45.87.249.145", exclusiveEnd: "45.87.249.146", timeout: 83 * time.Minute},
		{value: "5.6.7.9", start: "5.6.7.9", exclusiveEnd: "5.6.7.10", timeout: 61 * time.Minute},
		// Add the adjacent pair in descending order with distinct timeouts so
		// the kernel must preserve both boundary roles at 5.6.8.10.
		{value: "5.6.8.10", start: "5.6.8.10", exclusiveEnd: "5.6.8.11", timeout: 131 * time.Minute},
		{value: "5.6.8.9", start: "5.6.8.9", exclusiveEnd: "5.6.8.10", timeout: 97 * time.Minute},
		{value: "2001:db8::9", start: "2001:db8::9", exclusiveEnd: "2001:db8::a", timeout: 149 * time.Minute},
		{value: "198.51.100.0/24", start: "198.51.100.0", exclusiveEnd: "198.51.101.0", timeout: 173 * time.Minute},
		{value: "2001:db8:1::/64", start: "2001:db8:1::", exclusiveEnd: "2001:db8:1:1::", timeout: 197 * time.Minute},
		{value: "203.0.113.40", start: "203.0.113.40", exclusiveEnd: "203.0.113.41"},
	}
	byValue := make(map[string]kernelIntervalExpectation, len(intervals))
	for _, interval := range intervals {
		byValue[interval.value] = interval
	}

	// Cleanup remains best effort because the harness flushes the entire
	// disposable namespace after this process exits. It prevents a failed
	// assertion from obscuring subsequent package tests in the same binary.
	defer func() {
		values := make([]string, 0, len(byValue))
		for value := range byValue {
			values = append(values, value)
		}
		sort.Strings(values)
		for _, value := range values {
			_ = manager.Unban(value)
		}
	}()

	active := make(map[string]kernelIntervalExpectation, len(intervals))
	assertKernelManagerRawIntervals(t, manager, active)

	for _, interval := range intervals[:7] {
		if err := manager.BanWithTTL(interval.value, interval.timeout); err != nil {
			t.Fatalf("add timed interval %s through NftablesManager: %v", interval.value, err)
		}
		active[interval.value] = interval
	}
	permanent := intervals[7]
	if err := manager.BanPermanent(permanent.value); err != nil {
		t.Fatalf("add permanent interval %s through NftablesManager: %v", permanent.value, err)
	}
	active[permanent.value] = permanent
	assertKernelManagerRawIntervals(t, manager, active)

	// A singleton starting at the beginning of an active CIDR is ambiguous in
	// an interval set. The manager must reject it conservatively and preserve
	// the complete CIDR, including its timeout, in both layers.
	overlapManager, err := newNftablesManager(func() nftablesConnection { return &nftables.Conn{} })
	if err != nil {
		t.Fatalf("initialize overlap probe NftablesManager: %v", err)
	}
	if err := overlapManager.BanWithTTL("198.51.100.0", 251*time.Minute); err == nil {
		t.Fatal("overlapping singleton unexpectedly replaced the active IPv4 CIDR")
	}
	assertKernelManagerRawIntervals(t, manager, active)

	// Two adjacent /25 intervals have the same outer boundaries as their
	// covering /24, but the internal boundary and distinct TTLs make them
	// separate lifecycle records. Broad add, reconcile, and remove operations
	// must all fail closed without changing either half.
	leftHalf := kernelIntervalExpectation{
		value:        "198.19.0.0/25",
		start:        "198.19.0.0",
		exclusiveEnd: "198.19.0.128",
		timeout:      211 * time.Minute,
	}
	rightHalf := kernelIntervalExpectation{
		value:        "198.19.0.128/25",
		start:        "198.19.0.128",
		exclusiveEnd: "198.19.1.0",
		timeout:      223 * time.Minute,
	}
	for _, half := range []kernelIntervalExpectation{leftHalf, rightHalf} {
		if err := manager.BanWithTTL(half.value, half.timeout); err != nil {
			t.Fatalf("add nested-interval fixture %s through NftablesManager: %v", half.value, err)
		}
		active[half.value] = half
		byValue[half.value] = half
	}
	assertKernelManagerRawIntervals(t, manager, active)
	for _, operation := range []struct {
		name string
		run  func() error
	}{
		{name: "ban", run: func() error { return manager.BanWithTTL("198.19.0.0/24", 239*time.Minute) }},
		{name: "reconcile", run: func() error { return manager.ReconcileBanTTL("198.19.0.0/24", 239*time.Minute) }},
		{name: "unban", run: func() error { return manager.Unban("198.19.0.0/24") }},
	} {
		if err := operation.run(); err == nil || !strings.Contains(err.Error(), "existing internal interval boundary") {
			t.Fatalf("broad %s over adjacent /25 records returned %v, want conservative rejection", operation.name, err)
		}
		assertKernelManagerRawIntervals(t, manager, active)
	}

	// Reconcile every timed element to the already-requested TTL and replay
	// the permanent element. Exact raw cardinality proves the replay is
	// idempotent and did not create duplicate starts or end markers.
	for _, interval := range intervals[:7] {
		if err := manager.ReconcileBanTTL(interval.value, interval.timeout); err != nil {
			t.Fatalf("idempotently replay timed interval %s through NftablesManager: %v", interval.value, err)
		}
	}
	if err := manager.BanPermanent(permanent.value); err != nil {
		t.Fatalf("idempotently replay permanent interval %s through NftablesManager: %v", permanent.value, err)
	}
	assertKernelManagerRawIntervals(t, manager, active)

	expiring := kernelIntervalExpectation{
		value:        "192.0.2.199",
		start:        "192.0.2.199",
		exclusiveEnd: "192.0.2.200",
		timeout:      2 * time.Second,
	}
	neighbor := kernelIntervalExpectation{
		value:        "192.0.2.200",
		start:        "192.0.2.200",
		exclusiveEnd: "192.0.2.201",
		timeout:      17 * time.Minute,
	}
	byValue[expiring.value] = expiring
	byValue[neighbor.value] = neighbor
	if err := manager.BanWithTTL(neighbor.value, neighbor.timeout); err != nil {
		t.Fatalf("add long-lived neighbor %s through NftablesManager: %v", neighbor.value, err)
	}
	active[neighbor.value] = neighbor
	if err := manager.ReconcileBanTTL(neighbor.value, neighbor.timeout); err != nil {
		t.Fatalf("idempotently replay long-lived neighbor %s through NftablesManager: %v", neighbor.value, err)
	}
	if err := manager.BanWithTTL(expiring.value, expiring.timeout); err != nil {
		t.Fatalf("add short-lived interval %s through NftablesManager: %v", expiring.value, err)
	}
	active[expiring.value] = expiring
	if err := manager.ReconcileBanTTL(expiring.value, expiring.timeout); err != nil {
		t.Fatalf("idempotently replay short-lived interval %s through NftablesManager: %v", expiring.value, err)
	}
	assertKernelManagerRawIntervals(t, manager, active)
	residueObserved := waitForKernelTimedStartExpiration(t, manager, expiring, 10*time.Second)
	assertKernelManagerTreatsExpiredIntervalAsAbsent(t, manager, expiring.value)
	assertExactNftSetLookup(t, expiring.value, false)
	assertExactNftSetLookup(t, neighbor.value, true)

	// Depending on the kernel GC model, the exclusive marker may remain after
	// its timed start stops matching or may already have been collected. Re-ban
	// directly, without a pre-delete, and require one exact closed interval in
	// both layers in either case.
	if residueObserved {
		t.Log("kernel retained coherent exclusive-end residue after timed expiry")
	} else {
		t.Log("kernel collected the complete timed interval before observation")
	}
	expiring.timeout = 5 * time.Second
	if err := manager.BanWithTTL(expiring.value, expiring.timeout); err != nil {
		t.Fatalf("re-ban expired interval %s directly through NftablesManager: %v", expiring.value, err)
	}
	active[expiring.value] = expiring
	assertKernelManagerRawIntervals(t, manager, active)
	if err := manager.Unban(expiring.value); err != nil {
		t.Fatalf("remove re-banned interval %s through NftablesManager: %v", expiring.value, err)
	}
	delete(active, expiring.value)
	assertKernelManagerRawIntervals(t, manager, active)

	renewed := active["5.6.7.9"]
	renewed.timeout = 229 * time.Minute
	if err := manager.ReconcileBanTTL(renewed.value, renewed.timeout); err != nil {
		t.Fatalf("renew interval %s through NftablesManager: %v", renewed.value, err)
	}
	active[renewed.value] = renewed
	assertKernelManagerRawIntervals(t, manager, active)

	converted := active["45.87.249.145"]
	converted.timeout = 0
	if err := manager.BanPermanent(converted.value); err != nil {
		t.Fatalf("convert interval %s to permanent through NftablesManager: %v", converted.value, err)
	}
	active[converted.value] = converted
	assertKernelManagerRawIntervals(t, manager, active)

	// Remove a renewed singleton, one half of an adjacent pair, an IPv6
	// singleton, and both CIDR families. Every snapshot proves that the exact
	// exclusive marker disappears without widening or removing a neighbour.
	for _, value := range []string{
		"5.6.7.9",
		"5.6.8.9",
		"2001:db8::9",
		"198.51.100.0/24",
		"2001:db8:1::/64",
	} {
		if err := manager.Unban(value); err != nil {
			t.Fatalf("remove interval %s through NftablesManager: %v", value, err)
		}
		delete(active, value)
		assertKernelManagerRawIntervals(t, manager, active)
	}

	remaining := make([]string, 0, len(active))
	for value := range active {
		remaining = append(remaining, value)
	}
	sort.Strings(remaining)
	for _, value := range remaining {
		if err := manager.Unban(value); err != nil {
			t.Fatalf("remove final interval %s through NftablesManager: %v", value, err)
		}
		delete(active, value)
	}
	assertKernelManagerRawIntervals(t, manager, active)
	if err := manager.LastError(); err != nil {
		t.Fatalf("real NftablesManager retained an operation error after successful cleanup: %v", err)
	}
	// The deliberate fail-closed overlap probes latch this manager instance in
	// degraded health even though they do not mutate the kernel. Reattest from a
	// fresh connection so final health reflects the actual four-set state rather
	// than erasing that diagnostic history.
	reattested, err := newNftablesManager(func() nftablesConnection { return &nftables.Conn{} })
	if err != nil {
		t.Fatalf("reattest real NftablesManager after cleanup: %v", err)
	}
	if reattested.Health() != HealthHealthy {
		t.Fatalf("reattested NftablesManager health = %s, want %s", reattested.Health(), HealthHealthy)
	}
	t.Log("SYSWARDEN_MANAGER_KERNEL_RAW_INTERVALS_OK")
}

func waitForKernelTimedStartExpiration(t *testing.T, manager *NftablesManager, interval kernelIntervalExpectation, timeout time.Duration) bool {
	t.Helper()
	start := kernelLabAddressBytes(t, interval.start)
	end := kernelLabAddressBytes(t, interval.exclusiveEnd)
	deadline := time.Now().Add(timeout)
	for {
		// Kernel versions can collect the start and exclusive end together or
		// retain the raw end marker until a later same-set commit. Both states are
		// valid once the start is absent, provided inet and netdev stay coherent.
		manager.mu.RLock()
		sets := []struct {
			name string
			set  *nftables.Set
		}{
			{name: "inet", set: manager.inetSet},
			{name: "netdev", set: manager.netdevSet},
		}
		allStartsExpired := true
		coherentEndState := true
		var commonEndState *bool
		states := make([]string, 0, len(sets))
		for _, set := range sets {
			elements, err := manager.conn.GetSetElements(set.set)
			if err != nil {
				manager.mu.RUnlock()
				t.Fatalf("read raw elements while waiting for %s to expire: %v", interval.value, err)
			}
			startPresent := false
			endPresent := false
			for _, element := range elements {
				startPresent = startPresent || (!element.IntervalEnd && bytes.Equal(element.Key, start))
				endPresent = endPresent || (element.IntervalEnd && bytes.Equal(element.Key, end))
			}
			states = append(states, fmt.Sprintf("%s(start=%t,end=%t)", set.name, startPresent, endPresent))
			allStartsExpired = allStartsExpired && !startPresent
			if commonEndState == nil {
				observed := endPresent
				commonEndState = &observed
			} else if *commonEndState != endPresent {
				coherentEndState = false
			}
		}
		manager.mu.RUnlock()
		if allStartsExpired && coherentEndState {
			return commonEndState != nil && *commonEndState
		}
		if time.Now().After(deadline) {
			t.Fatalf("kernel did not expose coherent functional expiry for %s after %s: %v", interval.value, timeout, states)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func assertKernelManagerTreatsExpiredIntervalAsAbsent(t *testing.T, manager *NftablesManager, value string) {
	t.Helper()
	entry, err := parseFirewallEntry(value)
	if err != nil {
		t.Fatalf("parse expired manager entry %s: %v", value, err)
	}
	manager.mu.RLock()
	defer manager.mu.RUnlock()
	for _, layer := range manager.layersForKeyLocked(entry.key) {
		_, present, unterminated, err := manager.elementStateLocked(layer.set, entry)
		if err != nil {
			t.Fatalf("%s lookup of expired entry %s: %v", layer.name, value, err)
		}
		if present || unterminated {
			t.Fatalf("%s lookup still considers expired entry %s active", layer.name, value)
		}
	}
}

func assertExactNftSetLookup(t *testing.T, value string, wantPresent bool) {
	t.Helper()
	address, err := netip.ParseAddr(value)
	if err != nil || address.String() != value {
		t.Fatalf("exact nft lookup requires a canonical IP address, found %q: %v", value, err)
	}
	sets := []struct {
		family string
		table  string
		set    string
	}{
		{family: "inet", table: "syswarden", set: "banned_ips"},
		{family: "netdev", table: "syswarden_hw_drop", set: "banned_ips"},
	}
	for _, set := range sets {
		command := exec.Command("nft", "get", "element", set.family, set.table, set.set, "{", value, "}") // #nosec G204 -- nft and set identifiers are fixed test fixtures, value is a canonical netip address, and no shell is invoked
		command.Env = append(os.Environ(), "LC_ALL=C", "LANG=C")
		output, err := command.CombinedOutput()
		if wantPresent {
			if err != nil {
				t.Fatalf("exact nft lookup did not find active %s in %s %s %s: %v: %s", value, set.family, set.table, set.set, err, strings.TrimSpace(string(output)))
			}
			if !strings.Contains(string(output), value) {
				t.Fatalf("exact nft lookup for active %s in %s %s %s returned unrelated output: %s", value, set.family, set.table, set.set, strings.TrimSpace(string(output)))
			}
			continue
		}
		var exitError *exec.ExitError
		if err == nil || !errors.As(err, &exitError) || exitError.ExitCode() == 0 {
			t.Fatalf("exact nft lookup unexpectedly found expired %s in %s %s %s: %s", value, set.family, set.table, set.set, strings.TrimSpace(string(output)))
		}
		if !strings.Contains(string(output), "No such file or directory") {
			t.Fatalf("exact nft lookup for expired %s in %s %s %s failed ambiguously: %v: %s", value, set.family, set.table, set.set, err, strings.TrimSpace(string(output)))
		}
	}
}

func assertKernelManagerRawIntervals(t *testing.T, manager *NftablesManager, active map[string]kernelIntervalExpectation) {
	t.Helper()

	manager.mu.RLock()
	defer manager.mu.RUnlock()
	sets := []struct {
		name string
		set  *nftables.Set
		ipv4 bool
	}{
		{name: "inet syswarden banned_ips", set: manager.inetSet, ipv4: true},
		{name: "inet syswarden banned_ips6", set: manager.inetSet6, ipv4: false},
		{name: "netdev syswarden_hw_drop banned_ips", set: manager.netdevSet, ipv4: true},
		{name: "netdev syswarden_hw_drop banned_ips6", set: manager.netdevSet6, ipv4: false},
	}

	for _, set := range sets {
		if set.set == nil {
			t.Fatalf("%s handle is nil", set.name)
		}
		expected := make(map[string]kernelElementExpectation)
		for _, interval := range active {
			start := kernelLabAddressBytes(t, interval.start)
			if (len(start) == 4) != set.ipv4 {
				continue
			}
			end := kernelLabAddressBytes(t, interval.exclusiveEnd)
			expected[kernelLabElementID(start, false)] = kernelElementExpectation{interval: interval}
			expected[kernelLabElementID(end, true)] = kernelElementExpectation{interval: interval, end: true}
		}

		elements, err := manager.conn.GetSetElements(set.set)
		if err != nil {
			t.Fatalf("read raw netlink elements from %s: %v", set.name, err)
		}
		if len(elements) != len(expected) {
			t.Fatalf("%s has %d raw elements, want %d exact start/end elements: %#v", set.name, len(elements), len(expected), elements)
		}
		seen := make(map[string]bool, len(elements))
		for _, element := range elements {
			if len(element.KeyEnd) != 0 {
				t.Fatalf("%s contains unsupported direct KeyEnd interval %x-%x", set.name, element.Key, element.KeyEnd)
			}
			id := kernelLabElementID(element.Key, element.IntervalEnd)
			want, ok := expected[id]
			if !ok {
				t.Fatalf("%s contains unexpected raw element key=%x interval_end=%t", set.name, element.Key, element.IntervalEnd)
			}
			if seen[id] {
				t.Fatalf("%s contains duplicate raw element key=%x interval_end=%t", set.name, element.Key, element.IntervalEnd)
			}
			seen[id] = true
			if want.end {
				if element.Timeout != 0 || element.Expires != 0 {
					t.Fatalf("%s end marker for %s has timeout=%s expiry=%s", set.name, want.interval.value, element.Timeout, element.Expires)
				}
				continue
			}
			if element.Timeout != want.interval.timeout {
				t.Fatalf("%s start for %s has timeout=%s, want %s", set.name, want.interval.value, element.Timeout, want.interval.timeout)
			}
			if want.interval.timeout == 0 {
				if element.Expires != 0 {
					t.Fatalf("%s permanent start for %s has expiry=%s", set.name, want.interval.value, element.Expires)
				}
				continue
			}
			if element.Expires <= 0 || element.Expires > want.interval.timeout {
				t.Fatalf("%s timed start for %s has expiry=%s outside (0,%s]", set.name, want.interval.value, element.Expires, want.interval.timeout)
			}
		}
		for id, want := range expected {
			if !seen[id] {
				role := "start"
				if want.end {
					role = "exclusive end"
				}
				t.Fatalf("%s is missing exact %s marker for %s", set.name, role, want.interval.value)
			}
		}
	}
}

func kernelLabAddressBytes(t *testing.T, value string) []byte {
	t.Helper()
	address, err := netip.ParseAddr(value)
	if err != nil {
		t.Fatalf("parse kernel expectation address %q: %v", value, err)
	}
	if address.Is4() {
		value := address.As4()
		return append([]byte(nil), value[:]...)
	}
	value16 := address.As16()
	return append([]byte(nil), value16[:]...)
}

func kernelLabElementID(key []byte, intervalEnd bool) string {
	return fmt.Sprintf("%x/%t", key, intervalEnd)
}
