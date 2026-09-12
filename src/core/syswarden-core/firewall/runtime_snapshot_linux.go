//go:build linux

package firewall

import (
	"bytes"
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/google/nftables"
)

const maximumNativeSnapshotEntries = 16384

type nativeLayerObservation struct {
	elements  []nftables.SetElement
	startedAt time.Time
	endedAt   time.Time
}

func (m *NftablesManager) observeMutationLocked(entry firewallEntry, observe func(NativeRuntimeEntrySnapshot) error) error {
	if err := m.refreshHandlesLocked(); err != nil {
		return err
	}
	snapshots, err := m.nativeRuntimeSnapshotsLocked([]firewallEntry{entry}, false)
	if err != nil {
		return err
	}
	return observe(snapshots[0])
}

func (m *NftablesManager) WithNativeRuntimeSnapshot(ctx context.Context, entries []string, consume func([]NativeRuntimeEntrySnapshot) error) error {
	if ctx == nil || consume == nil || len(entries) > maximumNativeSnapshotEntries {
		return fmt.Errorf("native runtime snapshot requires bounded entries, a context, and a callback")
	}
	parsed := make([]firewallEntry, 0, len(entries))
	seen := make(map[string]bool, len(entries))
	for _, value := range entries {
		entry, err := parseFirewallEntry(value)
		if err != nil || entry.text != value || seen[value] {
			return fmt.Errorf("native runtime snapshot entries must be unique and canonical")
		}
		seen[value] = true
		parsed = append(parsed, entry)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	lock, err := acquireFirewallRuntimeLock()
	if err != nil {
		return err
	}
	defer releaseFirewallRuntimeLock(lock)
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := m.refreshHandlesLocked(); err != nil {
		return err
	}
	snapshots, err := m.nativeRuntimeSnapshotsLocked(parsed, true)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return consume(snapshots)
}

// Each set is read once. Sorting supports bounded binary-search lookups for
// each tracked entry instead of rescanning a full set for every claim.
func (m *NftablesManager) nativeRuntimeSnapshotsLocked(entries []firewallEntry, requireTrackedInventory bool) ([]NativeRuntimeEntrySnapshot, error) {
	layers := []nftablesLayer{{name: "inet", set: m.inetSet}, {name: "netdev", set: m.netdevSet},
		{name: "inet6", set: m.inetSet6}, {name: "netdev6", set: m.netdevSet6}}
	observations := make(map[string]nativeLayerObservation, len(layers))
	tracked := make(map[string]bool, len(entries))
	for _, entry := range entries {
		tracked[string(entry.key)] = true
	}
	for _, layer := range layers {
		if layer.set == nil {
			return nil, fmt.Errorf("native runtime evidence lacks expected %s layer", layer.name)
		}
		observation := nativeLayerObservation{startedAt: time.Now().UTC()}
		elements, err := m.conn.GetSetElements(layer.set)
		observation.endedAt = time.Now().UTC()
		if err != nil {
			return nil, fmt.Errorf("read native %s evidence: %w", layer.name, err)
		}
		if len(elements) > 2*maximumNativeSnapshotEntries || observation.endedAt.Before(observation.startedAt) ||
			observation.endedAt.Sub(observation.startedAt) > time.Second {
			return nil, fmt.Errorf("native runtime layer %s exceeds inventory or capture bounds", layer.name)
		}
		observation.elements = append([]nftables.SetElement{}, elements...)
		sort.Slice(observation.elements, func(i, j int) bool {
			return bytes.Compare(observation.elements[i].Key, observation.elements[j].Key) < 0
		})
		if requireTrackedInventory {
			seen := make(map[string]bool, len(elements))
			for _, element := range elements {
				if element.IntervalEnd {
					continue
				}
				key := string(element.Key)
				if !tracked[key] || seen[key] || len(element.KeyEnd) != 0 {
					return nil, fmt.Errorf("native runtime %s inventory contains an untracked or ambiguous claim", layer.name)
				}
				seen[key] = true
			}
		}
		observations[layer.name] = observation
	}
	result := make([]NativeRuntimeEntrySnapshot, 0, len(entries))
	for _, entry := range entries {
		snapshot, err := nativeRuntimeEntrySnapshot(entry, m.layersForKeyLocked(entry.key), observations, requireTrackedInventory)
		if err != nil {
			return nil, err
		}
		result = append(result, snapshot)
	}
	return result, nil
}

func nativeRuntimeEntrySnapshot(entry firewallEntry, layers []nftablesLayer, observations map[string]nativeLayerObservation, requireTrackedInventory bool) (NativeRuntimeEntrySnapshot, error) {
	var snapshot NativeRuntimeEntrySnapshot
	var earliestExpiry, earliestUpperBound, latestLowerBound time.Time
	for index, layer := range layers {
		observation := observations[layer.name]
		if !requireTrackedInventory && nativeTargetInsideDifferentInterval(observation.elements, entry.key) {
			return NativeRuntimeEntrySnapshot{}, fmt.Errorf("native %s target %s is inside another retained interval", layer.name, entry.text)
		}
		element, present, open, err := indexedNativeElementState(observation.elements, entry)
		if err != nil || open {
			return NativeRuntimeEntrySnapshot{}, fmt.Errorf("native %s entry %s is ambiguous: %v", layer.name, entry.text, err)
		}
		permanent := present && element.Timeout == 0 && element.Expires == 0
		var expiry time.Time
		if present && !permanent {
			if element.Timeout <= 0 || element.Expires <= 0 || element.Expires > element.Timeout+time.Second {
				return NativeRuntimeEntrySnapshot{}, fmt.Errorf("native %s lifetime evidence is invalid", layer.name)
			}
			// Netlink encodes the remaining lifetime in whole milliseconds.
			// Keep the read window and that wire precision separate from
			// a real difference between the two enforcement deadlines.
			expiry = observation.endedAt.Add(element.Expires + time.Millisecond)
			lowerBound := observation.startedAt.Add(element.Expires)
			if earliestExpiry.IsZero() || lowerBound.Before(earliestExpiry) {
				earliestExpiry = lowerBound
			}
			if earliestUpperBound.IsZero() || expiry.Before(earliestUpperBound) {
				earliestUpperBound = expiry
			}
			if lowerBound.After(latestLowerBound) {
				latestLowerBound = lowerBound
			}
		}
		if index == 0 {
			snapshot = NativeRuntimeEntrySnapshot{Entry: entry.text, Present: present, Permanent: permanent, ExpiresAt: expiry}
		} else if snapshot.Present != present || snapshot.Permanent != permanent {
			return NativeRuntimeEntrySnapshot{}, fmt.Errorf("native runtime layers disagree for %s", entry.text)
		}
		if expiry.After(snapshot.ExpiresAt) {
			snapshot.ExpiresAt = expiry
		}
		if observation.endedAt.After(snapshot.CapturedAt) {
			snapshot.CapturedAt = observation.endedAt
		}
	}
	if !snapshot.ExpiresAt.IsZero() && (latestLowerBound.Sub(earliestUpperBound) > 2*time.Second || !earliestExpiry.After(snapshot.CapturedAt)) {
		return NativeRuntimeEntrySnapshot{}, fmt.Errorf("native runtime expiry is divergent or elapsed during capture for %s", entry.text)
	}
	return snapshot, nil
}

func nativeTargetInsideDifferentInterval(elements []nftables.SetElement, key []byte) bool {
	start := sort.Search(len(elements), func(index int) bool { return bytes.Compare(elements[index].Key, key) >= 0 })
	for index := start; index < len(elements) && bytes.Equal(elements[index].Key, key); index++ {
		if elements[index].IntervalEnd {
			return false
		}
	}
	if start == 0 {
		return false
	}
	previousKey := elements[start-1].Key
	for index := start - 1; index >= 0 && bytes.Equal(elements[index].Key, previousKey); index-- {
		if !elements[index].IntervalEnd {
			return true
		}
	}
	return false
}

func indexedNativeElementState(elements []nftables.SetElement, entry firewallEntry) (nftables.SetElement, bool, bool, error) {
	start := sort.Search(len(elements), func(index int) bool { return bytes.Compare(elements[index].Key, entry.key) >= 0 })
	expected := nftablesIntervalElements(entry, 0)
	endKey := entry.key
	if len(expected) == 2 {
		endKey = expected[1].Key
	}
	end := sort.Search(len(elements), func(index int) bool { return bytes.Compare(elements[index].Key, endKey) > 0 })
	if end < len(elements) {
		// One following boundary preserves the unterminated-interval ambiguity
		// check made by the native mutator's shared parser.
		end++
	}
	return nftablesElementState(elements[start:end], entry)
}
