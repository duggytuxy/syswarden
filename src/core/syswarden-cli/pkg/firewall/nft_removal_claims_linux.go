//go:build linux

package firewall

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"syswarden-cli/pkg/runtimehistory"
	"time"
)

type nftRuntimeCapture struct{ start, end time.Time }
type nftRuntimeClaim struct {
	record   runtimehistory.Claim
	interval nftInetInterval
	expiry   time.Time
}
type nftRuntimeObservedClaim struct {
	permanent    bool
	lower, upper time.Time
}
type nftRuntimeClaimProof struct {
	claims   map[string]map[string]nftRuntimeClaim
	windows  map[string]nftRuntimeCapture
	observed map[string]map[string]nftRuntimeObservedClaim
}

func nftRuntimeIntervalKey(interval nftInetInterval) string {
	return interval.first.String() + ":" + interval.last.String()
}

func newNFTRuntimeClaimProof(history *nftRuntimeHistoryLease, windows map[string]nftRuntimeCapture) (*nftRuntimeClaimProof, error) {
	if history == nil || history.digest() == "" {
		return nil, nil
	}
	proof := &nftRuntimeClaimProof{claims: map[string]map[string]nftRuntimeClaim{"banned_ips": {}, "banned_ips6": {}}, windows: windows, observed: map[string]map[string]nftRuntimeObservedClaim{}}
	for _, family := range []string{"inet", "netdev"} {
		window, ok := windows[family]
		if !ok || window.start.IsZero() || window.end.Before(window.start) || window.end.Sub(window.start) > time.Second {
			return nil, fmt.Errorf("native runtime capture exceeds its time bound")
		}
	}
	for _, record := range history.evidence.model.Records {
		if record.State != "active" {
			continue
		}
		address, err := netip.ParseAddr(record.Entry)
		if err != nil {
			prefix, e := netip.ParsePrefix(record.Entry)
			if e != nil {
				return nil, e
			}
			address = prefix.Addr()
		}
		name, kind := "banned_ips", "addr4"
		if !address.Is4() {
			name, kind = "banned_ips6", "addr6"
		}
		parts, err := nftRetirementPopulationEntry(record.Entry, kind)
		if err != nil || len(parts) != 1 {
			return nil, fmt.Errorf("runtime claim interval is not exact")
		}
		claim := nftRuntimeClaim{record: record, interval: parts[0]}
		if record.ExpiresAt != "" {
			claim.expiry, err = time.Parse(time.RFC3339Nano, record.ExpiresAt)
			if err != nil {
				return nil, err
			}
		}
		key := nftRuntimeIntervalKey(parts[0])
		if _, duplicate := proof.claims[name][key]; duplicate {
			return nil, fmt.Errorf("runtime history contains equivalent active entries")
		}
		proof.claims[name][key] = claim
	}
	for _, claims := range proof.claims {
		ordered := make([]nftRuntimeClaim, 0, len(claims))
		for _, claim := range claims {
			ordered = append(ordered, claim)
		}
		slices.SortFunc(ordered, func(a, b nftRuntimeClaim) int { return a.interval.first.Cmp(b.interval.first) })
		for i := 1; i < len(ordered); i++ {
			if ordered[i].interval.first.Cmp(ordered[i-1].interval.last) <= 0 {
				return nil, fmt.Errorf("active native runtime claims overlap")
			}
		}
	}
	return proof, nil
}

func nftRuntimeElementSeconds(value any) (time.Duration, error) {
	number, ok := value.(json.Number)
	seconds, err := strconv.ParseUint(string(number), 10, 32)
	if !ok || err != nil || strconv.FormatUint(seconds, 10) != string(number) || seconds == 0 || seconds > 30*24*3600+2 {
		return 0, fmt.Errorf("native runtime lifetime is not a bounded positive integer")
	}
	return time.Duration(seconds) * time.Second, nil
}

func nftRuntimeElement(value any, kind string) (nftInetInterval, time.Duration, time.Duration, error) {
	var empty nftInetInterval
	var timeout, expires time.Duration
	if wrapper, ok := value.(map[string]any); ok {
		if raw, present := wrapper["elem"]; present {
			object, ok := raw.(map[string]any)
			if len(wrapper) != 1 || !ok || !legacyFail2banNFTFields(object, "val", "timeout expires") {
				return empty, 0, 0, fmt.Errorf("native runtime element has unsupported metadata")
			}
			value = object["val"]
			_, timed := object["timeout"]
			_, expiring := object["expires"]
			if timed != expiring {
				return empty, 0, 0, fmt.Errorf("native runtime lifetime is incomplete")
			}
			if timed {
				var err error
				timeout, err = nftRuntimeElementSeconds(object["timeout"])
				if err != nil {
					return empty, 0, 0, err
				}
				expires, err = nftRuntimeElementSeconds(object["expires"])
				if err != nil {
					return empty, 0, 0, err
				}
				if expires > timeout {
					return empty, 0, 0, fmt.Errorf("native runtime expiry exceeds its timeout")
				}
			}
		}
	}
	if object, ok := value.(map[string]any); ok {
		_, prefix := object["prefix"]
		_, span := object["range"]
		if len(object) != 1 || !prefix && !span {
			return empty, 0, 0, fmt.Errorf("native runtime element is not one exact address interval")
		}
	}
	remaining := 4
	parts, err := nftInetOperandIntervals(value, kind, 0, &remaining)
	if err != nil || len(parts) != 1 {
		return empty, 0, 0, fmt.Errorf("native runtime element interval is invalid")
	}
	return parts[0], timeout, expires, nil
}

func (proof *nftRuntimeClaimProof) inspect(family, name string, entries []any) error {
	if name != "banned_ips" && name != "banned_ips6" {
		if len(entries) != 0 {
			return fmt.Errorf("current nonstatic population requires separate runtime ownership attestation")
		}
		return nil
	}
	if proof == nil {
		if len(entries) != 0 {
			return fmt.Errorf("current nonstatic population requires separate runtime ownership attestation")
		}
		return nil
	}
	window, ok := proof.windows[family]
	if !ok || len(entries) > runtimehistory.MaximumRecords {
		return fmt.Errorf("native runtime population exceeds its scope")
	}
	layer := family + "/" + name
	if _, seen := proof.observed[layer]; seen {
		return fmt.Errorf("native runtime layer was observed more than once")
	}
	seen := make(map[string]nftRuntimeObservedClaim, len(entries))
	kind := "addr4"
	if name == "banned_ips6" {
		kind = "addr6"
	}
	for _, value := range entries {
		interval, timeout, expires, err := nftRuntimeElement(value, kind)
		if err != nil {
			return err
		}
		key := nftRuntimeIntervalKey(interval)
		claim, known := proof.claims[name][key]
		if _, duplicate := seen[key]; !known || duplicate {
			return fmt.Errorf("native runtime population contains an untracked or duplicate claim")
		}
		observed := nftRuntimeObservedClaim{permanent: timeout == 0}
		if observed.permanent != claim.expiry.IsZero() {
			return fmt.Errorf("native runtime permanence differs from its recorded claim")
		}
		if !observed.permanent {
			// nft JSON truncates seconds. Preserve the complete read window and
			// one wire unit; never silently refresh or extend a recorded ban.
			observed.lower = window.start.Add(expires)
			observed.upper = window.end.Add(expires + time.Second)
			if !claim.expiry.After(window.end) || claim.expiry.Before(observed.lower.Add(-2*time.Second)) || claim.expiry.After(observed.upper.Add(2*time.Second)) {
				return fmt.Errorf("native runtime deadline differs from its recorded claim")
			}
		}
		seen[key] = observed
	}
	for key, claim := range proof.claims[name] {
		if _, present := seen[key]; !present && (claim.expiry.IsZero() || claim.expiry.After(window.start)) {
			return fmt.Errorf("native runtime layer lacks a still-active recorded claim")
		}
	}
	proof.observed[layer] = seen
	return nil
}

func (proof *nftRuntimeClaimProof) complete() error {
	if proof == nil {
		return nil
	}
	for _, name := range []string{"banned_ips", "banned_ips6"} {
		inet, a := proof.observed["inet/"+name]
		ingress, b := proof.observed["netdev/"+name]
		if !a || !b || len(inet) != len(ingress) {
			return fmt.Errorf("native runtime layers have incomplete or inconsistent claim coverage")
		}
		for key, left := range inet {
			right, present := ingress[key]
			if !present || left.permanent != right.permanent || !left.permanent && (left.lower.Sub(right.upper) > 2*time.Second || right.lower.Sub(left.upper) > 2*time.Second) {
				return fmt.Errorf("native runtime layer lifetimes disagree")
			}
		}
	}
	return nil
}
