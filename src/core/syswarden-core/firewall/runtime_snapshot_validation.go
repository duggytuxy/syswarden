package firewall

import (
	"encoding/hex"
	"fmt"
	"net/netip"
	"time"
)

// ValidateRuntimeLifecycleSnapshot checks the portable local-history schema.
// Native enforcement is attested by the producer; consumers must also bind
// the containing document to their authenticated local telemetry channel.
func ValidateRuntimeLifecycleSnapshot(snapshot RuntimeLifecycleSnapshot) error {
	hexDigest := func(value string) bool {
		decoded, err := hex.DecodeString(value)
		return err == nil && len(decoded) == 32 && hex.EncodeToString(decoded) == value
	}
	parseTime := func(value string) (time.Time, error) {
		parsed, err := time.Parse(time.RFC3339Nano, value)
		if err != nil || parsed.IsZero() || parsed.UTC().Format(time.RFC3339Nano) != value {
			return time.Time{}, fmt.Errorf("local native history timestamp is not canonical")
		}
		return parsed, nil
	}
	if snapshot.SchemaVersion != 1 || snapshot.Sequence == 0 || !hexDigest(snapshot.Identity) || !hexDigest(snapshot.ModelSHA256) || snapshot.Claims == nil || len(snapshot.Claims) > 1024 {
		return fmt.Errorf("local native history identity or inventory is invalid")
	}
	updated, updatedErr := parseTime(snapshot.UpdatedAt)
	captured, capturedErr := parseTime(snapshot.CapturedAt)
	if updatedErr != nil || capturedErr != nil || captured.Before(updated) {
		return fmt.Errorf("local native history capture precedes its durable head")
	}
	counts := map[string]int{"active": snapshot.Active, "deleted": snapshot.Deleted, "expired": snapshot.Expired, "tombstoned": snapshot.Tombstoned}
	total := 0
	for _, count := range counts {
		if count < 0 || count > 16384 || total > 16384-count {
			return fmt.Errorf("local native history counters exceed bounds")
		}
		total += count
	}
	if !snapshot.Truncated && total != len(snapshot.Claims) || snapshot.Truncated && total <= len(snapshot.Claims) {
		return fmt.Errorf("local native history inventory and counters disagree")
	}
	observed := make(map[string]int)
	previous := ""
	for _, claim := range snapshot.Claims {
		address, addressErr := netip.ParseAddr(claim.Entry)
		canonical := addressErr == nil && address.Zone() == "" && !address.Is4In6() && address.String() == claim.Entry
		if !canonical {
			prefix, err := netip.ParsePrefix(claim.Entry)
			canonical = err == nil && !prefix.Addr().Is4In6() && prefix.Masked().String() == claim.Entry
		}
		if !canonical || claim.Entry <= previous || claim.Generation == 0 || claim.Generation > snapshot.Sequence {
			return fmt.Errorf("local native history claim identity is invalid")
		}
		previous = claim.Entry
		created, createdErr := parseTime(claim.CreatedAt)
		transition, transitionErr := parseTime(claim.TransitionAt)
		if createdErr != nil || transitionErr != nil || transition.Before(created) || transition.After(updated) {
			return fmt.Errorf("local native history transition chronology is invalid")
		}
		var expiry time.Time
		if claim.ExpiresAt != "" {
			var err error
			expiry, err = parseTime(claim.ExpiresAt)
			if err != nil || !expiry.After(created) {
				return fmt.Errorf("local native history expiry is invalid")
			}
		}
		switch claim.State {
		case "active":
			if claim.Cause != "verified-ban" || claim.ConfirmedAt != "" || !expiry.IsZero() && !expiry.After(captured) {
				return fmt.Errorf("local native active claim is invalid")
			}
		case "deleted", "expired", "tombstoned":
			if claim.Cause != "verified-deletion" && claim.Cause != "native-expiry" ||
				claim.State == "deleted" && claim.Cause != "verified-deletion" || claim.State == "expired" && claim.Cause != "native-expiry" ||
				claim.Cause == "native-expiry" && (expiry.IsZero() || transition.Before(expiry)) {
				return fmt.Errorf("local native terminal claim cause is invalid")
			}
			if claim.State == "tombstoned" {
				confirmed, err := parseTime(claim.ConfirmedAt)
				if err != nil || confirmed.Before(transition.Add(30*time.Second)) || confirmed.After(updated) {
					return fmt.Errorf("local native absence confirmation is invalid")
				}
			} else if claim.ConfirmedAt != "" {
				return fmt.Errorf("local native terminal claim is prematurely confirmed")
			}
		default:
			return fmt.Errorf("local native history state is invalid")
		}
		observed[claim.State]++
	}
	for state, count := range counts {
		if observed[state] > count || !snapshot.Truncated && observed[state] != count {
			return fmt.Errorf("local native history state counters are inconsistent")
		}
	}
	return nil
}
