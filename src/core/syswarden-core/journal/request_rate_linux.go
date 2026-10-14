package journal

import (
	"errors"
	"time"
)

const (
	MaxAuthorityRequestsPerWindow = 1024
	MaxAuthorityRateUIDs          = 256
	MinAuthorityRateWindow        = time.Second
	MaxAuthorityRateWindow        = time.Minute
)

var ErrAuthorityRateLimit = errors.New("local authority admission rate exhausted")

// Slots are allocated once at startup. Expired entries can be reused, but a new
// UID never evicts an unexpired quota. No caller-controlled key or timer is stored.
type authorityRateWindow struct {
	uid   uint32
	used  int
	until time.Time
}

func validAuthorityRateLimits(l AuthorityTransportLimits) bool {
	return l.RequestsPerUID >= 1 && l.RequestsPerUID <= MaxAuthorityRequestsPerWindow &&
		l.MaxRateUIDs >= 1 && l.MaxRateUIDs <= MaxAuthorityRateUIDs &&
		l.RateWindow >= MinAuthorityRateWindow && l.RateWindow <= MaxAuthorityRateWindow
}

// admitRate requires the transport mutex. It runs after kernel credentials and
// live-peer ceilings, before framing or authority dispatch. Admission consumes a
// slot even if input later fails, times out or disconnects; release never refunds
// it. Fixed windows permit a burst on each side of a boundary, not smooth pacing.
func (t *LocalAuthorityTransport) admitRate(uid uint32) bool {
	now := t.rateNow()
	if now.IsZero() || (!t.rateLast.IsZero() && now.Before(t.rateLast)) {
		return false
	}
	t.rateLast = now
	free := -1
	for i := range t.rate {
		slot := &t.rate[i]
		if slot.until.IsZero() || !now.Before(slot.until) {
			if free < 0 {
				free = i
			}
			continue
		}
		if slot.uid == uid {
			if slot.used >= t.limits.RequestsPerUID {
				return false
			}
			slot.used++
			return true
		}
	}
	if free < 0 {
		return false
	}
	t.rate[free] = authorityRateWindow{uid: uid, used: 1, until: now.Add(t.limits.RateWindow)}
	return true
}
