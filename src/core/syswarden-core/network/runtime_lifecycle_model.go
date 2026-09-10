package network

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"time"
)

const (
	runtimeLifecycleVersion           = 1
	runtimeLifecycleMaximumRecords    = 16384
	runtimeLifecycleConfirmationDelay = 30 * time.Second
)

// runtimeLifecycleRecord records a verified native transition, independently
// of the attack journal. An administrative ban never becomes a physical hit.
type runtimeLifecycleRecord struct {
	Entry        string `json:"entry"`
	Generation   uint64 `json:"generation"`
	State        string `json:"state"`
	Cause        string `json:"cause"`
	CreatedAt    string `json:"created_at"`
	TransitionAt string `json:"transition_at"`
	ExpiresAt    string `json:"expires_at,omitempty"`
	ConfirmedAt  string `json:"confirmed_at,omitempty"`
}

type runtimeLifecycleModel struct {
	SchemaVersion int                      `json:"schema_version"`
	Identity      string                   `json:"identity"`
	Sequence      uint64                   `json:"sequence"`
	UpdatedAt     string                   `json:"updated_at"`
	Records       []runtimeLifecycleRecord `json:"records"`
}

// runtimeLifecycleWitness is obtained while the authoritative host firewall
// lock is held. Complete requires agreement across every expected layer.
type runtimeLifecycleWitness struct {
	Complete  bool
	Present   bool
	Permanent bool
	ExpiresAt time.Time
}

func canonicalRuntimeLifecycleEntry(entry string) bool {
	if address, err := netip.ParseAddr(entry); err == nil {
		return address.Zone() == "" && !address.Is4In6() && address.String() == entry
	}
	prefix, err := netip.ParsePrefix(entry)
	return err == nil && !prefix.Addr().Is4In6() && prefix.Masked().String() == entry
}

func runtimeLifecycleTime(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || parsed.UTC().Format(time.RFC3339Nano) != value {
		return time.Time{}, fmt.Errorf("runtime lifecycle timestamp is not canonical")
	}
	return parsed, nil
}

func (model runtimeLifecycleModel) validate() error {
	identity, identityErr := hex.DecodeString(model.Identity)
	if model.SchemaVersion != runtimeLifecycleVersion || identityErr != nil || len(identity) != 32 ||
		hex.EncodeToString(identity) != model.Identity || model.Sequence == 0 || model.Records == nil ||
		len(model.Records) > runtimeLifecycleMaximumRecords {
		return fmt.Errorf("runtime lifecycle model identity or bounds are invalid")
	}
	updated, err := runtimeLifecycleTime(model.UpdatedAt)
	if err != nil {
		return err
	}
	previous := ""
	for _, record := range model.Records {
		if !canonicalRuntimeLifecycleEntry(record.Entry) || record.Entry <= previous || record.Generation == 0 || record.Generation > model.Sequence {
			return fmt.Errorf("runtime lifecycle inventory is not canonical")
		}
		previous = record.Entry
		created, firstErr := runtimeLifecycleTime(record.CreatedAt)
		transition, lastErr := runtimeLifecycleTime(record.TransitionAt)
		if firstErr != nil || lastErr != nil || transition.Before(created) || transition.After(updated) {
			return fmt.Errorf("runtime lifecycle chronology is invalid")
		}
		var expiry time.Time
		if record.ExpiresAt != "" {
			expiry, err = runtimeLifecycleTime(record.ExpiresAt)
			if err != nil || !expiry.After(created) {
				return fmt.Errorf("runtime lifecycle expiry is invalid")
			}
		}
		switch record.State {
		case "active":
			if record.Cause != "verified-ban" || record.ConfirmedAt != "" {
				return fmt.Errorf("active runtime lifecycle claim is invalid")
			}
		case "deleted", "expired", "tombstoned":
			if record.Cause != "verified-deletion" && record.Cause != "native-expiry" {
				return fmt.Errorf("runtime lifecycle cause is invalid")
			}
			if record.State == "deleted" && record.Cause != "verified-deletion" || record.State == "expired" && record.Cause != "native-expiry" {
				return fmt.Errorf("runtime lifecycle state and cause differ")
			}
			if record.Cause == "native-expiry" && (expiry.IsZero() || transition.Before(expiry)) {
				return fmt.Errorf("runtime lifecycle expiry is premature")
			}
			if record.State == "tombstoned" {
				confirmed, confirmErr := runtimeLifecycleTime(record.ConfirmedAt)
				if confirmErr != nil || confirmed.Before(transition.Add(runtimeLifecycleConfirmationDelay)) || confirmed.After(updated) {
					return fmt.Errorf("runtime absence confirmation is premature or invalid")
				}
			} else if record.ConfirmedAt != "" {
				return fmt.Errorf("unconfirmed runtime transition claims confirmation")
			}
		default:
			return fmt.Errorf("runtime lifecycle state is unknown")
		}
	}
	return nil
}

func (model runtimeLifecycleModel) wire() ([]byte, error) {
	if err := model.validate(); err != nil {
		return nil, err
	}
	wire, err := json.Marshal(model)
	if err != nil {
		return nil, err
	}
	return append(wire, '\n'), nil
}

func (model runtimeLifecycleModel) digest() (string, error) {
	wire, err := model.wire()
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(wire)
	return hex.EncodeToString(digest[:]), nil
}

func (model runtimeLifecycleModel) withRecord(record runtimeLifecycleRecord, now time.Time) (runtimeLifecycleModel, error) {
	if err := model.validate(); err != nil {
		return runtimeLifecycleModel{}, err
	}
	updated, _ := runtimeLifecycleTime(model.UpdatedAt)
	if now.Before(updated) || model.Sequence == ^uint64(0) {
		return runtimeLifecycleModel{}, fmt.Errorf("runtime lifecycle clock or sequence cannot advance")
	}
	result := model
	result.Sequence++
	result.UpdatedAt = now.UTC().Format(time.RFC3339Nano)
	result.Records = append([]runtimeLifecycleRecord{}, model.Records...)
	index := sort.Search(len(result.Records), func(index int) bool { return result.Records[index].Entry >= record.Entry })
	if index < len(result.Records) && result.Records[index].Entry == record.Entry {
		result.Records[index] = record
	} else {
		if len(result.Records) == runtimeLifecycleMaximumRecords {
			return runtimeLifecycleModel{}, fmt.Errorf("runtime lifecycle inventory is full")
		}
		result.Records = append(result.Records, runtimeLifecycleRecord{})
		copy(result.Records[index+1:], result.Records[index:])
		result.Records[index] = record
	}
	if err := result.validate(); err != nil {
		return runtimeLifecycleModel{}, err
	}
	return result, nil
}

func (model runtimeLifecycleModel) lookup(entry string) (runtimeLifecycleRecord, bool) {
	index := sort.Search(len(model.Records), func(index int) bool { return model.Records[index].Entry >= entry })
	if index == len(model.Records) || model.Records[index].Entry != entry {
		return runtimeLifecycleRecord{}, false
	}
	return model.Records[index], true
}

func (model runtimeLifecycleModel) verifiedBan(entry string, now time.Time, witness runtimeLifecycleWitness) (runtimeLifecycleModel, error) {
	if err := model.validateObservation(entry, now); err != nil {
		return runtimeLifecycleModel{}, err
	}
	if !witness.Complete || !witness.Present || witness.Permanent != witness.ExpiresAt.IsZero() ||
		!witness.Permanent && !witness.ExpiresAt.After(now) {
		return runtimeLifecycleModel{}, fmt.Errorf("runtime ban lacks a complete native presence witness")
	}
	record := runtimeLifecycleRecord{Entry: entry, Generation: 1, State: "active", Cause: "verified-ban",
		CreatedAt: now.UTC().Format(time.RFC3339Nano), TransitionAt: now.UTC().Format(time.RFC3339Nano)}
	if previous, exists := model.lookup(entry); exists {
		if previous.Generation == ^uint64(0) {
			return runtimeLifecycleModel{}, fmt.Errorf("runtime claim generation is exhausted")
		}
		record.Generation = previous.Generation + 1
	}
	if !witness.Permanent {
		record.ExpiresAt = witness.ExpiresAt.UTC().Format(time.RFC3339Nano)
	}
	return model.withRecord(record, now)
}

func (model runtimeLifecycleModel) verifiedDeletion(entry string, now time.Time, before, after runtimeLifecycleWitness) (runtimeLifecycleModel, error) {
	if err := model.validateObservation(entry, now); err != nil {
		return runtimeLifecycleModel{}, err
	}
	if !before.Complete || !validRuntimeAbsenceWitness(after) ||
		before.Present && before.Permanent != before.ExpiresAt.IsZero() {
		return runtimeLifecycleModel{}, fmt.Errorf("runtime deletion lacks complete native witnesses")
	}
	record, exists := model.lookup(entry)
	if !before.Present {
		if !exists || record.State != "active" {
			return model, nil
		}
		return model.observeAbsence(entry, now, after)
	}
	if !exists {
		record = runtimeLifecycleRecord{Entry: entry, Generation: 1, CreatedAt: now.UTC().Format(time.RFC3339Nano)}
	} else if record.State != "active" {
		return runtimeLifecycleModel{}, fmt.Errorf("terminal runtime claim reappeared without a verified ban")
	}
	record.State, record.Cause = "deleted", "verified-deletion"
	record.TransitionAt = now.UTC().Format(time.RFC3339Nano)
	record.ConfirmedAt = ""
	return model.withRecord(record, now)
}

// observeAbsence never guesses a deletion from missing kernel state. A tracked
// active claim must reach its recorded native expiry; otherwise drift is an
// error. Terminal absence is confirmed by a later independent kernel read.
func (model runtimeLifecycleModel) observeAbsence(entry string, now time.Time, witness runtimeLifecycleWitness) (runtimeLifecycleModel, error) {
	if err := model.validateObservation(entry, now); err != nil {
		return runtimeLifecycleModel{}, err
	}
	if !validRuntimeAbsenceWitness(witness) {
		return runtimeLifecycleModel{}, fmt.Errorf("runtime absence witness is incomplete")
	}
	record, exists := model.lookup(entry)
	if !exists {
		return runtimeLifecycleModel{}, fmt.Errorf("runtime absence has no tracked claim")
	}
	switch record.State {
	case "active":
		expiry, err := runtimeLifecycleTime(record.ExpiresAt)
		if err != nil || now.Before(expiry) {
			return runtimeLifecycleModel{}, fmt.Errorf("runtime claim disappeared without an attested deletion or elapsed native expiry")
		}
		record.State, record.Cause = "expired", "native-expiry"
		record.TransitionAt = now.UTC().Format(time.RFC3339Nano)
	case "deleted", "expired":
		transition, err := runtimeLifecycleTime(record.TransitionAt)
		if err != nil {
			return runtimeLifecycleModel{}, err
		}
		if now.Before(transition.Add(runtimeLifecycleConfirmationDelay)) {
			return model, nil
		}
		record.State = "tombstoned"
		record.ConfirmedAt = now.UTC().Format(time.RFC3339Nano)
	case "tombstoned":
		return model, nil
	default:
		return runtimeLifecycleModel{}, fmt.Errorf("runtime absence has an invalid prior state")
	}
	return model.withRecord(record, now)
}

func validRuntimeAbsenceWitness(witness runtimeLifecycleWitness) bool {
	return witness.Complete && !witness.Present && !witness.Permanent && witness.ExpiresAt.IsZero()
}

func (model runtimeLifecycleModel) validateObservation(entry string, now time.Time) error {
	if err := model.validate(); err != nil {
		return err
	}
	updated, _ := runtimeLifecycleTime(model.UpdatedAt)
	if !canonicalRuntimeLifecycleEntry(entry) || now.Before(updated) || now.IsZero() {
		return fmt.Errorf("runtime lifecycle observation has an invalid entry or clock")
	}
	return nil
}
