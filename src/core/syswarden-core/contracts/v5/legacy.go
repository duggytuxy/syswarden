package v5

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
)

// MigrationContext is assigned by a trusted ingestion boundary. It cannot be
// derived from a payload IP or jail name. Missing identities remain explicit.
// ReceivedAt is supplied by the caller, so replay does not invent a new clock.
type MigrationContext struct {
	EventID    Field
	NodeID     Field
	SourceID   Field
	ReceivedAt string
}

func legacyAction(s string) bool {
	return member("BANNED", "ALLOWED", "DETECTED", "SHADOW-ALERT",
		"SIMULATED-BAN", "COMPLIANCE-DRIFT")(s)
}

// ProjectLegacyV4 projects one frozen v4 event without changing its producer
// or wire format. Extensions are bounded and checked for JSON ambiguity, then
// left uninterpreted. The original digest covers every byte including them.
// Raw payload, numeric severity and inferred policy/ownership are not exported.
func ProjectLegacyV4(data []byte, context MigrationContext) (Event, error) {
	value, err := parseDocument(data)
	if err != nil {
		return Event{}, err
	}
	object, ok := value.(map[string]any)
	if !ok {
		return Event{}, invalid("legacy object")
	}
	fields := make(map[string]string)
	for _, name := range []string{"action", "timestamp", "ip", "jail", "payload"} {
		v, exists := object[name].(string)
		if !exists {
			return Event{}, invalid("legacy required field")
		}
		fields[name] = v
	}
	for key := range object {
		for _, reserved := range []string{"action", "timestamp", "ip", "jail", "payload", "severity"} {
			if key != reserved && strings.EqualFold(key, reserved) {
				return Event{}, invalid("legacy field alias")
			}
		}
	}
	if !legacyAction(fields["action"]) {
		return Event{}, invalid("legacy action")
	}
	if severity, exists := object["severity"]; exists {
		n, ok := severity.(json.Number)
		if !ok {
			return Event{}, invalid("legacy severity")
		}
		if _, err := n.Int64(); err != nil {
			return Event{}, invalid("legacy severity")
		}
	}
	absent := Field{State: Unavailable}
	hash := sha256.Sum256(data)
	e := Event{
		Schema: EventSchema, EventID: context.EventID, NodeID: context.NodeID,
		ObservedAt: Field{State: Present, Value: fields["timestamp"]},
		ReceivedAt: context.ReceivedAt, ClockQuality: "unknown",
		Provenance: Provenance{Format: "legacy_v4", SourceID: context.SourceID,
			OriginalSHA256: Field{State: Present, Value: hex.EncodeToString(hash[:])}},
		Subject:         Subject{Kind: "ip", Address: Field{State: Present, Value: fields["ip"]}},
		ObservationCode: Field{State: Present, Value: fields["action"]},
		Layer:           absent, Severity: absent, PolicyRef: absent, ActionRef: absent,
		ControlRef: absent, EvidenceRef: absent,
		Context: ContextReferences{Reputation: absent, Trust: absent, History: absent, Attribution: absent},
	}
	if fields["timestamp"] == "" {
		e.ObservedAt = Field{State: Missing}
	}
	if fields["ip"] == "" {
		e.Subject = Subject{Kind: "unknown", Address: Field{State: Missing}}
	}
	if err := e.Validate(); err != nil {
		return Event{}, err
	}
	return e, nil
}
