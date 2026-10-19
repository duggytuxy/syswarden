package v5

import (
	"errors"
	"fmt"
	"time"
)

const (
	NodeTransportGrantSchema     = "syswarden.node-transport-grant.v1"
	NodeProducerGrantSchema      = "syswarden.node-producer-grant.v1"
	MaxNodeCredentialLifetime    = 24 * time.Hour
	MaxNodeProducerGrantLifetime = 30 * 24 * time.Hour
)

var (
	ErrInvalidNodeGrant              = errors.New("invalid node admission grant")
	ErrUnsupportedNodeGrantSchema    = errors.New("unsupported node admission grant schema")
	ErrInvalidNodeGrantContext       = errors.New("invalid node admission context")
	ErrNodeGrantBindingMismatch      = errors.New("node admission grant does not match current registry context")
	ErrNodeGrantNotCurrent           = errors.New("node admission grant is inactive or outside its validity interval")
	ErrNodeCredentialBindingMismatch = errors.New("node credential does not match its admission grant")
)

// NodeTransportGrant is one immutable registry record, not enrollment or TLS
// authentication. Registry and Policy are independently approved generations.
// This schema grants no producer, browser, response or BunkerWeb authority.
type NodeTransportGrant struct {
	Schema            string        `json:"schema"`
	CredentialID      string        `json:"credential_id"`
	Identity          NodeIdentity  `json:"identity"`
	Registry          RateReference `json:"registry"`
	Policy            RateReference `json:"policy"`
	Status            string        `json:"status"`
	NotBefore         string        `json:"not_before"`
	NotAfter          string        `json:"not_after"`
	Algorithm         string        `json:"algorithm"`
	CertificateSHA256 string        `json:"certificate_sha256"`
	PublicKeySHA256   string        `json:"public_key_sha256"`
	IssuerSHA256      string        `json:"issuer_sha256"`
}

// NodeProducerGrant binds a different key purpose to exactly one source/schema.
// Source and schema identifiers have literal equality, never wildcard semantics.
// A caller must verify a sample's signature separately before using its content.
type NodeProducerGrant struct {
	Schema          string        `json:"schema"`
	GrantID         string        `json:"grant_id"`
	Identity        NodeIdentity  `json:"identity"`
	Registry        RateReference `json:"registry"`
	Policy          RateReference `json:"policy"`
	Status          string        `json:"status"`
	NotBefore       string        `json:"not_before"`
	NotAfter        string        `json:"not_after"`
	SourceID        string        `json:"source_id"`
	PayloadSchema   string        `json:"payload_schema"`
	KeyID           string        `json:"key_id"`
	Algorithm       string        `json:"algorithm"`
	PublicKeySHA256 string        `json:"public_key_sha256"`
}

func invalidNodeGrant(field string) error {
	return fmt.Errorf("%w: %s", ErrInvalidNodeGrant, field)
}

// Validate checks shape and coherence, including revoked historical records.
// Neither valid encoding nor a digest authenticates a registry generation.
func (g NodeTransportGrant) Validate() error {
	if g.Schema != NodeTransportGrantSchema {
		return ErrUnsupportedNodeGrantSchema
	}
	if !identifier(g.CredentialID) || !nodeGrantScope(g.Identity, g.Registry, g.Policy, g.Status) {
		return invalidNodeGrant("identity, references or status")
	}
	if !nodeGrantWindow(g.NotBefore, g.NotAfter, MaxNodeCredentialLifetime) {
		return invalidNodeGrant("credential lifetime")
	}
	if g.Algorithm != "ecdsa-p256" || !digest(g.CertificateSHA256) || !digest(g.PublicKeySHA256) || !digest(g.IssuerSHA256) {
		return invalidNodeGrant("credential profile")
	}
	return nil
}

func (g NodeProducerGrant) Validate() error {
	if g.Schema != NodeProducerGrantSchema {
		return ErrUnsupportedNodeGrantSchema
	}
	if !identifier(g.GrantID) || !nodeGrantScope(g.Identity, g.Registry, g.Policy, g.Status) {
		return invalidNodeGrant("identity, references or status")
	}
	if !nodeGrantWindow(g.NotBefore, g.NotAfter, MaxNodeProducerGrantLifetime) {
		return invalidNodeGrant("producer lifetime")
	}
	if !identifier(g.SourceID) || !identifier(g.PayloadSchema) || !identifier(g.KeyID) ||
		g.Algorithm != "ecdsa-p256-sha256" || !digest(g.PublicKeySHA256) {
		return invalidNodeGrant("producer profile")
	}
	return nil
}

func nodeGrantScope(identity NodeIdentity, registry, policy RateReference, status string) bool {
	return identity.Validate() == nil && registry.validate() && policy.validate() && member("active", "revoked")(status)
}

func nodeGrantWindow(start, end string, maximum time.Duration) bool {
	if !timestamp(start) || !timestamp(end) {
		return false
	}
	from, _ := time.Parse(time.RFC3339Nano, start)
	until, _ := time.Parse(time.RFC3339Nano, end)
	return until.After(from) && until.Sub(from) <= maximum
}

// NodeGrantReadContext must be obtained from independently authenticated current
// registry/policy state and a trusted clock. Copying it from a submitted grant
// defeats the check. It is a per-operation input, not a renewable cached lease.
type NodeGrantReadContext struct {
	Record   RateReference
	Identity NodeIdentity
	Registry RateReference
	Policy   RateReference
	Now      time.Time
}

func (c NodeGrantReadContext) validate() bool {
	return c.Record.validate() && c.Identity.Validate() == nil && c.Registry.validate() && c.Policy.validate() &&
		timestamp(c.Now.UTC().Format(time.RFC3339Nano))
}

func checkNodeGrantContext(c NodeGrantReadContext, id, hash string, identity NodeIdentity, registry, policy RateReference,
	status, start, end string) error {
	if !c.validate() {
		return ErrInvalidNodeGrantContext
	}
	if c.Record != (RateReference{Ref: id, SHA256: hash}) || c.Identity != identity || c.Registry != registry || c.Policy != policy {
		return ErrNodeGrantBindingMismatch
	}
	from, _ := time.Parse(time.RFC3339Nano, start)
	until, _ := time.Parse(time.RFC3339Nano, end)
	if status != "active" || c.Now.Before(from) || !c.Now.Before(until) {
		return ErrNodeGrantNotCurrent
	}
	return nil
}

// CheckCurrentNodeTransportGrant checks exact record, registry, policy and epoch
// bindings and exclusive expiry. It does not prove key possession or that the
// context still represents the live registry at a later commit boundary.
func CheckCurrentNodeTransportGrant(g NodeTransportGrant, c NodeGrantReadContext) error {
	hash, err := NodeTransportGrantSHA256(g)
	if err != nil {
		return err
	}
	return checkNodeGrantContext(c, g.CredentialID, hash, g.Identity, g.Registry, g.Policy, g.Status, g.NotBefore, g.NotAfter)
}

func CheckCurrentNodeProducerGrant(g NodeProducerGrant, c NodeGrantReadContext) error {
	hash, err := NodeProducerGrantSHA256(g)
	if err != nil {
		return err
	}
	return checkNodeGrantContext(c, g.GrantID, hash, g.Identity, g.Registry, g.Policy, g.Status, g.NotBefore, g.NotAfter)
}
