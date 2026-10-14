package journal

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"
)

func testCustodyPolicy() CustodyAccessPolicy {
	return CustodyAccessPolicy{PolicyID: "policy.fixture.1", Revision: 7, IssuerKeyID: "issuer.fixture.1", NotBefore: 1800000000, NotAfter: 1800003600,
		Enrollment: testEnrollment(), Grants: []CustodyLocalGrant{{UID: 2001, Operations: []CustodyOperation{CustodyCommit, CustodyResume}},
			{UID: 2002, Operations: []CustodyOperation{CustodyApplyRecovery, CustodyInspectRecovery}}}}
}
func testPolicyIssuer() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x24}, ed25519.SeedSize))
}
func signTestPolicy(t testing.TB, p CustodyAccessPolicy) ([]byte, []byte, CustodyPolicyTrust) {
	t.Helper()
	data, err := EncodeCustodyAccessPolicy(p)
	if err != nil {
		t.Fatal(err)
	}
	msg, err := CustodyAccessPolicySigningMessage(p)
	if err != nil {
		t.Fatal(err)
	}
	key := testPolicyIssuer()
	return data, ed25519.Sign(key, msg), CustodyPolicyTrust{Enabled: true, PolicyID: p.PolicyID, Revision: p.Revision, PolicySHA256: recoveryDigest(data),
		IssuerKeyID: p.IssuerKeyID, IssuerPublicKey: key.Public().(ed25519.PublicKey), Initial: p.Enrollment.Initial}
}
func policyNow(p CustodyAccessPolicy) time.Time { return time.Unix(p.NotBefore+1, 0) }

func TestCustodyPolicyCanonicalRoundTripAndOwnership(t *testing.T) {
	p := testCustodyPolicy()
	data, sig, trust := signTestPolicy(t, p)
	got, err := VerifyCustodyAccessPolicy(data, sig, trust, policyNow(p))
	if err != nil || !reflect.DeepEqual(got, p) {
		t.Fatal("verified policy mismatch", err)
	}
	got.Enrollment.Authority.PublicKey[0] ^= 1
	got.Grants[0].Operations[0] = CustodyApplyRecovery
	if again, err := VerifyCustodyAccessPolicy(data, sig, trust, policyNow(p)); err != nil || !reflect.DeepEqual(again, p) {
		t.Fatal("owned result mutated policy", err)
	}
	msg, err := CustodyAccessPolicySigningMessage(p)
	if err != nil || !bytes.Equal(msg, append([]byte(custodyPolicyDomain), data...)) {
		t.Fatal("signing domain", err)
	}
	msg[0] ^= 1
	if _, err := VerifyCustodyAccessPolicy(data, sig, trust, policyNow(p)); err != nil {
		t.Fatal(err)
	}
}

func TestCustodyPolicyBoundsAndGrantShape(t *testing.T) {
	cases := map[string]func(*CustodyAccessPolicy){
		"empty-id":                  func(p *CustodyAccessPolicy) { p.PolicyID = "" },
		"control-id":                func(p *CustodyAccessPolicy) { p.PolicyID = "a\nb" },
		"unicode-id":                func(p *CustodyAccessPolicy) { p.PolicyID = "polic\u00e9" },
		"long-id":                   func(p *CustodyAccessPolicy) { p.IssuerKeyID = strings.Repeat("x", 129) },
		"bad-checkpoint-id":         func(p *CustodyAccessPolicy) { p.Enrollment.Authority.KeyID = "a/b" },
		"zero-revision":             func(p *CustodyAccessPolicy) { p.Revision = 0 },
		"exhausted-revision":        func(p *CustodyAccessPolicy) { p.Revision = math.MaxUint64 },
		"negative-time":             func(p *CustodyAccessPolicy) { p.NotBefore = -1 },
		"zero-time":                 func(p *CustodyAccessPolicy) { p.NotBefore = 0 },
		"reverse-window":            func(p *CustodyAccessPolicy) { p.NotAfter = p.NotBefore - 1 },
		"empty-window":              func(p *CustodyAccessPolicy) { p.NotAfter = p.NotBefore },
		"time-overflow":             func(p *CustodyAccessPolicy) { p.NotAfter = math.MaxInt64 },
		"wrong-scope":               func(p *CustodyAccessPolicy) { p.Enrollment.Authority.Identity.NodeID = "other.fixture" },
		"initial-outside-key-range": func(p *CustodyAccessPolicy) { p.Enrollment.Authority.FirstSequence = 2 },
		"short-key":                 func(p *CustodyAccessPolicy) { p.Enrollment.Authority.PublicKey = []byte{1} },
		"invalid-uid":               func(p *CustodyAccessPolicy) { p.Grants[1].UID = math.MaxUint32 },
		"duplicate-uid":             func(p *CustodyAccessPolicy) { p.Grants[1].UID = p.Grants[0].UID },
		"unordered-uid":             func(p *CustodyAccessPolicy) { p.Grants[1].UID = 1 },
		"empty-operations":          func(p *CustodyAccessPolicy) { p.Grants[0].Operations = nil },
		"unknown-operation":         func(p *CustodyAccessPolicy) { p.Grants[0].Operations[0] = "finish" },
		"duplicate-operation":       func(p *CustodyAccessPolicy) { p.Grants[0].Operations[1] = CustodyCommit },
		"unordered-operation": func(p *CustodyAccessPolicy) {
			p.Grants[0].Operations = []CustodyOperation{CustodyResume, CustodyCommit}
		},
		"too-many-operations": func(p *CustodyAccessPolicy) { p.Grants[0].Operations = make([]CustodyOperation, 5) },
		"too-many-grants":     func(p *CustodyAccessPolicy) { p.Grants = make([]CustodyLocalGrant, MaxCustodyPolicyGrants+1) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			p := testCustodyPolicy()
			mutate(&p)
			if b, err := EncodeCustodyAccessPolicy(p); err == nil || b != nil {
				t.Fatal("invalid policy encoded")
			}
			if b, err := CustodyAccessPolicySigningMessage(p); err == nil || b != nil {
				t.Fatal("invalid policy signing bytes")
			}
		})
	}
	p := testCustodyPolicy()
	p.Revision = math.MaxUint64 - 1
	p.NotAfter = maxPolicyTime
	p.Grants = make([]CustodyLocalGrant, MaxCustodyPolicyGrants)
	for i := range p.Grants {
		p.Grants[i] = CustodyLocalGrant{UID: 3000 + uint32(i), Operations: []CustodyOperation{CustodyApplyRecovery, CustodyCommit, CustodyInspectRecovery, CustodyResume}}
	}
	data, sig, trust := signTestPolicy(t, p)
	if _, err := VerifyCustodyAccessPolicy(data, sig, trust, policyNow(p)); err != nil {
		t.Fatal("valid ceilings rejected", err)
	}
}

func TestCustodyPolicyRejectsAlternateDocuments(t *testing.T) {
	data, _, _ := signTestPolicy(t, testCustodyPolicy())
	cases := map[string][]byte{
		"empty": nil, "oversize": bytes.Repeat([]byte{' '}, MaxCustodyPolicyBytes+1), "trailing": append(bytes.Clone(data), '\n'),
		"null": []byte("null"), "array": []byte("[]"), "concatenated": append(bytes.Clone(data), data...),
		"duplicate":      bytes.Replace(data, []byte(`"revision":"7"`), []byte(`"revision":"6","revision":"7"`), 1),
		"unknown":        bytes.Replace(data, []byte(`"revision":"7"`), []byte(`"extra":true,"revision":"7"`), 1),
		"missing":        bytes.Replace(data, []byte(`"revision":"7",`), nil, 1),
		"zero-prefixed":  bytes.Replace(data, []byte(`"revision":"7"`), []byte(`"revision":"07"`), 1),
		"json-number":    bytes.Replace(data, []byte(`"revision":"7"`), []byte(`"revision":7`), 1),
		"uid-alias":      bytes.Replace(data, []byte(`"uid":"2001"`), []byte(`"uid":"02001"`), 1),
		"uid-overflow":   bytes.Replace(data, []byte(`"uid":"2001"`), []byte(`"uid":"4294967296"`), 1),
		"key-case":       bytes.Replace(data, []byte(`"public_key":"`), []byte(`"public_key":"F`), 1),
		"nested-unknown": bytes.Replace(data, []byte(`"uid":"2001"`), []byte(`"role":"root","uid":"2001"`), 1),
		"wrong-schema":   bytes.Replace(data, []byte(CustodyPolicySchema), []byte("syswarden.custody-access-policy.v2"), 1),
	}
	for name, b := range cases {
		t.Run(name, func(t *testing.T) {
			p, err := DecodeCustodyAccessPolicy(b)
			if err == nil || !reflect.DeepEqual(p, CustodyAccessPolicy{}) {
				t.Fatal("noncanonical document accepted")
			}
		})
	}
	p := testCustodyPolicy()
	p.Grants = nil
	data, _, _ = signTestPolicy(t, p)
	if !bytes.HasSuffix(data, []byte(`"grants":[]}`)) {
		t.Fatal("empty grants must encode as array")
	}
	bad := bytes.Replace(data, []byte(`"grants":[]`), []byte(`"grants":null`), 1)
	if _, err := DecodeCustodyAccessPolicy(bad); err == nil {
		t.Fatal("null grants accepted")
	}
}

func TestCustodyPolicyTrustDenials(t *testing.T) {
	for _, name := range []string{"disabled", "wrong-issuer", "short-issuer-key", "different-issuer-key", "wrong-policy-id", "old-revision", "future-revision", "bad-digest", "upper-digest", "other-root", "other-journal", "other-node", "other-epoch", "no-time", "before-window", "expired", "future-time", "unsigned", "bad-signature", "short-signature", "long-signature", "no-domain", "wrong-domain", "reused-checkpoint-key", "signed-changed-policy", "signed-same-revision-rollback"} {
		t.Run(name, func(t *testing.T) {
			p := testCustodyPolicy()
			data, sig, trust := signTestPolicy(t, p)
			now := policyNow(p)
			switch name {
			case "disabled":
				trust.Enabled = false
			case "wrong-issuer":
				trust.IssuerKeyID = "other.issuer"
			case "short-issuer-key":
				trust.IssuerPublicKey = []byte{1}
			case "different-issuer-key":
				trust.IssuerPublicKey[0] ^= 1
			case "wrong-policy-id":
				trust.PolicyID = "other.policy"
			case "old-revision":
				trust.Revision++
			case "future-revision":
				trust.Revision--
			case "bad-digest":
				trust.PolicySHA256 = ""
			case "upper-digest":
				trust.PolicySHA256 = strings.ToUpper(trust.PolicySHA256)
			case "other-root":
				trust.Initial.PreviousSHA256 = strings.Repeat("a", 64)
			case "other-journal":
				trust.Initial.Cursor.JournalID = "other.journal"
			case "other-node":
				trust.Initial.Cursor.Identity.NodeID = "other.node"
			case "other-epoch":
				trust.Initial.Cursor.Identity.Epoch = "other.epoch"
			case "no-time":
				now = time.Time{}
			case "before-window":
				now = time.Unix(p.NotBefore, -1)
			case "expired":
				now = time.Unix(p.NotAfter, 0)
			case "future-time":
				now = time.Unix(p.NotAfter+1, 0)
			case "unsigned":
				sig = nil
			case "bad-signature":
				sig[0] ^= 1
			case "short-signature":
				sig = sig[:63]
			case "long-signature":
				sig = append(sig, 0)
			case "no-domain":
				sig = ed25519.Sign(testPolicyIssuer(), data)
			case "wrong-domain":
				sig = ed25519.Sign(testPolicyIssuer(), append([]byte(custodyDomain), data...))
			case "reused-checkpoint-key":
				key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
				trust.IssuerPublicKey = key.Public().(ed25519.PublicKey)
				sig = ed25519.Sign(key, append([]byte(custodyPolicyDomain), data...))
			case "signed-changed-policy":
				p.Revision++
				data, sig, _ = signTestPolicy(t, p)
			case "signed-same-revision-rollback":
				p.Grants[0].UID--
				data, sig, _ = signTestPolicy(t, p)
			}
			got, err := VerifyCustodyAccessPolicy(data, sig, trust, now)
			if err == nil || !reflect.DeepEqual(got, CustodyAccessPolicy{}) {
				t.Fatal("trust failure returned a policy")
			}
		})
	}
}

func TestCustodyPolicyValidityBoundariesAndExplicitNoGrants(t *testing.T) {
	p := testCustodyPolicy()
	p.Grants = []CustodyLocalGrant{}
	data, sig, trust := signTestPolicy(t, p)
	for _, now := range []time.Time{time.Unix(p.NotBefore, 0), time.Unix(p.NotAfter, -1), policyNow(p).In(time.FixedZone("fixture", 3600))} {
		got, err := VerifyCustodyAccessPolicy(data, sig, trust, now)
		if err != nil || len(got.Grants) != 0 {
			t.Fatal("valid boundary rejected", err)
		}
	}
}

func TestCustodyPolicyGolden(t *testing.T) {
	data, sig, trust := signTestPolicy(t, testCustodyPolicy())
	// Values are cross-checked independently with Python JSON/SHA-256 and OpenSSL.
	if len(data) != 1021 || recoveryDigest(data) != "072dde3dddf753846ddafd91cde8fce4d99885ed514b28a670666f16c9687972" ||
		hex.EncodeToString(trust.IssuerPublicKey) != "58936604abda112bc94933569c82f8d0cc0ddf92a3f8329f2f448f7f484a594c" ||
		hex.EncodeToString(sig) != "8681af4e76d86cc8adddf857217c56f3b4abae54196979d40c6b3c8539644196e2edc21a0e0429c6d8b465cc28025cb42f1698d8d85411d35134058082495f0f" {
		t.Fatal("independent policy vector changed")
	}
}

func FuzzCustodyAccessPolicy(f *testing.F) {
	p := testCustodyPolicy()
	data, sig, trust := signTestPolicy(f, p)
	f.Add(data, sig, false)
	f.Add([]byte(`{}`), []byte{}, true)
	f.Fuzz(func(t *testing.T, doc, signature []byte, resign bool) {
		if len(doc) > MaxCustodyPolicyBytes+1 || len(signature) > 65 {
			return
		}
		current := trust
		if resign {
			current.PolicySHA256 = recoveryDigest(doc)
			signature = ed25519.Sign(testPolicyIssuer(), append([]byte(custodyPolicyDomain), doc...))
		}
		got, err := VerifyCustodyAccessPolicy(doc, signature, current, policyNow(p))
		if err != nil {
			if !reflect.DeepEqual(got, CustodyAccessPolicy{}) {
				t.Fatal("errored verification leaked authority")
			}
			return
		}
		canonical, err := EncodeCustodyAccessPolicy(got)
		if err != nil || !bytes.Equal(canonical, doc) || got.Enrollment.Initial != trust.Initial || got.Revision != trust.Revision {
			t.Fatal("verification normalized or changed scope")
		}
		var shape map[string]json.RawMessage
		if json.Unmarshal(doc, &shape) != nil || len(shape) != 9 {
			t.Fatal("unexpected document shape")
		}
	})
}
