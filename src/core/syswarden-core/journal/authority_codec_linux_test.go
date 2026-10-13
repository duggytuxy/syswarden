package journal

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestAuthorityRequestVocabularyAndOwnedProposal(t *testing.T) {
	p := testCustodyPolicy()
	p.Revision++
	change := authorityInstall(t, p)
	for _, r := range []authorityRequest{
		{Operation: "resume"}, {Operation: "commit", Segment: testName}, {Operation: "inspect-recovery"}, {Operation: "apply-recovery", PlanSHA256: strings.Repeat("a", 64)},
		{Operation: "inspect-policy", Change: &authorityChange{Operation: "disable"}}, {Operation: "apply-policy", Change: change, PlanSHA256: strings.Repeat("a", 64)},
	} {
		data := authorityMessage(t, r)
		owned := bytes.Clone(data)
		got, err := decodeAuthorityRequest(data)
		if err != nil {
			t.Fatal(err)
		}
		for i := range data {
			data[i] = 'x'
		}
		canonical, err := json.Marshal(got)
		if err != nil || !bytes.Equal(canonical, owned) {
			t.Fatal("request aliases caller memory")
		}
	}
	_, _, root := signTestPolicy(t, p)
	proposal, err := authorityChangeProposal(change, root)
	if err != nil {
		t.Fatal(err)
	}
	root.IssuerPublicKey[0] ^= 1
	change.Policy[0] ^= 1
	if proposal.Next.Trust.IssuerPublicKey[0] == root.IssuerPublicKey[0] || proposal.Next.Document[0] == change.Policy[0] {
		t.Fatal("proposal borrowed trust or bytes")
	}
	if proposal.Next.Trust.PolicySHA256 != recoveryDigest(proposal.Next.Document) || proposal.Next.Trust.Revision != p.Revision {
		t.Fatal("proposal binding lost")
	}
}

func TestAuthorityRequestCanonicalAndOperationRejection(t *testing.T) {
	good := string(authorityMessage(t, authorityRequest{Operation: "resume"}))
	disable := string(authorityMessage(t, authorityRequest{Operation: "inspect-policy", Change: &authorityChange{Operation: "disable"}}))
	p := testCustodyPolicy()
	p.Revision++
	install := string(authorityMessage(t, authorityRequest{Operation: "inspect-policy", Change: authorityInstall(t, p)}))
	cases := map[string][]byte{
		"empty": nil, "oversize": bytes.Repeat([]byte("x"), MaxAuthorityRequestBytes+1), "null": []byte("null"), "array": []byte("[]"),
		"trailing": []byte(good + "\n"), "spaces": []byte(" " + good), "duplicate": []byte(strings.Replace(good, `"operation":"resume"`, `"operation":"resume","operation":"resume"`, 1)),
		"unknown": []byte(strings.TrimSuffix(good, "}") + `,"uid":0}`), "explicit-null": []byte(strings.TrimSuffix(good, "}") + `,"change":null}`),
		"different-order": []byte(`{"id":"request.fixture.1","schema":"syswarden.local-authority-request.v1","operation":"resume"}`),
		"escaped-id":      []byte(strings.Replace(good, "request.fixture.1", `\u0072equest.fixture.1`, 1)),
		"wrong-schema":    []byte(strings.Replace(good, "request.v1", "request.v2", 1)), "missing-id": []byte(strings.Replace(good, `"id":"request.fixture.1",`, "", 1)),
		"unknown-operation":            authorityMessage(t, authorityRequest{Operation: "bootstrap"}),
		"resume-args":                  authorityMessage(t, authorityRequest{Operation: "resume", Segment: testName}),
		"commit-no-segment":            authorityMessage(t, authorityRequest{Operation: "commit"}),
		"commit-path":                  authorityMessage(t, authorityRequest{Operation: "commit", Segment: "../" + testName}),
		"commit-approval":              authorityMessage(t, authorityRequest{Operation: "commit", Segment: testName, PlanSHA256: strings.Repeat("a", 64)}),
		"recovery-no-approval":         authorityMessage(t, authorityRequest{Operation: "apply-recovery"}),
		"recovery-uppercase":           authorityMessage(t, authorityRequest{Operation: "apply-recovery", PlanSHA256: strings.Repeat("A", 64)}),
		"inspect-with-approval":        authorityMessage(t, authorityRequest{Operation: "inspect-recovery", PlanSHA256: strings.Repeat("a", 64)}),
		"inspect-policy-no-change":     authorityMessage(t, authorityRequest{Operation: "inspect-policy"}),
		"apply-policy-no-approval":     authorityMessage(t, authorityRequest{Operation: "apply-policy", Change: &authorityChange{Operation: "disable"}}),
		"disable-extra":                []byte(strings.Replace(disable, `"operation":"disable"`, `"operation":"disable","enabled":false`, 1)),
		"disable-null":                 []byte(strings.Replace(disable, `"operation":"disable"`, `"operation":"disable","policy":null`, 1)),
		"change-unknown":               []byte(strings.Replace(disable, `"operation":"disable"`, `"operation":"disable","path":"/synthetic"`, 1)),
		"change-duplicate":             []byte(strings.Replace(disable, `"operation":"disable"`, `"operation":"disable","operation":"disable"`, 1)),
		"install-no-enabled":           []byte(strings.Replace(install, `"enabled":true,`, "", 1)),
		"install-null-enabled":         []byte(strings.Replace(install, `"enabled":true`, `"enabled":null`, 1)),
		"install-wrong-signature-type": []byte(strings.Replace(install, `"signature":"`, `"signature":0,"untrusted":"`, 1)),
		"install-extra-trust":          []byte(strings.Replace(install, `"enabled":true`, `"enabled":true,"issuer_key":"untrusted"`, 1)),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := decodeAuthorityRequest(data)
			if err == nil || !reflect.DeepEqual(got, authorityRequest{}) {
				t.Fatal("invalid request accepted", err)
			}
		})
	}
	for _, change := range []*authorityChange{nil, {Operation: "bootstrap"}, {Operation: "disable", Signature: "x"}, {Operation: "install"}} {
		proposal, err := authorityChangeProposal(change, CustodyPolicyTrust{})
		if err == nil || !reflect.DeepEqual(proposal, CustodyPolicyChange{}) {
			t.Fatal("invalid proposal accepted")
		}
	}
}

func FuzzAuthorityRequest(f *testing.F) {
	for _, r := range []authorityRequest{{Operation: "resume"}, {Operation: "commit", Segment: testName}, {Operation: "apply-recovery", PlanSHA256: strings.Repeat("a", 64)}, {Operation: "inspect-policy", Change: &authorityChange{Operation: "disable"}}, {Operation: "inspect-policy", Change: authorityInstall(f, testCustodyPolicy())}} {
		f.Add(authorityMessage(f, r))
	}
	f.Add([]byte("{}"))
	f.Add([]byte(`{"schema":"syswarden.local-authority-request.v1","id":"fixture","operation":"resume","uid":0}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		r, err := decodeAuthorityRequest(data)
		if err != nil {
			if !reflect.DeepEqual(r, authorityRequest{}) {
				t.Fatal("failed decode exposed request")
			}
			return
		}
		if len(data) > MaxAuthorityRequestBytes {
			t.Fatal("size bypass")
		}
		encoded, err := json.Marshal(r)
		if err != nil || !bytes.Equal(data, encoded) {
			t.Fatal("noncanonical accepted")
		}
		again, err := decodeAuthorityRequest(encoded)
		if err != nil || !reflect.DeepEqual(r, again) {
			t.Fatal("unstable roundtrip")
		}
	})
}
