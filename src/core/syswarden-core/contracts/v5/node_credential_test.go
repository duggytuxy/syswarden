package v5

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"net"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// Every key is generated in memory for a synthetic, offline certificate fixture.
// No filesystem, network listener or production credential is used here.
type nodeCertificateFixture struct {
	root, issuer, leaf          *x509.Certificate
	rootKey, issuerKey, leafKey *ecdsa.PrivateKey
	rootDER, issuerDER, leafDER []byte
}

func newNodeTestKey(t testing.TB, curve elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func nodeTestCertificate(t testing.TB, template, parent *x509.Certificate, public any, signer *ecdsa.PrivateKey) ([]byte, *x509.Certificate) {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, template, parent, public, signer)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return der, c
}

func newNodeCertificateFixture(t testing.TB) nodeCertificateFixture {
	t.Helper()
	f := nodeCertificateFixture{rootKey: newNodeTestKey(t, elliptic.P256()), issuerKey: newNodeTestKey(t, elliptic.P256()), leafKey: newNodeTestKey(t, elliptic.P256())}
	start := time.Date(2026, 10, 19, 9, 0, 0, 0, time.UTC)
	r := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Synthetic root"},
		NotBefore: start.Add(-time.Hour), NotAfter: start.Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign, MaxPathLen: 1}
	f.rootDER, f.root = nodeTestCertificate(t, r, r, &f.rootKey.PublicKey, f.rootKey)
	i := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Synthetic issuer"},
		NotBefore: start.Add(-time.Hour), NotAfter: start.Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign, MaxPathLen: 0, MaxPathLenZero: true}
	f.issuerDER, f.issuer = nodeTestCertificate(t, i, f.root, &f.issuerKey.PublicKey, f.rootKey)
	u, err := url.Parse("urn:syswarden:node:credential.fixture")
	if err != nil {
		t.Fatal(err)
	}
	l := &x509.Certificate{SerialNumber: big.NewInt(3), NotBefore: start, NotAfter: start.Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, URIs: []*url.URL{u},
		BasicConstraintsValid: true, SignatureAlgorithm: x509.ECDSAWithSHA256}
	f.leafDER, f.leaf = nodeTestCertificate(t, l, f.issuer, &f.leafKey.PublicKey, f.issuerKey)
	return f
}

func (f nodeCertificateFixture) grant(t testing.TB) (NodeTransportGrant, NodeCertificateReadContext) {
	t.Helper()
	g := transportGrantFixture(t)
	g.CertificateSHA256 = nodeBytesSHA256(f.leafDER)
	g.PublicKeySHA256 = nodeBytesSHA256(f.leaf.RawSubjectPublicKeyInfo)
	g.IssuerSHA256 = nodeBytesSHA256(f.issuerDER)
	g.NotBefore = f.leaf.NotBefore.UTC().Format(time.RFC3339Nano)
	g.NotAfter = f.leaf.NotAfter.UTC().Format(time.RFC3339Nano)
	return g, NodeCertificateReadContext{Grant: transportGrantContext(t, g), RootSHA256: nodeBytesSHA256(f.rootDER)}
}

func TestNodeCredentialClientPathBinding(t *testing.T) {
	f := newNodeCertificateFixture(t)
	g, c := f.grant(t)
	before := bytes.Clone(f.leafDER)
	if err := CheckNodeTransportCertificateBinding(g, c, f.leafDER, f.issuerDER, f.rootDER); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, f.leafDER) {
		t.Fatal("certificate input mutated")
	}
	// Also support an explicitly pinned root that directly issues the leaf.
	f.leafDER, f.leaf = nodeTestCertificate(t, f.leaf, f.root, &f.leafKey.PublicKey, f.rootKey)
	f.issuerDER = f.rootDER
	g, c = f.grant(t)
	if err := CheckNodeTransportCertificateBinding(g, c, f.leafDER, f.issuerDER, f.rootDER); err != nil {
		t.Fatal("direct issuer rejected", err)
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := CheckNodeTransportCertificateBinding(g, c, f.leafDER, f.issuerDER, f.rootDER); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
}

func TestNodeCredentialRejectsLeafProfiles(t *testing.T) {
	f := newNodeCertificateFixture(t)
	cases := map[string]func(*x509.Certificate){
		"server only":       func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth} },
		"client and server": func(c *x509.Certificate) { c.ExtKeyUsage = append(c.ExtKeyUsage, x509.ExtKeyUsageServerAuth) },
		"any usage":         func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageAny} },
		"missing eku":       func(c *x509.Certificate) { c.ExtKeyUsage = nil },
		"unknown eku":       func(c *x509.Certificate) { c.UnknownExtKeyUsage = []asn1.ObjectIdentifier{{1, 2, 3, 4}} },
		"extra key usage":   func(c *x509.Certificate) { c.KeyUsage |= x509.KeyUsageKeyEncipherment },
		"no key usage":      func(c *x509.Certificate) { c.KeyUsage = 0 },
		"ca leaf":           func(c *x509.Certificate) { c.IsCA = true },
		"no san":            func(c *x509.Certificate) { c.URIs = nil },
		"duplicate san":     func(c *x509.Certificate) { c.URIs = append(c.URIs, c.URIs[0]) },
		"dns san":           func(c *x509.Certificate) { c.DNSNames = []string{"node.example.invalid"} },
		"ip san":            func(c *x509.Certificate) { c.IPAddresses = []net.IP{net.ParseIP("192.0.2.1")} },
		"email san":         func(c *x509.Certificate) { c.EmailAddresses = []string{"node@example.invalid"} },
		"foreign identity": func(c *x509.Certificate) {
			u := *c.URIs[0]
			u.Opaque = "syswarden:node:foreign"
			c.URIs = []*url.URL{&u}
		},
		"case alias": func(c *x509.Certificate) {
			u := *c.URIs[0]
			u.Opaque = "syswarden:node:Credential.fixture"
			c.URIs = []*url.URL{&u}
		},
		"unknown critical": func(c *x509.Certificate) {
			c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Critical: true, Value: []byte{5, 0}}}
		},
		"alternate signature": func(c *x509.Certificate) { c.SignatureAlgorithm = x509.ECDSAWithSHA384 },
		"ignored general name": func(c *x509.Certificate) {
			data, err := asn1.Marshal([]asn1.RawValue{{Class: 2, Tag: 6, Bytes: []byte("urn:syswarden:node:credential.fixture")}, {Class: 2, Tag: 8, Bytes: []byte{42, 3}}})
			if err != nil {
				t.Fatal(err)
			}
			c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Value: data}}
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			template := *f.leaf
			change(&template)
			bad := f
			bad.leafDER, bad.leaf = nodeTestCertificate(t, &template, f.issuer, &f.leafKey.PublicKey, f.issuerKey)
			g, c := bad.grant(t)
			if !errors.Is(CheckNodeTransportCertificateBinding(g, c, bad.leafDER, bad.issuerDER, bad.rootDER), ErrNodeCredentialBindingMismatch) {
				t.Fatal("wrong certificate profile accepted")
			}
		})
	}
	t.Run("non-P256 key", func(t *testing.T) {
		key := newNodeTestKey(t, elliptic.P384())
		bad := f
		bad.leafDER, bad.leaf = nodeTestCertificate(t, f.leaf, f.issuer, &key.PublicKey, f.issuerKey)
		g, c := bad.grant(t)
		if !errors.Is(CheckNodeTransportCertificateBinding(g, c, bad.leafDER, bad.issuerDER, bad.rootDER), ErrNodeCredentialBindingMismatch) {
			t.Fatal("wrong key curve accepted")
		}
	})
}

func TestNodeCredentialRejectsSubstitutionAndMalformedDER(t *testing.T) {
	f := newNodeCertificateFixture(t)
	g, c := f.grant(t)
	other := newNodeCertificateFixture(t)
	for _, part := range []string{"leaf", "issuer", "root"} {
		for _, mode := range []string{"empty", "too large", "trailing", "other"} {
			t.Run(part+"/"+mode, func(t *testing.T) {
				leaf, issuer, root := bytes.Clone(f.leafDER), bytes.Clone(f.issuerDER), bytes.Clone(f.rootDER)
				p, replacement := &leaf, other.leafDER
				if part == "issuer" {
					p, replacement = &issuer, other.issuerDER
				}
				if part == "root" {
					p, replacement = &root, other.rootDER
				}
				switch mode {
				case "empty":
					*p = nil
				case "too large":
					*p = bytes.Repeat([]byte{0}, MaxNodeCertificateBytes+1)
				case "trailing":
					*p = append(*p, 0)
				case "other":
					*p = replacement
				}
				if !errors.Is(CheckNodeTransportCertificateBinding(g, c, leaf, issuer, root), ErrNodeCredentialBindingMismatch) {
					t.Fatal("unbound DER accepted")
				}
				// Pin the malformed bytes too: syntax/path checks must remain independent.
				changed := g
				changed.CertificateSHA256 = nodeBytesSHA256(leaf)
				changed.IssuerSHA256 = nodeBytesSHA256(issuer)
				ctx := NodeCertificateReadContext{Grant: transportGrantContext(t, changed), RootSHA256: nodeBytesSHA256(root)}
				if !errors.Is(CheckNodeTransportCertificateBinding(changed, ctx, leaf, issuer, root), ErrNodeCredentialBindingMismatch) {
					t.Fatal("invalid repinned DER accepted")
				}
			})
		}
	}
	t.Run("signature corruption", func(t *testing.T) {
		leaf := bytes.Clone(f.leafDER)
		leaf[len(leaf)-1] ^= 1
		changed := g
		changed.CertificateSHA256 = nodeBytesSHA256(leaf)
		ctx := c
		ctx.Grant = transportGrantContext(t, changed)
		if !errors.Is(CheckNodeTransportCertificateBinding(changed, ctx, leaf, f.issuerDER, f.rootDER), ErrNodeCredentialBindingMismatch) {
			t.Fatal("corrupt signature accepted")
		}
	})
	for _, field := range []string{"public key", "before", "after"} {
		t.Run(field, func(t *testing.T) {
			changed := g
			switch field {
			case "public key":
				changed.PublicKeySHA256 = strings.Repeat("0", 64)
			case "before":
				changed.NotBefore = c.Grant.Now.Add(time.Second).Format(time.RFC3339Nano)
			case "after":
				changed.NotAfter = c.Grant.Now.Add(time.Hour).Format(time.RFC3339Nano)
			}
			ctx := c
			ctx.Grant = transportGrantContext(t, changed)
			if !errors.Is(CheckNodeTransportCertificateBinding(changed, ctx, f.leafDER, f.issuerDER, f.rootDER), ErrNodeCredentialBindingMismatch) {
				t.Fatal("mismatched grant profile accepted")
			}
		})
	}
	for _, mode := range []string{"missing root pin", "foreign epoch", "expiry", "revoked"} {
		t.Run(mode, func(t *testing.T) {
			ctx, changed := c, g
			switch mode {
			case "missing root pin":
				ctx.RootSHA256 = ""
			case "foreign epoch":
				ctx.Grant.Identity.Epoch = "foreign"
			case "expiry":
				ctx.Grant.Now = f.leaf.NotAfter
			case "revoked":
				changed.Status = "revoked"
				ctx.Grant = transportGrantContext(t, changed)
			}
			if CheckNodeTransportCertificateBinding(changed, ctx, f.leafDER, f.issuerDER, f.rootDER) == nil {
				t.Fatal("inactive or unbound credential accepted")
			}
		})
	}
}

func TestNodeCredentialIssuerAndRootConstraints(t *testing.T) {
	f := newNodeCertificateFixture(t)
	for _, part := range []string{"issuer", "root"} {
		for _, mode := range []string{"expired", "future", "not CA", "wrong usage", "server EKU"} {
			t.Run(part+"/"+mode, func(t *testing.T) {
				bad := f
				original := f.issuer
				if part == "root" {
					original = f.root
				}
				template := *original
				switch mode {
				case "expired":
					template.NotAfter = f.leaf.NotBefore.Add(-time.Second)
				case "future":
					template.NotBefore = f.leaf.NotBefore.Add(time.Second)
				case "not CA":
					template.IsCA = false
					template.MaxPathLen = -1
					template.MaxPathLenZero = false
				case "wrong usage":
					template.KeyUsage = x509.KeyUsageDigitalSignature
				case "server EKU":
					template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
				}
				if part == "root" {
					bad.rootDER, bad.root = nodeTestCertificate(t, &template, &template, &f.rootKey.PublicKey, f.rootKey)
				} else {
					bad.issuerDER, bad.issuer = nodeTestCertificate(t, &template, f.root, &f.issuerKey.PublicKey, f.rootKey)
				}
				g, c := bad.grant(t)
				if !errors.Is(CheckNodeTransportCertificateBinding(g, c, bad.leafDER, bad.issuerDER, bad.rootDER), ErrNodeCredentialBindingMismatch) {
					t.Fatal("invalid issuer chain accepted")
				}
			})
		}
	}
}

func TestNodeProducerKeyScopeAndPurpose(t *testing.T) {
	key := newNodeTestKey(t, elliptic.P256())
	public, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	g := producerGrantFixture(t)
	g.PublicKeySHA256 = nodeBytesSHA256(public)
	c := producerGrantContext(t, g)
	if err := CheckNodeProducerKeyBinding(g, c, g.SourceID, g.PayloadSchema, public); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"source", "schema", "key", "bad DER", "large DER", "curve", "revoked", "expired", "policy", "missing context"} {
		t.Run(name, func(t *testing.T) {
			changed, ctx, source, schema, data := g, c, g.SourceID, g.PayloadSchema, bytes.Clone(public)
			switch name {
			case "source":
				source += ".other"
			case "schema":
				schema += ".v2"
			case "key":
				data, _ = x509.MarshalPKIXPublicKey(&newNodeTestKey(t, elliptic.P256()).PublicKey)
			case "bad DER":
				data = []byte("untrusted public key")
				changed.PublicKeySHA256 = nodeBytesSHA256(data)
				ctx = producerGrantContext(t, changed)
			case "large DER":
				data = bytes.Repeat([]byte{0}, MaxNodePublicKeyBytes+1)
				changed.PublicKeySHA256 = nodeBytesSHA256(data)
				ctx = producerGrantContext(t, changed)
			case "curve":
				data, _ = x509.MarshalPKIXPublicKey(&newNodeTestKey(t, elliptic.P384()).PublicKey)
				changed.PublicKeySHA256 = nodeBytesSHA256(data)
				ctx = producerGrantContext(t, changed)
			case "revoked":
				changed.Status = "revoked"
				ctx = producerGrantContext(t, changed)
			case "expired":
				ctx.Now, _ = time.Parse(time.RFC3339Nano, g.NotAfter)
			case "policy":
				ctx.Policy.Ref += ".other"
			case "missing context":
				ctx = NodeGrantReadContext{}
			}
			if CheckNodeProducerKeyBinding(changed, ctx, source, schema, data) == nil {
				t.Fatal("foreign or inactive producer accepted")
			}
		})
	}
}
