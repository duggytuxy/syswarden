package v5

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"time"
)

const (
	MaxNodeCertificateBytes = 4096
	MaxNodePublicKeyBytes   = 256
)

// NodeCertificateReadContext pins the independent currently authorized root.
// Never obtain RootSHA256 from the submitted certificate chain. The caller owns
// current trust distribution, revocation and serialization with registry updates.
type NodeCertificateReadContext struct {
	Grant      NodeGrantReadContext
	RootSHA256 string
}

func nodeBytesSHA256(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func nodeP256PublicKey(data []byte) bool {
	if len(data) == 0 || len(data) > MaxNodePublicKeyBytes {
		return false
	}
	key, err := x509.ParsePKIXPublicKey(data)
	if err != nil {
		return false
	}
	public, ok := key.(*ecdsa.PublicKey)
	if !ok || public.Curve != elliptic.P256() {
		return false
	}
	canonical, err := x509.MarshalPKIXPublicKey(public)
	return err == nil && bytes.Equal(canonical, data)
}

// CheckNodeTransportCertificateBinding checks a current immutable grant, exact
// certificate/SPKI/issuer pins, a separately pinned root and an X.509 client path.
// All three inputs are bounded raw DER, never paths, URLs or mutable parsed
// certificate fields. Success does NOT establish a TLS peer's key possession,
// a live registry lease, observation validity, producer or action authority.
func CheckNodeTransportCertificateBinding(g NodeTransportGrant, c NodeCertificateReadContext, leafDER, issuerDER, rootDER []byte) error {
	if err := CheckCurrentNodeTransportGrant(g, c.Grant); err != nil {
		return err
	}
	if !digest(c.RootSHA256) {
		return ErrInvalidNodeGrantContext
	}
	for _, data := range [][]byte{leafDER, issuerDER, rootDER} {
		if len(data) == 0 || len(data) > MaxNodeCertificateBytes {
			return ErrNodeCredentialBindingMismatch
		}
	}
	if nodeBytesSHA256(leafDER) != g.CertificateSHA256 || nodeBytesSHA256(issuerDER) != g.IssuerSHA256 ||
		nodeBytesSHA256(rootDER) != c.RootSHA256 {
		return ErrNodeCredentialBindingMismatch
	}
	leaf, leafErr := x509.ParseCertificate(leafDER)
	issuer, issuerErr := x509.ParseCertificate(issuerDER)
	root, rootErr := x509.ParseCertificate(rootDER)
	if leafErr != nil || issuerErr != nil || rootErr != nil {
		return ErrNodeCredentialBindingMismatch
	}
	if !nodeTransportLeafProfile(leaf, g) {
		return ErrNodeCredentialBindingMismatch
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	intermediates := x509.NewCertPool()
	if !bytes.Equal(rootDER, issuerDER) {
		intermediates.AddCert(issuer)
	}
	chains, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates,
		CurrentTime: c.Grant.Now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	if err != nil {
		return ErrNodeCredentialBindingMismatch
	}
	for _, chain := range chains {
		if len(chain) >= 2 && len(chain) <= 3 && bytes.Equal(chain[1].Raw, issuerDER) &&
			bytes.Equal(chain[len(chain)-1].Raw, rootDER) {
			return nil
		}
	}
	return ErrNodeCredentialBindingMismatch
}

func nodeTransportLeafProfile(leaf *x509.Certificate, g NodeTransportGrant) bool {
	if leaf.IsCA || leaf.KeyUsage != x509.KeyUsageDigitalSignature ||
		len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth || len(leaf.UnknownExtKeyUsage) != 0 ||
		leaf.SignatureAlgorithm != x509.ECDSAWithSHA256 || !nodeP256PublicKey(leaf.RawSubjectPublicKeyInfo) ||
		nodeBytesSHA256(leaf.RawSubjectPublicKeyInfo) != g.PublicKeySHA256 ||
		leaf.NotBefore.UTC().Format(time.RFC3339Nano) != g.NotBefore ||
		leaf.NotAfter.UTC().Format(time.RFC3339Nano) != g.NotAfter {
		return false
	}
	// Check the full SAN extension, including GeneralName types ignored by Go's
	// URIs/DNSNames projections. Only the exact one-URI identity is permitted.
	expected, err := asn1.Marshal([]asn1.RawValue{{Class: 2, Tag: 6, Bytes: []byte("urn:syswarden:node:" + g.CredentialID)}})
	if err != nil {
		return false
	}
	for _, extension := range leaf.Extensions {
		if extension.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 17}) {
			return bytes.Equal(extension.Value, expected)
		}
	}
	return false
}

// CheckNodeProducerKeyBinding checks exact source/schema and canonical P-256 SPKI
// bytes against a current separate producer grant. It verifies no sample signature
// and grants no authority to a transport credential or BunkerWeb integration.
func CheckNodeProducerKeyBinding(g NodeProducerGrant, c NodeGrantReadContext, sourceID, payloadSchema string, publicKeyDER []byte) error {
	if err := CheckCurrentNodeProducerGrant(g, c); err != nil {
		return err
	}
	if sourceID != g.SourceID || payloadSchema != g.PayloadSchema || !nodeP256PublicKey(publicKeyDER) ||
		nodeBytesSHA256(publicKeyDER) != g.PublicKeySHA256 {
		return ErrNodeCredentialBindingMismatch
	}
	return nil
}
