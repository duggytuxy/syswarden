package network

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type haV2TestPKI struct {
	caPEM      []byte
	ca         *x509.Certificate
	caKey      *ecdsa.PrivateKey
	nextSerial int64
}

func newHAV2TestPKI(t *testing.T) *haV2TestPKI {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "SysWarden HA v2 test CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &haV2TestPKI{caPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), ca: certificate, caKey: key, nextSerial: 2}
}

func (pki *haV2TestPKI) node(t *testing.T, nodeID string) ([]byte, []byte, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(pki.nextSerial), Subject: pkix.Name{CommonName: nodeID}, DNSNames: []string{nodeID},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), BasicConstraintsValid: true,
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	pki.nextSerial++
	der, err := x509.CreateCertificate(rand.Reader, template, pki.ca, &key.PublicKey, pki.caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(der)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), hex.EncodeToString(digest[:])
}

func writeHAV2TLSFixture(t *testing.T, directory, name string, content []byte) string {
	t.Helper()
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestHAV2MTLSBindsPeerSANFingerprintAndVerifiedChain(t *testing.T) {
	leaf := &x509.Certificate{DNSNames: []string{"node-b"}, Raw: []byte("peer-certificate-der")}
	digest := sha256.Sum256(leaf.Raw)
	identity := &haV2TLSIdentity{
		PeerID: "node-b", Fingerprints: map[string]struct{}{hex.EncodeToString(digest[:]): {}},
	}
	valid := &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}, VerifiedChains: [][]*x509.Certificate{{leaf}}}
	if err := identity.verifyPeer(valid); err != nil {
		t.Fatalf("valid peer rejected: %v", err)
	}
	for name, state := range map[string]*tls.ConnectionState{
		"missing":           nil,
		"unverified":        {PeerCertificates: []*x509.Certificate{leaf}},
		"wrong SAN":         {PeerCertificates: []*x509.Certificate{{DNSNames: []string{"node-c"}, Raw: leaf.Raw}}, VerifiedChains: [][]*x509.Certificate{{leaf}}},
		"wrong fingerprint": {PeerCertificates: []*x509.Certificate{{DNSNames: []string{"node-b"}, Raw: []byte("other")}}, VerifiedChains: [][]*x509.Certificate{{leaf}}},
	} {
		t.Run(name, func(t *testing.T) {
			if err := identity.verifyPeer(state); err == nil {
				t.Fatal("unattested peer accepted")
			}
		})
	}
}

func TestHAV2TLSConfigsRequireTLS13AndClientIdentityForV2Verifier(t *testing.T) {
	identity := &haV2TLSIdentity{Certificate: tls.Certificate{}, Roots: x509.NewCertPool(), PeerID: "node-b", Fingerprints: map[string]struct{}{}}
	server := identity.serverConfig()
	client := identity.clientConfig()
	if server.MinVersion != tls.VersionTLS13 || server.ClientAuth != tls.VerifyClientCertIfGiven || client.MinVersion != tls.VersionTLS13 || client.ServerName != "node-b" || client.VerifyConnection == nil {
		t.Fatal("HA v2 TLS policy weakened")
	}
}

func TestHAV2MTLSOwnerOnlyFilesCompleteTLS13Handshake(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil { // #nosec G302 -- the owner-only TLS fixture directory requires execute permission
		t.Fatal(err)
	}
	pki := newHAV2TestPKI(t)
	certA, keyA, pinA := pki.node(t, "node-a")
	certB, keyB, pinB := pki.node(t, "node-b")
	caPath := writeHAV2TLSFixture(t, directory, "ca.crt", pki.caPEM)
	identityA, err := loadHAV2TLSIdentity(
		writeHAV2TLSFixture(t, directory, "node-a.crt", certA),
		writeHAV2TLSFixture(t, directory, "node-a.key", keyA), caPath,
		"node-a", "node-b", []string{pinB}, os.Geteuid(),
	)
	if err != nil {
		t.Fatal(err)
	}
	identityB, err := loadHAV2TLSIdentity(
		writeHAV2TLSFixture(t, directory, "node-b.crt", certB),
		writeHAV2TLSFixture(t, directory, "node-b.key", keyB), caPath,
		"node-b", "node-a", []string{pinA}, os.Geteuid(),
	)
	if err != nil {
		t.Fatal(err)
	}

	serverWire, clientWire := net.Pipe()
	deadline := time.Now().Add(2 * time.Second)
	_ = serverWire.SetDeadline(deadline)
	_ = clientWire.SetDeadline(deadline)
	server := tls.Server(serverWire, identityB.serverConfig())
	client := tls.Client(clientWire, identityA.clientConfig())
	serverResult := make(chan error, 1)
	go func() { serverResult <- server.Handshake() }()
	clientErr := client.Handshake()
	serverErr := <-serverResult
	defer server.Close()
	defer client.Close()
	if clientErr != nil || serverErr != nil {
		t.Fatalf("mutual TLS handshake client=%v server=%v", clientErr, serverErr)
	}
	clientState, serverState := client.ConnectionState(), server.ConnectionState()
	if clientState.Version != tls.VersionTLS13 || serverState.Version != tls.VersionTLS13 ||
		identityA.verifyPeer(&clientState) != nil || identityB.verifyPeer(&serverState) != nil {
		t.Fatalf("mutual TLS state client=%#v server=%#v", clientState, serverState)
	}

	if err := os.Chmod(filepath.Join(directory, "node-a.key"), 0640); err != nil { // #nosec G302 -- this adversarial fixture deliberately makes the private key group-readable
		t.Fatal(err)
	}
	if _, err := loadHAV2TLSIdentity(filepath.Join(directory, "node-a.crt"), filepath.Join(directory, "node-a.key"), caPath, "node-a", "node-b", []string{pinB}, os.Geteuid()); err == nil {
		t.Fatal("group-readable HA v2 private key was accepted")
	}
}

func TestHAV2SharedTLSKeepsVerifiedLegacyClientCertificateOptional(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil { // #nosec G302 -- the owner-only TLS fixture directory requires execute permission
		t.Fatal(err)
	}
	pki := newHAV2TestPKI(t)
	certB, keyB, _ := pki.node(t, "node-b")
	_, _, pinA := pki.node(t, "node-a")
	identityB, err := loadHAV2TLSIdentity(
		writeHAV2TLSFixture(t, directory, "node-b.crt", certB),
		writeHAV2TLSFixture(t, directory, "node-b.key", keyB),
		writeHAV2TLSFixture(t, directory, "ca.crt", pki.caPEM),
		"node-b", "node-a", []string{pinA}, os.Geteuid(),
	)
	if err != nil {
		t.Fatal(err)
	}
	serverWire, clientWire := net.Pipe()
	deadline := time.Now().Add(2 * time.Second)
	_ = serverWire.SetDeadline(deadline)
	_ = clientWire.SetDeadline(deadline)
	server := tls.Server(serverWire, identityB.serverConfig())
	client := tls.Client(clientWire, &tls.Config{
		MinVersion: tls.VersionTLS13, RootCAs: identityB.Roots, ServerName: "node-b",
	})
	serverResult := make(chan error, 1)
	go func() { serverResult <- server.Handshake() }()
	clientErr := client.Handshake()
	serverErr := <-serverResult
	defer server.Close()
	defer client.Close()
	if clientErr != nil || serverErr != nil {
		t.Fatalf("verified legacy TLS handshake client=%v server=%v", clientErr, serverErr)
	}
	if len(server.ConnectionState().PeerCertificates) != 0 {
		t.Fatal("legacy client unexpectedly supplied a client certificate")
	}
}

func TestHAV2MTLSRejectsNonCanonicalPEMMaterial(t *testing.T) {
	pki := newHAV2TestPKI(t)
	certA, keyA, _ := pki.node(t, "node-a")
	_, _, pinB := pki.node(t, "node-b")
	for name, mutate := range map[string]func([]byte, []byte, []byte) ([]byte, []byte, []byte){
		"certificate junk": func(cert, key, ca []byte) ([]byte, []byte, []byte) {
			return append([]byte("comment\n"), cert...), key, ca
		},
		"private key trailing data": func(cert, key, ca []byte) ([]byte, []byte, []byte) {
			return cert, append(key, []byte("not-pem")...), ca
		},
		"duplicate CA": func(cert, key, ca []byte) ([]byte, []byte, []byte) {
			return cert, key, append(append([]byte(nil), ca...), ca...)
		},
	} {
		t.Run(name, func(t *testing.T) {
			cert, key, ca := mutate(append([]byte(nil), certA...), append([]byte(nil), keyA...), append([]byte(nil), pki.caPEM...))
			caseDirectory := t.TempDir()
			if err := os.Chmod(caseDirectory, 0700); err != nil { // #nosec G302 -- the owner-only TLS fixture directory requires execute permission
				t.Fatal(err)
			}
			if _, err := loadHAV2TLSIdentity(
				writeHAV2TLSFixture(t, caseDirectory, "node-a.crt", cert),
				writeHAV2TLSFixture(t, caseDirectory, "node-a.key", key),
				writeHAV2TLSFixture(t, caseDirectory, "ca.crt", ca),
				"node-a", "node-b", []string{pinB}, os.Geteuid(),
			); err == nil {
				t.Fatal("non-canonical HA v2 TLS material accepted")
			}
		})
	}
}
