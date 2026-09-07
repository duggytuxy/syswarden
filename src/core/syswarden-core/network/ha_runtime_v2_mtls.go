package network

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
)

const maxHAV2TLSFileBytes int64 = 1024 * 1024

type haV2TLSIdentity struct {
	Certificate  tls.Certificate
	Roots        *x509.CertPool
	NodeID       string
	PeerID       string
	Fingerprints map[string]struct{}
}

func decodeStrictHAV2PEM(wire []byte, kind string, minimum, maximum int) ([]*pem.Block, error) {
	blocks := make([]*pem.Block, 0, minimum)
	rest := wire
	for {
		rest = bytes.TrimLeft(rest, " \t\r\n")
		if len(rest) == 0 {
			break
		}
		if !bytes.HasPrefix(rest, []byte("-----BEGIN ")) {
			return nil, fmt.Errorf("HA v2 %s contains non-PEM data", kind)
		}
		block, next := pem.Decode(rest)
		if block == nil || len(block.Headers) != 0 {
			return nil, fmt.Errorf("HA v2 %s contains an invalid PEM block", kind)
		}
		blocks = append(blocks, block)
		if len(blocks) > maximum {
			return nil, fmt.Errorf("HA v2 %s exceeds its PEM block bound", kind)
		}
		rest = next
	}
	if len(blocks) < minimum {
		return nil, fmt.Errorf("HA v2 %s is incomplete", kind)
	}
	return blocks, nil
}

func readHAV2TLSFile(path string, expectedOwnerUID int) ([]byte, error) {
	root, name, err := openHAReplicationStoreDirectory(path, expectedOwnerUID)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	info, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	owner, ownerErr := haFenceOwnerUID(info)
	if ownerErr != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || owner != expectedOwnerUID {
		return nil, fmt.Errorf("HA v2 TLS material must be an owner-only regular file")
	}
	return readHARegularFileBounded(root, name, maxHAV2TLSFileBytes)
}

func loadHAV2TLSIdentity(certPath, keyPath, caPath, nodeID, peerID string, fingerprints []string, expectedOwnerUID int) (*haV2TLSIdentity, error) {
	if !haReplicationIDRE.MatchString(nodeID) || !haReplicationIDRE.MatchString(peerID) || nodeID == peerID || len(fingerprints) < 1 || len(fingerprints) > 2 {
		return nil, fmt.Errorf("invalid HA v2 TLS identity mapping")
	}
	certPEM, err := readHAV2TLSFile(certPath, expectedOwnerUID)
	if err != nil {
		return nil, err
	}
	keyPEM, err := readHAV2TLSFile(keyPath, expectedOwnerUID)
	if err != nil {
		return nil, err
	}
	defer func() {
		for index := range keyPEM {
			keyPEM[index] = 0
		}
	}()
	caPEM, err := readHAV2TLSFile(caPath, expectedOwnerUID)
	if err != nil {
		return nil, err
	}
	certificateBlocks, err := decodeStrictHAV2PEM(certPEM, "certificate chain", 1, 16)
	if err != nil {
		return nil, err
	}
	for _, block := range certificateBlocks {
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("HA v2 certificate chain contains a non-certificate PEM block")
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return nil, fmt.Errorf("invalid HA v2 certificate chain")
		}
	}
	keyBlocks, err := decodeStrictHAV2PEM(keyPEM, "private key", 1, 1)
	if err != nil {
		return nil, err
	}
	switch keyBlocks[0].Type {
	case "PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY":
	default:
		return nil, fmt.Errorf("HA v2 private key uses an unsupported PEM type")
	}
	caBlocks, err := decodeStrictHAV2PEM(caPEM, "CA bundle", 1, 32)
	if err != nil {
		return nil, err
	}
	certificate, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil || len(certificate.Certificate) == 0 {
		return nil, fmt.Errorf("invalid HA v2 node certificate or key")
	}
	roots := x509.NewCertPool()
	seenCAs := make(map[string]struct{}, len(caBlocks))
	for _, block := range caBlocks {
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("HA v2 CA bundle contains a non-certificate PEM block")
		}
		ca, parseErr := x509.ParseCertificate(block.Bytes)
		if parseErr != nil || !ca.IsCA || !ca.BasicConstraintsValid {
			return nil, fmt.Errorf("invalid HA v2 CA certificate")
		}
		digest := sha256.Sum256(ca.Raw)
		key := hex.EncodeToString(digest[:])
		if _, duplicate := seenCAs[key]; duplicate {
			return nil, fmt.Errorf("duplicate HA v2 CA certificate")
		}
		seenCAs[key] = struct{}{}
		roots.AddCert(ca)
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil || leaf.VerifyHostname(nodeID) != nil {
		return nil, fmt.Errorf("HA v2 certificate SAN does not bind node ID")
	}
	intermediates := x509.NewCertPool()
	for _, raw := range certificate.Certificate[1:] {
		parsed, parseErr := x509.ParseCertificate(raw)
		if parseErr != nil {
			return nil, fmt.Errorf("invalid HA v2 certificate chain")
		}
		intermediates.AddCert(parsed)
	}
	for _, usage := range []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth} {
		if _, err := leaf.Verify(x509.VerifyOptions{DNSName: nodeID, Roots: roots, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{usage}}); err != nil {
			return nil, fmt.Errorf("HA v2 node certificate is not valid for mutual TLS: %w", err)
		}
	}
	certificate.Leaf = leaf
	pins := make(map[string]struct{}, len(fingerprints))
	for _, fingerprint := range fingerprints {
		if len(fingerprint) != 64 || fingerprint != string(bytes.ToLower([]byte(fingerprint))) {
			return nil, fmt.Errorf("invalid HA v2 peer fingerprint")
		}
		if _, err := hex.DecodeString(fingerprint); err != nil {
			return nil, fmt.Errorf("invalid HA v2 peer fingerprint")
		}
		if _, duplicate := pins[fingerprint]; duplicate {
			return nil, fmt.Errorf("duplicate HA v2 peer fingerprint")
		}
		pins[fingerprint] = struct{}{}
	}
	return &haV2TLSIdentity{Certificate: certificate, Roots: roots, NodeID: nodeID, PeerID: peerID, Fingerprints: pins}, nil
}

func (identity *haV2TLSIdentity) verifyPeer(state *tls.ConnectionState) error {
	if identity == nil || state == nil || len(state.PeerCertificates) == 0 || len(state.VerifiedChains) == 0 {
		return fmt.Errorf("verified HA v2 client certificate required")
	}
	leaf := state.PeerCertificates[0]
	if err := leaf.VerifyHostname(identity.PeerID); err != nil {
		return fmt.Errorf("HA v2 peer SAN mismatch")
	}
	digest := sha256.Sum256(leaf.Raw)
	if _, allowed := identity.Fingerprints[hex.EncodeToString(digest[:])]; !allowed {
		return fmt.Errorf("HA v2 peer certificate fingerprint mismatch")
	}
	return nil
}

func (identity *haV2TLSIdentity) serverConfig() *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{identity.Certificate}, MinVersion: tls.VersionTLS13,
		ClientAuth: tls.VerifyClientCertIfGiven, ClientCAs: identity.Roots,
	}
}

func (identity *haV2TLSIdentity) clientConfig() *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{identity.Certificate}, RootCAs: identity.Roots,
		ServerName: identity.PeerID, MinVersion: tls.VersionTLS13,
		VerifyConnection: func(state tls.ConnectionState) error { return identity.verifyPeer(&state) },
	}
}
