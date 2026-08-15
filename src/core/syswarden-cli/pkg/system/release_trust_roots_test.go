package system

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"testing"
)

func TestEmbeddedProductionReleaseTrustRootFingerprints(t *testing.T) {
	keys, err := embeddedTrustedReleaseKeys()
	if err != nil {
		t.Fatalf("parse embedded release trust roots: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("embedded release trust-root count = %d, want 1", len(keys))
	}
	publicKey, exists := keys["syswarden-update-2026-01"]
	if !exists {
		t.Fatal("embedded release key syswarden-update-2026-01 is missing")
	}
	if len(publicKey) != ed25519.PublicKeySize {
		t.Fatalf("embedded public-key length = %d, want %d", len(publicKey), ed25519.PublicKeySize)
	}
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatalf("marshal embedded public key: %v", err)
	}
	assertSHA256(t, "public DER", der, "883690247af3072880099f69abd93112666eb2c3debd026f9ef3f6f5d8dcd9f2")
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	assertSHA256(t, "public PEM", publicPEM, "6afaa957ded57c623831292c80bd7644e339044dafd31f0c3b59f76bd7b9c2a4")
}

func assertSHA256(t *testing.T, label string, data []byte, expected string) {
	t.Helper()
	digest := sha256.Sum256(data)
	if actual := hex.EncodeToString(digest[:]); actual != expected {
		t.Fatalf("%s SHA-256 = %s, want %s", label, actual, expected)
	}
}
