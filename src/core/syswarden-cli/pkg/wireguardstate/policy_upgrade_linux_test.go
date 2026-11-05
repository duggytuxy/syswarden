//go:build linux

package wireguardstate

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
)

func policyUpgradeFixture(t *testing.T, address, allowed string, shared bool) []byte {
	t.Helper()
	lines := strings.Split(string(exactTestServerConfiguration()), "\n")
	lines[1] = "Address = " + address
	lines[3] = "PrivateKey = " + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{11}, 32))
	lines[8] = "PublicKey = " + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{22}, 32))
	lines[9] = "PresharedKey = " + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{33}, 32))
	lines[10] = "AllowedIPs = " + allowed
	token := strings.Repeat("b", 64)
	lines[4] = strings.ReplaceAll(lines[4], strings.Repeat("a", 64), token)
	lines[4] = strings.ReplaceAll(lines[4], `"ens3"`, `"eth0.42"`)
	if shared {
		lines[4] = strings.TrimSuffix(lines[4], "'") + fmt.Sprintf(`; insert rule inet filter forward iifname "wg-syswarden" accept comment "syswarden-wg-forward-v1:%s"; insert rule inet filter forward oifname "wg-syswarden" accept comment "syswarden-wg-forward-v1:%s"'`, token, token)
	}
	server := []byte(strings.Join(lines, "\n"))
	if _, err := ParseServerConfiguration(server); err != nil {
		t.Fatal("synthetic v1 fixture is not canonical", err)
	}
	return server
}

func assertPolicyUpgradePreservesNonPostUpBytes(t *testing.T, old, target []byte) {
	t.Helper()
	oldLines, targetLines := bytes.Split(old, []byte("\n")), bytes.Split(target, []byte("\n"))
	if len(oldLines) != len(targetLines) {
		t.Fatal("policy upgrade changed the configuration line count")
	}
	for index := range oldLines {
		if index != 4 && !bytes.Equal(oldLines[index], targetLines[index]) {
			t.Fatalf("policy upgrade changed bytes outside PostUp at line %d", index+1)
		}
	}
	if bytes.Equal(oldLines[4], targetLines[4]) {
		t.Fatal("v1 PostUp was not upgraded")
	}
}

func TestScopedServerConfigurationPreservesIdentityKeysAndAllOtherBytes(t *testing.T) {
	for _, prefix := range []struct {
		name, address, allowed, subnet string
	}{
		{"default", "10.66.0.1/16", "10.66.0.2/32", "10.66.0.0/16"},
		{"large", "10.0.0.1/8", "10.0.0.2/32", "10.0.0.0/8"},
		{"documentation", "192.0.2.1/24", "192.0.2.2/32", "192.0.2.0/24"},
		{"smallest", "192.0.2.1/30", "192.0.2.2/32", "192.0.2.0/30"},
		{"zero-prefix", "0.0.0.1/0", "0.0.0.2/32", "0.0.0.0/0"},
	} {
		for _, shared := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/shared=%t", prefix.name, shared), func(t *testing.T) {
				server := policyUpgradeFixture(t, prefix.address, prefix.allowed, shared)
				original := bytes.Clone(server)
				identity, err := ParseServerConfiguration(server)
				if err != nil {
					t.Fatal(err)
				}
				target, err := ScopedServerConfiguration(server)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(server, original) {
					t.Fatal("policy upgrade mutated its input")
				}
				assertPolicyUpgradePreservesNonPostUpBytes(t, original, target)
				identity.PolicyVersion, identity.IPv4Subnet = 2, prefix.subnet
				actual, err := ParseServerConfiguration(target)
				if err != nil || actual != identity {
					t.Fatal("policy upgrade changed the token, egress, hook executables or shared-forward identity", err)
				}
				postUp := string(bytes.Split(target, []byte("\n"))[4])
				if strings.Contains(postUp, "syswarden-wg-v1:") || strings.Contains(postUp, "syswarden-wg-forward-v1:") {
					t.Fatal("policy upgrade retained a historical hook")
				}
				if shared && (strings.Count(postUp, "syswarden-wg-forward-v2:"+identity.OwnershipToken) != 2 ||
					!strings.Contains(postUp, fmt.Sprintf(`insert rule inet filter forward iifname "eth0.42" oifname "wg-syswarden" ip daddr %s ct state { established, related } accept`, prefix.subnet))) {
					t.Fatal("shared-forward upgrade did not retain two constrained versioned permits")
				}
				target[0] ^= 1
				if !bytes.Equal(server, original) {
					t.Fatal("v1 upgrade result shares its input backing array")
				}
			})
		}
	}
}

func TestScopedServerConfigurationV2IsIdempotentAndDetached(t *testing.T) {
	for _, shared := range []bool{false, true} {
		server := policyUpgradeFixture(t, "192.0.2.1/30", "192.0.2.2/32", shared)
		scoped, err := ScopedServerConfiguration(server)
		if err != nil {
			t.Fatal(err)
		}
		original := bytes.Clone(scoped)
		result, err := ScopedServerConfiguration(scoped)
		if err != nil || !bytes.Equal(result, original) || !bytes.Equal(scoped, original) {
			t.Fatal("v2 policy was changed on repeated transformation", err)
		}
		result[0] ^= 1
		if !bytes.Equal(scoped, original) {
			t.Fatal("idempotent v2 result shares its input backing array")
		}
	}
}

func TestScopedServerConfigurationRejectsModifiedOrUnsafeInput(t *testing.T) {
	valid := policyUpgradeFixture(t, "192.0.2.1/30", "192.0.2.2/32", false)
	mutateLine := func(index int, replacement string) []byte {
		lines := strings.Split(string(valid), "\n")
		lines[index] = replacement
		return []byte(strings.Join(lines, "\n"))
	}
	cases := map[string][]byte{
		"nil":                   nil,
		"empty":                 {},
		"missing-final-newline": bytes.TrimSuffix(valid, []byte("\n")),
		"truncated-interface":   bytes.Clone(valid[:len("[Interface]")]),
		"truncated-peer":        bytes.Clone(valid[:bytes.Index(valid, []byte("[Peer]"))+len("[Peer]")]),
		"oversize":              append(bytes.Clone(valid), bytes.Repeat([]byte("x"), maximumOwnedArtifactBytes)...),
		"extra-hook":            bytes.Replace(valid, []byte("; add chain"), []byte("; /bin/false; add chain"), 1),
		"changed-masquerade":    bytes.Replace(valid, []byte(" masquerade;"), []byte(" accept;"), 1),
		"changed-forward":       bytes.Replace(valid, []byte(`iifname "wg-syswarden" accept`), []byte(`iifname "wg-syswarden" drop`), 1),
		"changed-postdown":      mutateLine(5, "PostDown = /bin/sh -c true"),
		"relative-executable":   bytes.Replace(valid, []byte("/usr/sbin/nft"), []byte("nft"), 1),
		"unknown-policy":        bytes.Replace(valid, []byte("syswarden-wg-v1:"), []byte("syswarden-wg-v9:"), 1),
		"invalid-token":         bytes.Replace(valid, []byte(strings.Repeat("b", 64)), []byte(strings.Repeat("z", 64)), 1),
		"invalid-private-key":   mutateLine(3, "PrivateKey = not-a-key"),
		"short-public-key":      mutateLine(8, "PublicKey = "+base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{22}, 31))),
		"invalid-preshared-key": mutateLine(9, "PresharedKey = not-a-key"),
		"tunnel-egress":         bytes.ReplaceAll(valid, []byte(`"eth0.42"`), []byte(`"wg-syswarden"`)),
		"unsafe-egress":         bytes.ReplaceAll(valid, []byte(`"eth0.42"`), []byte(`"eth0;false"`)),
		"empty-egress":          bytes.ReplaceAll(valid, []byte(`"eth0.42"`), []byte(`""`)),
		"ipv6-address":          mutateLine(1, "Address = 2001:db8::1/64"),
		"too-small-subnet":      mutateLine(1, "Address = 192.0.2.1/31"),
		"wrong-server-host":     mutateLine(1, "Address = 192.0.2.2/30"),
		"wrong-peer-host":       mutateLine(10, "AllowedIPs = 192.0.2.3/32"),
		"extra-peer":            append(bytes.Clone(valid), []byte("\n[Peer]\n")...),
		"embedded-nul":          bytes.Replace(valid, []byte("[Peer]"), []byte("[Peer]\x00"), 1),
	}
	shared := policyUpgradeFixture(t, "192.0.2.1/30", "192.0.2.2/32", true)
	cases["shared-token-mismatch"] = bytes.Replace(shared, []byte("syswarden-wg-forward-v1:"+strings.Repeat("b", 64)), []byte("syswarden-wg-forward-v1:"+strings.Repeat("c", 64)), 1)
	cases["shared-version-mismatch"] = bytes.Replace(shared, []byte("syswarden-wg-forward-v1:"), []byte("syswarden-wg-forward-v2:"), 1)
	for name, server := range cases {
		t.Run(name, func(t *testing.T) {
			original := bytes.Clone(server)
			target, err := ScopedServerConfiguration(server)
			if err == nil || target != nil {
				t.Fatal("unsafe configuration produced an upgrade candidate")
			}
			if !bytes.Equal(server, original) {
				t.Fatal("refused upgrade changed input bytes")
			}
		})
	}
}
