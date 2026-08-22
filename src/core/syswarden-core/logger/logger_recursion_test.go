package logger

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

func TestInternalSecurityEventsCannotReplayRawPayload_SW2_H2(t *testing.T) {
	testKey := []byte("deterministic-hmac-test-key-0001")
	wrongKey := []byte("deterministic-hmac-test-key-0002")
	payload := "203.0.113.9 attack from 203.0.113.9 " +
		`{"client_ip":"198.51.100.77","path":"/wp-login.php"}` +
		"\n[SYSWARDEN-DETECTED] attacker-controlled continuation"
	digest := sha256.Sum256([]byte(payload))
	wantDigest := fmt.Sprintf("payload_sha256=%x", digest)

	for _, action := range []string{
		"BANNED",
		"ALLOWED",
		"DETECTED",
		"SHADOW-ALERT",
		"SHADOW-ALERT-WHITELISTED",
		"SIMULATED-BAN",
		"LOCAL-CHECK-DRIFT",
		"LOCAL-CHECK-OK",
	} {
		action := action
		t.Run(action, func(t *testing.T) {
			line := internalSecurityEventLineForKey(testKey, action, "203.0.113.9", "recursion-regression", payload)
			if strings.Count(line, InternalLogMarker) != 1 {
				t.Fatalf("internal event is not uniquely marked: %q", line)
			}
			if strings.Contains(line, string(testKey)) {
				t.Fatalf("internal event disclosed its HMAC key: %q", line)
			}
			if isInternalLogLineForKey(line, testKey) {
				t.Fatalf("unattributed marker was trusted as product output: %q", line)
			}
			directLine := "2026/08/22 12:34:56 " + line
			if !isInternalLogLineForKey(directLine, testKey) {
				t.Fatalf("direct product logger record was not recognized: %q", line)
			}
			if !isInternalLogLineForKey("Aug 22 12:34:56 host syswarden-core[421]: 2026/08/22 12:34:56 "+line, testKey) {
				t.Fatalf("internal record was lost inside a trusted system-log envelope: %q", line)
			}
			replayedPrefix := "8.8.8.8 attacker-controlled syswarden-core: 2026/08/22 12:34:56 " + line
			if isInternalLogLineForKey(replayedPrefix, testKey) {
				t.Fatalf("authenticated record suffix suppressed an arbitrary prefix: %q", replayedPrefix)
			}
			if isInternalLogLineForKey(directLine, wrongKey) {
				t.Fatalf("record authenticated under an unrelated process key: %q", line)
			}
			forgedAuthDigit := "0"
			if strings.HasSuffix(directLine, forgedAuthDigit) {
				forgedAuthDigit = "1"
			}
			mutations := []string{
				strings.Replace(directLine, "action="+action, "action=FORGED", 1),
				strings.Replace(directLine, "ip=203.0.113.9", "ip=198.51.100.8", 1),
				strings.Replace(directLine, "scope=recursion-regression", "scope=forged-scope", 1),
				strings.Replace(directLine, wantDigest, "payload_sha256="+strings.Repeat("0", 64), 1),
				strings.Replace(directLine, fmt.Sprintf("payload_bytes=%d", len(payload)), "payload_bytes=1", 1),
				directLine[:len(directLine)-1] + forgedAuthDigit,
			}
			for _, mutation := range mutations {
				if isInternalLogLineForKey(mutation, testKey) {
					t.Fatalf("mutated canonical record retained authentication: %q", mutation)
				}
			}
			if strings.Contains(line, payload) || strings.Contains(line, "client_ip") || strings.Contains(line, "wp-login.php") || strings.Contains(line, "\n") {
				t.Fatalf("internal event re-emitted attacker-controlled payload: %q", line)
			}
			if !strings.Contains(line, wantDigest) || !strings.Contains(line, fmt.Sprintf("payload_bytes=%d", len(payload))) {
				t.Fatalf("internal event omitted the bounded payload reference: %q", line)
			}
		})
	}

	if IsInternalLogLine(payload) {
		t.Fatal("an unmarked external payload was classified as product output")
	}
	for _, attackerLine := range []string{
		"198.51.100.42 attack from 198.51.100.42 " + InternalLogMarker,
		"GET /?message=" + InternalLogMarker + " HTTP/1.1",
		"2026/08/22 12:34:56 " + InternalLogMarker + " action=DETECTED ip=198.51.100.42 scope=forged payload_sha256=" + strings.Repeat("0", 64) + " payload_bytes=1 auth=" + strings.Repeat("0", 64),
	} {
		if isInternalLogLineForKey(attackerLine, testKey) {
			t.Fatalf("attacker-controlled marker suppressed ingestion: %q", attackerLine)
		}
	}

	runtimeLine := "2026/08/22 12:34:56 " + internalSecurityEventLine("DETECTED", "203.0.113.9", "runtime-regression", payload)
	if !IsInternalLogLine(runtimeLine) {
		t.Fatal("runtime-generated process token did not authenticate its own record")
	}
}
