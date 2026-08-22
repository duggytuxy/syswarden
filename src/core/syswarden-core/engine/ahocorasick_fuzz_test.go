package engine

import (
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

const maxEngineInputFuzzBytes = 32 * 1024

func FuzzEngineNetworkAndURLInput(f *testing.F) {
	seeds := []string{
		"",
		"192.0.2.55 - - [date] GET /",
		`{"remote_ip":"198.51.100.8","status":403}`,
		`{"client_ip":"2001:db8::8","status":403}`,
		`{"remote_ip":"198.51.100.8","client_ip":"192.0.2.55"}`,
		`prefix {"client_ip":"198.51.100.8"}`,
		"Failed password for root from 192.0.2.44 port 22",
		`198.51.100.7 Failed password for invalid user {"client_ip":"192.0.2.99"} from 203.0.113.5 port 22`,
		"Failed password for root from 999.0.2.44 port 22",
		"GET /..%2Fetc%2Fpasswd HTTP/1.1",
		"GET /..%ZZetc%2Fpasswd HTTP/1.1",
		"scanner user-agent sqlmap",
		"\x00\xff%00%ff",
	}
	for _, seed := range seeds {
		f.Add(seed)
	}
	engine := newFuzzEngine(f)

	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > maxEngineInputFuzzBytes {
			t.Skip()
		}

		firstIP := ExtractIP(input)
		secondIP := ExtractIP(input)
		if firstIP != secondIP {
			t.Fatalf("ExtractIP(%q) is not deterministic: %q, then %q", input, firstIP, secondIP)
		}
		if firstIP != "" {
			addr, err := netip.ParseAddr(firstIP)
			if err != nil {
				t.Fatalf("ExtractIP(%q) returned an invalid address %q", input, firstIP)
			}
			if addr != addr.Unmap() {
				t.Fatalf("ExtractIP(%q) returned a non-canonical mapped address %q", input, firstIP)
			}
			if addr.IsUnspecified() || addr.IsLoopback() {
				t.Fatalf("ExtractIP(%q) returned an excluded local address %q", input, firstIP)
			}
		}

		firstMatch := engine.Scan(input)
		secondMatch := engine.Scan(input)
		if !reflect.DeepEqual(firstMatch, secondMatch) {
			t.Fatalf("Engine.Scan(%q) is not deterministic: first %#v, second %#v", input, firstMatch, secondMatch)
		}
		if firstMatch != nil && firstMatch.Payload != input {
			t.Fatalf("Engine.Scan(%q) changed the recorded payload to %q", input, firstMatch.Payload)
		}
		if firstMatch != nil && firstMatch.Host.IsValid() {
			if firstMatch.Host != firstMatch.Host.Unmap() {
				t.Fatalf("Engine.Scan(%q) returned a non-canonical mapped host %v", input, firstMatch.Host)
			}
			if firstMatch.Host.IsUnspecified() || firstMatch.Host.IsLoopback() {
				t.Fatalf("Engine.Scan(%q) returned an excluded host %v", input, firstMatch.Host)
			}
		}
	})
}

func newFuzzEngine(f *testing.F) *Engine {
	f.Helper()
	configPath := filepath.Join(f.TempDir(), "signatures.json")
	config := `{
  "rules": [
    {
      "id": "ssh-auth",
      "type": "regex",
      "pattern": "^(?:[0-9A-Fa-f:.]+ )?Failed password .* from <HOST>(?: port [0-9]+)?$",
      "service": "sshd",
      "action": "track",
      "threshold": 3,
      "window": 60,
      "trusted_host_capture": true
    },
    {
      "id": "encoded-probe",
      "type": "aho-corasick",
      "patterns": ["../etc/passwd", "sqlmap"],
      "service": "http",
      "action": "ban"
    }
  ]
}`
	if err := os.WriteFile(configPath, []byte(config), 0600); err != nil {
		f.Fatalf("write fuzz signature fixture: %v", err)
	}
	engine, err := NewEngine(configPath, 5, 60)
	if err != nil {
		f.Fatalf("create fuzz engine: %v", err)
	}
	return engine
}
