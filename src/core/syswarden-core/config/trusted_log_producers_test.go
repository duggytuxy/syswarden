package config

import (
	"reflect"
	"strings"
	"testing"
)

func TestTrustedLogProducerPolicyIsExplicitAndBounded(t *testing.T) {
	valid := "/var/log/waf/access.log=999 /srv/audit/modsec.log=100999"
	got, err := ParseTrustedLogProducers(valid)
	if err != nil || !reflect.DeepEqual(got, map[string]uint32{"/var/log/waf/access.log": 999, "/srv/audit/modsec.log": 100999}) {
		t.Fatalf("policy=%v err=%v", got, err)
	}
	for _, raw := range []string{" ", " /a=1", "/a=1 ", "/a=1  /b=2", "/a=1\t/b=2", "relative=1", "/=1", "/a/../b=1", "/a*=1", "/a?=1", "/a[0]=1", "/a\\b=1", "/a=0", "/a=65534", "/a=4294967295", "/a=4294967296", "/a=-1", "/a=+1", "/a=01", "/a=1=2", "/a=1 /a=2", "/a=1\n", "/a\xff=1", strings.Repeat("x", 16385), "/" + strings.Repeat("x", 4096) + "=1"} {
		if result, err := ParseTrustedLogProducers(raw); err == nil || result != nil {
			t.Errorf("accepted malformed policy %q", raw)
		}
	}
	var excessive []string
	for i := 0; i < 33; i++ {
		excessive = append(excessive, "/"+strings.Repeat("a", i+1)+"=1")
	}
	if _, err := ParseTrustedLogProducers(strings.Join(excessive, " ")); err == nil {
		t.Fatal("accepted more than 32 grants")
	}
	if empty, err := ParseTrustedLogProducers(""); err != nil || len(empty) != 0 {
		t.Fatalf("default not empty: %v %v", empty, err)
	}
}

func TestDirectBridgeLogPatternsRetainDefaultsWithoutDuplicateGrants(t *testing.T) {
	if got := DirectBridgeLogPatterns(nil); len(got) != 0 {
		t.Fatal(got)
	}
	policy := map[string]uint32{"/var/log/auth.log": 123, "/srv/log/access.log": 456}
	paths := DirectBridgeLogPatterns(policy)
	seen := map[string]bool{}
	for _, path := range paths {
		if seen[path] {
			t.Fatal("duplicate", path)
		}
		seen[path] = true
	}
	for _, path := range []string{"/var/log/nginx/*.log", "/var/log/apache2/*.log", "/var/log/httpd/*.log", "/var/log/auth.log", "/var/log/secure", "/var/log/syslog", "/var/log/messages", "/srv/log/access.log"} {
		if !seen[path] {
			t.Fatal("missing", path)
		}
	}
	paths[0] = "modified"
	if DirectBridgeLogPatterns(policy)[0] == "modified" {
		t.Fatal("mutable shared defaults")
	}
}

func FuzzTrustedLogProducers(f *testing.F) {
	for _, seed := range []string{"", "/var/log/access.log=999", "/a=65534", "/a=1 /b=2"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		got, err := ParseTrustedLogProducers(raw)
		if err != nil {
			return
		}
		if len(got) > 32 {
			t.Fatal("unbounded policy")
		}
		for path, uid := range got {
			if path == "" || uid == 0 || uid == 65534 || uid == 4294967295 {
				t.Fatal("invalid accepted grant")
			}
		}
	})
}
