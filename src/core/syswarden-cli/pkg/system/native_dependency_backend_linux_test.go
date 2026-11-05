//go:build linux

package system

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestNativeRetentionProviderGeneration(t *testing.T) {
	for _, c := range []struct {
		value string
		want  int
	}{
		{"4.20.0\n", 4}, {"4.21.1.2\nprovider details\n", 4},
		{"dnf5 version 5.4.3.0\nlibdnf5 version 5.4.3.0\n", 5},
		{"", 0}, {"4.20.0", 0}, {"dnf5 version 6.0.0.0\n", 0}, {"dnf5 version 5.4.3.0-foreign\n", 0},
		{"dnf version 4.20.0\n", 0}, {" 4.20.0\n", 0}, {"4.20.0\r\n", 0}, {"4.20.0\n\x00\n", 0},
		{"5.4.3.0\n", 0}, {strings.Repeat("a", 65537) + "\n", 0},
	} {
		got, err := nativeRetentionGeneration([]byte(c.value))
		if got != c.want || (err != nil) != (c.want == 0) {
			t.Fatalf("generation for %q: %d %v", c.value, got, err)
		}
	}
}

func TestNativeRetentionDNF5ReasonVocabulary(t *testing.T) {
	for input, want := range map[string]string{"User": "user", "Group": "group", "External User": "external-user", "Dependency": "dependency", "Weak Dependency": "weak-dependency"} {
		got, err := normalizeDNF5RetentionReasons([]byte("rsyslog\t" + input + "\n"))
		if err != nil || string(got) != "rsyslog\t"+want+"\n" {
			t.Fatalf("reason %q: %q %v", input, got, err)
		}
		reasons, err := retentionReasons("/usr/bin/dnf", []string{"rsyslog"}, got)
		if err != nil || reasons["rsyslog"] != want {
			t.Fatal(reasons, err)
		}
		if retentionProtected(want) != (input == "User" || input == "Group" || input == "External User") {
			t.Fatal("wrong retention classification", input)
		}
	}
	for _, bad := range []string{"", "rsyslog\tuser\n", "rsyslog\tUnknown\n", "rsyslog\tUser", "rsyslog\tUser\r\n", "rsyslog\tUser\n\n", "rsyslog\tUser\textra\n", "rsyslog\tUser\x00\n"} {
		if _, err := normalizeDNF5RetentionReasons([]byte(bad)); err == nil {
			t.Fatalf("invalid reason accepted: %q", bad)
		}
	}
	for _, bad := range []string{"other\tUser\n", "rsyslog\tUser\nrsyslog\tUser\n"} {
		data, err := normalizeDNF5RetentionReasons([]byte(bad))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := retentionReasons("/usr/bin/dnf", []string{"rsyslog"}, data); err == nil {
			t.Fatal("scope bypass", bad)
		}
	}
}

func TestNativeRetentionDNF5CommandBoundary(t *testing.T) {
	for _, op := range []string{"reasons", "retain"} {
		want := []string{"--no-plugins", "--cacheonly", "--disable-repo=*", "-q"}
		if op == "retain" {
			want = append(want, "--assumeyes", "mark", "user", "rsyslog")
		} else {
			want = append(want, "repoquery", "--installed", "--queryformat", "%{name}\t%{reason}\n", "rsyslog")
		}
		path, args, err := nativeRetentionCommandVariant("/usr/bin/dnf", op, []string{"rsyslog"}, 5)
		if err != nil || path != "/usr/bin/dnf" || !reflect.DeepEqual(args, want) {
			t.Fatal(path, args, err)
		}
		for _, names := range [][]string{nil, {"--nogpgcheck"}, {"other"}, {"rsyslog", "rsyslog"}, {"rsyslog=1"}} {
			if _, _, err := nativeRetentionCommandVariant("/usr/bin/dnf", op, names, 5); err == nil {
				t.Fatal("unsafe selection", names)
			}
		}
	}
	for _, g := range []int{0, 3, 6} {
		if _, _, err := nativeRetentionCommandVariant("/usr/bin/dnf", "retain", []string{"rsyslog"}, g); err == nil {
			t.Fatal("unqualified generation", g)
		}
	}
	for _, c := range []struct {
		manager string
		names   []string
	}{{"/tmp/dnf", nil}, {"/usr/bin/apt-get", nil}, {"/usr/bin/dnf", []string{"rsyslog"}}} {
		if _, _, err := nativeRetentionCommandVariant(c.manager, "provider", c.names, 5); err == nil {
			t.Fatal("unsafe provider", c)
		}
	}
}

func TestNativeRetentionProviderBinding(t *testing.T) {
	for _, scenario := range []string{"dnf4", "dnf5", "drift", "probe failure", "unknown", "manager changed", "recursive probe", "apt", "dpkg"} {
		t.Run(scenario, func(t *testing.T) {
			manager := "/usr/bin/dnf"
			version := "4.20.0\n"
			want := 4
			switch scenario {
			case "dnf5":
				version = "dnf5 version 5.4.3.0\n"
				want = 5
			case "unknown":
				version = "6.0.0\n"
			case "apt":
				manager = "/usr/bin/apt-get"
			case "dpkg":
				manager = "/usr/bin/dpkg"
			}
			probes, operations := 0, 0
			execute := func(ctx context.Context, got, op string, names []string, generation int) ([]byte, error) {
				if got != manager {
					t.Fatal("manager escaped binding", got)
				}
				if op == "provider" {
					probes++
					if generation != 4 || len(names) != 0 {
						t.Fatal("unexpected version command scope")
					}
					if scenario == "probe failure" {
						return nil, errors.New("unavailable")
					}
					if scenario == "drift" && probes > 1 {
						return []byte("4.21.0\n"), nil
					}
					return []byte(version), nil
				}
				operations++
				if generation != want || op != "retain" || !reflect.DeepEqual(names, []string{"rsyslog"}) {
					t.Fatal("wrong bound operation", op, generation, names)
				}
				return []byte("ok\n"), nil
			}
			bound, err := bindNativeRetentionRunner(t.Context(), manager, execute)
			if scenario == "probe failure" || scenario == "unknown" {
				if err == nil || operations != 0 {
					t.Fatal("invalid initial observation accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			got, op := manager, "retain"
			if scenario == "manager changed" {
				got = "/usr/bin/yum"
			}
			if scenario == "recursive probe" {
				op = "provider"
			}
			_, err = bound(t.Context(), got, op, []string{"rsyslog"})
			blocked := scenario == "drift" || scenario == "manager changed" || scenario == "recursive probe"
			if (err != nil) != blocked || operations != map[bool]int{true: 0, false: 1}[blocked] {
				t.Fatal("binding decision", operations, err)
			}
			if (scenario == "apt" || scenario == "dpkg") && probes != 0 {
				t.Fatal("DEB probed RPM provider")
			}
		})
	}
	if _, err := bindNativeRetentionRunner(t.Context(), "/usr/bin/dnf", nil); err == nil {
		t.Fatal("missing runner accepted")
	}
}
