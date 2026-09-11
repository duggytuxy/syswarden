package security

import (
	"errors"
	"os/user"
	"strings"
	"testing"
)

func TestAuthenticationLogWriterPreservesConfiguredRsyslogIdentity(t *testing.T) {
	lookup := func(name string) (*user.User, error) {
		if name != "syslog" {
			t.Fatalf("unexpected account lookup %q", name)
		}
		return &user.User{Username: "syslog", Uid: "100", Gid: "101"}, nil
	}
	writer, err := resolveAuthenticationLogWriter([]byte("$FileOwner syslog\n$PrivDropToUser syslog\n$PrivDropToGroup syslog\n"), lookup)
	if err != nil || writer.name != "syslog" || writer.uid != 100 {
		t.Fatalf("unprivileged native auth writer lost write access: %+v %v", writer, err)
	}
	root, err := resolveAuthenticationLogWriter([]byte("# $PrivDropToUser syslog\nmodule(load=\"imuxsock\")\n"), lookup)
	if err != nil || root.name != "root" || root.uid != 0 {
		t.Fatalf("native root writer changed: %+v %v", root, err)
	}
	for _, input := range []string{"$PrivDropToUser alice\n", "$PrivDropToUser syslog\n$PrivDropToUser root\n", "global(privdrop.user.name=\"syslog\")\n"} {
		if _, err := resolveAuthenticationLogWriter([]byte(input), lookup); err == nil {
			t.Fatalf("ambiguous or unsupported declaration accepted: %q", input)
		}
	}
	for _, uid := range []string{"0", "-1", "0100", "4294967295", "4294967296", "invalid"} {
		if _, err := resolveAuthenticationLogWriter([]byte("$PrivDropToUser syslog\n"), func(string) (*user.User, error) {
			return &user.User{Username: "syslog", Uid: uid}, nil
		}); err == nil {
			t.Fatalf("unsafe configured writer UID accepted: %q", uid)
		}
	}
	if _, err := resolveAuthenticationLogWriter([]byte("$PrivDropToUser syslog\n"), func(string) (*user.User, error) {
		return nil, errors.New("account unavailable")
	}); err == nil {
		t.Fatal("failed account resolution silently selected root")
	}
}

func TestAuthenticationLogRotationRetainsWriterAtSecureModes(t *testing.T) {
	for _, mode := range []string{"0640", "0600"} {
		input := []byte("{\n  create " + mode + " root adm\n}\n")
		output, changed, err := hardenLogrotateCreateRules(input, "create 0640 syslog adm")
		if err != nil || !changed || !strings.Contains(string(output), "create "+mode+" syslog adm") {
			t.Fatalf("rotation made the hardened auth log unwritable: %s %t %v", output, changed, err)
		}
		stable, changed, err := hardenLogrotateCreateRules(output, "create 0640 syslog adm")
		if err != nil || changed || string(stable) != string(output) {
			t.Fatalf("secure configured writer was not stable: %s %t %v", stable, changed, err)
		}
	}
}
