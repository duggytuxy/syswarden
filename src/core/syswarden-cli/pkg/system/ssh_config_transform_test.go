package system

import (
	"strings"
	"testing"
)

func TestNormalizeSSHForwardingIsStrictAndIdempotent(t *testing.T) {
	input := "#AllowTcpForwarding yes\nAllowTcpForwarding yes\nAllowTcpForwarding=yes\nallowtcpforwarding = local\nInclude /etc/ssh/sshd_config.d/*.conf\nMatch User backup\nallowtcpforwarding local\nPasswordAuthentication yes\n"
	wantFragments := []string{
		"# SYSWARDEN OVERRIDE: AllowTcpForwarding yes",
		"# SYSWARDEN OVERRIDE: AllowTcpForwarding=yes",
		"# SYSWARDEN OVERRIDE: allowtcpforwarding = local",
		"# SYSWARDEN OVERRIDE: allowtcpforwarding local",
		"PasswordAuthentication yes",
		"AllowTcpForwarding no",
	}
	got := normalizeSSHForwarding(input)
	for _, fragment := range wantFragments {
		if !strings.Contains(got, fragment) {
			t.Fatalf("normalized config lacks %q:\n%s", fragment, got)
		}
	}
	if strings.Count(got, "AllowTcpForwarding no") != 1 {
		t.Fatalf("normalized config must contain one active directive:\n%s", got)
	}
	if strings.Index(got, "AllowTcpForwarding no") > strings.Index(got, "Include ") ||
		strings.Index(got, "AllowTcpForwarding no") > strings.Index(got, "Match User") {
		t.Fatalf("global forwarding directive must precede Include and Match blocks:\n%s", got)
	}
	if again := normalizeSSHForwarding(got); again != got {
		t.Fatalf("normalization is not idempotent:\nfirst:\n%s\nsecond:\n%s", got, again)
	}
}

func TestParseSSHDirectiveAcceptsOpenSSHEqualsForms(t *testing.T) {
	for _, test := range []struct {
		line    string
		keyword string
		value   string
	}{
		{line: "AllowTcpForwarding=yes", keyword: "AllowTcpForwarding", value: "yes"},
		{line: "AllowTcpForwarding = yes", keyword: "AllowTcpForwarding", value: "yes"},
		{line: "AllowTcpForwarding= yes", keyword: "AllowTcpForwarding", value: "yes"},
		{line: "Match User backup", keyword: "Match", value: "User backup"},
	} {
		keyword, value, active := parseSSHDirective(test.line)
		if !active || keyword != test.keyword || value != test.value {
			t.Fatalf("parse %q = (%q, %q, %t)", test.line, keyword, value, active)
		}
	}
}

func TestNormalizeSSHDirectivesRejectsUnapprovedInput(t *testing.T) {
	for _, directives := range []map[string]string{
		{"PermitRootLogin": "yes"},
		{"AllowTcpForwarding": "yes"},
		{"X11Forwarding": "no\nPermitRootLogin yes"},
	} {
		if _, err := normalizeSSHDirectives("", directives); err == nil {
			t.Fatalf("unapproved SSH directives accepted: %#v", directives)
		}
	}
}
