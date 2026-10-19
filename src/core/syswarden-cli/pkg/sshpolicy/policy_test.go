package sshpolicy

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func inventory(main string) map[string][]byte { return map[string][]byte{MainPath: []byte(main)} }

const includeDropIns = "Include /etc/ssh/sshd_config.d/*.conf\n"

func TestPrepareProfilesPreservesSource(t *testing.T) {
	for _, profile := range []Profile{Forwarding, CIS} {
		t.Run(fmt.Sprint(profile), func(t *testing.T) {
			main := includeDropIns + "Port 2222\nAuthenticationMethods publickey\nPasswordAuthentication no\nPermitRootLogin no\n"
			files := inventory(main)
			candidate, err := Prepare(profile, files)
			if err != nil {
				t.Fatal(err)
			}
			if string(files[MainPath]) != main || len(files) != 1 {
				t.Fatal("source inventory changed")
			}
			content := string(candidate.Bytes())
			want := "# SysWarden SSH hardening policy v1\n# Managed publication requires a separate ownership receipt.\nAllowTcpForwarding no\n"
			if profile == CIS {
				want += "X11Forwarding no\nMaxAuthTries 4\nClientAliveInterval 300\nClientAliveCountMax 3\n"
			}
			if content != want {
				t.Fatal("fixed policy bytes differ from the independently specified profile")
			}
			if !strings.Contains(content, "AllowTcpForwarding no\n") {
				t.Fatal("missing base policy")
			}
			if strings.Contains(content, "X11Forwarding") != (profile == CIS) {
				t.Fatal("wrong profile")
			}
			for _, forbidden := range []string{"Port ", "PasswordAuthentication ", "AuthenticationMethods ", "PermitRootLogin ", "Match ", "Include "} {
				if strings.Contains(content, forbidden) {
					t.Fatalf("unexpected directive %s", forbidden)
				}
			}
			copyBytes := candidate.Bytes()
			copyBytes[0] = 'X'
			if candidate.Bytes()[0] != '#' {
				t.Fatal("candidate aliases exposed bytes")
			}
			files[MainPath][0] = 'X'
			if string(candidate.Bytes()) != content {
				t.Fatal("candidate aliases caller bytes")
			}
		})
	}
}

func TestPrepareIncludeLayouts(t *testing.T) {
	cases := []struct {
		name, main string
		extra      map[string][]byte
		wantErr    bool
	}{
		{"absolute-glob", includeDropIns, nil, false},
		{"relative-glob", "Include sshd_config.d/*.conf\n", nil, false},
		{"quoted-glob", "  iNcLuDe = \"/etc/ssh/sshd_config.d/*.conf\" # policy\r\n", nil, false},
		{"literal", "Include " + DropInPath, nil, false},
		{"multiple-patterns", "Include /etc/ssh/absent/*.conf /etc/ssh/sshd_config.d/*.conf", nil, false},
		{"question-pattern", "Include /etc/ssh/sshd_config.d/??-*.conf", nil, false},
		{"bracket-pattern", "Include /etc/ssh/sshd_config.d/[0-9][0-9]-*.conf", nil, true},
		{"negated-bracket", "Include /etc/ssh/sshd_config.d/[!a]*.conf", nil, true},
		{"nested", "Include /etc/ssh/nested.conf", map[string][]byte{"/etc/ssh/nested.conf": []byte(includeDropIns)}, false},
		{"vendor-include", "Include /etc/crypto-policies/back-ends/opensshserver.config\n" + includeDropIns, map[string][]byte{"/etc/crypto-policies/back-ends/opensshserver.config": []byte("Ciphers aes256-ctr\n")}, false},
		{"after-match-unrelated", includeDropIns + "Match User administrator\n PasswordAuthentication no", nil, false},
		{"matching-policy-before", "AllowTcpForwarding no\n" + includeDropIns, nil, false},
		{"matching-conditional-policy", includeDropIns + "Match User administrator\nAllowTcpForwarding no", nil, false},
		{"missing-include", "Port 2222", nil, true},
		{"comment-only", "# " + includeDropIns, nil, true},
		{"missing-pattern", "Include", nil, true},
		{"conditional", "Match User administrator\n" + includeDropIns, nil, true},
		{"match-all", "Match all\n" + includeDropIns, nil, true},
		{"conditional-exact", "Match Address 192.0.2.0/24\nInclude " + DropInPath, nil, true},
		{"repeated", includeDropIns + includeDropIns, nil, true},
		{"overlapping-patterns", "Include /etc/ssh/sshd_config.d/*.conf " + DropInPath, nil, true},
		{"self-cycle", "Include " + MainPath, nil, true},
		{"cycle", "Include /etc/ssh/nested.conf", map[string][]byte{"/etc/ssh/nested.conf": []byte("Include " + MainPath)}, true},
		{"quote-not-closed", "Include \"/etc/ssh/sshd_config.d/*.conf", nil, true},
		{"quote-suffix", "Include \"/etc/ssh/sshd_config.d/*.conf\"extra", nil, true},
		{"escaped", "Include /etc/ssh/sshd_config.d/\\*.conf", nil, true},
		{"traversal", "Include /etc/ssh/../ssh/sshd_config.d/*.conf", nil, true},
		{"relative-traversal", "Include ../ssh/sshd_config.d/*.conf", nil, true},
		{"malformed-glob", "Include /etc/ssh/[bad", nil, true},
		{"space-in-pattern", "Include \"/etc/ssh/a b/*.conf\"", nil, true},
		{"nul", includeDropIns + "#\x00", nil, true},
		{"legacy-override", "# SYSWARDEN OVERRIDE: AllowTcpForwarding yes\n" + includeDropIns, nil, true},
		{"legacy-cis", "# --- SYSWARDEN CIS SSH HARDENING ---\n" + includeDropIns, nil, true},
		{"earlier-conflicting", "AllowTcpForwarding yes\n" + includeDropIns, nil, true},
		{"later-conflicting", includeDropIns + "AllowTcpForwarding yes", nil, true},
		{"conditional-conflicting", includeDropIns + "Match Group developers\n AllowTcpForwarding local", nil, true},
		{"lexical-earlier-match", includeDropIns, map[string][]byte{"/etc/ssh/sshd_config.d/00-admin.conf": []byte("Match User administrator\n")}, true},
		{"lexical-later-conflict", includeDropIns, map[string][]byte{"/etc/ssh/sshd_config.d/99-admin.conf": []byte("AllowTcpForwarding yes\n")}, true},
		{"match-in-include", "Include /etc/ssh/nested.conf\n" + includeDropIns, map[string][]byte{"/etc/ssh/nested.conf": []byte("Match User administrator\n")}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			files := inventory(tc.main)
			for name, value := range tc.extra {
				files[name] = value
			}
			candidate, err := Prepare(Forwarding, files)
			if (err != nil) != tc.wantErr {
				t.Fatalf("Prepare error=%v, expected rejection=%v", err, tc.wantErr)
			}
			if err != nil && !reflect.DeepEqual(candidate, Candidate{}) {
				t.Fatal("rejected plan returned partial candidate")
			}
		})
	}
}

func TestPrepareAllControlledDirectives(t *testing.T) {
	policy, _ := directives(CIS)
	for _, item := range policy {
		for _, scope := range []string{"", "Match User administrator\n"} {
			for _, syntax := range []string{item.key + " yes", strings.ToUpper(item.key) + "=yes", item.key + " = \"yes\""} {
				t.Run(item.key+scope+syntax, func(t *testing.T) {
					if _, err := Prepare(CIS, inventory(includeDropIns+scope+syntax)); err == nil {
						t.Fatal("accepted conflicting policy")
					}
				})
			}
			for _, syntax := range []string{item.key + " " + item.value, strings.ToUpper(item.key) + "=\"" + item.value + "\" # comment"} {
				if _, err := Prepare(CIS, inventory(includeDropIns+scope+syntax)); err != nil {
					t.Fatalf("same policy rejected: %v", err)
				}
			}
		}
	}
}

func TestPrepareBoundsAndExistingFile(t *testing.T) {
	cases := map[string]map[string][]byte{
		"empty": {}, "missing-main": {"/etc/ssh/example.conf": nil},
		"existing-reserved": {MainPath: []byte(includeDropIns), DropInPath: nil},
		"relative-path":     {MainPath: []byte(includeDropIns), "example.conf": nil},
		"traversal-path":    {MainPath: []byte(includeDropIns), "/etc/ssh/../example.conf": nil},
		"newline-path":      {MainPath: []byte(includeDropIns), "/etc/ssh/example\n.conf": nil},
		"glob-path":         {MainPath: []byte(includeDropIns), "/etc/ssh/*.conf": nil},
		"control-path":      {MainPath: []byte(includeDropIns), "/etc/ssh/a\x1b.conf": nil},
		"non-ascii-path":    {MainPath: []byte(includeDropIns), "/etc/ssh/\u00e9.conf": nil},
		"oversize":          inventory(strings.Repeat("#", MaxBytes+1)),
		"line":              inventory(includeDropIns + strings.Repeat("#", MaxLineBytes+1)),
		"patterns":          inventory(includeDropIns + strings.Repeat("Include /etc/ssh/absent*.conf\n", MaxExpansions)),
	}
	many := inventory(includeDropIns)
	for i := 0; i < MaxFiles; i++ {
		many[fmt.Sprintf("/etc/ssh/extra-%d", i)] = nil
	}
	cases["count"] = many
	deep := inventory("Include /etc/ssh/depth-0\n")
	for i := 0; i <= MaxIncludeDepth; i++ {
		deep[fmt.Sprintf("/etc/ssh/depth-%d", i)] = fmt.Appendf(nil, "Include /etc/ssh/depth-%d\n", i+1)
	}
	cases["depth"] = deep
	amplify := inventory(includeDropIns + strings.Repeat("Include /etc/ssh/large.conf\n", 12))
	amplify["/etc/ssh/large.conf"] = bytes.Repeat([]byte("# bounded comment\n"), MaxBytes/40)
	cases["amplification"] = amplify
	for name, files := range cases {
		t.Run(name, func(t *testing.T) {
			if result, err := Prepare(CIS, files); err == nil || result != (Candidate{}) {
				t.Fatal("accepted unsafe inventory or returned partial candidate")
			}
		})
	}
	if _, err := Prepare(Profile(0), inventory(includeDropIns)); err == nil {
		t.Fatal("accepted zero profile")
	}
	if _, err := Prepare(Profile(255), inventory(includeDropIns)); err == nil {
		t.Fatal("accepted unknown profile")
	}
}

func TestSourceDigestIsDeterministicAndComplete(t *testing.T) {
	a := inventory(includeDropIns)
	a["/etc/ssh/unused.conf"] = []byte("# unchanged")
	b := map[string][]byte{"/etc/ssh/unused.conf": []byte("# unchanged"), MainPath: []byte(includeDropIns)}
	first, err := Prepare(CIS, a)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Prepare(CIS, b)
	if err != nil || first.SourceDigest() != second.SourceDigest() {
		t.Fatal("nondeterministic digest")
	}
	if first.SourceDigest() == ([sha256.Size]byte{}) {
		t.Fatal("empty digest")
	}
	// Independently reproduced using Python hashlib and struct.pack('>Q', n).
	if fmt.Sprintf("%x", first.SourceDigest()) != "9db390b3c23bb7ba12eca3e9f6fa29a4a077b7e63bdacf2ee970ed5de3555ae1" {
		t.Fatal("inventory framing changed")
	}
	b["/etc/ssh/unused.conf"] = []byte("# changed")
	third, err := Prepare(CIS, b)
	if err != nil || first.SourceDigest() == third.SourceDigest() {
		t.Fatal("unmatched file bytes omitted from digest")
	}
	delete(b, "/etc/ssh/unused.conf")
	fourth, err := Prepare(CIS, b)
	if err != nil || first.SourceDigest() == fourth.SourceDigest() {
		t.Fatal("inventory membership omitted from digest")
	}
}

func TestCheckEffective(t *testing.T) {
	for _, profile := range []Profile{Forwarding, CIS} {
		candidate, err := Prepare(profile, inventory(includeDropIns))
		if err != nil {
			t.Fatal(err)
		}
		policy, _ := directives(profile)
		output := "port 2222\npasswordauthentication no\n"
		for _, item := range policy {
			output += strings.ToLower(item.key) + " " + item.value + "\n"
		}
		if err := candidate.CheckEffective([]byte(output)); err != nil {
			t.Fatal(err)
		}
		for _, bad := range []string{"", "port 2222\n", output + "allowtcpforwarding no\n", output + "allowtcpforwarding yes\n", strings.ReplaceAll(output, "allowtcpforwarding no", "allowtcpforwarding no extra"), output + "\x00", output + strings.Repeat("x", MaxLineBytes+1), strings.Repeat("x", MaxBytes+1)} {
			if err := candidate.CheckEffective([]byte(bad)); err == nil {
				t.Fatal("accepted malformed or incomplete effective output")
			}
		}
		for _, item := range policy {
			bad := strings.Replace(output, strings.ToLower(item.key)+" "+item.value, strings.ToLower(item.key)+" unexpected", 1)
			if err := candidate.CheckEffective([]byte(bad)); err == nil {
				t.Fatal("accepted conflicting effective value")
			}
		}
	}
	if err := (Candidate{}).CheckEffective([]byte("allowtcpforwarding no\n")); err == nil {
		t.Fatal("zero candidate accepted")
	}
}

func FuzzPrepare(f *testing.F) {
	for _, seed := range []string{includeDropIns, "Match all\n" + includeDropIns, "Include \"unterminated", includeDropIns + "AllowTcpForwarding yes"} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > MaxBytes+1 {
			t.Skip()
		}
		candidate, err := Prepare(CIS, map[string][]byte{MainPath: input})
		if err != nil {
			if candidate != (Candidate{}) {
				t.Fatal("partial candidate on failure")
			}
			return
		}
		if candidate.SourceDigest() == ([sha256.Size]byte{}) || !strings.Contains(string(candidate.Bytes()), "AllowTcpForwarding no\n") {
			t.Fatal("invalid successful candidate")
		}
		again, err := Prepare(CIS, map[string][]byte{MainPath: input})
		if err != nil || candidate != again {
			t.Fatal("nondeterministic candidate")
		}
	})
}

func FuzzCheckEffective(f *testing.F) {
	for _, seed := range []string{"allowtcpforwarding no\n", "allowtcpforwarding yes\n", "allowtcpforwarding no\nallowtcpforwarding no\n", "\x00"} {
		f.Add([]byte(seed))
	}
	candidate, err := Prepare(Forwarding, inventory(includeDropIns))
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > MaxBytes+1 {
			t.Skip()
		}
		before := bytes.Clone(input)
		_ = candidate.CheckEffective(input)
		if !bytes.Equal(before, input) {
			t.Fatal("validator modified evidence")
		}
	})
}
