package sshpolicy

import (
	"bytes"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestPrepareEnvironmentBoundaries(t *testing.T) {
	// Observation hints are not authority to grant forwarding or adopt files.
	t.Setenv("SSH_CONNECTION", "192.0.2.10 40000 192.0.2.20 2222")
	t.Setenv("ANSIBLE_SSH_COMMON_ARGS", "-o ProxyJump=jump.example")
	const automation = "# Ansible managed\n" +
		"Subsystem sftp internal-sftp\nMaxSessions 12\nPermitTTY yes\n" +
		"AuthenticationMethods publickey,keyboard-interactive\nUsePAM yes\n" +
		"TrustedUserCAKeys /etc/ssh/admin-ca.pub\n" +
		"AuthorizedPrincipalsFile /etc/ssh/principals/%u\n" +
		"AllowUsers automation administrator\nAllowAgentForwarding no\n"
	cases := []struct {
		name, external string
		wantErr        bool
	}{
		{"automation-target", automation, false},
		{"management-comment-is-not-authority", "# Ansible managed bastion\nAllowTcpForwarding local\n", true},
		{"bastion-global", "AllowTcpForwarding local\nPermitOpen 192.0.2.30:22\n", true},
		{"bastion-user", "Match User jump\nAllowTcpForwarding local\nPermitOpen 192.0.2.30:22\n", true},
		{"bastion-group", "Match Group jump-users\nAllowTcpForwarding local\nPermitOpen 192.0.2.30:22\n", true},
		{"bastion-default-explicit", "AllowTcpForwarding yes\n", true},
		{"remote-forwarding-owner", "Match User automation\nAllowTcpForwarding remote\n", true},
		{"disabled-but-owned-forwarding", "DisableForwarding yes\nAllowTcpForwarding local\n", true},
	}
	for _, profile := range []Profile{Forwarding, CIS} {
		for _, tc := range cases {
			t.Run(fmt.Sprintf("%d/%s", profile, tc.name), func(t *testing.T) {
				const externalPath = "/etc/ssh/sshd_config.d/50-automation.conf"
				files := inventory(includeDropIns)
				files[externalPath] = []byte(tc.external)
				before := make(map[string][]byte, len(files))
				for path, data := range files {
					before[path] = bytes.Clone(data)
				}
				candidate, err := Prepare(profile, files)
				if (err != nil) != tc.wantErr {
					t.Fatalf("preparation error = %v; want rejection = %v", err, tc.wantErr)
				}
				if !reflect.DeepEqual(files, before) {
					t.Fatal("administrator or automation input changed")
				}
				if tc.wantErr {
					if candidate != (Candidate{}) {
						t.Fatal("conflicting role returned a partial policy")
					}
					return
				}
				for _, line := range strings.Split(automation, "\n") {
					if line != "" && strings.Contains(string(candidate.Bytes()), line) {
						t.Fatalf("candidate adopted administrator directive %q", line)
					}
				}
				if !strings.Contains(string(candidate.Bytes()), "AllowTcpForwarding no\n") {
					t.Fatal("environment hint granted a forwarding exception")
				}
			})
		}
	}
	for _, external := range []string{
		"MaxAuthTries 2\n", "ClientAliveInterval 60\n", "ClientAliveCountMax 1\n",
	} {
		t.Run("external-stricter-"+strings.Fields(external)[0], func(t *testing.T) {
			files := inventory(includeDropIns + "# Ansible managed\n" + external)
			before := bytes.Clone(files[MainPath])
			if candidate, err := Prepare(CIS, files); err == nil || candidate != (Candidate{}) {
				t.Fatal("silently replaced an external policy with a weaker fixed profile")
			}
			if !bytes.Equal(before, files[MainPath]) {
				t.Fatal("external policy bytes changed")
			}
		})
	}
}
