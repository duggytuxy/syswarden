//go:build linux

package sshpolicy

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// This opt-in oracle runs only the local daemon's parser, never a listener,
// service manager or production path. Missing tools fail when requested.
func TestOpenSSHOracle(t *testing.T) {
	if os.Getenv("SYSWARDEN_SSH_ORACLE_TEST") != "1" {
		t.Skip("set SYSWARDEN_SSH_ORACLE_TEST=1 for the installed OpenSSH parser oracle")
	}
	_, err := exec.LookPath("sshd")
	if err != nil {
		t.Fatal(err)
	}
	_, err = exec.LookPath("ssh-keygen")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	run := func(t *testing.T, operation string) []byte {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		var process *exec.Cmd
		switch operation {
		case "syntax":
			process = exec.CommandContext(ctx, "sshd", "-t", "-f", "sshd_config")
		case "global":
			process = exec.CommandContext(ctx, "sshd", "-T", "-f", "sshd_config")
		case "connection":
			process = exec.CommandContext(ctx, "sshd", "-T", "-f", "sshd_config", "-C", "user=administrator,host=fixture.example,addr=192.0.2.10,laddr=192.0.2.20,lport=2222")
		case "other-user":
			process = exec.CommandContext(ctx, "sshd", "-T", "-f", "sshd_config", "-C", "user=unrelated,host=fixture.example,addr=192.0.2.10,laddr=192.0.2.20,lport=2222")
		case "keygen":
			process = exec.CommandContext(ctx, "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", "fixture-host-key")
		default:
			t.Fatal("unsupported oracle executable")
		}
		process.Dir = dir
		output, err := process.CombinedOutput()
		if err != nil {
			t.Fatalf("OpenSSH parser command failed: %v: %s", err, output)
		}
		return output
	}
	key := filepath.Join(dir, "fixture-host-key")
	run(t, "keygen")
	write := func(path, content string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	t.Run("vendor-crypto-policy", func(t *testing.T) {
		const policy = "Ciphers aes256-ctr\nMACs hmac-sha2-256\n"
		fixture := vendorInventoryFixture(t, policy)
		candidate, err := fixture.open().Prepare(CIS)
		if err != nil {
			t.Fatal(err)
		}
		// Translate the fixture to ordinary temporary absolute paths for the
		// real parser. No production path, crypto-policy tool or listener runs.
		target := filepath.Join(dir, "vendor-policy.txt")
		alias := filepath.Join(dir, "vendor-policy.config")
		dropIn := filepath.Join(dir, "vendor-test-hardening.conf")
		write(target, policy)
		if err := os.Symlink(target, alias); err != nil {
			t.Fatal(err)
		}
		write(dropIn, string(candidate.Bytes()))
		write(filepath.Join(dir, "sshd_config"), "Include "+dropIn+"\nInclude "+alias+"\nHostKey "+key+"\nUsePAM no\nPasswordAuthentication no\n")
		run(t, "syntax")
		output := run(t, "global")
		if err := candidate.CheckEffective(output); err != nil {
			t.Fatal(err)
		}
		for _, kept := range []string{"ciphers aes256-ctr\n", "macs hmac-sha2-256\n", "passwordauthentication no\n"} {
			if !strings.Contains(string(output), kept) {
				t.Fatalf("vendor or administrator policy changed: %s", kept)
			}
		}
		root, err := os.OpenRoot(dir)
		if err != nil {
			t.Fatal(err)
		}
		defer root.Close()
		if content, err := root.ReadFile("vendor-policy.txt"); err != nil || string(content) != policy {
			t.Fatal("parser fixture policy was modified")
		}
	})
	for _, profile := range []Profile{Forwarding, CIS} {
		t.Run(map[Profile]string{Forwarding: "forwarding", CIS: "cis"}[profile], func(t *testing.T) {
			fixture := filepath.Join(dir, "sshd_config")
			include := filepath.Join(dir, "00-syswarden-hardening.conf")
			main := "Include " + include + "\nPort 2222\nHostKey " + key + "\nPasswordAuthentication no\nAuthenticationMethods publickey\nPermitRootLogin no\nUsePAM no\nSubsystem sftp internal-sftp\nMaxSessions 12\nPermitTTY yes\n"
			candidate, err := Prepare(profile, inventory(includeDropIns))
			if err != nil {
				t.Fatal(err)
			}
			write(include, string(candidate.Bytes()))
			write(fixture, main)
			run(t, "syntax")
			for _, operation := range []string{"global", "connection"} {
				output := run(t, operation)
				if err := candidate.CheckEffective(output); err != nil {
					t.Fatal(err)
				}
				for _, kept := range []string{"port 2222\n", "passwordauthentication no\n", "authenticationmethods publickey\n", "permitrootlogin no\n", "subsystem sftp internal-sftp\n", "maxsessions 12\n", "permittty yes\n"} {
					if !strings.Contains(string(output), kept) {
						t.Fatalf("administrator setting changed: %s", kept)
					}
				}
			}
			write(fixture, "AllowTcpForwarding yes\n"+main)
			if err := candidate.CheckEffective(run(t, "global")); err == nil {
				t.Fatal("earlier main directive did not defeat candidate as expected")
			}
			write(fixture, main+"Match User administrator\n AllowTcpForwarding yes\n")
			if err := candidate.CheckEffective(run(t, "global")); err != nil {
				t.Fatalf("global view unexpectedly rejected: %v", err)
			}
			if err := candidate.CheckEffective(run(t, "connection")); err == nil {
				t.Fatal("Match override was missed")
			}
			const jumpPolicy = "Match User administrator\n AllowTcpForwarding local\n PermitOpen 192.0.2.30:22\n AllowAgentForwarding no\n"
			files := inventory(includeDropIns + jumpPolicy)
			if rejected, err := Prepare(profile, files); err == nil || rejected != (Candidate{}) {
				t.Fatal("target profile accepted an administrator-owned bastion policy")
			}
			if string(files[MainPath]) != includeDropIns+jumpPolicy {
				t.Fatal("bastion policy was modified on refusal")
			}
			write(fixture, main+jumpPolicy)
			run(t, "syntax")
			if err := candidate.CheckEffective(run(t, "global")); err != nil {
				t.Fatalf("bastion default view unexpectedly rejected: %v", err)
			}
			jump := run(t, "connection")
			for _, kept := range []string{"allowtcpforwarding local\n", "permitopen 192.0.2.30:22\n", "allowagentforwarding no\n"} {
				if !strings.Contains(string(jump), kept) {
					t.Fatalf("administrator bastion restriction changed: %s", kept)
				}
			}
			if err := candidate.CheckEffective(jump); err == nil {
				t.Fatal("bastion context falsely accepted as a no-forwarding target")
			}
			if err := candidate.CheckEffective(run(t, "other-user")); err != nil {
				t.Fatalf("bastion exception unexpectedly applies to unrelated user: %v", err)
			}
			write(fixture, main)
			if err := os.Remove(include); err != nil {
				t.Fatal(err)
			}
			run(t, "syntax")
			if err := candidate.CheckEffective(run(t, "global")); err == nil {
				t.Fatal("absent drop-in falsely enforces policy")
			}
		})
	}
}
