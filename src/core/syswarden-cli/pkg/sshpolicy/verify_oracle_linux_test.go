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

func TestOpenSSHSealedVerificationOracle(t *testing.T) {
	if os.Getenv("SYSWARDEN_SSH_ORACLE_TEST") != "1" {
		t.Skip("set SYSWARDEN_SSH_ORACLE_TEST=1 for the installed OpenSSH parser oracle")
	}
	root, err := os.Open("/")
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	daemon, err := openSSHD(root, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer daemon.file.Close()
	t.Run("private-parser-error", func(t *testing.T) {
		image, err := newParserImage(map[string][]byte{
			MainPath: []byte("PrivateFixtureDirective secret-fixture-value\n"),
		})
		if err != nil {
			t.Fatal(err)
		}
		defer image.Close()
		result, err := daemon.run(context.Background(), image, "syntax", "")
		if err == nil || result != nil || strings.Contains(err.Error(), "secret-fixture") || strings.Contains(err.Error(), "PrivateFixture") {
			t.Fatal("parser failure returned private output or a successful result")
		}
		cancelled, cancel := context.WithCancel(context.Background())
		cancel()
		if result, err := daemon.run(cancelled, image, "syntax", ""); err == nil || result != nil {
			t.Fatal("cancelled parser returned a successful result")
		}
	})
	directory := t.TempDir()
	key := filepath.Join(directory, "fixture-key")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if output, err := exec.CommandContext(ctx, "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", key).CombinedOutput(); err != nil { // #nosec G204 -- Fixed fixture key generation writes only inside t.TempDir; no operator configuration or secret is passed.
		t.Fatalf("fixture key: %v %s", err, output)
	}
	for _, profile := range []string{"forwarding", "cis", "observe"} {
		t.Run(profile, func(t *testing.T) {
			main := includeDropIns + "HostKey " + key + "\nPort 2222\nUsePAM no\nPasswordAuthentication no\nAuthenticationMethods publickey\nSubsystem sftp internal-sftp\nInclude /etc/ssh/access.conf\n"
			f := planFixture(t, main)
			f.write("/etc/ssh/access.conf", "Match User administrator\n MaxSessions 12\n PermitTTY no\nMatch all\n")
			declaration, err := parseIntent([]byte(validIntentJSON))
			if err != nil {
				t.Fatal(err)
			}
			declaration.Profile = profile
			if profile == "observe" {
				declaration.Owner, declaration.Role = "external", "jump-host"
				f.write("/etc/ssh/access.conf", "Match User administrator\n AllowTcpForwarding local\n PermitOpen 192.0.2.30:22\nMatch all\n")
			}
			for index, route := range []string{"proxyjump", "ansible"} {
				access := declaration.Contexts[0]
				access.ID, access.Route = route, route
				if index == 1 {
					access.User = "unrelated"
				}
				declaration.Contexts = append(declaration.Contexts, access)
			}
			f.intent(declaration)
			plan := f.plan()
			// The live baseline is a temporary file with only its fixture Include
			// paths translated. The candidate uses the production sealed-FD runner.
			baseline := filepath.Join(directory, "baseline-"+profile)
			translated := strings.ReplaceAll(main, "/etc/ssh/", f.path("/etc/ssh/")+"/")
			if err := os.WriteFile(baseline, []byte(translated), 0600); err != nil {
				t.Fatal(err)
			}
			run := func(ctx context.Context, image *parserImage, mode, access string) ([]byte, error) {
				if image != nil {
					return daemon.run(ctx, image, mode, access)
				}
				flag := "-T"
				if mode == "syntax" {
					flag = "-t"
				}
				args := []string{flag, "-f", baseline}
				if access != "" {
					args = append(args, "-C", access)
				}
				process := exec.CommandContext(ctx, "/proc/self/fd/3", args...) // #nosec G204 -- The trusted daemon descriptor parses only temporary oracle fixtures and validated synthetic contexts in fixed -t/-T modes.
				process.ExtraFiles = []*os.File{daemon.file}
				process.Env = []string{"LC_ALL=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
				output, err := process.CombinedOutput()
				if err != nil {
					t.Fatalf("temporary baseline parser: %v %s", err, output)
				}
				return output, err
			}
			recheck := func() error {
				current, err := inspectPlan(f.root, os.Geteuid())
				if err != nil {
					return err
				}
				if current.summary != plan.summary {
					return ErrInventoryChanged
				}
				return daemon.recheck(root, 0)
			}
			summary, err := verifyPlan(ctx, plan, daemon.digest, run, recheck)
			if err != nil || !summary.ParserVerified || summary.ContextsVerified != 3 || summary.RuntimeActivated || summary.Plan.ApplyAvailable {
				t.Fatalf("sealed verification: %+v %v", summary, err)
			}
			if _, err := os.Lstat(f.path(DropInPath)); !os.IsNotExist(err) {
				t.Fatal("verification published the drop-in")
			}
		})
	}
}
