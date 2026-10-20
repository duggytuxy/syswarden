//go:build linux

package sshpolicy

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestOpenSSHPublicationOracle(t *testing.T) {
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
	directory := t.TempDir()
	scratch, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer scratch.Close()
	key := filepath.Join(directory, "fixture-key")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if output, err := exec.CommandContext(ctx, "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", key).CombinedOutput(); err != nil { // #nosec G204 -- Fixed fixture-only host key generation; no production path or secret.
		t.Fatalf("fixture key: %v %s", err, output)
	}
	for _, profile := range []string{"forwarding", "cis", "legacy-cis"} {
		t.Run(profile, func(t *testing.T) {
			content := includeDropIns + "HostKey " + key + "\nPort 2222\nUsePAM no\nPasswordAuthentication no\nAuthenticationMethods publickey\nInclude /etc/ssh/access.conf\n"
			if profile == "legacy-cis" {
				content = "AllowTcpForwarding no\n" + strings.Join(legacyCISBlock, "\n") + "\n" + content
			}
			f := planFixture(t, content)
			f.write("/etc/ssh/access.conf", "Match User administrator\n MaxSessions 12\n PermitTTY no\nMatch all\n")
			declaration, err := parseIntent([]byte(validIntentJSON))
			if err != nil {
				t.Fatal(err)
			}
			declaration.Profile = profile
			if profile == "legacy-cis" {
				declaration.Profile = "cis"
				declaration.Legacy = &legacyIntent{Attribution: "operator-reviewed", MainSHA256: digestBytes([]byte(content))}
				for line := 1; line <= 7; line++ {
					declaration.Legacy.Edits = append(declaration.Legacy.Edits, legacyEdit{line, "remove"})
				}
			}
			for _, route := range []string{"proxyjump", "ansible"} {
				access := declaration.Contexts[0]
				access.ID, access.Route = route, route
				declaration.Contexts = append(declaration.Contexts, access)
			}
			f.intent(declaration)
			if err := os.MkdirAll(f.path(sshStateParent), 0700); err != nil {
				t.Fatal(err)
			}
			if err := provisionSSHState(f.root, os.Geteuid(), sshProvisionDefaults()); err != nil {
				t.Fatal(err)
			}
			plan := f.plan()
			before := fixtureMainImage(t, f)
			main, err := newSSHAnonymousStage(fixtureDirectory(t, f, "/etc/ssh"), plan.main,
				before.state.mode&0777, before.state.gid, before.attrs, os.Geteuid())
			if err != nil {
				t.Fatal(err)
			}
			defer main.Close()
			drop, err := newSSHAnonymousStage(fixtureDirectory(t, f, "/etc/ssh/sshd_config.d"), plan.candidate.Bytes(),
				0600, before.state.gid, before.attrs, os.Geteuid())
			if err != nil {
				t.Fatal(err)
			}
			defer drop.Close()
			record, err := prepareSSHRecord(plan, plan.summary.PlanSHA256, daemon.digest, before, main, drop, os.Geteuid())
			if err != nil {
				t.Fatal(err)
			}
			journal := fixtureJournal(t, f)
			if err := journal.write(record); err != nil {
				t.Fatal(err)
			}
			// Read current main bytes on every live invocation. Only fixture
			// Include paths are translated; their files are the actual published
			// inodes. The same pinned installed parser handles sealed candidates.
			livePath := filepath.Join(directory, "live-"+profile)
			run := func(ctx context.Context, image *parserImage, mode, access string) ([]byte, error) {
				if image != nil {
					return daemon.run(ctx, image, mode, access)
				}
				live, err := os.ReadFile(f.path(MainPath))
				if err != nil {
					return nil, err
				}
				translated := strings.ReplaceAll(string(live), "/etc/ssh/", f.path("/etc/ssh/")+"/")
				if err := scratch.WriteFile("live-"+profile, []byte(translated), 0600); err != nil {
					return nil, err
				}
				flag := "-T"
				if mode == "syntax" {
					flag = "-t"
				}
				args := []string{flag, "-f", livePath}
				if access != "" {
					args = append(args, "-C", access)
				}
				process := exec.CommandContext(ctx, "/proc/self/fd/3", args...) // #nosec G204 -- Pinned installed parser, fixed syntax/effective modes, temporary fixture configuration; never a listener.
				process.ExtraFiles = []*os.File{daemon.file}
				process.Env = []string{"LC_ALL=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
				return process.CombinedOutput()
			}
			if err := publishSSHConfiguration(ctx, journal, plan, main, drop, run,
				func() error { return daemon.recheck(root, 0) }, sshPublicationDefaults()); err != nil {
				t.Fatal(err)
			}
			if profile == "legacy-cis" && bytes.Equal(before.data, fixtureMainImage(t, f).data) {
				t.Fatal("legacy directives were not migrated")
			}
			position, err := inspectSSHPublication(journal)
			if err != nil || position != (sshPublicationPosition{3, "complete"}) {
				t.Fatal("publication evidence cannot be verified", position, err)
			}
			if err := journal.Close(); err != nil {
				t.Fatal(err)
			}
			journal = fixtureJournal(t, f)
			if err := rollbackSSHConfiguration(ctx, journal, plan.summary.PlanSHA256, run,
				func() error { return daemon.recheck(root, 0) }, sshPublicationDefaults()); err != nil {
				t.Fatal(err)
			}
			assertSSHRestored(t, f, record, journal)
		})
	}
}
