//go:build linux

package firewall

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func fixtureLegacyFail2banNFTExecutable(t *testing.T, path string) {
	t.Helper()
	lookup, validator := nftExecutableLookPath, nftExecutableValidator
	nftExecutableLookPath = func(string) (string, error) { return path, nil }
	nftExecutableValidator = validateTestLinuxWrapperExecutable
	t.Cleanup(func() { nftExecutableLookPath, nftExecutableValidator = lookup, validator })
}

func TestLegacyFail2banNFTExecutableRejectsUnboundCommandsAndChangedBinary(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nft-fixture")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil { // #nosec G306 -- An owner-only isolated executable fixture.
		t.Fatal(err)
	}
	fixtureLegacyFail2banNFTExecutable(t, path)
	content, claim := fixtureLegacyFail2banNFT(t, true)
	plan, err := prepareLegacyFail2banNFTTransition(content, []legacyFail2banNFTClaim{claim})
	if err != nil {
		t.Fatal(err)
	}
	runner, err := newLegacyFail2banNFTRunner(plan)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, args := range [][]string{{"flush", "ruleset"}, {"delete", "table", "inet", "f2b-table"}, {"-j", "list", "table", "inet", "administrator"}, {"-j", "-f", "-"}} {
		if _, err := runner.Run(ctx, nil, args...); err == nil {
			t.Fatal("unbound executable command accepted")
		}
	}
	if _, err := runner.Run(ctx, []byte(`{"nftables":[]}`), "-j", "-f", "-"); err == nil {
		t.Fatal("different input accepted")
	}
	if _, err := runner.Run(ctx, plan.transaction, "-j", "-f", "-"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 1\n"), 0700); err != nil { // #nosec G306 -- Changes only the isolated executable fixture.
		t.Fatal(err)
	}
	if _, err := runner.Run(ctx, plan.transaction, "-j", "-f", "-"); err == nil {
		t.Fatal("changed executable accepted")
	}
}

type fixtureLegacyFail2banNFTPrivateIntent struct {
	Family, Table, Before, After, Claims, Transaction, Digest string
}

type fixtureLegacyFail2banNFTInterruptedRunner struct{ nftCommandRunner }

func (runner fixtureLegacyFail2banNFTInterruptedRunner) Run(ctx context.Context, input []byte, args ...string) ([]byte, error) {
	output, err := runner.nftCommandRunner.Run(ctx, input, args...)
	if err == nil && input != nil && os.Getenv("SYSWARDEN_FAIL2BAN_NFT_EXIT_AFTER_APPLY") == "1" {
		os.Exit(76)
	}
	return output, err
}

// This opt-in test operates only in an independently created network
// namespace, against synthetic jails. The private intent and action claim are
// fixture authorization, not production ownership or full removal acceptance.
func TestLegacyFail2banNFTLiveFixture(t *testing.T) {
	path := os.Getenv("SYSWARDEN_FAIL2BAN_RUNTIME_FIXTURE_ROOT")
	if path == "" {
		t.Skip("requires a disposable Fail2ban network fixture")
	}
	parent := os.Getenv("SYSWARDEN_TEST_PARENT_NETNS")
	current, err := os.Readlink("/proc/self/ns/net")
	if err != nil || parent == "" || parent == current || os.Geteuid() != 0 {
		t.Fatal("kernel fixture must run as mapped root in a distinct network namespace")
	}
	client := fixtureLegacyFail2banRuntimeClient(t)
	binary, err := os.ReadFile("/usr/bin/nft")
	if err != nil {
		t.Fatal(err)
	}
	if err := client.host.root.WriteFile("nft-fixture", binary, 0700); err != nil { // #nosec G306 -- Owner-only copy of the installed binary inside an isolated fixture root.
		t.Fatal(err)
	}
	fixtureLegacyFail2banNFTExecutable(t, filepath.Join(path, "nft-fixture"))
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	query := func(ctx context.Context, args []string) (legacyFail2banValue, error) {
		child, done := context.WithTimeout(ctx, 5*time.Second)
		defer done()
		return client.query(child, args)
	}
	baseline, err := inspectLegacyFail2banRuntime(ctx, query)
	if err != nil {
		t.Fatal(err)
	}
	if _, found := baseline.jails["syswarden-portscan"]; found {
		t.Fatal("target must be stopped before exact kernel retirement")
	}
	if len(baseline.jails["administrator-web"].bans) != 1 {
		t.Fatal("administrator protection is missing")
	}
	claim := legacyFail2banNFTClaim{"syswarden-portscan", os.Getenv("SYSWARDEN_FAIL2BAN_NFT_PROFILE"), "ip", strings.Repeat("a", 64), strings.Repeat("b", 64), []string{"127.0.0.2"}}
	table := "syswarden_f2b"
	if claim.profile == "nftables-allports" {
		table = "f2b-table"
	} else if claim.profile != "syswarden-nft" {
		t.Fatal("unsupported kernel fixture profile")
	}
	var plan legacyFail2banNFTTransition
	var intent fixtureLegacyFail2banNFTPrivateIntent
	content, err := client.host.root.ReadFile("nft-intent.json")
	if os.IsNotExist(err) {
		runner, err := newExecNFTCommandRunner()
		if err != nil {
			t.Fatal(err)
		}
		observation, err := runLegacyFail2banNFT(ctx, runner.(execNFTCommandRunner), table, nil)
		if err != nil {
			t.Fatal(err)
		}
		plan, err = prepareLegacyFail2banNFTTransition(observation, []legacyFail2banNFTClaim{claim})
		if err != nil {
			t.Fatal(err)
		}
		intent = fixtureLegacyFail2banNFTPrivateIntent{plan.family, plan.table, string(plan.before), string(plan.after), string(plan.claims), string(plan.transaction), plan.sha256}
		content, err = json.Marshal(intent)
		if err != nil {
			t.Fatal(err)
		}
		file, err := client.host.root.OpenFile("nft-intent.json", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := file.Write(content); err != nil {
			t.Fatal(err)
		}
		if err := file.Sync(); err != nil {
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		dir, err := client.host.root.Open(".")
		if err != nil {
			t.Fatal(err)
		}
		if err := dir.Sync(); err != nil {
			t.Fatal(err)
		}
		_ = dir.Close()
	} else if err != nil {
		t.Fatal(err)
	} else {
		if err := json.Unmarshal(content, &intent); err != nil {
			t.Fatal(err)
		}
		canonical, err := json.Marshal(intent)
		if err != nil || !bytes.Equal(canonical, content) {
			t.Fatal("noncanonical fixture recovery intent")
		}
		plan = legacyFail2banNFTTransition{intent.Family, intent.Table, []byte(intent.Before), []byte(intent.After), []byte(intent.Claims), []byte(intent.Transaction), intent.Digest}
	}
	if plan.table != table || plan.sha256 != plan.digest() {
		t.Fatal("fixture recovery intent changed")
	}
	bound, err := client.host.snapshot("/nft-intent.json")
	if err != nil || bound.identity.Mode().Perm() != 0600 || !bytes.Equal(bound.content, content) {
		t.Fatal("fixture runtime intent is not private and exact", err)
	}
	guard := func(ctx context.Context, digest string) error {
		if err := client.guard(); err != nil {
			return err
		}
		actual, err := client.host.snapshot("/nft-intent.json")
		if err != nil || !sameLegacyFail2banSource(bound, actual) || !bytes.Equal(actual.content, content) || digest != plan.sha256 {
			return fmt.Errorf("fixture retirement intent changed")
		}
		now, err := inspectLegacyFail2banRuntime(ctx, query)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(baseline, now) {
			return fmt.Errorf("fixture unrelated service state changed")
		}
		return nil
	}
	runner, err := newLegacyFail2banNFTRunner(plan)
	if err != nil {
		t.Fatal(err)
	}
	if err := applyLegacyFail2banNFTTransition(ctx, fixtureLegacyFail2banNFTInterruptedRunner{runner}, plan, guard); err != nil {
		t.Fatal(err)
	}
	t.Log("Exact Go kernel retirement preserved shared objects and resumed the private fixture intent.")
}
