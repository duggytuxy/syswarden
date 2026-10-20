//go:build linux

package sshpolicy

import (
	"context"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestSSHIntermediateAcceptsOnlyReviewedValuesAndUnrelatedSettings(t *testing.T) {
	before := sshEffective{"allowtcpforwarding": {"local"}, "port": {"2222", "2223"}}
	after := sshEffective{"allowtcpforwarding": {"no"}, "port": {"2222", "2223"}}
	allowed := map[string]bool{"allowtcpforwarding": true}
	for _, output := range []sshEffective{before, after} {
		if err := compareSSHIntermediate(before, output, after, allowed); err != nil {
			t.Fatal(err)
		}
	}
	for _, scenario := range []string{"third value", "missing", "empty", "duplicate", "port", "reordered", "extra", "missing baseline", "missing candidate"} {
		t.Run(scenario, func(t *testing.T) {
			initial := sshEffective{"allowtcpforwarding": {"local"}, "port": {"2222", "2223"}}
			final := sshEffective{"allowtcpforwarding": {"no"}, "port": {"2222", "2223"}}
			middle := sshEffective{"allowtcpforwarding": {"no"}, "port": {"2222", "2223"}}
			switch scenario {
			case "third value":
				middle["allowtcpforwarding"] = []string{"yes"}
			case "missing":
				delete(middle, "allowtcpforwarding")
			case "empty":
				middle["allowtcpforwarding"] = nil
			case "duplicate":
				middle["allowtcpforwarding"] = []string{"no", "no"}
			case "port":
				middle["port"] = []string{"22"}
			case "reordered":
				middle["port"] = []string{"2223", "2222"}
			case "extra":
				middle["permitrootlogin"] = []string{"yes"}
			case "missing baseline":
				delete(initial, "allowtcpforwarding")
			case "missing candidate":
				delete(final, "allowtcpforwarding")
			}
			err := compareSSHIntermediate(initial, middle, final, allowed)
			if err == nil || strings.Contains(err.Error(), "2222") {
				t.Fatal("accepted or disclosed an unreviewed intermediate setting", err)
			}
		})
	}
}

func TestVerifyPlanRejectsIntermediateSyntaxPolicyAndAccessChanges(t *testing.T) {
	for _, scenario := range []string{"syntax", "policy", "access", "context", "recheck"} {
		t.Run(scenario, func(t *testing.T) {
			f := planFixture(t, includeDropIns)
			plan := f.plan()
			calls, checks := 0, 0
			run := func(_ context.Context, image *parserImage, mode, access string) ([]byte, error) {
				calls++
				if mode == "syntax" {
					if calls == 3 && scenario == "syntax" {
						return nil, errors.New("fixture intermediate syntax failure")
					}
					return nil, nil
				}
				value, port := "yes", "2222"
				if image != nil && len(image.files) == 2 {
					value = "no"
				}
				// Four syntax calls, then four graphs per effective context.
				intermediate := calls == 7 || calls == 11
				if intermediate {
					switch scenario {
					case "policy":
						value = "remote"
					case "access":
						port = "22"
					case "context":
						if access != "" {
							port = "22"
						}
					}
				}
				return []byte("port " + port + "\nallowtcpforwarding " + value + "\n"), nil
			}
			recheck := func() error {
				checks++
				if scenario == "recheck" && checks == 6 {
					return ErrInventoryChanged
				}
				return nil
			}
			result, err := verifyPlan(context.Background(), plan, strings.Repeat("a", 64), run, recheck)
			if err == nil || result != (VerificationSummary{}) {
				t.Fatal("claimed verification after an intermediate failure")
			}
			if !reflect.DeepEqual(f.plan().inventory, plan.inventory) {
				t.Fatal("preflight changed live inputs")
			}
		})
	}
}

func TestSSHMainStageIdentityAndIncludeIsolation(t *testing.T) {
	transaction := strings.Repeat("a", 64)
	stage, err := sshMainStagePath(transaction)
	if err != nil || stage != "/etc/ssh/.syswarden-ssh-main-"+transaction {
		t.Fatal("noncanonical stage path", err)
	}
	for _, bad := range []string{"", "../other", strings.Repeat("A", 64), strings.Repeat("a", 63), strings.Repeat("a", 65)} {
		if _, err := sshMainStagePath(bad); err == nil {
			t.Fatal("accepted malformed transaction identity")
		}
	}
	for _, location := range []string{"original", "candidate", "nested", "conditional", "reserved policy"} {
		for _, pattern := range []string{stage, ".syswarden-ssh-main-*", "/etc/ssh/.*", "/etc/ssh/.syswarden-ssh-main-?*"} {
			t.Run(location+"/"+pattern, func(t *testing.T) {
				plan := planFixture(t, includeDropIns).plan()
				line := []byte("Include " + pattern + "\n")
				switch location {
				case "original":
					plan.inventory.files[MainPath] = append(plan.inventory.files[MainPath], line...)
				case "candidate":
					plan.main = append(plan.main, line...)
				case "nested":
					plan.inventory.files["/etc/ssh/nested.conf"] = line
				case "conditional":
					plan.inventory.files["/etc/ssh/access.conf"] = append([]byte("Match User fixture\n"), line...)
				case "reserved policy":
					plan.candidate.content += string(line)
				}
				if err := checkSSHPublicationIsolation(plan, transaction); err == nil {
					t.Fatal("allowed an Include to consume a named stage or displaced original")
				}
			})
		}
	}
	t.Run("disjoint", func(t *testing.T) {
		plan := planFixture(t, includeDropIns+"Include /etc/ssh/administrator-*.conf\n").plan()
		if err := checkSSHPublicationIsolation(plan, transaction); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("external", func(t *testing.T) {
		plan := planFixture(t, includeDropIns).plan()
		plan.intent.Owner = "external"
		if err := checkSSHPublicationIsolation(plan, transaction); err == nil {
			t.Fatal("planned a stage for externally managed SSH")
		}
	})
}

func TestSSHPreparationRejectsStageIncludeBeforeWritingJournal(t *testing.T) {
	f, plan, before, main, drop := preparationFixtureWithMain(t,
		includeDropIns+"Include /etc/ssh/.syswarden-ssh-main-*\n")
	record, err := prepareSSHRecord(plan, plan.summary.PlanSHA256, strings.Repeat("a", 64), before, main, drop, os.Geteuid())
	if err == nil || record.Transaction != "" {
		t.Fatal("prepared a transaction whose stage is SSH input")
	}
	if _, err := os.Lstat(f.path(sshJournalDirectory + "/" + sshPreparedRecord)); !os.IsNotExist(err) {
		t.Fatal("wrote recovery state after unsafe preparation")
	}
	if !reflect.DeepEqual(f.plan().inventory, plan.inventory) {
		t.Fatal("changed live input during refused preparation")
	}
}
