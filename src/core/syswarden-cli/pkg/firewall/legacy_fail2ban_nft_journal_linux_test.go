//go:build linux

package firewall

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
)

func fixtureLegacyFail2banNFTJournal(t *testing.T, upstream bool) (nftPersistenceFilesystem, legacyFail2banRetirementPlan, legacyFail2banNFTJournalRecord) {
	t.Helper()
	_, host, files := fixtureLegacyFail2banJournal(t)
	if err := persistLegacyFail2banPlanUsing(host, files, acceptLegacyFail2banJournalFixture, defaultLegacyRetirementFileOps()); err != nil {
		t.Fatal(err)
	}
	content, claim := fixtureLegacyFail2banNFT(t, upstream)
	claim.filePlan = files.sha256
	claims := []legacyFail2banNFTClaim{claim}
	if upstream {
		ipv6 := claim
		ipv6.addressFamily, ipv6.bans = "ip6", nil
		claims = append(claims, ipv6)
	}
	plan, err := prepareLegacyFail2banNFTTransition(content, claims)
	if err != nil {
		t.Fatal(err)
	}
	quiescence := fixtureLegacyFail2banQuiescenceRecord(files.sha256)
	return host, files, makeLegacyFail2banNFTJournalRecord(quiescence, []legacyFail2banNFTTransition{plan})
}

func TestLegacyFail2banNFTJournalRebuildsCommandsAndBindsEveryFamily(t *testing.T) {
	for _, change := range []string{"none", "schema", "wrong-file-plan", "wrong-actions", "wrong-jail", "missing-family", "changed-transaction", "changed-after", "changed-digest", "duplicate-plan", "duplicate-claim", "noncanonical-claim"} {
		t.Run(change, func(t *testing.T) {
			_, _, record := fixtureLegacyFail2banNFTJournal(t, true)
			original, _, _, err := encodeLegacyFail2banNFTJournalRecord(record)
			if err != nil {
				t.Fatal(err)
			}
			switch change {
			case "schema":
				record.Schema = "different"
			case "wrong-file-plan":
				record.Quiescence.FilePlan = strings.Repeat("d", 64)
			case "wrong-actions":
				record.Quiescence.Actions = strings.Repeat("e", 64)
			case "wrong-jail":
				record.Quiescence.Targets = []string{"administrator"}
			case "changed-transaction":
				record.Plans[0].Transaction = `{"nftables":[{"flush":{"ruleset":null}}]}`
			case "changed-after":
				record.Plans[0].After = `[]`
			case "changed-digest":
				record.Plans[0].Digest = strings.Repeat("f", 64)
			case "duplicate-plan":
				record.Plans = append(record.Plans, record.Plans[0])
			case "noncanonical-claim":
				record.Plans[0].Claims += "\n"
			case "missing-family", "duplicate-claim":
				claims, err := decodeLegacyFail2banNFTClaims([]byte(record.Plans[0].Claims))
				if err != nil {
					t.Fatal(err)
				}
				if change == "missing-family" {
					claims = claims[:1]
				} else {
					claims = append(claims, claims[0])
				}
				encoded, err := encodeLegacyFail2banNFTClaims(claims)
				if err != nil {
					t.Fatal(err)
				}
				record.Plans[0].Claims = string(encoded)
			}
			content, digest, plans, err := encodeLegacyFail2banNFTJournalRecord(record)
			if change == "none" {
				if err != nil || !bytes.Equal(content, original) || digest == "" || len(plans) != 1 {
					t.Fatal("valid exact kernel intent rejected", err)
				}
			} else if err == nil || content != nil || digest != "" || plans != nil {
				t.Fatal("changed or incomplete intent returned a kernel plan", change)
			}
		})
	}
}

func TestLegacyFail2banNFTJournalPublishesDurablyWithoutChangingActiveFiles(t *testing.T) {
	host, files, record := fixtureLegacyFail2banNFTJournal(t, false)
	ctx := context.Background()
	guard := func(context.Context) error { _, err := inspectLegacyFail2banPlanState(host, files.binding); return err }
	journal, err := publishLegacyFail2banNFTIntent(ctx, host, record, guard, defaultLegacyRetirementFileOps())
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.verifyTransition(ctx, journal.plans[0].sha256); err == nil {
		t.Fatal("kernel transition accepted without its durable quiescence intent")
	}
	if _, err := publishLegacyFail2banQuiescenceIntent(ctx, host, record.Quiescence, guard, defaultLegacyRetirementFileOps()); err != nil {
		t.Fatal(err)
	}
	if err := journal.verifyTransition(ctx, journal.plans[0].sha256); err != nil {
		t.Fatal(err)
	}
	if err := journal.verifyTransition(ctx, strings.Repeat("f", 64)); err == nil {
		t.Fatal("an unrelated transaction was included in the kernel intent")
	}
	repeated, err := publishLegacyFail2banNFTIntent(ctx, host, record, guard, defaultLegacyRetirementFileOps())
	if err != nil || !sameLegacyFail2banSource(journal.file, repeated.file) || journal.evidenceSHA256() != repeated.evidenceSHA256() {
		t.Fatal("repeated publication replaced the kernel intent", err)
	}
	record.Plans[0].Transaction = "changed by caller"
	if err := journal.verifyTransition(ctx, journal.plans[0].sha256); err != nil {
		t.Fatal("caller alias changed the immutable private record", err)
	}
	if err := reattestLegacyFail2banPlanInventory(host, files.baseline); err != nil {
		t.Fatal("kernel publication changed active configuration", err)
	}
}

func TestLegacyFail2banNFTJournalResumesUnconfirmedPublication(t *testing.T) {
	for _, point := range []string{"kernel-staged", "kernel-intent-durable", "sync"} {
		t.Run(point, func(t *testing.T) {
			host, files, record := fixtureLegacyFail2banNFTJournal(t, false)
			guard := func(context.Context) error { _, err := inspectLegacyFail2banPlanState(host, files.binding); return err }
			ops := defaultLegacyRetirementFileOps()
			ops.checkpoint = func(phase string) error {
				if phase == point {
					return fmt.Errorf("injected interrupted kernel publication")
				}
				return nil
			}
			if point == "sync" {
				ops.sync = func(*os.File) error { return fmt.Errorf("injected unavailable synchronization") }
			}
			ctx := context.Background()
			if journal, err := publishLegacyFail2banNFTIntent(ctx, host, record, guard, ops); err == nil || journal != nil {
				t.Fatal("unconfirmed publication returned a usable journal")
			}
			if _, err := publishLegacyFail2banNFTIntent(ctx, host, record, guard, defaultLegacyRetirementFileOps()); err != nil {
				t.Fatal("exact publication did not resume", err)
			}
			content, _, _, err := encodeLegacyFail2banNFTJournalRecord(record)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := readLegacyFail2banNFTIntent(ctx, host, record.Quiescence, fmt.Sprintf("%x", sha256.Sum256(content)), guard); err != nil {
				t.Fatal("durable kernel intent could not be reloaded", err)
			}
			if err := reattestLegacyFail2banPlanInventory(host, files.baseline); err != nil {
				t.Fatal("failed publication changed active files", err)
			}
		})
	}
}

func TestLegacyFail2banNFTJournalKeepsDistinctReviewedObservations(t *testing.T) {
	host, _, record := fixtureLegacyFail2banNFTJournal(t, false)
	ctx := context.Background()
	guard := func(context.Context) error { return nil }
	first, err := publishLegacyFail2banNFTIntent(ctx, host, record, guard, defaultLegacyRetirementFileOps())
	if err != nil {
		t.Fatal(err)
	}
	claims, err := decodeLegacyFail2banNFTClaims([]byte(record.Plans[0].Claims))
	if err != nil {
		t.Fatal(err)
	}
	observation := []byte(`{"nftables":` + strings.ReplaceAll(record.Plans[0].Before, "127.0.0.3", "127.0.0.4") + `}`)
	updated, err := prepareLegacyFail2banNFTTransition(observation, claims)
	if err != nil {
		t.Fatal(err)
	}
	record = makeLegacyFail2banNFTJournalRecord(record.Quiescence, []legacyFail2banNFTTransition{updated})
	second, err := publishLegacyFail2banNFTIntent(ctx, host, record, guard, defaultLegacyRetirementFileOps())
	if err != nil || first.path == second.path || first.evidenceSHA256() == second.evidenceSHA256() {
		t.Fatal("distinct reviewed administrator state replaced existing evidence", err)
	}
	for _, expected := range []*legacyFail2banNFTJournal{first, second} {
		loaded, err := readLegacyFail2banNFTIntent(ctx, host, record.Quiescence, expected.evidenceSHA256(), guard)
		if err != nil || !sameLegacyFail2banSource(expected.file, loaded.file) || !bytes.Equal(expected.content, loaded.content) {
			t.Fatal("exact digest did not select the original immutable evidence", err)
		}
	}
	if loaded, err := readLegacyFail2banNFTIntent(ctx, host, record.Quiescence, strings.Repeat("a", 64), guard); err == nil || loaded != nil {
		t.Fatal("unknown digest selected another available kernel journal")
	}
}

func TestLegacyFail2banNFTJournalRejectsDiskAndInvocationChanges(t *testing.T) {
	for _, change := range []string{"unknown-field", "duplicate-field", "changed-transaction", "public-file", "public-directory", "invocation"} {
		t.Run(change, func(t *testing.T) {
			host, _, record := fixtureLegacyFail2banNFTJournal(t, false)
			ctx := context.Background()
			guard := func(context.Context) error { return nil }
			journal, err := publishLegacyFail2banNFTIntent(ctx, host, record, guard, defaultLegacyRetirementFileOps())
			if err != nil {
				t.Fatal(err)
			}
			content := bytes.Clone(journal.content)
			switch change {
			case "unknown-field":
				content = append([]byte(`{"extra":true,`), content[1:]...)
			case "duplicate-field":
				content = append([]byte(`{"schema":"duplicate",`), content[1:]...)
			case "changed-transaction":
				record.Plans[0].Transaction = `{"nftables":[]}`
				content, err = json.Marshal(record)
			case "public-file":
				err = host.root.Chmod(journal.path[1:]+"/kernel.json", 0644) // #nosec G302 -- Deliberately invalid private-journal metadata in an isolated fixture.
			case "public-directory":
				err = host.root.Chmod(journal.path[1:], 0755) // #nosec G302 -- Deliberately invalid recovery-directory metadata in an isolated fixture.
			case "invocation":
				record.Quiescence.Invocation = strings.Repeat("d", 32)
			}
			if err != nil {
				t.Fatal(err)
			}
			if change == "unknown-field" || change == "duplicate-field" || change == "changed-transaction" {
				if err := host.root.WriteFile(journal.path[1:]+"/kernel.json", content, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if loaded, err := readLegacyFail2banNFTIntent(ctx, host, record.Quiescence, journal.evidenceSHA256(), guard); err == nil || loaded != nil {
				t.Fatal("changed kernel recovery evidence accepted", change)
			}
		})
	}
}
