//go:build linux

package firewall

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

const legacyIPTablesFixtureInput = "/root/iptables-capture/review.json"

func fixtureLegacyIPTablesRecovery(t *testing.T) (*legacyIPTablesRecovery, *legacyIPTablesObservation) {
	t.Helper()
	_, host := fixtureNFTPersistenceFilesystem(t)
	for _, path := range []string{"root/iptables-capture", "var/backups"} {
		if err := host.root.MkdirAll(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	before, generated, inputs := legacyIPTablesTestGeneration(t)
	pair := func(observation legacyIPTablesObservation) ([]byte, []byte) {
		var lines []string
		var handles []uint64
		for _, rule := range observation.rules {
			lines, handles = append(lines, rule.line), append(handles, rule.handle)
		}
		return legacyIPTablesFixture(t, lines, handles)
	}
	beforeNFT, beforeSave := pair(before)
	generatedNFT, generatedSave := pair(generated)
	epoch := nftRemovalEpoch{"11111111-2222-3333-4444-555555555555", 4, 19}
	document := legacyIPTablesInputDocument{Schema: legacyIPTablesInputSchema, Generation: "v4.02.8", Epoch: epoch, Inputs: inputs}
	for _, source := range []struct {
		kind string
		data []byte
	}{
		{"configuration", []byte("synthetic independently retained original configuration\n")},
		{"nft-before", beforeNFT}, {"nft-generated", generatedNFT}, {"iptables-generated", generatedSave}, {"iptables-before", beforeSave},
	} {
		name := source.kind + ".txt"
		if err := host.root.WriteFile("root/iptables-capture/"+name, source.data, 0600); err != nil {
			t.Fatal(err)
		}
		document.Evidence = append(document.Evidence, nftHistoricalInputEvidence{source.kind, name, nftSHA256Hex(source.data)})
	}
	content, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if err := host.root.WriteFile("root/iptables-capture/review.json", content, 0600); err != nil {
		t.Fatal(err)
	}
	origin, err := inspectLegacyIPTablesInputs(host, legacyIPTablesFixtureInput, epoch)
	if err != nil {
		t.Fatal(err)
	}
	producers := nftRemovalProducerInspection{digest: strings.Repeat("a", 64), verify: func(context.Context) error { return nil }}
	plan, err := prepareLegacyIPTablesPlan(before, generated, generated, inputs, origin.digest)
	if err != nil {
		t.Fatal(err)
	}
	record := legacyIPTablesRecoveryRecord{"syswarden-historical-iptables-retirement-v1", origin.path, origin.digest, producers.digest, epoch, string(generatedNFT), string(generatedSave), plan.digest}
	plan, review, err := bindLegacyIPTablesRecovery(origin, producers.digest, record)
	if err != nil {
		t.Fatal(err)
	}
	current := generated
	session := &legacyIPTablesRecovery{host: host, origin: origin, producers: producers, epoch: func() (nftRemovalEpoch, error) { return epoch, nil }, plan: plan, review: review, record: record}
	session.observer = func(context.Context) (legacyIPTablesObservation, []byte, []byte, error) {
		return current, nil, nil, nil
	}
	return session, &current
}

type legacyIPTablesFixtureFence struct {
	applyFn func(context.Context, func() error) error
	closed  bool
}

func (fence *legacyIPTablesFixtureFence) apply(ctx context.Context, guard func() error) error {
	return fence.applyFn(ctx, guard)
}
func (fence *legacyIPTablesFixtureFence) close() { fence.closed = true }

func fixtureLegacyIPTablesFenceFactory(t *testing.T, current *legacyIPTablesObservation, writes *int, afterWrite error) legacyIPTablesFenceFactory {
	t.Helper()
	return func(ctx context.Context, inspect func(context.Context) ([]nftGenerationRuleTarget, error)) (nftRemovalFence, error) {
		targets, err := inspect(ctx)
		if err != nil {
			return nil, err
		}
		selected := make(map[uint64]bool)
		for _, target := range targets {
			selected[target.Handle] = true
		}
		return &legacyIPTablesFixtureFence{applyFn: func(_ context.Context, guard func() error) error {
			if err := guard(); err != nil {
				return err
			}
			var lines []string
			var handles []uint64
			for _, rule := range current.rules {
				if !selected[rule.handle] {
					lines, handles = append(lines, rule.line), append(handles, rule.handle)
				}
			}
			*current = legacyIPTablesTestObservation(t, lines, handles)
			*writes++
			return afterWrite
		}}, nil
	}
}

func TestLegacyIPTablesRecoveryDurableRetryPreservesAdministratorRules(t *testing.T) {
	session, current := fixtureLegacyIPTablesRecovery(t)
	ctx := context.Background()
	before, err := session.summary(ctx)
	if err != nil || before.AlreadyComplete || before.RetainedRuleCount != 2 || len(before.Targets) != 18 || before.DeletesSharedTable {
		t.Fatal("incorrect bounded preview", before, err)
	}
	if _, err := session.host.snapshot(legacyIPTablesBackupRoot + "/" + session.review + "/kernel.json"); err == nil {
		t.Fatal("dry run persisted an intent")
	}
	writes := 0
	factory := fixtureLegacyIPTablesFenceFactory(t, current, &writes, nil)
	if err := session.apply(ctx, session.review, defaultLegacyRetirementFileOps(), factory); err != nil {
		t.Fatal(err)
	}
	if len(current.rules) != 2 || current.rules[0].handle != 2 || current.rules[1].handle != 3 || writes != 1 {
		t.Fatal("identical administrator rules changed")
	}
	_, original, err := readLegacyIPTablesRecord(session.host, session.review)
	if err != nil {
		t.Fatal(err)
	}
	if err := session.apply(ctx, session.review, defaultLegacyRetirementFileOps(), factory); err != nil || writes != 1 {
		t.Fatal("retry repeated deletion", err)
	}
	_, after, err := readLegacyIPTablesRecord(session.host, session.review)
	if err != nil || !sameLegacyFail2banSource(original, after) {
		t.Fatal("retry replaced the original private intent", err)
	}
	summary, err := session.summary(ctx)
	if err != nil || !summary.AlreadyComplete || summary.StopsProductServices || summary.ChangesSharedRules {
		t.Fatal("completed retry state is inaccurate", err)
	}
	epoch, _ := session.epoch()
	observe := func(context.Context) (legacyIPTablesObservation, error) { return *current, nil }
	if err := authorizeLegacyIPTablesPreservationUsing(ctx, session.host, epoch, observe); err != nil {
		t.Fatal("exact administrator remainder was not recognized", err)
	}
	current.rules[0].line = "changed administrator rule"
	if err := authorizeLegacyIPTablesPreservationUsing(ctx, session.host, epoch, observe); err == nil {
		t.Fatal("changed remainder borrowed an old receipt")
	}
}

func TestLegacyIPTablesRecoveryResumesUnconfirmedCommittedTransaction(t *testing.T) {
	session, current := fixtureLegacyIPTablesRecovery(t)
	writes := 0
	uncertain := errors.New("synthetic interrupted acknowledgement")
	factory := fixtureLegacyIPTablesFenceFactory(t, current, &writes, uncertain)
	if err := session.apply(context.Background(), session.review, defaultLegacyRetirementFileOps(), factory); !errors.Is(err, uncertain) || writes != 1 {
		t.Fatal("uncertain commit did not retain its failure", err)
	}
	if err := session.apply(context.Background(), session.review, defaultLegacyRetirementFileOps(), factory); err != nil || writes != 1 {
		t.Fatal("exact completed retry repeated an uncertain transaction", err)
	}
}

func TestLegacyIPTablesRecoveryRefusesDriftBeforeKernelWrite(t *testing.T) {
	for _, kind := range []string{"digest", "origin bytes", "origin mode", "origin missing", "private directory", "boot", "namespace", "producers", "current rules", "intent modified", "intent missing after commit", "new producer during fence", "journal sync failure"} {
		t.Run(kind, func(t *testing.T) {
			session, current := fixtureLegacyIPTablesRecovery(t)
			ctx := context.Background()
			ops := defaultLegacyRetirementFileOps()
			writes := 0
			factory := fixtureLegacyIPTablesFenceFactory(t, current, &writes, nil)
			review := session.review
			checked := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			switch kind {
			case "digest":
				review = strings.Repeat("b", 64)
			case "origin bytes":
				checked(session.host.root.WriteFile("root/iptables-capture/configuration.txt", []byte("changed"), 0600))
			case "origin mode":
				checked(session.host.root.Chmod("root/iptables-capture/configuration.txt", 0644))
			case "origin missing":
				checked(session.host.root.Remove("root/iptables-capture/nft-before.txt"))
			case "private directory":
				checked(session.host.root.Chmod("root/iptables-capture", 0755))
			case "boot", "namespace":
				epoch, _ := session.epoch()
				if kind == "boot" {
					epoch.BootID = strings.Repeat("b", 36)
				} else {
					epoch.Inode++
				}
				session.epoch = func() (nftRemovalEpoch, error) { return epoch, nil }
			case "producers":
				session.producers.verify = func(context.Context) error { return errors.New("producer changed") }
			case "current rules":
				current.rules[0].line = "changed"
			case "intent modified":
				checked(session.persist(ctx, ops))
				checked(session.host.root.WriteFile(strings.TrimPrefix(legacyIPTablesBackupRoot, "/")+"/"+review+"/kernel.json", []byte("{}"), 0600))
			case "intent missing after commit":
				checked(session.apply(ctx, review, ops, factory))
				checked(session.host.root.Remove(strings.TrimPrefix(legacyIPTablesBackupRoot, "/") + "/" + review + "/kernel.json"))
				writes = 0
			case "new producer during fence":
				original := factory
				factory = func(ctx context.Context, inspect func(context.Context) ([]nftGenerationRuleTarget, error)) (nftRemovalFence, error) {
					fence, err := original(ctx, inspect)
					session.producers.verify = func(context.Context) error { return errors.New("new producer") }
					return fence, err
				}
			case "journal sync failure":
				ops.checkpoint = func(point string) error {
					if point == "kernel-staged" {
						return errors.New("synthetic interruption")
					}
					return nil
				}
			}
			if err := session.apply(ctx, review, ops, factory); err == nil || writes != 0 {
				t.Fatal("unsafe recovery reached a kernel mutation", err, writes)
			}
		})
	}
}

func TestLegacyIPTablesOriginRejectsUnsupportedOrFabricatedCapture(t *testing.T) {
	for _, kind := range []string{"generation", "missing original text", "duplicate evidence", "traversal", "fingerprint", "schema", "unknown field", "duplicate field", "symlink", "hardlink"} {
		t.Run(kind, func(t *testing.T) {
			session, _ := fixtureLegacyIPTablesRecovery(t)
			document := session.origin.document
			write := true
			switch kind {
			case "generation":
				document.Generation = "v4.10.3"
			case "missing original text":
				document.Evidence = document.Evidence[:4]
			case "duplicate evidence":
				document.Evidence[1].File = document.Evidence[0].File
			case "traversal":
				document.Evidence[0].File = "../configuration.txt"
			case "fingerprint":
				document.Evidence[0].SHA256 = strings.Repeat("b", 64)
			case "schema":
				document.Schema = "operator generated current guess"
			case "symlink", "hardlink":
				write = false
				if err := session.host.root.Remove("root/iptables-capture/configuration.txt"); err != nil {
					t.Fatal(err)
				}
				var err error
				if kind == "symlink" {
					err = session.host.root.Symlink("nft-before.txt", "root/iptables-capture/configuration.txt")
				} else {
					err = session.host.root.Link("root/iptables-capture/nft-before.txt", "root/iptables-capture/configuration.txt")
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			if write {
				content, err := json.Marshal(document)
				if err != nil {
					t.Fatal(err)
				}
				if kind == "unknown field" || kind == "duplicate field" {
					field := `"unknown":true,`
					if kind == "duplicate field" {
						field = `"generation":"v4.02.8",`
					}
					content = append([]byte("{"+field), content[1:]...)
				}
				if err := session.host.root.WriteFile("root/iptables-capture/review.json", content, 0600); err != nil {
					t.Fatal(err)
				}
			}
			epoch, _ := session.epoch()
			if _, err := inspectLegacyIPTablesInputs(session.host, legacyIPTablesFixtureInput, epoch); err == nil {
				t.Fatal("unsafe or incomplete historical origin accepted")
			}
		})
	}
}

func TestLegacyIPTablesRecoveryRequiresExplicitExternalAuthorization(t *testing.T) {
	for _, test := range []struct {
		digest    string
		confirmed bool
	}{{"invalid", false}, {"invalid", true}, {strings.Repeat("a", 64), false}} {
		called := false
		prepare := func() error { called = true; return fmt.Errorf("must not run") }
		if _, err := ApplyLegacyIPTablesRecovery(context.Background(), legacyIPTablesFixtureInput, test.digest, test.confirmed, prepare); err == nil || called {
			t.Fatal("unreviewed recovery reached service preparation")
		}
	}
	session, _ := fixtureLegacyIPTablesRecovery(t)
	changed := session.record
	changed.Save += "# unexpected original observation\n"
	// Save metadata comments do not change executable rule semantics. The
	// durable record still compares exact original bytes on every retry.
	if reflect.DeepEqual(changed, session.record) {
		t.Fatal("fixture did not change")
	}
	changed.Plan = strings.Repeat("c", 64)
	if _, _, err := bindLegacyIPTablesRecovery(session.origin, session.producers.digest, changed); err == nil {
		t.Fatal("changed journal plan was trusted by digest alone")
	}
}
