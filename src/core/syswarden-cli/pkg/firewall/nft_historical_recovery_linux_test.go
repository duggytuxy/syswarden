//go:build linux

package firewall

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
)

const nftHistoricalCapturePath = "/root/historical-inputs/review.json"

func fixtureNFTHistoricalInputCapture(t *testing.T, host nftPersistenceFilesystem, input nftV4028PersistenceInputs) nftHistoricalInputInspection {
	t.Helper()
	if err := host.root.MkdirAll("root/historical-inputs", 0700); err != nil {
		t.Fatal(err)
	}
	// Synthetic independent evidence files. The product does not claim that a
	// file hash authenticates their origin; the operator reviews that separately.
	configuration := []byte("fixture independently retained original configuration\n")
	observations := []byte("fixture independently retained original interface and port observations\n")
	document := nftHistoricalInputDocument{nftHistoricalInputSchema, "v4.02.8", input, []nftHistoricalInputEvidence{
		{"configuration", "configuration.txt", nftSHA256Hex(configuration)},
		{"host-inputs", "observations.txt", nftSHA256Hex(observations)},
	}}
	content, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	for path, data := range map[string][]byte{"review.json": content, "configuration.txt": configuration, "observations.txt": observations} {
		if err := host.root.WriteFile("root/historical-inputs/"+path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	inspection, err := inspectNFTHistoricalInputs(host, nftHistoricalCapturePath)
	if err != nil {
		t.Fatal(err)
	}
	return inspection
}

func fixtureNFTHistoricalSourceRecovery(t *testing.T) *nftHistoricalRecovery {
	t.Helper()
	host, _, _ := fixtureNFTPersistenceGraphRecord(t)
	fixture := fixtureNFTV4028Files(t)[0]
	if err := host.root.WriteFile(legacyNFTIncludePath[1:], []byte(fixture.source), 0600); err != nil {
		t.Fatal(err)
	}
	if err := host.root.MkdirAll("var/backups", 0700); err != nil {
		t.Fatal(err)
	}
	origin := fixtureNFTHistoricalInputCapture(t, host, fixture.input)
	producers := nftRemovalProducerInspection{entries: []string{nftSharedFixturePath}, digest: strings.Repeat("a", 64), verify: func(context.Context) error { return nil }}
	session, err := prepareNFTHistoricalRecovery(context.Background(), host, origin, producers, "", func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	return session
}

func TestHistoricalInputCaptureRejectsUnsafeOrChangedEvidence(t *testing.T) {
	for _, mutation := range []string{"modified-file", "missing-file", "public-file", "public-directory", "symlink", "hardlink", "self-source", "duplicate-source", "traversal", "unknown-generation", "unknown-field", "duplicate-field", "wrong-fingerprint", "missing-evidence", "outside-root"} {
		t.Run(mutation, func(t *testing.T) {
			session := fixtureNFTHistoricalSourceRecovery(t)
			host := session.host
			document := session.origin.document
			path := nftHistoricalCapturePath
			writeDocument := false
			checked := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			switch mutation {
			case "modified-file":
				checked(host.root.WriteFile("root/historical-inputs/configuration.txt", []byte("changed"), 0600))
			case "missing-file":
				checked(host.root.Remove("root/historical-inputs/configuration.txt"))
			case "public-file":
				checked(host.root.Chmod("root/historical-inputs/configuration.txt", 0644))
			case "public-directory":
				checked(host.root.Chmod("root/historical-inputs", 0755))
			case "symlink", "hardlink":
				checked(host.root.Remove("root/historical-inputs/configuration.txt"))
				if mutation == "symlink" {
					checked(host.root.Symlink("observations.txt", "root/historical-inputs/configuration.txt"))
				} else {
					checked(host.root.Link("root/historical-inputs/observations.txt", "root/historical-inputs/configuration.txt"))
				}
			case "self-source":
				document.Evidence[0].File = "review.json"
				writeDocument = true
			case "duplicate-source":
				document.Evidence[1].File = document.Evidence[0].File
				writeDocument = true
			case "traversal":
				document.Evidence[0].File = "../operator-policy.nft"
				writeDocument = true
			case "unknown-generation":
				document.Generation = "current"
				writeDocument = true
			case "unknown-field", "duplicate-field":
				content, err := host.read(path)
				checked(err)
				prefix := `{"unknown":true,`
				if mutation == "duplicate-field" {
					prefix = `{"schema":"` + nftHistoricalInputSchema + `",`
				}
				checked(host.root.WriteFile(path[1:], append([]byte(prefix), content[1:]...), 0600))
			case "wrong-fingerprint":
				document.Evidence[0].SHA256 = strings.Repeat("f", 64)
				writeDocument = true
			case "missing-evidence":
				document.Evidence = document.Evidence[:1]
				writeDocument = true
			case "outside-root":
				path = legacyNFTIncludePath
			}
			if writeDocument {
				content, err := json.Marshal(document)
				checked(err)
				checked(host.root.WriteFile(path[1:], content, 0600))
			}
			if _, err := inspectNFTHistoricalInputs(host, path); err == nil {
				t.Fatal("unsafe historical input capture accepted")
			}
			if mutation == "modified-file" || mutation == "missing-file" || mutation == "public-file" || mutation == "public-directory" {
				if err := session.origin.verify(host); err == nil {
					t.Fatal("changed capture accepted by retained guard")
				}
			}
		})
	}
}

func TestHistoricalPersistenceRecoveryRetiresOnlyBoundSource(t *testing.T) {
	session := fixtureNFTHistoricalSourceRecovery(t)
	host := session.host
	admin, err := host.read("/root/operator-policy.nft")
	if err != nil {
		t.Fatal(err)
	}
	capture, err := host.read(nftHistoricalCapturePath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := host.root.Stat("var/backups/syswarden-retired-v1"); !os.IsNotExist(err) {
		t.Fatal("dry run wrote recovery state", err)
	}
	before, err := session.summary()
	if err != nil || before.ChangesKernelRules || before.AlreadyComplete || !before.RequiresOriginalInputReview {
		t.Fatal(before, err)
	}
	if err := session.apply(context.Background(), session.plan.sha256, defaultLegacyRetirementFileOps()); err != nil {
		t.Fatal(err)
	}
	assertNFTPersistenceRecoveryComplete(t, host, session.plan.graph, session.plan.sha256)
	for path, expected := range map[string][]byte{"/root/operator-policy.nft": admin, nftHistoricalCapturePath: capture} {
		actual, err := host.read(path)
		if err != nil || !bytes.Equal(actual, expected) {
			t.Fatal("independent source changed", path, err)
		}
	}
	resumed, err := prepareNFTHistoricalRecovery(context.Background(), host, session.origin, session.producers, session.plan.sha256, session.absent)
	if err != nil {
		t.Fatal(err)
	}
	if err := resumed.apply(context.Background(), session.plan.sha256, defaultLegacyRetirementFileOps()); err != nil {
		t.Fatal(err)
	}
	result, err := resumed.summary()
	if err != nil || !result.AlreadyComplete || result.StopsProductServices {
		t.Fatal(result, err)
	}
	wire, err := json.Marshal(result)
	if err != nil || bytes.Contains(wire, []byte("independently retained")) || bytes.Contains(wire, []byte("TCPPorts")) {
		t.Fatal("private source content exposed", err)
	}
}

func TestHistoricalPersistenceRecoveryRefusesLostAuthorityBeforeEdits(t *testing.T) {
	for _, mutation := range []string{"inputs", "producers", "runtime", "wrong-review", "current-authority", "current-journal", "current-progress", "foreign-content", "old-schema"} {
		t.Run(mutation, func(t *testing.T) {
			session := fixtureNFTHistoricalSourceRecovery(t)
			host := session.host
			reviewed := session.plan.sha256
			switch mutation {
			case "inputs":
				if err := host.root.WriteFile("root/historical-inputs/observations.txt", []byte("changed"), 0600); err != nil {
					t.Fatal(err)
				}
			case "producers":
				session.producers.verify = func(context.Context) error { return fmt.Errorf("producer resumed") }
			case "runtime":
				session.absent = func(context.Context) error { return fmt.Errorf("table appeared") }
			case "wrong-review":
				reviewed = strings.Repeat("f", 64)
			case "current-authority":
				if err := host.root.MkdirAll(strings.TrimPrefix(nftStateDirectory, "/"), 0700); err != nil {
					t.Fatal(err)
				}
				if err := host.root.WriteFile(strings.TrimPrefix(nftStateDirectory, "/")+"/"+nftPolicyOwnershipName, []byte("unrelated receipt"), 0600); err != nil {
					t.Fatal(err)
				}
			case "current-journal", "current-progress":
				path := nftTransactionJournalPath(nftStateDirectory)
				if mutation == "current-progress" {
					path = nftRemovalProgressPath
				}
				if err := host.root.MkdirAll(strings.TrimPrefix(nftStateDirectory, "/"), 0700); err != nil {
					t.Fatal(err)
				}
				if err := host.root.WriteFile(strings.TrimPrefix(path, "/"), []byte("unrelated modern state"), 0600); err != nil {
					t.Fatal(err)
				}
			case "foreign-content":
				original, err := host.read(legacyNFTIncludePath)
				if err != nil {
					t.Fatal(err)
				}
				if err := host.root.WriteFile(legacyNFTIncludePath[1:], append(original, []byte("table inet administrator {}\n")...), 0600); err != nil {
					t.Fatal(err)
				}
			case "old-schema":
				session.plan.binding.Schema = nftHistoricalPersistenceSchema
			}
			original, err := host.read(nftSharedFixturePath)
			if err != nil {
				t.Fatal(err)
			}
			if err := session.apply(context.Background(), reviewed, defaultLegacyRetirementFileOps()); err == nil {
				t.Fatal("unbound retirement accepted")
			}
			after, err := host.read(nftSharedFixturePath)
			if err != nil || !bytes.Equal(original, after) {
				t.Fatal("shared source changed on refusal", err)
			}
		})
	}
}

func TestHistoricalPersistenceRecoveryResumesEachDurabilityBoundary(t *testing.T) {
	for _, phase := range []string{"graph-plan-durable", "historical-source-staged", "historical-source-binding-durable", "shared-edit-exchanged", "graph-shared-edits-durable", "source-retired", "graph-retirement-durable"} {
		t.Run(phase, func(t *testing.T) {
			session := fixtureNFTHistoricalSourceRecovery(t)
			interrupted := errors.New("fixture interruption")
			ops := defaultLegacyRetirementFileOps()
			ops.checkpoint = func(actual string) error {
				if actual == phase {
					return interrupted
				}
				return nil
			}
			if err := session.apply(context.Background(), session.plan.sha256, ops); !errors.Is(err, interrupted) {
				t.Fatal("interruption boundary not reached", err)
			}
			resumed, err := prepareNFTHistoricalRecovery(context.Background(), session.host, session.origin, session.producers, session.plan.sha256, session.absent)
			if err != nil {
				t.Fatal("exact interrupted review did not reopen", err)
			}
			if err := resumed.apply(context.Background(), resumed.plan.sha256, defaultLegacyRetirementFileOps()); err != nil {
				t.Fatal(err)
			}
			assertNFTPersistenceRecoveryComplete(t, session.host, session.plan.graph, session.plan.sha256)
		})
	}
}

func TestHistoricalPersistenceRecoveryRefusesMissingBindingAfterEdits(t *testing.T) {
	for _, phase := range []string{"shared-edit-exchanged", "source-retired"} {
		t.Run(phase, func(t *testing.T) {
			session := fixtureNFTHistoricalSourceRecovery(t)
			interrupted := errors.New("fixture interruption")
			ops := defaultLegacyRetirementFileOps()
			ops.checkpoint = func(actual string) error {
				if actual == phase {
					return interrupted
				}
				return nil
			}
			if err := session.apply(context.Background(), session.plan.sha256, ops); !errors.Is(err, interrupted) {
				t.Fatal(err)
			}
			path := legacyFail2banPlanPath(session.plan.sha256) + "/historical-source.json"
			if err := session.host.root.Remove(strings.TrimPrefix(path, "/")); err != nil {
				t.Fatal(err)
			}
			before, err := session.host.read(nftSharedFixturePath)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := prepareNFTHistoricalRecovery(context.Background(), session.host, session.origin, session.producers, session.plan.sha256, session.absent); err == nil {
				t.Fatal("missing original binding was reconstructed after active edits")
			}
			after, err := session.host.read(nftSharedFixturePath)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("shared file changed on refusal", err)
			}
		})
	}
}

func TestHistoricalInputCapturePreservesOpaqueOriginalConfiguration(t *testing.T) {
	session := fixtureNFTHistoricalSourceRecovery(t)
	original := []byte("[administrator]\ninclude = \"/original/configuration\"\n")
	document := session.origin.document
	document.Evidence[0].SHA256 = nftSHA256Hex(original)
	description, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := session.host.root.WriteFile("root/historical-inputs/configuration.txt", original, 0600); err != nil {
		t.Fatal(err)
	}
	if err := session.host.root.WriteFile(nftHistoricalCapturePath[1:], description, 0600); err != nil {
		t.Fatal(err)
	}
	inspection, err := inspectNFTHistoricalInputs(session.host, nftHistoricalCapturePath)
	if err != nil {
		t.Fatal("opaque original configuration was interpreted as nftables source", err)
	}
	if err := inspection.verify(session.host); err != nil {
		t.Fatal(err)
	}
	retained, err := session.host.read("/root/historical-inputs/configuration.txt")
	if err != nil || !bytes.Equal(retained, original) {
		t.Fatal("original evidence changed", err)
	}
	if err := session.host.root.WriteFile("root/historical-inputs/configuration.txt", append(original, '#'), 0600); err != nil {
		t.Fatal(err)
	}
	if err := inspection.verify(session.host); err == nil {
		t.Fatal("changed opaque evidence was accepted")
	}
}
