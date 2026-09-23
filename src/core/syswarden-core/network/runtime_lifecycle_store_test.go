package network

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRuntimeLifecycleCanonicalReadRejectsAmbiguousTypedAndRawJSON(t *testing.T) {
	model, now := lifecycleModelFixture()
	model, err := model.verifiedBan("192.0.2.7", now, runtimeLifecycleWitness{Complete: true, Present: true, Permanent: true})
	if err != nil {
		t.Fatal(err)
	}
	anchor, err := lifecycleAnchor(model)
	if err != nil {
		t.Fatal(err)
	}
	journal := runtimeLifecycleJournal{Version: 1, Before: &model, Intent: &runtimeLifecycleIntent{
		Entry: "192.0.2.7", Present: true, Permanent: true, PreparedAt: now.Format(time.RFC3339Nano),
	}}
	for _, schema := range []struct {
		name        string
		value       any
		destination func() any
	}{
		{"state", model, func() any { return new(runtimeLifecycleModel) }},
		{"anchor", anchor, func() any { return new(runtimeLifecycleAnchor) }},
		{"journal", journal, func() any { return new(runtimeLifecycleJournal) }},
		{"raw", journal, func() any { return new(json.RawMessage) }},
	} {
		t.Run(schema.name, func(t *testing.T) {
			store := openLifecycleTestStore(t, lifecyclePrivateTestDirectory(t))
			wire, err := json.Marshal(schema.value)
			if err != nil {
				t.Fatal(err)
			}
			canonical := string(wire) + "\n"
			if err := store.root.WriteFile("fixture.json", []byte(canonical), 0600); err != nil {
				t.Fatal(err)
			}
			if exists, err := store.readFile("fixture.json", schema.destination()); err != nil || !exists {
				t.Fatalf("canonical fixture rejected: %v", err)
			}
			firstKeyEnd := strings.Index(canonical, ":1,")
			if firstKeyEnd < 0 {
				t.Fatal("fixture must begin with version 1")
			}
			firstField := canonical[1 : firstKeyEnd+3]
			cases := map[string]string{
				"duplicate-top-level": "{" + firstField + canonical[1:],
				"trailing-document":   canonical + "{}\n",
			}
			if strings.Contains(canonical, `"entry":"192.0.2.7"`) {
				cases["duplicate-nested"] = strings.Replace(canonical, `"entry":"192.0.2.7"`, `"entry":"192.0.2.7","entry":"192.0.2.7"`, 1)
				cases["escaped-duplicate-nested"] = strings.Replace(canonical, `"entry":"192.0.2.7"`, `"\u0065ntry":"192.0.2.8","entry":"192.0.2.7"`, 1)
			}
			if schema.name != "raw" {
				cases["unknown-field"] = `{"extra":true,` + canonical[1:]
				cases["case-alias"] = strings.Replace(canonical, `"sequence":`, `"Sequence":`, 1)
				cases["missing-field"] = "{" + canonical[firstKeyEnd+3:]
			}
			for name, corrupt := range cases {
				t.Run(name, func(t *testing.T) {
					if corrupt == canonical {
						t.Fatal("corruption was not exercised")
					}
					if err := store.root.WriteFile("fixture.json", []byte(corrupt), 0600); err != nil {
						t.Fatal(err)
					}
					if _, err := store.readFile("fixture.json", schema.destination()); err == nil {
						t.Fatal("ambiguous or noncanonical JSON was accepted")
					}
				})
			}
		})
	}
}

func lifecyclePrivateTestDirectory(t *testing.T) string {
	t.Helper()
	path, err := os.MkdirTemp("", "sw-lifecycle-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(path) })
	return path
}

func openLifecycleTestStore(t *testing.T, path string) *runtimeLifecycleStore {
	t.Helper()
	store, err := openRuntimeLifecycleStore(path, os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.close)
	return store
}

func TestRuntimeLifecycleStoreRecoversEveryWitnessedPublicationBoundary(t *testing.T) {
	for _, boundary := range []string{"pending.json", "state.json", "anchor.json"} {
		t.Run(boundary, func(t *testing.T) {
			path := lifecyclePrivateTestDirectory(t)
			store := openLifecycleTestStore(t, path)
			_, now := lifecycleModelFixture()
			initial, err := store.initialize(now)
			if err != nil {
				t.Fatal(err)
			}
			intent := runtimeLifecycleIntent{Entry: "192.0.2.7", Present: true, Permanent: true, PreparedAt: now.Format(time.RFC3339Nano)}
			if err := store.prepare(intent); err != nil {
				t.Fatal(err)
			}
			candidate, err := initial.verifiedBan(intent.Entry, now, runtimeLifecycleWitness{Complete: true, Present: true, Permanent: true})
			if err != nil {
				t.Fatal(err)
			}
			store.afterPublish = func(name string) error {
				if name == boundary {
					return errors.New("simulated process loss after durable publication")
				}
				return nil
			}
			if err := store.commit(candidate); err == nil {
				t.Fatal("publication fault was not exercised")
			}
			store.close()
			reopened := openLifecycleTestStore(t, path)
			recovered, pending, err := reopened.load()
			if err != nil || pending != nil || len(recovered.Records) != 1 || recovered.Records[0].State != "active" {
				t.Fatalf("witnessed transaction did not recover: %+v, %+v, %v", recovered, pending, err)
			}
			want, _ := candidate.digest()
			got, _ := recovered.digest()
			if got != want {
				t.Fatal("recovery changed the witnessed model")
			}
			if _, err := reopened.root.Lstat("pending.json"); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("recovered WAL was not retired: %v", err)
			}
		})
	}
}

func TestRuntimeLifecycleStoreNeverTurnsAnIntentIntoEvidence(t *testing.T) {
	path := lifecyclePrivateTestDirectory(t)
	store := openLifecycleTestStore(t, path)
	_, now := lifecycleModelFixture()
	if _, err := store.initialize(now); err != nil {
		t.Fatal(err)
	}
	intent := runtimeLifecycleIntent{Entry: "192.0.2.7", Present: true, ExpiresAt: now.Add(time.Minute).Format(time.RFC3339Nano), PreparedAt: now.Format(time.RFC3339Nano)}
	if err := store.prepare(intent); err != nil {
		t.Fatal(err)
	}
	store.close()
	reopened := openLifecycleTestStore(t, path)
	model, pending, err := reopened.load()
	if err != nil || pending == nil || pending.Candidate != nil || len(model.Records) != 0 {
		t.Fatalf("unwitnessed intent became an active claim: %+v, %+v, %v", model, pending, err)
	}
	if err := reopened.prepare(intent); err == nil {
		t.Fatal("new mutation replaced unrecovered intent")
	}
}

func TestRuntimeLifecycleStoreRejectsLossTamperingAndConcurrentInstances(t *testing.T) {
	for _, fault := range []string{"missing-state", "missing-anchor", "corrupt-state", "unknown-field", "duplicate-field", "hardlink", "symlink", "second-instance", "directory-replacement"} {
		t.Run(fault, func(t *testing.T) {
			parent := t.TempDir()
			parentRoot, err := os.OpenRoot(parent)
			if err != nil {
				t.Fatal(err)
			}
			defer parentRoot.Close()
			if err := parentRoot.Mkdir("history", 0700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(parent, "history")
			store := openLifecycleTestStore(t, path)
			_, now := lifecycleModelFixture()
			if _, err := store.initialize(now); err != nil {
				t.Fatal(err)
			}
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			switch fault {
			case "missing-state":
				must(store.root.Remove("state.json"))
			case "missing-anchor":
				must(store.root.Remove("anchor.json"))
			case "corrupt-state", "unknown-field", "duplicate-field":
				wire, err := store.root.ReadFile("state.json")
				must(err)
				corrupt := strings.Replace(string(wire), `"sequence":1`, `"sequence":2`, 1)
				if fault == "unknown-field" {
					corrupt = strings.Replace(string(wire), "{", `{"unexpected":true,`, 1)
				}
				if fault == "duplicate-field" {
					corrupt = strings.Replace(string(wire), "{", `{"sequence":1,`, 1)
				}
				must(store.root.WriteFile("state.json", []byte(corrupt), 0600))
			case "hardlink":
				must(store.root.Link("state.json", "second-link.json"))
			case "symlink":
				must(store.root.Rename("state.json", "saved.json"))
				must(store.root.Symlink("saved.json", "state.json"))
			case "second-instance":
				second, err := openRuntimeLifecycleStore(path, os.Geteuid())
				if err == nil {
					second.close()
					t.Fatal("second runtime acquired a live store")
				}
				return
			case "directory-replacement":
				must(parentRoot.Rename("history", "displaced"))
				must(parentRoot.Mkdir("history", 0700))
			}
			if _, _, err := store.load(); err == nil {
				t.Fatal("untrusted or lost history was accepted")
			}
		})
	}
}

func TestRuntimeLifecycleStoreGenesisRecoveryAndNoSilentReset(t *testing.T) {
	for _, boundary := range []string{"pending.json", "state.json", "anchor.json"} {
		t.Run(boundary, func(t *testing.T) {
			path := lifecyclePrivateTestDirectory(t)
			store := openLifecycleTestStore(t, path)
			if _, _, err := store.load(); err == nil {
				t.Fatal("existing empty directory silently initialized history")
			}
			store.afterPublish = func(name string) error {
				if name == boundary {
					return errors.New("simulated genesis publication failure")
				}
				return nil
			}
			_, now := lifecycleModelFixture()
			if _, err := store.initialize(now); err == nil {
				t.Fatal("genesis fault was not exercised")
			}
			store.close()
			reopened := openLifecycleTestStore(t, path)
			model, pending, err := reopened.load()
			if err != nil || pending != nil || model.Sequence != 1 || len(model.Records) != 0 {
				t.Fatalf("genesis did not recover: %+v, %v", model, err)
			}
			if _, err := reopened.initialize(now); err == nil {
				t.Fatal("existing history was reset")
			}
		})
	}
}
