package network

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

func intentSlotFixture(t *testing.T) (*runtimeLifecycleStore, runtimeLifecycleModel, runtimeLifecycleIntent) {
	t.Helper()
	store := openLifecycleTestStore(t, lifecyclePrivateTestDirectory(t))
	_, now := lifecycleModelFixture()
	model, err := store.initialize(now)
	if err != nil {
		t.Fatal(err)
	}
	return store, model, runtimeLifecycleIntent{Entry: "192.0.2.7", Present: true, Permanent: true, PreparedAt: now.Format(time.RFC3339Nano)}
}

func intentSlotWire(t *testing.T, frame runtimeIntentFrame) []byte {
	t.Helper()
	wire, err := encodeRuntimeIntentFrame(frame)
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func TestRuntimeIntentFrameRejectsEveryTornPrefixAndMixedSector(t *testing.T) {
	model, now := lifecycleModelFixture()
	anchor, _ := lifecycleAnchor(model)
	idle := intentSlotWire(t, runtimeIntentFrame{Version: 1, Anchor: anchor})
	intent := runtimeLifecycleIntent{Entry: "192.0.2.7", Present: true, Permanent: true, PreparedAt: now.Format(time.RFC3339Nano)}
	prepared := intentSlotWire(t, runtimeIntentFrame{Version: 1, Anchor: anchor, Intent: &intent})
	nextAnchor := anchor
	nextAnchor.Sequence++
	nextAnchor.Digest = strings.Repeat("ab", 32)
	nextIntent := intent
	nextIntent.Entry = "2001:db8::7"
	nextIntent.PreparedAt = now.Add(time.Second).Format(time.RFC3339Nano)
	next := intentSlotWire(t, runtimeIntentFrame{Version: 1, Anchor: nextAnchor, Intent: &nextIntent})
	for _, pair := range [][2][]byte{{idle, prepared}, {prepared, idle}, {prepared, next}, {next, prepared}} {
		for prefix := 0; prefix <= runtimeIntentSlotSize; prefix++ {
			mixed := bytes.Clone(pair[0])
			copy(mixed[:prefix], pair[1][:prefix])
			_, err := decodeRuntimeIntentFrame(mixed)
			if err == nil && !bytes.Equal(mixed, pair[0]) && !bytes.Equal(mixed, pair[1]) {
				t.Fatalf("partial frame accepted at prefix %d", prefix)
			}
		}
		for mask := 0; mask < 256; mask++ {
			mixed := bytes.Clone(pair[0])
			for sector := 0; sector < 8; sector++ {
				if mask&(1<<sector) != 0 {
					copy(mixed[sector*512:(sector+1)*512], pair[1][sector*512:(sector+1)*512])
				}
			}
			_, err := decodeRuntimeIntentFrame(mixed)
			if err == nil && !bytes.Equal(mixed, pair[0]) && !bytes.Equal(mixed, pair[1]) {
				t.Fatalf("mixed-sector frame accepted at mask %d", mask)
			}
		}
	}
}

func TestRuntimeIntentFrameRejectsRehashedAmbiguousPayload(t *testing.T) {
	model, _ := lifecycleModelFixture()
	anchor, _ := lifecycleAnchor(model)
	original := intentSlotWire(t, runtimeIntentFrame{Version: 1, Anchor: anchor})
	size := int(binary.BigEndian.Uint32(original[8:12]))
	payload := string(original[runtimeIntentHeader : runtimeIntentHeader+size])
	for name, corrupt := range map[string]string{
		"duplicate":         "{\"version\":1," + payload[1:],
		"alias":             strings.Replace(payload, `"version":1`, `"Version":1`, 1),
		"escaped-duplicate": "{\"\\u0076ersion\":1," + payload[1:],
		"unknown":           "{\"unexpected\":1," + payload[1:],
		"trailing":          payload + "{}",
		"null-intent":       strings.TrimSuffix(payload, "}") + ",\"intent\":null}",
	} {
		t.Run(name, func(t *testing.T) {
			wire := make([]byte, runtimeIntentSlotSize)
			copy(wire, "SWINT001")
			binary.BigEndian.PutUint32(wire[8:12], uint32(len(corrupt)))
			copy(wire[runtimeIntentHeader:], corrupt)
			digest := sha256.Sum256(wire)
			copy(wire[12:runtimeIntentHeader], digest[:])
			if _, err := decodeRuntimeIntentFrame(wire); err == nil {
				t.Fatal("ambiguous payload accepted despite canonical requirement")
			}
		})
	}
}

func TestRuntimeIntentSlotRefusesMissingUnsafeAndMismatchedStorageAfterReopen(t *testing.T) {
	for _, fault := range []string{"missing", "short", "mode", "hardlink", "symlink", "corrupt", "wrong-head"} {
		t.Run(fault, func(t *testing.T) {
			store, model, _ := intentSlotFixture(t)
			path := store.path
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			switch fault {
			case "missing":
				must(store.root.Remove(runtimeIntentSlotName))
			case "short":
				must(store.intentSlot.Truncate(100))
			case "mode":
				must(store.intentSlot.Chmod(0644))
			case "hardlink":
				must(store.root.Link(runtimeIntentSlotName, "second-slot"))
			case "symlink":
				must(store.root.Rename(runtimeIntentSlotName, "saved-slot"))
				must(store.root.Symlink("saved-slot", runtimeIntentSlotName))
			case "corrupt":
				_, err := store.intentSlot.WriteAt([]byte("x"), 100)
				must(err)
			case "wrong-head":
				anchor, _ := lifecycleAnchor(model)
				anchor.Sequence++
				must(store.writeIntentSlot(runtimeIntentFrame{Version: 1, Anchor: anchor}))
			}
			store.close()
			reopened := openLifecycleTestStore(t, path)
			if _, _, err := reopened.load(); err == nil {
				t.Fatal("new-format history silently accepted unsafe or missing slot")
			}
		})
	}
}

func TestRuntimeIntentSlotRefusesReplacementDuringInstance(t *testing.T) {
	store, _, intent := intentSlotFixture(t)
	wire, err := store.root.ReadFile(runtimeIntentSlotName)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.root.Rename(runtimeIntentSlotName, "old-slot"); err != nil {
		t.Fatal(err)
	}
	if err := store.root.WriteFile(runtimeIntentSlotName, wire, 0600); err != nil {
		t.Fatal(err)
	}
	if err := store.prepare(intent); err == nil {
		t.Fatal("live slot identity replacement was accepted")
	}
}

func TestRuntimeIntentSlotPrepareFailureNeverReachesNativeMutation(t *testing.T) {
	for _, fault := range []string{"short", "write-error", "sync-error", "readback"} {
		t.Run(fault, func(t *testing.T) {
			manager, native := lifecycleManagerFixture(t)
			switch fault {
			case "short", "write-error":
				manager.store.writeSlot = func(file *os.File, wire []byte) (int, error) {
					n, err := file.WriteAt(wire[:48], 0)
					if err == nil && fault == "write-error" {
						err = io.ErrUnexpectedEOF
					}
					return n, err
				}
			case "sync-error":
				manager.store.syncSlot = func(*os.File) error { return errors.New("injected sync failure") }
			case "readback":
				manager.store.syncSlot = func(file *os.File) error {
					if _, err := file.WriteAt([]byte("x"), 100); err != nil {
						return err
					}
					return file.Sync()
				}
			}
			if err := manager.Ban("192.0.2.7"); err == nil {
				t.Fatal("injected intent failure was ignored")
			}
			if len(native.entries) != 0 {
				t.Fatal("native mutation preceded durable verified intent")
			}
			path := manager.store.path
			manager.store.close()
			reopened := openLifecycleTestStore(t, path)
			model, pending, err := reopened.load()
			if err == nil && (pending == nil || len(model.Records) != 0) {
				t.Fatal("failed prepare was treated as a completed outcome or empty idle state")
			}
		})
	}
}

func TestRuntimeIntentSlotCommitRetiresExactFrameWithoutAnotherSlotWrite(t *testing.T) {
	store, initial, intent := intentSlotFixture(t)
	if err := store.prepare(intent); err != nil {
		t.Fatal(err)
	}
	wire, err := store.root.ReadFile(runtimeIntentSlotName)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(wire)
	now, _ := runtimeLifecycleTime(intent.PreparedAt)
	candidate, err := initial.verifiedBan(intent.Entry, now, runtimeLifecycleWitness{Complete: true, Present: true, Permanent: true})
	if err != nil {
		t.Fatal(err)
	}
	store.writeSlot = func(*os.File, []byte) (int, error) {
		t.Error("commit rewrote the intent slot")
		return 0, errors.New("unexpected write")
	}
	if err := store.commit(&candidate); err != nil {
		t.Fatal(err)
	}
	if candidate.RetiredIntent != fmt.Sprintf("%x", digest) {
		t.Fatal("durable model does not bind the exact consumed frame")
	}
	after, err := store.root.ReadFile(runtimeIntentSlotName)
	if err != nil || !bytes.Equal(wire, after) {
		t.Fatal("commit changed consumed intent bytes")
	}
	path := store.path
	store.close()
	reopened := openLifecycleTestStore(t, path)
	model, pending, err := reopened.load()
	if err != nil || pending != nil || model.RetiredIntent != candidate.RetiredIntent {
		t.Fatalf("retired frame was replayed as pending: %v", err)
	}
}

func TestRuntimeIntentSlotNoOpRetiresOnlyMetadataAndSnapshotUsesDurableDigest(t *testing.T) {
	manager, _ := lifecycleManagerFixture(t)
	before, _, err := manager.store.load()
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Unban("192.0.2.100"); err != nil {
		t.Fatal(err)
	}
	after, pending, err := manager.store.load()
	if err != nil || pending != nil || after.Sequence != before.Sequence || after.Identity != before.Identity || len(after.Records) != 0 || after.RetiredIntent == "" {
		t.Fatalf("no-op transition changed claims or lost intent: %v", err)
	}
	snapshot, err := manager.RuntimeLifecycleStateSnapshot(1024)
	if err != nil {
		t.Fatal(err)
	}
	digest, _ := after.digest()
	if snapshot.ModelSHA256 != digest {
		t.Fatal("snapshot digest differs from durable state")
	}
	if err := manager.Unban("192.0.2.101"); err != nil {
		t.Fatal(err)
	}
	final, pending, err := manager.store.load()
	if err != nil || pending != nil || final.RetiredIntent == after.RetiredIntent {
		t.Fatal("second no-op did not bind its own intent")
	}
}

func TestRuntimeIntentSlotRejectsReplayOfPreviouslyRetiredFrame(t *testing.T) {
	manager, _ := lifecycleManagerFixture(t)
	if err := manager.Ban("192.0.2.7"); err != nil {
		t.Fatal(err)
	}
	old, err := manager.store.root.ReadFile(runtimeIntentSlotName)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Unban("192.0.2.7"); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.store.intentSlot.WriteAt(old, 0); err != nil {
		t.Fatal(err)
	}
	path := manager.store.path
	manager.store.close()
	if _, _, err := openLifecycleTestStore(t, path).load(); err == nil {
		t.Fatal("stale valid frame replay was accepted")
	}
}

func TestRuntimeIntentJournalRejectsWrongRetiredFrameBeforePublishingClaims(t *testing.T) {
	store, initial, intent := intentSlotFixture(t)
	if err := store.prepare(intent); err != nil {
		t.Fatal(err)
	}
	now, _ := runtimeLifecycleTime(intent.PreparedAt)
	candidate, err := initial.verifiedBan(intent.Entry, now, runtimeLifecycleWitness{Complete: true, Present: true, Permanent: true})
	if err != nil {
		t.Fatal(err)
	}
	candidate.RetiredIntent = strings.Repeat("ab", 32)
	journal := runtimeLifecycleJournal{Version: 1, Before: &initial, Intent: &intent, Candidate: &candidate}
	if err := journal.validate(); err == nil {
		t.Fatal("wrong consumed frame was accepted")
	}
	if err := store.publish("pending.json", journal); err != nil {
		t.Fatal(err)
	}
	path := store.path
	store.close()
	reopened := openLifecycleTestStore(t, path)
	if _, _, err := reopened.load(); err == nil {
		t.Fatal("recovery admitted wrong consumed frame")
	}
	var state runtimeLifecycleModel
	if _, err := reopened.readFile("state.json", &state); err != nil || len(state.Records) != 0 {
		t.Fatal("invalid candidate changed durable claims")
	}
}

func TestRuntimeIntentSlotLossCannotBeRecreatedFromNonGenesisJournal(t *testing.T) {
	store, initial, intent := intentSlotFixture(t)
	if err := store.prepare(intent); err != nil {
		t.Fatal(err)
	}
	now, _ := runtimeLifecycleTime(intent.PreparedAt)
	candidate, err := initial.verifiedBan(intent.Entry, now, runtimeLifecycleWitness{Complete: true, Present: true, Permanent: true})
	if err != nil {
		t.Fatal(err)
	}
	store.afterPublish = func(name string) error {
		if name == "pending.json" {
			return errors.New("interrupted after witnessed candidate")
		}
		return nil
	}
	if err := store.commit(&candidate); err == nil {
		t.Fatal("fault not exercised")
	}
	if err := store.root.Remove(runtimeIntentSlotName); err != nil {
		t.Fatal(err)
	}
	path := store.path
	store.close()
	if _, _, err := openLifecycleTestStore(t, path).load(); err == nil {
		t.Fatal("non-genesis recovery recreated lost required storage")
	}
}

func TestRuntimeIntentSlotPreservesLegacyAtomicIntentRecovery(t *testing.T) {
	store := openLifecycleTestStore(t, lifecyclePrivateTestDirectory(t))
	model, now := lifecycleModelFixture()
	journal := runtimeLifecycleJournal{Version: 1, Initializing: true, Candidate: &model}
	if err := store.publish("pending.json", journal); err != nil {
		t.Fatal(err)
	}
	if err := store.finish(journal); err != nil {
		t.Fatal(err)
	}
	intent := runtimeLifecycleIntent{Entry: "192.0.2.7", Present: true, Permanent: true, PreparedAt: now.Format(time.RFC3339Nano)}
	if err := store.prepare(intent); err != nil {
		t.Fatal(err)
	}
	if _, err := store.root.Lstat("pending.json"); err != nil {
		t.Fatal("legacy intent was not atomically journaled")
	}
	if _, err := store.root.Lstat(runtimeIntentSlotName); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("legacy history was silently migrated")
	}
	path := store.path
	store.close()
	reopened := openLifecycleTestStore(t, path)
	recovered, pending, err := reopened.load()
	if err != nil || pending == nil || recovered.IntentFormat != 0 {
		t.Fatalf("legacy intent recovery changed: %v", err)
	}
	candidate, err := recovered.verifiedBan(intent.Entry, now, runtimeLifecycleWitness{Complete: true, Present: true, Permanent: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.commit(&candidate); err != nil {
		t.Fatal(err)
	}
	if _, pending, err := reopened.load(); err != nil || pending != nil {
		t.Fatalf("legacy completion failed: %v", err)
	}
}
