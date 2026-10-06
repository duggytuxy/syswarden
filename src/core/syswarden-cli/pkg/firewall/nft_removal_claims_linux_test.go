//go:build linux

package firewall

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"syscall"
	"syswarden-cli/pkg/runtimehistory"
	"syswarden-cli/pkg/wireguardstate"
	"testing"
	"time"
)

func fixtureNativeHistoryModel(now time.Time) runtimehistory.Model {
	return runtimehistory.Model{SchemaVersion: 1, IntentFormat: 1, Identity: strings.Repeat("1", 64), Sequence: 2, UpdatedAt: now.Add(-time.Minute).Format(time.RFC3339Nano), Records: []runtimehistory.Claim{{Entry: "192.0.2.4", Generation: 1, State: "active", Cause: "verified-ban", CreatedAt: now.Add(-time.Minute).Format(time.RFC3339Nano), TransitionAt: now.Add(-time.Minute).Format(time.RFC3339Nano), ExpiresAt: now.Add(10 * time.Minute).Format(time.RFC3339Nano)}}}
}

func fixtureNativeHistoryFiles(t *testing.T, host nftPersistenceFilesystem, model runtimehistory.Model) map[string][]byte {
	t.Helper()
	frame := struct {
		Version int                    `json:"version"`
		Anchor  runtimehistory.Anchor  `json:"anchor"`
		Intent  *runtimehistory.Intent `json:"intent,omitempty"`
	}{1, runtimehistory.Anchor{Version: 1, Identity: model.Identity, Sequence: 1, Digest: strings.Repeat("2", 64)}, &runtimehistory.Intent{Entry: model.Records[0].Entry, Present: true, ExpiresAt: model.Records[0].ExpiresAt, PreparedAt: model.UpdatedAt, PreserveStronger: true}}
	payload, err := json.Marshal(frame)
	if err != nil {
		t.Fatal(err)
	}
	size := len(payload)
	if size < 1 || size > 4096-44 {
		t.Fatal("synthetic frame exceeds its fixed payload bound")
		return nil
	}
	intent := make([]byte, 4096)
	copy(intent, "SWINT001")
	binary.BigEndian.PutUint32(intent[8:12], uint32(size))
	copy(intent[44:], payload)
	sum := sha256.Sum256(intent)
	copy(intent[12:44], sum[:])
	model.RetiredIntent = fmt.Sprintf("%x", sha256.Sum256(intent))
	state, err := json.Marshal(model)
	if err != nil {
		t.Fatal(err)
	}
	state = append(state, '\n')
	anchor, err := json.Marshal(runtimehistory.Anchor{Version: 1, Identity: model.Identity, Sequence: model.Sequence, Digest: fmt.Sprintf("%x", sha256.Sum256(state))})
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{"state.json": state, "anchor.json": append(anchor, '\n'), "intent.slot": intent}
	if err := host.root.MkdirAll(nftRuntimeHistoryPath[1:], 0700); err != nil {
		t.Fatal(err)
	}
	for name, wire := range files {
		if err := host.root.WriteFile(nftRuntimeHistoryPath[1:]+"/"+name, wire, 0600); err != nil {
			t.Fatal(err)
		}
	}
	return files
}

func fixtureNativeClaimProof(t *testing.T, now time.Time, model runtimehistory.Model) *nftRuntimeClaimProof {
	t.Helper()
	proof, err := newNFTRuntimeClaimProof(&nftRuntimeHistoryLease{evidence: nftRuntimeHistoryEvidence{digest: strings.Repeat("1", 64), model: model}}, map[string]nftRuntimeCapture{"inet": {now, now.Add(100 * time.Millisecond)}, "netdev": {now, now.Add(100 * time.Millisecond)}})
	if err != nil {
		t.Fatal(err)
	}
	return proof
}

func fixtureNativeTimedElement(entry string, seconds string) any {
	return map[string]any{"elem": map[string]any{"val": entry, "timeout": json.Number("660"), "expires": json.Number(seconds)}}
}

func TestNFTRuntimeClaimsMatchExactDualStackLifetimes(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	model := fixtureNativeHistoryModel(now)
	claim := model.Records[0]
	claim.Entry, claim.ExpiresAt = "2001:db8::/64", ""
	model.Records = append(model.Records, claim)
	proof := fixtureNativeClaimProof(t, now, model)
	for _, family := range []string{"inet", "netdev"} {
		if err := proof.inspect(family, "banned_ips", []any{fixtureNativeTimedElement("192.0.2.4", "600")}); err != nil {
			t.Fatal(err)
		}
		prefix := map[string]any{"prefix": map[string]any{"addr": "2001:db8::", "len": json.Number("64")}}
		if err := proof.inspect(family, "banned_ips6", []any{prefix}); err != nil {
			t.Fatal(err)
		}
	}
	if err := proof.complete(); err != nil {
		t.Fatal(err)
	}
}

func TestNFTRuntimeClaimsRefuseForeignOrChangedPopulation(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	for _, kind := range []string{"foreign", "deleted", "duplicate", "unknown-metadata", "expired", "permanent", "missing-active", "missing-layer", "later-deadline", "earlier-deadline", "fractional", "timeout-only", "overflow", "foreign-set"} {
		t.Run(kind, func(t *testing.T) {
			model := fixtureNativeHistoryModel(now)
			if kind == "deleted" {
				model.Records[0].State = "deleted"
			}
			if kind == "expired" {
				model.Records[0].ExpiresAt = now.Add(-time.Second).Format(time.RFC3339Nano)
			}
			proof := fixtureNativeClaimProof(t, now, model)
			entries := []any{fixtureNativeTimedElement("192.0.2.4", "600")}
			name := "banned_ips"
			body := entries[0].(map[string]any)["elem"].(map[string]any)
			switch kind {
			case "foreign":
				body["val"] = "192.0.2.5"
			case "duplicate":
				entries = append(entries, entries[0])
			case "unknown-metadata":
				body["comment"] = "administrator"
			case "permanent":
				entries = []any{"192.0.2.4"}
			case "missing-active":
				entries = nil
			case "later-deadline":
				body["expires"] = json.Number("610")
			case "earlier-deadline":
				body["expires"] = json.Number("590")
			case "fractional":
				body["expires"] = json.Number("600.0")
			case "timeout-only":
				delete(body, "expires")
			case "overflow":
				body["timeout"] = json.Number("999999999999999")
			case "foreign-set":
				name = "administrator"
			}
			err := proof.inspect("inet", name, entries)
			if kind == "missing-layer" {
				if err != nil {
					t.Fatal(err)
				}
				err = proof.complete()
			}
			if err == nil {
				t.Fatal("unproven runtime population accepted")
			}
		})
	}
}

func TestNFTRuntimeClaimsAllowOnlySettledAbsence(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	for _, state := range []string{"deleted", "expired", "active"} {
		model := fixtureNativeHistoryModel(now)
		model.Records[0].State = state
		model.Records[0].ExpiresAt = now.Add(-time.Second).Format(time.RFC3339Nano)
		proof := fixtureNativeClaimProof(t, now, model)
		for _, family := range []string{"inet", "netdev"} {
			for _, name := range []string{"banned_ips", "banned_ips6"} {
				if err := proof.inspect(family, name, nil); err != nil {
					t.Fatal(err)
				}
			}
		}
		if err := proof.complete(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestNFTRuntimeHistoryLeaseBindsFilesAndExcludesWriters(t *testing.T) {
	for _, kind := range []string{"stable", "busy", "extra", "changed", "replaced", "mode", "hardlink"} {
		t.Run(kind, func(t *testing.T) {
			host, _, _ := fixtureNFTPersistenceGraphRecord(t)
			files := fixtureNativeHistoryFiles(t, host, fixtureNativeHistoryModel(time.Now().UTC()))
			if kind == "busy" {
				file, err := host.root.Open(nftRuntimeHistoryPath[1:])
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = file.Close() }()
				if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
					t.Fatal(err)
				}
				if lease, err := acquireNFTRuntimeHistory(host); err == nil {
					lease.close()
					t.Fatal("live core lease ignored")
				}
				return
			}
			lease, err := acquireNFTRuntimeHistory(host)
			if err != nil {
				t.Fatal(err)
			}
			defer lease.close()
			path := nftRuntimeHistoryPath[1:] + "/state.json"
			switch kind {
			case "extra":
				err = host.root.WriteFile(nftRuntimeHistoryPath[1:]+"/operator.txt", []byte("Keep this data.\n"), 0600)
			case "changed":
				err = host.root.WriteFile(path, append(bytes.Clone(files["state.json"]), ' '), 0600)
			case "replaced":
				if err = host.root.Remove(path); err == nil {
					err = host.root.WriteFile(path, files["state.json"], 0600)
				}
			case "mode":
				err = host.root.Chmod(path, 0644)
			case "hardlink":
				err = host.root.Link(path, "operator-history")
			}
			if err != nil {
				t.Fatal(err)
			}
			err = lease.verify()
			if (err == nil) != (kind == "stable") {
				t.Fatal("unexpected lease revalidation", kind, err)
			}
			if _, err := host.root.Lstat(path); err != nil {
				t.Fatal("verification removed source evidence", err)
			}
		})
	}
}

func TestNFTRuntimeHistoryDigestBindsPersistentFilesystemAndStrictLease(t *testing.T) {
	directory := legacyFail2banPlanDirectory{Path: nftRuntimeHistoryPath, Device: 17, Inode: 23, Mode: syscall.S_IFDIR | 0700, NLink: 2, FilesystemUUID: strings.Repeat("1", 32)}
	records := []nftPersistenceGraphSourceRecord{{Artifact: wireguardstate.Artifact{Path: nftRuntimeHistoryPath + "/state.json", Device: 17, Inode: 29, Mode: 0600, NLink: 1, SHA256: strings.Repeat("2", 64), FilesystemUUID: directory.FilesystemUUID}, Size: 512, ModifiedNS: 100, Xattrs: strings.Repeat("3", 64)}}
	durable, strict, err := nftRuntimeHistoryDigests(directory, records)
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"same", "device", "directory-uuid", "file-uuid", "directory-no-uuid", "file-no-uuid", "directory-inode", "file-inode", "content", "mode", "xattrs", "mtime", "invalid-uuid"} {
		t.Run(kind, func(t *testing.T) {
			nextDirectory := directory
			nextRecords := append([]nftPersistenceGraphSourceRecord(nil), records...)
			switch kind {
			case "device":
				nextDirectory.Device++
				nextRecords[0].Artifact.Device++
			case "directory-uuid":
				nextDirectory.FilesystemUUID = strings.Repeat("4", 32)
			case "file-uuid":
				nextRecords[0].Artifact.FilesystemUUID = strings.Repeat("4", 32)
			case "directory-no-uuid":
				nextDirectory.FilesystemUUID = ""
			case "file-no-uuid":
				nextRecords[0].Artifact.FilesystemUUID = ""
			case "directory-inode":
				nextDirectory.Inode++
			case "file-inode":
				nextRecords[0].Artifact.Inode++
			case "content":
				nextRecords[0].Artifact.SHA256 = strings.Repeat("4", 64)
			case "mode":
				nextRecords[0].Artifact.Mode = 0644
			case "xattrs":
				nextRecords[0].Xattrs = strings.Repeat("4", 64)
			case "mtime":
				nextRecords[0].ModifiedNS++
			case "invalid-uuid":
				nextRecords[0].Artifact.FilesystemUUID = "unknown"
			}
			nextDurable, nextStrict, err := nftRuntimeHistoryDigests(nextDirectory, nextRecords)
			if kind == "invalid-uuid" {
				if err == nil {
					t.Fatal("invalid filesystem identity accepted")
				}
				return
			}
			if err != nil || (nextDurable == durable) != (kind == "same" || kind == "device") || (nextStrict == strict) != (kind == "same") {
				t.Fatal("durable or operation-local identity boundary was weakened", err)
			}
		})
	}
	if records[0].Artifact.Device != 17 || directory.Device != 17 {
		t.Fatal("digest normalization changed original evidence")
	}
	// A missing persistent identity never authorizes device renumbering.
	directory.FilesystemUUID = ""
	records[0].Artifact.FilesystemUUID = ""
	durable, strict, err = nftRuntimeHistoryDigests(directory, records)
	if err != nil || durable != strict {
		t.Fatal("legacy identity did not retain strict device binding", err)
	}
	directory.Device++
	records[0].Artifact.Device++
	nextDurable, _, err := nftRuntimeHistoryDigests(directory, records)
	if err != nil || nextDurable == durable {
		t.Fatal("unproven device change accepted", err)
	}
}

func TestNFTRuntimeClaimsBindDurableKernelIntent(t *testing.T) {
	fixture := fixtureNFTCurrentFiles(t)[7]
	host, plan, guard := fixtureNFTCurrentRuntimePlan(t, fixture, true)
	fixtureNativeHistoryFiles(t, host, fixtureNativeHistoryModel(time.Now().UTC()))
	lease, err := acquireNFTRuntimeHistory(host)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.close()
	runner := fixtureNFTCurrentRuntimeRunner(fixture)
	for target, wire := range runner.tables {
		if target.family != "inet" && target.family != "netdev" || target.name == "administrator" {
			continue
		}
		document, err := decodeLegacyFail2banNFTJSON(wire)
		if err != nil {
			t.Fatal(err)
		}
		for _, raw := range document["nftables"].([]any) {
			if set, ok := raw.(map[string]any)["set"].(map[string]any); ok && set["name"] == "banned_ips" {
				set["elem"] = []any{fixtureNativeTimedElement("192.0.2.4", "600")}
			}
		}
		runner.tables[target], err = json.Marshal(document)
		if err != nil {
			t.Fatal(err)
		}
	}
	applied := false
	factory := func(ctx context.Context, inspect func(context.Context) ([]nftTableTarget, error)) (nftRemovalFence, error) {
		targets, err := inspect(ctx)
		if err != nil {
			return nil, err
		}
		return &nftRemovalFixtureFence{run: func(_ context.Context, check func() error) error {
			if err := check(); err != nil {
				return err
			}
			wire, err := host.read(legacyFail2banPlanPath(plan.sha256) + "/kernel-retirement.json")
			if err != nil {
				return err
			}
			var record nftRemovalKernelIntent
			if err := json.Unmarshal(wire, &record); err != nil {
				return err
			}
			if record.History != lease.digest() {
				return fmt.Errorf("history was not durable before native deletion")
			}
			for _, target := range targets {
				delete(runner.tables, target)
			}
			applied = true
			return nil
		}}, nil
	}
	if err := retireNFTCurrentRuntimeUsing(context.Background(), host, plan, plan.sha256, guard, runner, defaultLegacyRetirementFileOps(), factory, lease); err != nil {
		t.Fatal(err)
	}
	if !applied || len(runner.tables) != 1 {
		t.Fatal("native removal or administrator preservation was incomplete")
	}
	if _, err := os.Stat(host.root.Name() + nftRuntimeHistoryPath + "/state.json"); err != nil {
		t.Fatal("kernel cleanup removed original history", err)
	}
}
