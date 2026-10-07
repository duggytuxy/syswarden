//go:build linux

package firewall

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

const retainedLegacyFail2banFixture = `table inet syswarden_f2b {
    set f2b-syswarden-portscan { type ipv4_addr; elements = { 127.0.0.2 } }
    chain syswarden-portscan { type filter hook input priority -1; policy accept; ip saddr @f2b-syswarden-portscan drop; }
    chain administrator { type filter hook input priority -2; policy accept; ip saddr 127.0.0.3 drop; }
}
`

func TestLegacyFail2banRetainedPersistenceRequiresCompleteIndependentEvidence(t *testing.T) {
	for _, change := range []string{"none", "unretired-files", "unfinished-edit", "missing-review", "changed-source", "changed-inode", "missing-original", "wrong-path", "other-reference", "quoted-name", "kernel", "empty-kernel-remainder", "changed-during-observation"} {
		t.Run(change, func(t *testing.T) {
			host, files, kernel := fixtureLegacyFail2banNFTJournal(t, false)
			if change == "empty-kernel-remainder" {
				entries, err := legacyFail2banNFTEntries(append(append([]byte(`{"nftables":`), []byte(kernel.Plans[0].Before)...), '}'), "inet", "syswarden_f2b")
				if err != nil {
					t.Fatal(err)
				}
				var product []any
				for _, entry := range entries {
					_, table := entry.(map[string]any)["table"]
					if table || legacyFail2banNFTContains(entry, map[string]bool{"syswarden-portscan": true}) {
						product = append(product, entry)
					}
				}
				wire, err := json.Marshal(map[string]any{"nftables": product})
				if err != nil {
					t.Fatal(err)
				}
				claims, err := decodeLegacyFail2banNFTClaims([]byte(kernel.Plans[0].Claims))
				if err != nil {
					t.Fatal(err)
				}
				plan, err := prepareLegacyFail2banNFTTransition(wire, claims)
				if err != nil {
					t.Fatal(err)
				}
				kernel = makeLegacyFail2banNFTJournalRecord(kernel.Quiescence, []legacyFail2banNFTTransition{plan})
			}
			if err := host.root.WriteFile("etc/nftables.conf", []byte(retainedLegacyFail2banFixture), 0600); err != nil {
				t.Fatal(err)
			}
			loader := &nftPersistenceLoaderInspection{digest: strings.Repeat("a", 64), status: nftPersistenceLoaderStatus{entries: []string{"/etc/nftables.conf"}}}
			record, review, err := prepareLegacyFail2banPersistence(host, loader, files.sha256, kernel)
			if err != nil {
				t.Fatal(err)
			}
			guard := func() error { _, err := inspectLegacyFail2banPersistenceState(host, record, review); return err }
			if _, err := persistLegacyFail2banPersistenceReview(host, record, review, guard, defaultLegacyRetirementFileOps()); err != nil {
				t.Fatal(err)
			}
			planner := func(content []byte) (nftPersistenceEdit, error) {
				return planLegacyFail2banPersistence(content, kernel)
			}
			shared, err := prepareNFTPersistenceSharedEditUsing(host, "/etc/nftables.conf", review, guard, defaultLegacyRetirementFileOps(), planner)
			if err != nil {
				t.Fatal(err)
			}
			if change != "unfinished-edit" {
				if err := applyNFTPersistenceSharedEditUsing(host, shared, func(bool) error { return guard() }, defaultLegacyRetirementFileOps(), planner); err != nil {
					t.Fatal(err)
				}
			}
			if change != "unretired-files" {
				if err := resumeLegacyFail2banPlanUsing(host, files.sha256, acceptLegacyFail2banJournalFixture, defaultLegacyRetirementFileOps()); err != nil {
					t.Fatal(err)
				}
			}
			path := "/etc/nftables.conf"
			content, err := host.read(path)
			if err != nil {
				t.Fatal(err)
			}
			switch change {
			case "missing-review":
				err = host.root.Remove(legacyFail2banPersistencePath(files.sha256, review)[1:] + "/intent.json")
			case "changed-source":
				err = host.root.WriteFile(path[1:], append(bytes.Clone(content), '#', 'x', '\n'), 0600)
			case "changed-inode":
				err = host.root.Rename(path[1:], "etc/operator-saved.nft")
				if err == nil {
					err = host.root.WriteFile(path[1:], content, 0600)
				}
			case "missing-original":
				err = host.root.Remove(nftPersistenceSharedDirectory(shared)[1:] + "/original")
			case "wrong-path":
				path = "/etc/unreviewed.nft"
			case "other-reference":
				content = append(content, []byte("include \"/etc/syswarden-unreviewed.nft\"\n")...)
			case "quoted-name":
				content = bytes.Replace(content, []byte("table inet syswarden_f2b"), []byte("table inet \"syswarden_f2b\""), 1)
			}
			if err != nil {
				t.Fatal(err)
			}
			observations := 0
			observe := func(plan legacyFail2banNFTTransition) error {
				observations++
				if plan.table != "syswarden_f2b" || plan.sha256 != plan.digest() {
					t.Fatal("unbound table observation")
				}
				if change == "kernel" {
					return errors.New("reviewed kernel remainder changed")
				}
				if change == "changed-during-observation" {
					return host.root.WriteFile(path[1:], append(bytes.Clone(content), '#', 'x', '\n'), 0600)
				}
				return nil
			}
			unresolved := unresolvedNFTPersistentProductReferenceUsing(host, path, content, observe)
			if unresolved != (change != "none") || change == "none" && observations != 1 {
				t.Fatal("incorrect retained-table completion boundary", change, unresolved, observations)
			}
		})
	}
}

func TestLegacyFail2banRetainedKernelAllowsOnlyHandleRenumbering(t *testing.T) {
	content, claim := fixtureLegacyFail2banNFT(t, false)
	plan, err := prepareLegacyFail2banNFTTransition(content, []legacyFail2banNFTClaim{claim})
	if err != nil {
		t.Fatal(err)
	}
	after := append(append([]byte(`{"nftables":`), plan.after...), '}')
	for _, change := range []string{"none", "handles", "original-targets", "administrator-rule"} {
		t.Run(change, func(t *testing.T) {
			wire := bytes.Clone(after)
			if change == "original-targets" {
				wire = content
			} else if change != "none" {
				model, err := decodeLegacyFail2banNFTJSON(wire)
				if err != nil {
					t.Fatal(err)
				}
				for index, entry := range model["nftables"].([]any) {
					for kind, data := range entry.(map[string]any) {
						value := data.(map[string]any)
						if change == "handles" {
							value["handle"] = index + 100
						} else if kind == "rule" {
							value["expr"] = []any{map[string]any{"accept": nil}}
						}
					}
				}
				wire, err = json.Marshal(model)
				if err != nil {
					t.Fatal(err)
				}
			}
			if err := matchRetainedLegacyFail2banKernel(wire, plan); (err == nil) != (change == "none" || change == "handles") {
				t.Fatal("incorrect retained native table comparison", change, err)
			}
		})
	}
}
