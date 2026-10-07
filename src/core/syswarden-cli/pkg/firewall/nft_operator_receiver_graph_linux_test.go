//go:build linux

package firewall

import (
	"fmt"
	"strings"
	"testing"
)

func TestNFTOperatorReceiverGraphRequiresSingleStableReachability(t *testing.T) {
	model, err := prepareNFTOperatorReceiver(fixtureNFTOperatorReceiverRules())
	if err != nil {
		t.Fatal(err)
	}
	receiver := "/etc/nftables.d/operator-policy.nft"
	for _, kind := range []string{"valid", "valid-product-populations", "missing", "changed-source", "changed-after-graph", "duplicate-include", "repeated-nested-source", "cycle", "late-flush", "included-flush", "delete-table", "quoted-delete-table", "reset-rules", "extra-definition", "nested-include", "variables", "second-entry"} {
		t.Run(kind, func(t *testing.T) {
			sources := map[string][]byte{
				"/etc/nftables.conf": []byte("#!/usr/sbin/nft -f\nflush ruleset\ntable inet administrator { chain input { type filter hook input priority -2; policy accept; ip saddr 192.0.2.9 drop; } }\ninclude \"" + receiver + "\"\n"),
				receiver:             append([]byte(nil), model.source...),
			}
			entries := []string{"/etc/nftables.conf"}
			switch kind {
			case "valid-product-populations":
				sources["/etc/nftables.conf"] = append(sources["/etc/nftables.conf"], []byte("add element inet syswarden syswarden_whitelist { 192.0.2.1 }\n")...)
			case "missing":
				sources["/etc/nftables.conf"] = []byte("flush ruleset\n")
			case "changed-source":
				sources[receiver] = []byte(strings.Replace(string(model.source), "policy accept", "policy drop", 1))
			case "duplicate-include":
				sources["/etc/nftables.conf"] = append(sources["/etc/nftables.conf"], []byte("include \""+receiver+"\"\n")...)
			case "repeated-nested-source":
				sources["/etc/nftables.conf"] = []byte("include \"/etc/branch.nft\"\ninclude \"/etc/branch.nft\"\n")
				sources["/etc/branch.nft"] = []byte("include \"" + receiver + "\"\n")
			case "cycle":
				sources["/etc/nftables.conf"] = append(sources["/etc/nftables.conf"], []byte("include \"/etc/nftables.conf\"\n")...)
			case "late-flush":
				sources["/etc/nftables.conf"] = append(sources["/etc/nftables.conf"], []byte("flush ruleset\n")...)
			case "included-flush":
				sources["/etc/nftables.conf"] = append(sources["/etc/nftables.conf"], []byte("include \"/etc/late.nft\"\n")...)
				sources["/etc/late.nft"] = []byte("flush ruleset\n")
			case "delete-table":
				sources["/etc/nftables.conf"] = append(sources["/etc/nftables.conf"], []byte("delete table inet "+model.table+"\n")...)
			case "quoted-delete-table":
				sources["/etc/nftables.conf"] = append(sources["/etc/nftables.conf"], []byte("delete table inet \""+model.table+"\"\n")...)
			case "reset-rules":
				sources["/etc/nftables.conf"] = append(sources["/etc/nftables.conf"], []byte("reset rules\n")...)
			case "extra-definition":
				sources["/etc/nftables.conf"] = append(sources["/etc/nftables.conf"], model.source...)
			case "nested-include":
				sources["/etc/nftables.conf"] = []byte("table inet administrator { include \"" + receiver + "\"\n}\n")
			case "variables":
				sources["/etc/nftables.conf"] = append([]byte("define receiver = 1\n"), sources["/etc/nftables.conf"]...)
			case "second-entry":
				entries = append(entries, "/etc/other.nft")
				sources["/etc/other.nft"] = []byte("table inet independent {}\n")
			}
			read := func(path string) (nftPersistenceRead, error) {
				wire, ok := sources[path]
				if !ok {
					return nftPersistenceRead{}, fmt.Errorf("fixture source missing")
				}
				return nftPersistenceRead{content: wire}, nil
			}
			graph, err := inspectNFTPersistenceGraph(entries, nftPersistenceGraphReader{read: read, expand: func(string) ([]string, error) { return nil, fmt.Errorf("unconfigured fixture wildcard") }})
			if err == nil {
				if kind == "changed-after-graph" {
					sources[receiver] = append(sources[receiver], []byte("# Changed\n")...)
				}
				err = verifyNFTOperatorReceiverGraph(model, receiver, graph, func(path string) ([]byte, error) { file, err := read(path); return file.content, err })
			}
			wanted := kind == "valid" || kind == "valid-product-populations"
			if (err == nil) != wanted {
				t.Fatal("receiver reload boundary mismatch", kind, err)
			}
		})
	}
}
