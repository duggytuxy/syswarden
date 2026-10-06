//go:build linux

package firewall

import (
	"fmt"
	"strings"
	"testing"
)

func TestNFTOperatorReceiverScopedLoader(t *testing.T) {
	model, err := prepareNFTOperatorReceiver(fixtureNFTOperatorReceiverRules())
	if err != nil {
		t.Fatal(err)
	}
	receiver := "/etc/nftables.d/operator-policy.nft"
	fragment := "/etc/nftables.d/site-input.nft"
	include := "include \"" + receiver + "\"\n"
	reset := "add table inet " + model.table + "\nflush table inet " + model.table + "\n"
	administrator := "table inet administrator { chain input { type filter hook input priority -2; policy accept; ip saddr 192.0.2.9 drop; }; }\n"
	nested := "table inet administrator { chain input { type filter hook input priority -2; policy accept; include \"" + fragment + "\"\n}; }\n"
	for _, test := range []struct {
		name     string
		entry    string
		fragment string
		extra    map[string][]byte
		valid    bool
	}{
		{name: "scoped-receiver", entry: reset + include, valid: true},
		{name: "scoped-administrator", entry: "destroy table inet administrator\n" + administrator + reset + include, valid: true},
		{name: "nested-administrator", entry: nested + reset + include, fragment: "ip saddr 192.0.2.9 counter drop\n", valid: true},
		{name: "empty-administrator-fragment", entry: nested + reset + include, fragment: "# Independent administrator rules\n", valid: true},
		{name: "recursive-administrator-fragment", entry: nested + reset + include, fragment: "include \"/etc/site-more.nft\"\n", extra: map[string][]byte{"/etc/site-more.nft": []byte("ip6 saddr 2001:db8::9 drop\n")}, valid: true},
		{name: "receiver-in-top-level-branch", entry: administrator + "include \"/etc/branch.nft\"\n", extra: map[string][]byte{"/etc/branch.nft": []byte(reset + include)}, valid: true},
		{name: "scoped-comments-and-separators", entry: strings.ReplaceAll(reset, "\n", "; # Scoped reload\n\n") + include, valid: true},
		{name: "unreset-receiver", entry: administrator + include},
		{name: "unreset-nested-administrator", entry: nested + include},
		{name: "reset-after-receiver", entry: include + reset},
		{name: "flush-without-add", entry: "flush table inet " + model.table + "\n" + include},
		{name: "add-without-flush", entry: "add table inet " + model.table + "\n" + include},
		{name: "reset-wrong-family", entry: strings.ReplaceAll(reset, "inet", "ip") + include},
		{name: "reset-wrong-target", entry: strings.ReplaceAll(reset, model.table, "independent") + include},
		{name: "reset-quoted-target", entry: strings.ReplaceAll(reset, model.table, "\""+model.table+"\"") + include},
		{name: "reset-variable-target", entry: strings.ReplaceAll(reset, model.table, "$receiver") + include},
		{name: "reset-interrupted", entry: strings.Replace(reset, "\n", "\n"+administrator, 1) + include},
		{name: "reset-nonadjacent-include", entry: reset + administrator + include},
		{name: "reset-wrong-include", entry: reset + "include \"/etc/branch.nft\"\n", extra: map[string][]byte{"/etc/branch.nft": []byte(include)}},
		{name: "receiver-evaluated-twice", entry: reset + include + reset + include},
		{name: "late-global-flush", entry: reset + include + "flush ruleset\n"},
		{name: "destroy-receiver", entry: "destroy table inet " + model.table + "\n" + reset + include},
		{name: "destroy-wrong-administrator", entry: "destroy table inet other\n" + administrator + reset + include},
		{name: "destroy-wrong-family", entry: "destroy table ip administrator\n" + administrator + reset + include},
		{name: "destroy-nonadjacent", entry: "destroy table inet administrator\n" + reset + include + administrator},
		{name: "destroy-reserved-product", entry: "destroy table inet syswarden\ntable inet syswarden {}\n" + reset + include},
		{name: "destroy-reserved-vpn", entry: "destroy table inet syswarden_wg\ntable inet syswarden_wg {}\n" + reset + include},
		{name: "fragment-escapes-chain", entry: nested + reset + include, fragment: "}\nflush ruleset\n{\n"},
		{name: "fragment-declares-table", entry: nested + reset + include, fragment: administrator},
		{name: "fragment-flushes-ruleset", entry: nested + reset + include, fragment: "flush ruleset\n"},
		{name: "fragment-includes-receiver", entry: nested + reset + include, fragment: include},
		{name: "fragment-resets-receiver", entry: nested + reset + include, fragment: reset},
		{name: "fragment-has-variable", entry: nested + reset + include, fragment: "ip saddr $network drop\n"},
		{name: "fragment-in-reserved-product", entry: strings.Replace(nested, "administrator", "syswarden", 1) + reset + include, fragment: "ip saddr 192.0.2.9 drop\n"},
		{name: "fragment-reused-at-top-level", entry: nested + "include \"" + fragment + "\"\n" + reset + include, fragment: "# Context matters even for an empty fragment\n"},
		{name: "table-has-variable", entry: strings.Replace(administrator, "192.0.2.9", "$network", 1) + reset + include},
	} {
		t.Run(test.name, func(t *testing.T) {
			files := map[string][]byte{
				"/etc/nftables.conf": []byte(test.entry),
				receiver:             model.source,
				fragment:             []byte(test.fragment),
			}
			for path, content := range test.extra {
				files[path] = content
			}
			read := func(path string) (nftPersistenceRead, error) {
				content, ok := files[path]
				if !ok {
					return nftPersistenceRead{}, fmt.Errorf("missing synthetic source")
				}
				return nftPersistenceRead{content: content}, nil
			}
			graph, err := inspectNFTPersistenceGraph([]string{"/etc/nftables.conf"}, nftPersistenceGraphReader{
				read: read, expand: func(string) ([]string, error) { return nil, fmt.Errorf("no synthetic wildcard") },
			})
			if err == nil {
				err = verifyNFTOperatorReceiverGraph(model, receiver, graph, func(path string) ([]byte, error) { return files[path], nil })
			}
			if (err == nil) != test.valid {
				t.Fatalf("scoped reload boundary mismatch: valid=%v, error=%v", test.valid, err)
			}
		})
	}
}
