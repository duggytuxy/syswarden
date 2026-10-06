//go:build linux

package firewall

import (
	"crypto/sha256"
	"fmt"
	"io/fs"
	"strings"
	"testing"
)

func fixtureNFTPersistenceReader(files map[string]string, reads map[string]int) nftPersistenceGraphReader {
	return nftPersistenceGraphReader{
		read: func(path string) (nftPersistenceRead, error) {
			reads[path]++
			content, exists := files[path]
			if !exists {
				return nftPersistenceRead{}, fs.ErrNotExist
			}
			return nftPersistenceRead{content: []byte(content)}, nil
		},
		expand: func(pattern string) ([]string, error) {
			var matches []string
			for path := range files {
				match, err := matchNFTPersistenceWildcard(pattern, path)
				if err != nil {
					return nil, err
				}
				if match {
					matches = append(matches, path)
				}
			}
			return matches, nil
		},
	}
}

func TestNFTPersistenceGraphBindsIncludedFilesAndPreservesCustomPolicy(t *testing.T) {
	files := map[string]string{
		"/etc/nftables.conf":                "#!/usr/sbin/nft -f\ninclude \"/etc/nftables.d/*.nft\"\n",
		"/etc/nftables.d/10-admin.nft":      "table inet admin { chain input { type filter hook input priority 0; policy accept; } }\n",
		"/etc/nftables.d/20-historical.nft": legacyNFTIncludeMarker + "\n" + legacyNFTIncludeLine + "\n",
		legacyNFTIncludePath:                "table inet syswarden_table { chain input {} }\n",
	}
	reads := make(map[string]int)
	graph, err := inspectNFTPersistenceGraph([]string{"/etc/nftables.conf"}, fixtureNFTPersistenceReader(files, reads))
	if err != nil {
		t.Fatal(err)
	}
	if len(graph.sources) != len(files) || len(graph.expansions) != 1 || len(graph.expansions[0].paths) != 2 {
		t.Fatalf("graph is incomplete: %#v", graph)
	}
	for index, source := range graph.sources {
		if index > 0 && graph.sources[index-1].path >= source.path {
			t.Fatal("source inventory is not deterministic")
		}
		if reads[source.path] != 1 || source.sha256 != sha256.Sum256([]byte(files[source.path])) {
			t.Fatal("source evidence is not bound to one read")
		}
		if source.path == "/etc/nftables.d/20-historical.nft" {
			if len(source.edit.content) != 0 || len(source.edit.removed) != 1 {
				t.Fatal("exact marked include was not proposed for retirement")
			}
		} else if string(source.edit.content) != files[source.path] || len(source.edit.removed) != 0 {
			t.Fatal("graph proposed changing an administrator file or deleting a table by name")
		}
	}
}

func TestNFTPersistenceGraphRejectsUnsafeOrIncompleteDependencies(t *testing.T) {
	for name, files := range map[string]map[string]string{
		"missing":            {"/etc/nftables.conf": "include \"/etc/missing.nft\"\n"},
		"relative":           {"/etc/nftables.conf": "include \"custom.nft\"\n"},
		"traversal":          {"/etc/nftables.conf": "include \"/etc/sub/../custom.nft\"\n"},
		"wildcard_directory": {"/etc/nftables.conf": "include \"/etc/*/custom.nft\"\n"},
		"malformed_wildcard": {"/etc/nftables.conf": "include \"/etc/[.nft\"\n"},
		"self_cycle":         {"/etc/nftables.conf": "include \"/etc/nftables.conf\"\n"},
		"indirect_cycle": {
			"/etc/nftables.conf": "include \"/etc/other.nft\"\n",
			"/etc/other.nft":     "include \"/etc/nftables.conf\"\n",
		},
		"ambiguous_historical": {"/etc/nftables.conf": legacyNFTIncludeLine + "\n", legacyNFTIncludePath: ""},
		"invalid_nested":       {"/etc/nftables.conf": "include \"/etc/broken.nft\"\n", "/etc/broken.nft": "table inet custom {"},
	} {
		t.Run(name, func(t *testing.T) {
			graph, err := inspectNFTPersistenceGraph([]string{"/etc/nftables.conf"}, fixtureNFTPersistenceReader(files, make(map[string]int)))
			if err == nil || len(graph.sources) != 0 || len(graph.expansions) != 0 {
				t.Fatal("unverified include graph returned a partial edit plan")
			}
		})
	}
}

func TestNFTPersistenceGraphDeduplicatesReadButRetainsEmptyWildcardEvidence(t *testing.T) {
	files := map[string]string{
		"/etc/nftables.conf": "include \"/etc/a.nft\"\ninclude \"/etc/a.nft\"\ninclude \"/etc/empty/*.nft\"\n",
		"/etc/a.nft":         "# administrator fragment\n",
	}
	reads := make(map[string]int)
	graph, err := inspectNFTPersistenceGraph([]string{"/etc/nftables.conf", "/etc/a.nft"}, fixtureNFTPersistenceReader(files, reads))
	if err != nil || len(graph.sources) != 2 || reads["/etc/a.nft"] != 1 ||
		len(graph.expansions) != 1 || len(graph.expansions[0].paths) != 0 {
		t.Fatalf("duplicate or empty wildcard evidence is wrong: %#v, %v", graph, err)
	}
}

func TestNFTPersistenceGraphRejectsInvalidWildcardResults(t *testing.T) {
	for name, matches := range map[string][]string{
		"unrelated":      {"/etc/other/custom.nft"},
		"relative":       {"custom.nft"},
		"duplicate":      {"/etc/nftables.d/custom.nft", "/etc/nftables.d/custom.nft"},
		"still_wildcard": {"/etc/nftables.d/*.nft"},
		"over_limit":     make([]string, maximumNFTPersistenceFiles+1),
	} {
		t.Run(name, func(t *testing.T) {
			reader := nftPersistenceGraphReader{
				read: func(string) (nftPersistenceRead, error) {
					return nftPersistenceRead{content: []byte("include \"/etc/nftables.d/*.nft\"\n")}, nil
				},
				expand: func(string) ([]string, error) { return matches, nil },
			}
			if _, err := inspectNFTPersistenceGraph([]string{"/etc/nftables.conf"}, reader); err == nil {
				t.Fatal("invalid wildcard result was accepted")
			}
		})
	}
}

func TestNFTPersistenceGraphBoundsResourceUse(t *testing.T) {
	for _, limit := range []string{"depth", "files", "edges", "bytes"} {
		t.Run(limit, func(t *testing.T) {
			files := map[string]string{"/etc/nftables.conf": ""}
			switch limit {
			case "depth":
				previous := "/etc/nftables.conf"
				for index := 0; index <= maximumNFTPersistenceGraphDepth; index++ {
					next := fmt.Sprintf("/etc/fragment%d.nft", index)
					files[previous] = "include \"" + next + "\"\n"
					files[next] = ""
					previous = next
				}
			case "files":
				for index := 0; index < maximumNFTPersistenceFiles; index++ {
					path := fmt.Sprintf("/etc/fragment%d.nft", index)
					files["/etc/nftables.conf"] += "include \"" + path + "\"\n"
					files[path] = ""
				}
			case "edges":
				files["/etc/nftables.conf"] = strings.Repeat("include \"/etc/empty.nft\"\n", maximumNFTPersistenceIncludes+1)
				files["/etc/empty.nft"] = ""
			case "bytes":
				files["/etc/nftables.conf"] = "include \"/etc/a.nft\"\ninclude \"/etc/b.nft\"\n"
				files["/etc/a.nft"] = "#" + strings.Repeat("a", maximumNFTPersistenceBytes-1)
				files["/etc/b.nft"] = "#" + strings.Repeat("b", maximumNFTPersistenceBytes-1)
			}
			if _, err := inspectNFTPersistenceGraph([]string{"/etc/nftables.conf"}, fixtureNFTPersistenceReader(files, make(map[string]int))); err == nil {
				t.Fatal("resource limit was not enforced")
			}
		})
	}
}
