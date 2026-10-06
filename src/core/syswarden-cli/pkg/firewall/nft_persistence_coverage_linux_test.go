//go:build linux

package firewall

import (
	"crypto/sha256"
	"strings"
	"testing"
)

func fixtureNFTPersistenceCoverage(t *testing.T, files map[string]string) (nftPersistenceGraph, []nftPersistenceRetiredSource) {
	t.Helper()
	graph, err := inspectNFTPersistenceGraph([]string{"/etc/nftables.conf"}, fixtureNFTPersistenceReader(files, make(map[string]int)))
	if err != nil {
		t.Fatal(err)
	}
	return graph, []nftPersistenceRetiredSource{{legacyNFTIncludePath, sha256.Sum256([]byte(files[legacyNFTIncludePath]))}}
}

func TestNFTPersistenceRetirementCoverageKeepsIndependentAdministratorSources(t *testing.T) {
	files := map[string]string{
		"/etc/nftables.conf":        "include \"/etc/nftables.d/*.nft\"\n" + legacyNFTIncludeMarker + "\n" + legacyNFTIncludeLine + "\n",
		"/etc/nftables.d/admin.nft": "table inet administrator { chain input {} }\n",
		legacyNFTIncludePath:        "table inet syswarden_table { chain input {} }\n",
	}
	graph, retired := fixtureNFTPersistenceCoverage(t, files)
	if err := verifyNFTPersistenceRetirementCoverage(graph, retired); err != nil {
		t.Fatal(err)
	}
	if err := verifyNFTPersistenceRetirementCoverage(graph, nil); err == nil {
		t.Fatal("detached the fragment without explicit retirement evidence")
	}
}

func TestNFTPersistenceRetirementCoverageRejectsTransitiveAdministratorLoss(t *testing.T) {
	files := map[string]string{
		"/etc/nftables.conf": legacyNFTIncludeMarker + "\n" + legacyNFTIncludeLine + "\n",
		legacyNFTIncludePath: "table inet syswarden_table { chain input {} }\ninclude \"/etc/operator.nft\"\n",
		"/etc/operator.nft":  "table inet administrator { chain input {} }\n",
	}
	graph, retired := fixtureNFTPersistenceCoverage(t, files)
	if err := verifyNFTPersistenceRetirementCoverage(graph, retired); err == nil || !strings.Contains(err.Error(), "/etc/operator.nft") {
		t.Fatalf("lost the administrator dependency without identifying it: %v", err)
	}
	// A surviving independent path keeps the child reachable. This checks
	// dependency coverage only, not whether the mixed fragment is owned.
	files["/etc/nftables.conf"] += "include \"/etc/operator.nft\"\n"
	graph, retired = fixtureNFTPersistenceCoverage(t, files)
	if err := verifyNFTPersistenceRetirementCoverage(graph, retired); err != nil {
		t.Fatal(err)
	}
}

func TestNFTPersistenceRetirementCoverageAccountsForWildcardDeletionAndLiteralReferences(t *testing.T) {
	files := map[string]string{
		"/etc/nftables.conf":               "include \"/etc/syswarden/*.nft\"\n",
		legacyNFTIncludePath:               "table inet syswarden_table { chain input {} }\n",
		"/etc/syswarden/administrator.nft": "table inet administrator { chain input {} }\n",
	}
	graph, retired := fixtureNFTPersistenceCoverage(t, files)
	if err := verifyNFTPersistenceRetirementCoverage(graph, retired); err != nil {
		t.Fatal(err)
	}
	files["/etc/syswarden/administrator.nft"] += "include \"/etc/shared/required.nft\"\n"
	files["/etc/shared/required.nft"] = "# required administrator policy\n"
	graph, retired = fixtureNFTPersistenceCoverage(t, files)
	retired = append(retired, nftPersistenceRetiredSource{"/etc/shared/required.nft", sha256.Sum256([]byte(files["/etc/shared/required.nft"]))})
	if err := verifyNFTPersistenceRetirementCoverage(graph, retired); err == nil || !strings.Contains(err.Error(), "unresolved include") {
		t.Fatalf("left a dangling literal include: %v", err)
	}
}

func TestNFTPersistenceRetirementCoverageRejectsStaleOrAmbiguousEvidence(t *testing.T) {
	for _, change := range []string{"digest", "unknown", "duplicate", "entry", "empty", "source_duplicate", "source_digest", "wildcard_duplicate"} {
		t.Run(change, func(t *testing.T) {
			files := map[string]string{
				"/etc/nftables.conf": "include \"/etc/syswarden/*.nft\"\n",
				legacyNFTIncludePath: "table inet syswarden_table {}\n",
			}
			graph, retired := fixtureNFTPersistenceCoverage(t, files)
			switch change {
			case "digest":
				retired[0].sha256[0] ^= 1
			case "unknown":
				retired[0].path = "/etc/uninspected.nft"
			case "duplicate":
				retired = append(retired, retired[0])
			case "entry":
				retired = append(retired, nftPersistenceRetiredSource{"/etc/nftables.conf", sha256.Sum256([]byte(files["/etc/nftables.conf"]))})
			case "empty":
				graph = nftPersistenceGraph{}
			case "source_duplicate":
				graph.sources = append(graph.sources, graph.sources[0])
			case "source_digest":
				graph.sources[0].edit.originalSHA256[0] ^= 1
			case "wildcard_duplicate":
				graph.expansions = append(graph.expansions, graph.expansions[0])
			}
			if err := verifyNFTPersistenceRetirementCoverage(graph, retired); err == nil {
				t.Fatal("accepted incomplete retirement evidence")
			}
		})
	}
}
