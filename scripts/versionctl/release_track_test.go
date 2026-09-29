package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func resolveTrackFixture(repo, tag string) (releaseTrackDecision, string, error) {
	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	err := run([]string{"release-track", "--repo", repo, "--tag", tag}, stdout, stderr)
	var result releaseTrackDecision
	if err == nil {
		err = json.Unmarshal(stdout.Bytes(), &result)
	}
	return result, stdout.String(), err
}

func TestReleaseTrackUsesOriginatingTransitionBeforeAndAfterTag(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ prefix, previous, target, track string }{
		{"Patch", "v4.03.3", "v4.03.4", "intermediate-validation"},
		{"Minor", "v4.03.3", "v4.04.0", "intermediate-validation"},
		{"Major", "v4.03.3", "v4.10.0", "intermediate-validation"},
		{"Upgrade", "v4.10.0", "v5.00.0", "full-qualification"},
		{"Upgrade", "v5.32.7", "v6.00.0", "full-qualification"},
	} {
		t.Run(tc.prefix+tc.target, func(t *testing.T) {
			t.Parallel()
			repo := newReleaseHistoryRepository(t, tc.previous)
			parent := strings.TrimSpace(string(runTestGit(t, repo, "rev-parse", "HEAD")))
			writeReleaseTransition(t, repo, tc.target)
			commitReleaseFixture(t, repo, tc.prefix+" : prepare generation or intermediate release")
			origin := strings.TrimSpace(string(runTestGit(t, repo, "rev-parse", "HEAD")))
			for i := 0; i < 3; i++ {
				writeReleaseTestFile(t, repo, fmt.Sprintf("followup-%d.txt", i), []byte("reviewed correction\n"))
				commitReleaseFixture(t, repo, "Fix : reviewed corrective PR")
			}
			head := strings.TrimSpace(string(runTestGit(t, repo, "rev-parse", "HEAD")))
			for _, tagged := range []bool{false, true} {
				if tagged {
					tagReleaseFixture(t, repo, tc.target)
				}
				before := string(runTestGit(t, repo, "status", "--porcelain=v1"))
				result, wire, err := resolveTrackFixture(repo, tc.target)
				if err != nil {
					t.Fatalf("release-track: %v", err)
				}
				if result.Schema != "syswarden-release-track/v1" || result.Prefix != BumpType(tc.prefix) || result.Track != tc.track || result.Release != tc.target || result.PreviousVersion != tc.previous || result.FollowupCommits != 3 || result.TransitionCommit != origin || result.TransitionParent != parent || result.CandidateCommit != head {
					t.Fatalf("incorrect provenance or selection: %s", wire)
				}
				if result.QualificationPassed || result.PublicationAuthorized {
					t.Fatal("classification granted acceptance")
				}
				after := string(runTestGit(t, repo, "status", "--porcelain=v1"))
				if before != after || after != "" {
					t.Fatalf("repository changed: %q -> %q", before, after)
				}
				if !tagged {
					if _, err := validateReleaseFixture(repo, tc.target); err == nil {
						t.Fatal("existing tag requirement was weakened")
					}
					if got := string(runTestGit(t, repo, "tag", "--list", tc.target)); got != "" {
						t.Fatal("classification created a tag")
					}
				}
			}
		})
	}
}

func TestReleaseTrackRejectsInvalidTransitionsWithoutJSON(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ name, message, target string }{
		{"major_cannot_change_generation", "Major : new generation", "v5.00.0"},
		{"upgrade_cannot_stay_in_generation", "Upgrade : intermediate", "v4.10.0"},
		{"body_is_not_a_prefix", "Docs : release proposal\n\nUpgrade : next generation", "v5.00.0"},
		{"unknown_prefix", "Release : new generation", "v5.00.0"},
		{"empty_upgrade_description", "Upgrade :", "v5.00.0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			repo := newReleaseHistoryRepository(t, "v4.03.3")
			writeReleaseTransition(t, repo, tc.target)
			commitReleaseFixture(t, repo, tc.message)
			_, wire, err := resolveTrackFixture(repo, tc.target)
			if err == nil || wire != "" {
				t.Fatalf("invalid transition emitted classification: %q, %v", wire, err)
			}
		})
	}
}

func TestReleaseTrackRejectsMisleadingFollowupAndSource(t *testing.T) {
	t.Parallel()
	for _, mutation := range []string{"versioning-followup", "wrong-tag", "dirty-source", "dirty-changelog", "moved-existing-tag"} {
		t.Run(mutation, func(t *testing.T) {
			t.Parallel()
			repo := newReleaseHistoryRepository(t, "v4.10.0")
			writeReleaseTransition(t, repo, "v5.00.0")
			commitReleaseFixture(t, repo, "Upgrade : new generation")
			requested := "v5.00.0"
			switch mutation {
			case "versioning-followup":
				writeReleaseTestFile(t, repo, "fix.txt", []byte("correction"))
				commitReleaseFixture(t, repo, "Patch : pretend this is intermediate")
			case "wrong-tag":
				requested = "v5.01.0"
			case "dirty-source":
				appendTestRepoFile(t, repo, "src/core/syswarden-cli/cmd/install.go", "// changed after HEAD\n")
			case "dirty-changelog":
				appendTestRepoFile(t, repo, changelogPath, "\nchanged\n")
			case "moved-existing-tag":
				tagReleaseFixture(t, repo, requested)
				writeReleaseTestFile(t, repo, "fix.txt", []byte("correction"))
				commitReleaseFixture(t, repo, "Fix : correction after tag")
			}
			_, wire, err := resolveTrackFixture(repo, requested)
			if err == nil || wire != "" {
				t.Fatalf("invalid context emitted classification: %q, %v", wire, err)
			}
		})
	}
}

func TestReleaseTrackArithmeticExamples(t *testing.T) {
	for _, tc := range []struct {
		bump           BumpType
		version, track string
	}{
		{BumpPatch, "v0.00.1", "intermediate-validation"},
		{BumpMinor, "v0.01.0", "intermediate-validation"},
		{BumpMajor, "v0.10.0", "intermediate-validation"},
		{BumpUpgrade, "v1.00.0", "full-qualification"},
	} {
		version, err := nextVersion(Version{}, tc.bump)
		if err != nil || version.String() != tc.version {
			t.Fatalf("arithmetic %s: %s %v", tc.bump, version, err)
		}
		track, err := releaseTrackForBump(tc.bump)
		if err != nil || track != tc.track {
			t.Fatalf("track %s: %s %v", tc.bump, track, err)
		}
	}
	if _, err := releaseTrackForBump("Release"); err == nil {
		t.Fatal("unknown prefix accepted")
	}
}
