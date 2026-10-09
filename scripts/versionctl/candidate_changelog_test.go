package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

func changelogTestDigest(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func candidateChangelogFixture(t *testing.T) (string, []byte, []byte, candidateChangelogPolicy) {
	t.Helper()
	repo := newReleaseHistoryRepository(t, "v4.10.2")
	writeReleaseTransition(t, repo, "v4.10.3")
	commitReleaseFixture(t, repo, "Patch : prepare an intermediate correction")
	base := readTestRepoFile(t, repo, changelogPath)
	candidate := bytes.Replace(base, []byte("- **CI/CD:**"), []byte("- Record the reviewed correction.\n- **CI/CD:**"), 1)
	if bytes.Equal(base, candidate) {
		t.Fatal("fixture did not change the active release block")
	}
	_, history, ok := bytes.Cut(base, []byte("\n---\n"))
	if !ok {
		t.Fatal("fixture has no release separator")
	}
	policy := candidateChangelogPolicy{
		ParentSHA:       strings.TrimSpace(string(runTestGit(t, repo, "rev-parse", "HEAD"))),
		Version:         "v4.10.3",
		Subject:         "Docs : complete the v4.10.3 correction record",
		BaseSHA256:      changelogTestDigest(base),
		CandidateSHA256: changelogTestDigest(candidate),
		HistorySHA256:   changelogTestDigest(history),
	}
	return repo, base, candidate, policy
}

func TestCandidateChangelogCorrectionRejectsUnboundChanges(t *testing.T) {
	t.Parallel()
	_, base, candidate, approved := candidateChangelogFixture(t)
	version, err := parseVersion(approved.Version)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		"exact", "squash", "body", "parent", "version", "subject", "prefix",
		"suffix", "zero-pr", "leading-zero-pr", "multiple-suffixes", "changed-base",
		"changed-candidate", "unchanged", "history", "missing-separator",
		"history-digest", "invalid-parent-policy", "invalid-digest-policy",
	} {
		t.Run(name, func(t *testing.T) {
			policy := approved
			parent, previous, current := policy.ParentSHA, version, version
			message := policy.Subject
			old, next := bytes.Clone(base), bytes.Clone(candidate)
			wantError := true
			switch name {
			case "exact":
				wantError = false
			case "squash":
				message += " (#123)"
				wantError = false
			case "body":
				message += "\n\nReview context."
				wantError = false
			case "parent":
				parent = strings.Repeat("f", 40)
			case "version":
				current.Patch++
			case "subject":
				message = "Docs : unrelated changes"
			case "prefix":
				message = "Patch : complete the v4.10.3 correction record"
			case "suffix":
				message += " and other changes"
			case "zero-pr":
				message += " (#0)"
			case "leading-zero-pr":
				message += " (#0123)"
			case "multiple-suffixes":
				message += " (#123) (#456)"
			case "changed-base":
				old = append(old, '\n')
			case "changed-candidate":
				next = append(next, '\n')
			case "unchanged":
				next = bytes.Clone(old)
				policy.CandidateSHA256 = policy.BaseSHA256
			case "history":
				next = append(next, []byte("Historical change.\n")...)
				policy.CandidateSHA256 = changelogTestDigest(next)
			case "missing-separator":
				old = bytes.ReplaceAll(old, []byte("\n---\n"), []byte("\n"))
				policy.BaseSHA256 = changelogTestDigest(old)
			case "history-digest":
				policy.HistorySHA256 = strings.Repeat("0", 64)
			case "invalid-parent-policy":
				policy.ParentSHA = "main"
			case "invalid-digest-policy":
				policy.CandidateSHA256 = "not-a-digest"
			}
			err := validateCandidateChangelogCorrection(policy, parent, previous, current, message, old, next)
			if (err != nil) != wantError {
				t.Fatalf("correction error = %v, want error %t", err, wantError)
			}
		})
	}
}

func TestCandidateChangelogCommitRequiresUnpublishedImmediateParent(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"prospective", "committed", "squash", "existing-tag", "later-parent", "dirty-commit", "wrong-actual-subject", "tag-error"} {
		t.Run(name, func(t *testing.T) {
			repo, base, candidate, policy := candidateChangelogFixture(t)
			message := policy.Subject
			if name == "squash" {
				message += " (#123)"
			}
			writeReleaseTestFile(t, repo, changelogPath, candidate)
			switch name {
			case "committed", "squash":
				commitReleaseFixture(t, repo, message)
			case "existing-tag":
				tagReleaseFixture(t, repo, policy.Version)
			case "later-parent":
				commitReleaseFixture(t, repo, message)
				writeReleaseTestFile(t, repo, "later.txt", []byte("Later change.\n"))
				commitReleaseFixture(t, repo, "Docs : later change")
			case "dirty-commit":
				writeReleaseTestFile(t, repo, changelogPath, base)
				writeReleaseTestFile(t, repo, "other.txt", []byte("Other change.\n"))
				commitReleaseFixture(t, repo, message)
				writeReleaseTestFile(t, repo, changelogPath, candidate)
			case "wrong-actual-subject":
				commitReleaseFixture(t, repo, "Docs : unrelated commit")
			}
			var git gitClient = realGit{}
			if name == "tag-error" {
				git = failingCandidateTagGit{}
			}
			output := &bytes.Buffer{}
			app := application{git: git, out: output, candidateFollowupPolicy: &policy}
			err := app.run([]string{"validate-commit", "--repo", repo, "--base-ref", policy.ParentSHA, "--commit-message", message}, &bytes.Buffer{})
			wantError := name != "prospective" && name != "committed" && name != "squash"
			if (err != nil) != wantError {
				t.Fatalf("validation error = %v, want error %t, output %s", err, wantError, output)
			}
			if wantError && output.Len() != 0 {
				t.Fatalf("refused correction emitted success: %s", output)
			}
		})
	}
}

type failingCandidateTagGit struct{ realGit }

func (failingCandidateTagGit) tagExists(string, string) (bool, error) {
	return false, errors.New("tag observation failed")
}

func TestCandidateChangelogReleaseKeepsOriginalPatchAndRejectsReplay(t *testing.T) {
	t.Parallel()
	repo, base, candidate, policy := candidateChangelogFixture(t)
	writeReleaseTestFile(t, repo, changelogPath, candidate)
	commitReleaseFixture(t, repo, policy.Subject+" (#123)")
	output := &bytes.Buffer{}
	app := application{git: realGit{}, out: output, candidateFollowupPolicy: &policy}
	args := []string{"release-track", "--repo", repo, "--tag", policy.Version}
	if err := app.run(args, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), `"prefix":"Patch"`) || !strings.Contains(output.String(), `"track":"intermediate-validation"`) {
		t.Fatalf("correction changed the release track: %s", output)
	}
	tagReleaseFixture(t, repo, policy.Version)
	if err := app.run([]string{"validate-release", "--repo", repo, "--tag", policy.Version}, &bytes.Buffer{}); err != nil {
		t.Fatalf("original correction must remain verifiable at its release tag: %v", err)
	}
	runTestGit(t, repo, "tag", "-d", policy.Version)
	writeReleaseTestFile(t, repo, changelogPath, base)
	commitReleaseFixture(t, repo, "Docs : try to reset the correction")
	writeReleaseTestFile(t, repo, changelogPath, candidate)
	commitReleaseFixture(t, repo, policy.Subject)
	output.Reset()
	if err := app.run(args, &bytes.Buffer{}); err == nil || output.Len() != 0 {
		t.Fatalf("release chain accepted a replay: error %v, output %s", err, output)
	}
}

func TestCandidateChangelogProductionPolicyIsBounded(t *testing.T) {
	want := candidateChangelogPolicy{
		ParentSHA:       "703d767f3379056df52ac3f84307382ec9342b9a",
		Version:         "v4.10.3",
		Subject:         "Docs : complete the v4.10.3 correction record",
		BaseSHA256:      "b8e6c41f6fbc1196908881f83a64092dd1c186852396b66bb07ca47a749f5dfe",
		CandidateSHA256: "251666fea4e76954ba3b410827be06b162e73c2696327975ebfc0a00afe29ebd",
		HistorySHA256:   "bb34967be4fe79304870e516e510f18df5234829aaa6ac98c02cae94a3695208",
	}
	if approvedCandidateChangelog != want {
		t.Fatalf("unreviewed candidate policy: %#v", approvedCandidateChangelog)
	}
}

func TestCandidateChangelogV4104PolicyIsBoundToItsOwnParent(t *testing.T) {
	want := candidateChangelogPolicy{
		ParentSHA:       "edf8b40a7bdd011ee788704ba30d8b355234e473",
		Version:         "v4.10.4",
		Subject:         "Fix : complete v4.10.4 security and mirror corrections",
		BaseSHA256:      "15b4656cd27f53f93232f09763a333f865e722f9b6230f6bd10d01dfef058c64",
		CandidateSHA256: "cfdf9aed98c78348ad1ef41069b5109a90b6de7f38b1663af9976a68315cac5d",
		HistorySHA256:   "6c403f15b332d5b201a986a3554ea91ebd35308c710737a18096739298e1f2bd",
	}
	app := application{}
	if approvedCandidateChangelogV4104 != want || app.candidateChangelogPolicy(want.ParentSHA) != want {
		t.Fatal("v4.10.4 correction differs from its exact policy")
	}
	if app.candidateChangelogPolicy(approvedCandidateChangelog.ParentSHA) != approvedCandidateChangelog {
		t.Fatal("historical v4.10.3 correction policy changed")
	}
	if app.candidateChangelogPolicy(strings.Repeat("f", 40)) == want {
		t.Fatal("v4.10.4 correction was selected for an unrelated parent")
	}
}
