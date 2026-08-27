package main

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func newReleaseHistoryRepository(t *testing.T, version string) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	repo := t.TempDir()
	writeFixture(t, repo, version)
	for _, arguments := range [][]string{
		{"init", "-q", "-b", "main"},
		{"config", "user.name", "Release Validation Test"},
		{"config", "user.email", "release-validation@example.invalid"},
		{"add", "."},
		{"commit", "-qm", "Test : establish version baseline"},
	} {
		runTestGit(t, repo, arguments...)
	}
	return repo
}

func writeReleaseTestFile(t *testing.T, repo, path string, data []byte) {
	t.Helper()
	root, err := openRepositoryRoot(repo)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	file, err := root.OpenFile(
		filepath.FromSlash(path),
		os.O_WRONLY|os.O_CREATE|os.O_TRUNC,
		0o600,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func writeReleaseTransition(t *testing.T, repo, target string) {
	t.Helper()
	contents, err := readWorktree(repo)
	if err != nil {
		t.Fatal(err)
	}
	current, err := inspectSnapshot(contents)
	if err != nil {
		t.Fatal(err)
	}
	next, err := parseVersion(target)
	if err != nil {
		t.Fatal(err)
	}
	updated, err := replaceVersionTokens(contents, current, next)
	if err != nil {
		t.Fatal(err)
	}
	for path, data := range updated {
		writeReleaseTestFile(t, repo, path, data)
	}
	baseline, err := readRepoFile(repo, changelogPath)
	if err != nil {
		t.Fatal(err)
	}
	writeReleaseTestFile(t, repo, changelogPath, prependRelease(target, baseline))
}

func commitReleaseFixture(t *testing.T, repo, message string) {
	t.Helper()
	runTestGit(t, repo, "add", ".")
	runTestGit(t, repo, "commit", "-qm", message)
}

func tagReleaseFixture(t *testing.T, repo, tag string) {
	t.Helper()
	runTestGit(t, repo, "tag", "-am", "Version "+tag, tag)
}

func validateReleaseFixture(repo, tag string) (string, error) {
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	err := run([]string{"validate-release", "--repo", repo, "--tag", tag}, stdout, stderr)
	return stdout.String() + stderr.String(), err
}

func validateReleaseFixtureWithRewritePolicy(repo, tag string, policy changelogRewritePolicy) (string, error) {
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	app := application{
		git:                  realGit{},
		out:                  stdout,
		getenv:               os.Getenv,
		releaseRewritePolicy: &policy,
	}
	err := app.run([]string{"validate-release", "--repo", repo, "--tag", tag}, stderr)
	return stdout.String() + stderr.String(), err
}

func TestValidateReleaseAcceptsEveryBumpWithDirectAndFollowupTags(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		bump string
		tag  string
	}{
		{name: "patch", bump: "Patch : prepare release", tag: "v4.03.4"},
		{name: "minor", bump: "Minor : prepare release", tag: "v4.04.0"},
		{name: "major", bump: "Major : prepare release", tag: "v4.10.0"},
		{name: "upgrade", bump: "Upgrade : prepare release", tag: "v5.00.0"},
	}
	for _, test := range tests {
		test := test
		for _, followups := range []int{0, 2} {
			followups := followups
			t.Run(fmt.Sprintf("%s_followups_%d", test.name, followups), func(t *testing.T) {
				t.Parallel()
				repo := newReleaseHistoryRepository(t, "v4.03.3")
				writeReleaseTransition(t, repo, test.tag)
				commitReleaseFixture(t, repo, test.bump)
				for index := 0; index < followups; index++ {
					if index == 0 {
						appendTestRepoFile(t, repo, "src/core/syswarden-cli/cmd/install.go", "// reviewed release follow-up\n")
					} else {
						writeReleaseTestFile(
							t,
							repo,
							fmt.Sprintf("qualification-%d.txt", index),
							[]byte("qualified\n"),
						)
					}
					commitReleaseFixture(t, repo, fmt.Sprintf("Qualification : follow-up %d", index+1))
				}
				tagReleaseFixture(t, repo, test.tag)
				before := string(runTestGit(t, repo, "status", "--porcelain=v1"))
				output, err := validateReleaseFixture(repo, test.tag)
				if err != nil {
					t.Fatalf("validate-release: %v\n%s", err, output)
				}
				if !strings.Contains(output, fmt.Sprintf("%d non-versioning follow-up commit(s)", followups)) {
					t.Fatalf("unexpected validation output: %s", output)
				}
				after := string(runTestGit(t, repo, "status", "--porcelain=v1"))
				if before != after || after != "" {
					t.Fatalf("validate-release changed repository status: before=%q after=%q", before, after)
				}
			})
		}
	}
}

func TestValidateReleaseRejectsTagsBeforeGenericChainContract(t *testing.T) {
	t.Parallel()
	repo := newReleaseHistoryRepository(t, "v4.03.3")
	for _, tag := range []string{"v4.03.0", "v4.03.1", "v4.03.2"} {
		tag := tag
		t.Run(tag, func(t *testing.T) {
			t.Parallel()
			if _, err := validateReleaseFixture(repo, tag); err == nil ||
				!strings.Contains(err.Error(), "predates the generic release-chain contract introduced at v4.03.3") {
				t.Fatalf("historical boundary error = %v", err)
			}
		})
	}
}

func TestValidateReleasePreservesSingleUseDigestBoundV4033Rewrite(t *testing.T) {
	newPolicy := func(t *testing.T, repo string) (changelogRewritePolicy, []byte) {
		t.Helper()
		baseline, err := readRepoFile(repo, changelogPath)
		if err != nil {
			t.Fatal(err)
		}
		history := bytes.Replace(
			baseline,
			[]byte("Validate the version contract"),
			[]byte("Seal the published release status"),
			1,
		)
		return changelogRewritePolicy{
			From:          "v4.03.2",
			To:            "v4.03.3",
			BaseSHA256:    fmt.Sprintf("%x", sha256.Sum256(baseline)),
			HistorySHA256: fmt.Sprintf("%x", sha256.Sum256(history)),
		}, history
	}
	prepare := func(t *testing.T, base, target string) (string, changelogRewritePolicy, []byte) {
		t.Helper()
		repo := newReleaseHistoryRepository(t, base)
		policy, history := newPolicy(t, repo)
		writeReleaseTransition(t, repo, target)
		return repo, policy, history
	}

	t.Run("exact v4.03.2 to v4.03.3 rewrite", func(t *testing.T) {
		repo, policy, history := prepare(t, "v4.03.2", "v4.03.3")
		writeReleaseTestFile(t, repo, changelogPath, prependRelease("v4.03.3", history))
		commitReleaseFixture(t, repo, "Patch : seal history")
		tagReleaseFixture(t, repo, "v4.03.3")
		if output, err := validateReleaseFixtureWithRewritePolicy(repo, "v4.03.3", policy); err != nil {
			t.Fatalf("approved digest-bound rewrite: %v\n%s", err, output)
		}
	})

	t.Run("one byte history mutation", func(t *testing.T) {
		repo, policy, history := prepare(t, "v4.03.2", "v4.03.3")
		mutated := append([]byte(nil), history...)
		mutated[len(mutated)-2] ^= 1
		writeReleaseTestFile(t, repo, changelogPath, prependRelease("v4.03.3", mutated))
		commitReleaseFixture(t, repo, "Patch : mutate history")
		tagReleaseFixture(t, repo, "v4.03.3")
		if _, err := validateReleaseFixtureWithRewritePolicy(repo, "v4.03.3", policy); err == nil || !strings.Contains(err.Error(), "history digest does not match") {
			t.Fatalf("mutated history error = %v", err)
		}
	})

	for _, test := range []struct {
		name    string
		target  string
		message string
	}{
		{name: "does not extend to patch", target: "v4.03.4", message: "Patch : next release"},
		{name: "does not extend to minor", target: "v4.04.0", message: "Minor : next release"},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			repo, policy, history := prepare(t, "v4.03.3", test.target)
			writeReleaseTestFile(t, repo, changelogPath, prependRelease(test.target, history))
			commitReleaseFixture(t, repo, test.message)
			tagReleaseFixture(t, repo, test.target)
			if _, err := validateReleaseFixtureWithRewritePolicy(repo, test.target, policy); err == nil || !strings.Contains(err.Error(), "preserve the complete baseline") {
				t.Fatalf("reused rewrite error = %v", err)
			}
		})
	}
}

func TestValidateReleaseRejectsTagSourceAndWorktreeDrift(t *testing.T) {
	t.Parallel()
	t.Run("missing tag", func(t *testing.T) {
		repo := newReleaseHistoryRepository(t, "v4.03.3")
		writeReleaseTransition(t, repo, "v4.03.4")
		commitReleaseFixture(t, repo, "Patch : prepare release")
		if _, err := validateReleaseFixture(repo, "v4.03.4"); err == nil || !strings.Contains(err.Error(), "does not exist") {
			t.Fatalf("missing tag error = %v", err)
		}
	})

	t.Run("tag points elsewhere", func(t *testing.T) {
		repo := newReleaseHistoryRepository(t, "v4.03.3")
		writeReleaseTransition(t, repo, "v4.03.4")
		commitReleaseFixture(t, repo, "Patch : prepare release")
		tagReleaseFixture(t, repo, "v4.03.4")
		writeReleaseTestFile(t, repo, "after-tag.txt", []byte("advanced\n"))
		commitReleaseFixture(t, repo, "Qualification : advance HEAD")
		if _, err := validateReleaseFixture(repo, "v4.03.4"); err == nil || !strings.Contains(err.Error(), "does not resolve") {
			t.Fatalf("moved tag error = %v", err)
		}
	})

	t.Run("source does not match tag", func(t *testing.T) {
		repo := newReleaseHistoryRepository(t, "v4.03.3")
		writeReleaseTransition(t, repo, "v4.03.4")
		commitReleaseFixture(t, repo, "Patch : prepare release")
		tagReleaseFixture(t, repo, "v4.03.5")
		if _, err := validateReleaseFixture(repo, "v4.03.5"); err == nil || !strings.Contains(err.Error(), "does not match source version") {
			t.Fatalf("source mismatch error = %v", err)
		}
	})

	t.Run("managed worktree differs from HEAD", func(t *testing.T) {
		repo := newReleaseHistoryRepository(t, "v4.03.3")
		writeReleaseTransition(t, repo, "v4.03.4")
		commitReleaseFixture(t, repo, "Patch : prepare release")
		tagReleaseFixture(t, repo, "v4.03.4")
		appendTestRepoFile(t, repo, "src/core/syswarden-cli/cmd/install.go", "// uncommitted drift\n")
		if _, err := validateReleaseFixture(repo, "v4.03.4"); err == nil || !strings.Contains(err.Error(), "worktree do not match HEAD") {
			t.Fatalf("worktree drift error = %v", err)
		}
	})
}

func TestValidateReleaseRejectsInvalidFollowups(t *testing.T) {
	t.Parallel()
	t.Run("changelog drift", func(t *testing.T) {
		repo := newReleaseHistoryRepository(t, "v4.03.3")
		writeReleaseTransition(t, repo, "v4.03.4")
		commitReleaseFixture(t, repo, "Patch : prepare release")
		appendTestRepoFile(t, repo, changelogPath, "\n# unauthorized note\n")
		commitReleaseFixture(t, repo, "Qualification : change release notes")
		tagReleaseFixture(t, repo, "v4.03.4")
		if _, err := validateReleaseFixture(repo, "v4.03.4"); err == nil || !strings.Contains(err.Error(), "changed changelog.md") {
			t.Fatalf("changelog drift error = %v", err)
		}
	})

	t.Run("versioning prefix without bump", func(t *testing.T) {
		repo := newReleaseHistoryRepository(t, "v4.03.3")
		writeReleaseTransition(t, repo, "v4.03.4")
		commitReleaseFixture(t, repo, "Patch : prepare release")
		writeReleaseTestFile(t, repo, "metadata.txt", []byte("metadata\n"))
		commitReleaseFixture(t, repo, "Patch : metadata only")
		tagReleaseFixture(t, repo, "v4.03.4")
		if _, err := validateReleaseFixture(repo, "v4.03.4"); err == nil || !strings.Contains(err.Error(), "preserves version") {
			t.Fatalf("unchanged version error = %v", err)
		}
	})

	t.Run("malformed versioning prefix", func(t *testing.T) {
		repo := newReleaseHistoryRepository(t, "v4.03.3")
		writeReleaseTransition(t, repo, "v4.03.4")
		commitReleaseFixture(t, repo, "Patch : prepare release")
		writeReleaseTestFile(t, repo, "metadata.txt", []byte("metadata\n"))
		commitReleaseFixture(t, repo, "Patch :")
		tagReleaseFixture(t, repo, "v4.03.4")
		if _, err := validateReleaseFixture(repo, "v4.03.4"); err == nil || !strings.Contains(err.Error(), "invalid release-chain commit") {
			t.Fatalf("malformed prefix error = %v", err)
		}
	})

	t.Run("non-versioning version drift", func(t *testing.T) {
		repo := newReleaseHistoryRepository(t, "v4.03.3")
		writeReleaseTransition(t, repo, "v4.03.4")
		commitReleaseFixture(t, repo, "Patch : prepare release")
		writeReleaseTransition(t, repo, "v4.03.5")
		commitReleaseFixture(t, repo, "Qualification : unauthorized version drift")
		tagReleaseFixture(t, repo, "v4.03.5")
		if _, err := validateReleaseFixture(repo, "v4.03.5"); err == nil || !strings.Contains(err.Error(), "without a Patch, Minor, Major, or Upgrade prefix") {
			t.Fatalf("version drift error = %v", err)
		}
	})

	t.Run("partial version token drift restored before tag", func(t *testing.T) {
		repo := newReleaseHistoryRepository(t, "v4.03.3")
		writeReleaseTransition(t, repo, "v4.03.4")
		commitReleaseFixture(t, repo, "Patch : prepare release")
		path := versionTargets[0].Path
		original := readTestRepoFile(t, repo, path)
		drifted := bytes.Replace(original, []byte("v4.03.4"), []byte("v4.03.5"), 1)
		writeReleaseTestFile(t, repo, path, drifted)
		commitReleaseFixture(t, repo, "Qualification : introduce partial token drift")
		writeReleaseTestFile(t, repo, path, original)
		commitReleaseFixture(t, repo, "Qualification : restore partial token drift")
		tagReleaseFixture(t, repo, "v4.03.4")
		if _, err := validateReleaseFixture(repo, "v4.03.4"); err == nil || !strings.Contains(err.Error(), "invalid release source") {
			t.Fatalf("partial token drift error = %v", err)
		}
	})

	t.Run("README version target removed and restored before tag", func(t *testing.T) {
		repo := newReleaseHistoryRepository(t, "v4.03.3")
		writeReleaseTransition(t, repo, "v4.03.4")
		commitReleaseFixture(t, repo, "Patch : prepare release")
		path := "README.md"
		original := readTestRepoFile(t, repo, path)
		withoutVersion := bytes.Replace(
			original,
			[]byte("Current source version: **v4.03.4**.\n"),
			nil,
			1,
		)
		if bytes.Equal(withoutVersion, original) {
			t.Fatal("README fixture did not contain the scoped version target")
		}
		writeReleaseTestFile(t, repo, path, withoutVersion)
		commitReleaseFixture(t, repo, "Qualification : remove README version target")
		writeReleaseTestFile(t, repo, path, original)
		commitReleaseFixture(t, repo, "Qualification : restore README version target")
		tagReleaseFixture(t, repo, "v4.03.4")
		if _, err := validateReleaseFixture(repo, "v4.03.4"); err == nil || !strings.Contains(err.Error(), "invalid non-versioning release source") {
			t.Fatalf("restored README version target error = %v", err)
		}
	})
}

func TestValidateReleaseRejectsInvalidTransitionsAndHistoryShape(t *testing.T) {
	t.Parallel()
	t.Run("wrong bump", func(t *testing.T) {
		repo := newReleaseHistoryRepository(t, "v4.03.3")
		writeReleaseTransition(t, repo, "v4.04.0")
		commitReleaseFixture(t, repo, "Patch : wrong release class")
		tagReleaseFixture(t, repo, "v4.04.0")
		if _, err := validateReleaseFixture(repo, "v4.04.0"); err == nil || !strings.Contains(err.Error(), "requires v4.03.4") {
			t.Fatalf("wrong bump error = %v", err)
		}
	})

	t.Run("rewritten historical changelog", func(t *testing.T) {
		repo := newReleaseHistoryRepository(t, "v4.03.3")
		writeReleaseTransition(t, repo, "v4.03.4")
		path := changelogPath
		data := readTestRepoFile(t, repo, path)
		data = bytes.Replace(data, []byte("# Release v4.03.3"), []byte("# Release v4.03.2"), 1)
		writeReleaseTestFile(t, repo, path, data)
		commitReleaseFixture(t, repo, "Patch : rewrite history")
		tagReleaseFixture(t, repo, "v4.03.4")
		if _, err := validateReleaseFixture(repo, "v4.03.4"); err == nil || !strings.Contains(err.Error(), "preserve the complete baseline") {
			t.Fatalf("historical rewrite error = %v", err)
		}
	})

	t.Run("root has no transition", func(t *testing.T) {
		repo := newReleaseHistoryRepository(t, "v4.03.4")
		tagReleaseFixture(t, repo, "v4.03.4")
		if _, err := validateReleaseFixture(repo, "v4.03.4"); err == nil || !strings.Contains(err.Error(), "before repository root") {
			t.Fatalf("missing transition error = %v", err)
		}
	})

	t.Run("merge commit", func(t *testing.T) {
		repo := newReleaseHistoryRepository(t, "v4.03.3")
		writeReleaseTransition(t, repo, "v4.03.4")
		commitReleaseFixture(t, repo, "Patch : prepare release")
		runTestGit(t, repo, "checkout", "-qb", "side")
		writeReleaseTestFile(t, repo, "side.txt", []byte("side\n"))
		commitReleaseFixture(t, repo, "Qualification : side follow-up")
		runTestGit(t, repo, "checkout", "-q", "main")
		writeReleaseTestFile(t, repo, "main.txt", []byte("main\n"))
		commitReleaseFixture(t, repo, "Qualification : main follow-up")
		runTestGit(t, repo, "merge", "--no-ff", "-qm", "Qualification : merge follow-ups", "side")
		tagReleaseFixture(t, repo, "v4.03.4")
		if _, err := validateReleaseFixture(repo, "v4.03.4"); err == nil || !strings.Contains(err.Error(), "expected exactly one") {
			t.Fatalf("merge error = %v", err)
		}
	})

	t.Run("version drift restored before tag", func(t *testing.T) {
		repo := newReleaseHistoryRepository(t, "v4.03.3")
		writeReleaseTransition(t, repo, "v4.03.4")
		commitReleaseFixture(t, repo, "Patch : prepare release")
		writeReleaseTransition(t, repo, "v4.03.5")
		commitReleaseFixture(t, repo, "Qualification : introduce drift")
		writeReleaseTransition(t, repo, "v4.03.4")
		commitReleaseFixture(t, repo, "Qualification : restore drift")
		tagReleaseFixture(t, repo, "v4.03.4")
		if _, err := validateReleaseFixture(repo, "v4.03.4"); err == nil || !strings.Contains(err.Error(), "without a Patch, Minor, Major, or Upgrade prefix") {
			t.Fatalf("restored drift error = %v", err)
		}
	})
}
