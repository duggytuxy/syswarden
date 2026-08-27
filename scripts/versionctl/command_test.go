package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type fakeGit struct {
	base           snapshot
	tags           map[string]bool
	headMatchesTag bool
	lock           string
	fileErr        error
	tagErr         error
	refErr         error
	lockErr        error
	prepareErr     error
	verifyErr      error
	prepareState   gitPrepareState
}

func (git *fakeGit) fileAtRef(_ string, _ string, path string) ([]byte, error) {
	if git.fileErr != nil {
		return nil, git.fileErr
	}
	data, ok := git.base[path]
	if !ok {
		return nil, errors.New("missing fake base file")
	}
	return data, nil
}

func (git *fakeGit) tagExists(_ string, tag string) (bool, error) {
	if git.tagErr != nil {
		return false, git.tagErr
	}
	return git.tags[tag], nil
}

func (git *fakeGit) tagMatchesHead(_ string, _ string) (bool, error) {
	if git.refErr != nil {
		return false, git.refErr
	}
	return git.headMatchesTag, nil
}

func (git *fakeGit) commitParents(_ string, _ string) ([]string, error) {
	return nil, errors.New("fake Git history is not configured")
}

func (git *fakeGit) commitMessage(_ string, _ string) (string, error) {
	return "", errors.New("fake Git history is not configured")
}

func (git *fakeGit) lockPath(_ string) (string, error) {
	if git.lockErr != nil {
		return "", git.lockErr
	}
	return git.lock, nil
}

func (git *fakeGit) capturePrepareState(_ string, expectedHead string) (gitPrepareState, error) {
	if git.prepareErr != nil {
		return gitPrepareState{}, git.prepareErr
	}
	state := git.prepareState
	if state.Head == "" {
		state = gitPrepareState{
			Head:   "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			Branch: "main",
			Refs:   "refs/heads/main",
		}
	}
	if expectedHead != "" && expectedHead != state.Head {
		return gitPrepareState{}, errors.New("unexpected fake HEAD")
	}
	return state, nil
}

func (git *fakeGit) verifyPrepareState(_ string, _ gitPrepareState) error {
	return git.verifyErr
}

func (git *fakeGit) worktreeOutsideTargetsDigest(repo string) (string, error) {
	return filesystemOutsideTargetsDigest(repo)
}

func testApplication(t *testing.T, repo string, base snapshot) (application, *bytes.Buffer, *fakeGit) {
	t.Helper()
	if base == nil {
		contents := snapshotFiles(t, repo)
		version, err := inspectSnapshot(contents)
		if err != nil {
			t.Fatal(err)
		}
		base = fixtureBaseline(version.String())
	}
	output := &bytes.Buffer{}
	git := &fakeGit{base: base, tags: make(map[string]bool), headMatchesTag: true, lock: filepath.Join(repo, ".git", "versionctl.lock")}
	if err := os.MkdirAll(filepath.Dir(git.lock), 0o700); err != nil {
		t.Fatal(err)
	}
	return application{git: git, out: output, getenv: func(string) string { return "" }}, output, git
}

func snapshotFiles(t *testing.T, repo string) snapshot {
	t.Helper()
	contents, err := readWorktree(repo)
	if err != nil {
		t.Fatal(err)
	}
	copy := make(snapshot, len(contents))
	for path, data := range contents {
		copy[path] = append([]byte(nil), data...)
	}
	return copy
}

func snapshotsEqual(left, right snapshot) bool {
	if len(left) != len(right) {
		return false
	}
	for path, data := range left {
		if !bytes.Equal(data, right[path]) {
			return false
		}
	}
	return true
}

func readTestRepoFile(t *testing.T, repo, path string) []byte {
	t.Helper()
	data, err := readRepoFile(repo, path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func appendTestRepoFile(t *testing.T, repo, path, text string) {
	t.Helper()
	root, err := openRepositoryRoot(repo)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	file, err := root.OpenFile(filepath.FromSlash(path), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString(text); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestDryRunIsNonMutating(t *testing.T) {
	t.Parallel()
	repo := t.TempDir()
	writeFixture(t, repo, "v4.02.8")
	if err := os.WriteFile(filepath.Join(repo, changelogPath), prependRelease("v4.02.9", validChangelog("v4.02.8")), 0o600); err != nil {
		t.Fatal(err)
	}
	before := snapshotFiles(t, repo)
	changelogBefore := readTestRepoFile(t, repo, changelogPath)
	app, output, _ := testApplication(t, repo, nil)
	err := app.run([]string{"dry-run", "--repo", repo, "--commit-message", "Patch : validate versioning"}, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("dry-run: %v", err)
	}
	after := snapshotFiles(t, repo)
	changelogAfter := readTestRepoFile(t, repo, changelogPath)
	if !snapshotsEqual(before, after) || !bytes.Equal(changelogBefore, changelogAfter) {
		t.Fatal("dry-run modified repository files")
	}
	if _, err := os.Stat(filepath.Join(repo, ".git", "versionctl.lock")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("dry-run left a lock file: %v", err)
	}
	if !strings.Contains(output.String(), "Expected version: v4.02.9") {
		t.Fatalf("unexpected dry-run output: %s", output)
	}
}

func TestDryRunBootstrapsScopedREADMEFromHistoricalHead(t *testing.T) {
	t.Parallel()
	repo := t.TempDir()
	writeFixture(t, repo, "v4.02.8")
	if err := os.WriteFile(filepath.Join(repo, changelogPath), prependRelease("v4.02.9", validChangelog("v4.02.8")), 0o600); err != nil {
		t.Fatal(err)
	}
	base := fixtureBaseline("v4.02.8")
	base["README.md"] = []byte("# Historical README without a scoped current-version statement\n")
	app, output, _ := testApplication(t, repo, base)
	if err := app.run([]string{"dry-run", "--repo", repo, "--commit-message", "Patch : bootstrap documentation version"}, &bytes.Buffer{}); err != nil {
		t.Fatalf("README bootstrap dry-run: %v", err)
	}
	if !strings.Contains(output.String(), "Expected version: v4.02.9") {
		t.Fatalf("unexpected bootstrap dry-run output: %s", output)
	}
}

func TestValidateOrdinaryBootstrapCommitFromHistoricalREADME(t *testing.T) {
	t.Parallel()
	repo := t.TempDir()
	writeFixture(t, repo, "v4.02.8")
	base := fixtureBaseline("v4.02.8")
	base["README.md"] = []byte("# Historical README without a scoped current-version statement\n")
	app, _, _ := testApplication(t, repo, base)
	if err := app.run([]string{"validate-commit", "--repo", repo, "--base-ref", "BASE", "--commit-message", "Docs : establish the documentation baseline"}, &bytes.Buffer{}); err != nil {
		t.Fatalf("ordinary README bootstrap commit: %v", err)
	}
}

func TestInspectPrintsOnlyValidatedVersion(t *testing.T) {
	t.Parallel()
	repo := t.TempDir()
	writeFixture(t, repo, "v4.02.8")
	app, output, _ := testApplication(t, repo, nil)
	if err := app.run([]string{"inspect", "--repo", repo}, &bytes.Buffer{}); err != nil {
		t.Fatalf("inspect: %v", err)
	}
	if output.String() != "v4.02.8\n" {
		t.Fatalf("inspect output = %q, want machine-readable version only", output.String())
	}

	if err := os.WriteFile(filepath.Join(repo, changelogPath), validChangelog("v4.02.7"), 0o600); err != nil {
		t.Fatal(err)
	}
	output.Reset()
	if err := app.run([]string{"inspect", "--repo", repo}, &bytes.Buffer{}); err == nil {
		t.Fatal("inspect should reject a changelog/source mismatch")
	}
	if output.Len() != 0 {
		t.Fatalf("failed inspect wrote stdout: %q", output.String())
	}
}

func TestApplyUpdatesOnlyVersionTargets(t *testing.T) {
	t.Parallel()
	repo := t.TempDir()
	writeFixture(t, repo, "v4.02.8")
	changelog := prependRelease("v4.02.9", validChangelog("v4.02.8"))
	if err := os.WriteFile(filepath.Join(repo, changelogPath), changelog, 0o600); err != nil {
		t.Fatal(err)
	}
	app, output, _ := testApplication(t, repo, nil)
	err := app.run([]string{"apply", "--repo", repo, "--commit-message", "Patch : validate versioning"}, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	contents := snapshotFiles(t, repo)
	version, err := inspectSnapshot(contents)
	if err != nil || version.String() != "v4.02.9" {
		t.Fatalf("applied version = (%s, %v)", version, err)
	}
	actualChangelog := readTestRepoFile(t, repo, changelogPath)
	if !bytes.Equal(actualChangelog, changelog) {
		t.Fatal("apply modified changelog.md")
	}
	if _, err := os.Stat(filepath.Join(repo, ".git", "versionctl.lock")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("apply left a lock file: %v", err)
	}
	if !strings.Contains(output.String(), "Mode: apply") {
		t.Fatalf("unexpected apply output: %s", output)
	}
}

func TestApplyRefusesAutomationEnvironments(t *testing.T) {
	for _, test := range []struct {
		name  string
		value string
	}{
		{name: "CI", value: "1"},
		{name: "GITHUB_ACTIONS", value: "true"},
		{name: "ACT", value: " YES "},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			repo := t.TempDir()
			writeFixture(t, repo, "v4.02.8")
			if err := os.WriteFile(filepath.Join(repo, changelogPath), prependRelease("v4.02.9", validChangelog("v4.02.8")), 0o600); err != nil {
				t.Fatal(err)
			}
			before := snapshotFiles(t, repo)
			app, _, _ := testApplication(t, repo, nil)
			app.getenv = func(name string) string {
				if name == test.name {
					return test.value
				}
				return ""
			}
			err := app.run([]string{"apply", "--repo", repo, "--commit-message", "Patch : validation"}, &bytes.Buffer{})
			if err == nil || !strings.Contains(err.Error(), test.name) {
				t.Fatalf("apply error = %v, want refusal naming %s", err, test.name)
			}
			if !snapshotsEqual(before, snapshotFiles(t, repo)) {
				t.Fatal("automation refusal mutated version targets")
			}
			if _, err := os.Stat(filepath.Join(repo, ".git", "versionctl.lock")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("automation refusal created a lock: %v", err)
			}
		})
	}
}

func TestAutomationAllowsReadOnlyModes(t *testing.T) {
	t.Parallel()
	repo := t.TempDir()
	writeFixture(t, repo, "v4.02.8")
	if err := os.WriteFile(filepath.Join(repo, changelogPath), prependRelease("v4.02.9", validChangelog("v4.02.8")), 0o600); err != nil {
		t.Fatal(err)
	}
	app, _, _ := testApplication(t, repo, nil)
	app.getenv = func(string) string { return "true" }
	if err := app.run([]string{"dry-run", "--repo", repo, "--commit-message", "Patch : validation"}, &bytes.Buffer{}); err != nil {
		t.Fatalf("dry-run should remain available in automation: %v", err)
	}
}

func TestTruthyAutomationValues(t *testing.T) {
	t.Parallel()
	for _, value := range []string{"1", "true", "TRUE", " yes ", "On"} {
		if !isTruthy(value) {
			t.Errorf("isTruthy(%q) = false", value)
		}
	}
	for _, value := range []string{"", "0", "false", "no", "off", "unexpected"} {
		if isTruthy(value) {
			t.Errorf("isTruthy(%q) = true", value)
		}
	}
}

func TestPrepareFailuresNeverMutateTargets(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		configure func(t *testing.T, repo string, git *fakeGit)
	}{
		{name: "changelog missing future release", configure: func(t *testing.T, repo string, _ *fakeGit) {
			if err := os.WriteFile(filepath.Join(repo, changelogPath), validChangelog("v4.02.8"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "tag exists", configure: func(_ *testing.T, _ string, git *fakeGit) { git.tags["v4.02.9"] = true }},
		{name: "unexpected occurrence", configure: func(t *testing.T, repo string, _ *fakeGit) {
			appendTestRepoFile(t, repo, versionTargets[0].Path, "extra = \"v4.02.8\"\n")
		}},
		{name: "active lock", configure: func(t *testing.T, _ string, git *fakeGit) {
			if err := os.WriteFile(git.lock, []byte("pid=1\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			repo := t.TempDir()
			writeFixture(t, repo, "v4.02.8")
			if err := os.WriteFile(filepath.Join(repo, changelogPath), prependRelease("v4.02.9", validChangelog("v4.02.8")), 0o600); err != nil {
				t.Fatal(err)
			}
			app, _, git := testApplication(t, repo, nil)
			test.configure(t, repo, git)
			before := snapshotFiles(t, repo)
			err := app.run([]string{"apply", "--repo", repo, "--commit-message", "Patch : validation"}, &bytes.Buffer{})
			if err == nil {
				t.Fatal("apply unexpectedly succeeded")
			}
			after := snapshotFiles(t, repo)
			if !snapshotsEqual(before, after) {
				t.Fatalf("failed apply mutated version targets: %v", err)
			}
		})
	}
}

func TestValidateCommit(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name             string
		baseVersion      string
		candidateVersion string
		changelogVersion string
		message          string
		tagExists        bool
		tagPhase         bool
		tagMatchesHead   bool
		wantError        bool
	}{
		{name: "patch", baseVersion: "v4.02.8", candidateVersion: "v4.02.9", changelogVersion: "v4.02.9", message: "Patch : fix", wantError: false},
		{name: "minor", baseVersion: "v4.02.8", candidateVersion: "v4.03.0", changelogVersion: "v4.03.0", message: "Minor : feature", wantError: false},
		{name: "major", baseVersion: "v4.12.3", candidateVersion: "v4.20.0", changelogVersion: "v4.20.0", message: "Major : hardening", wantError: false},
		{name: "upgrade", baseVersion: "v4.99.9", candidateVersion: "v5.00.0", changelogVersion: "v5.00.0", message: "Upgrade : engine", wantError: false},
		{name: "ordinary unchanged", baseVersion: "v4.02.8", candidateVersion: "v4.02.8", changelogVersion: "v4.02.8", message: "Docs : clarify", wantError: false},
		{name: "ordinary unchanged tag phase", baseVersion: "v4.02.8", candidateVersion: "v4.02.8", changelogVersion: "v4.02.8", message: "Docs : clarify", tagPhase: true, tagExists: true, tagMatchesHead: true, wantError: true},
		{name: "wrong bump", baseVersion: "v4.02.8", candidateVersion: "v4.03.0", changelogVersion: "v4.03.0", message: "Patch : fix", wantError: true},
		{name: "ordinary changed", baseVersion: "v4.02.8", candidateVersion: "v4.02.9", changelogVersion: "v4.02.9", message: "Docs : clarify", wantError: true},
		{name: "wrong changelog", baseVersion: "v4.02.8", candidateVersion: "v4.02.9", changelogVersion: "v4.02.8", message: "Patch : fix", wantError: true},
		{name: "existing tag", baseVersion: "v4.02.8", candidateVersion: "v4.02.9", changelogVersion: "v4.02.9", message: "Patch : fix", tagExists: true, wantError: true},
		{name: "tag phase", baseVersion: "v4.02.8", candidateVersion: "v4.02.9", changelogVersion: "v4.02.9", message: "Patch : fix", tagExists: true, tagPhase: true, tagMatchesHead: true, wantError: false},
		{name: "tag phase missing tag", baseVersion: "v4.02.8", candidateVersion: "v4.02.9", changelogVersion: "v4.02.9", message: "Patch : fix", tagPhase: true, tagMatchesHead: true, wantError: true},
		{name: "tag phase wrong commit", baseVersion: "v4.02.8", candidateVersion: "v4.02.9", changelogVersion: "v4.02.9", message: "Patch : fix", tagExists: true, tagPhase: true, tagMatchesHead: false, wantError: true},
		{name: "empty version description", baseVersion: "v4.02.8", candidateVersion: "v4.02.8", changelogVersion: "v4.02.8", message: "Patch : ", wantError: true},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			repo := t.TempDir()
			writeFixture(t, repo, test.candidateVersion)
			base := fixtureBaseline(test.baseVersion)
			candidateChangelog := append([]byte(nil), base[changelogPath]...)
			if _, recognized, _ := parseCommitMessage(test.message); recognized {
				candidateChangelog = prependRelease(test.changelogVersion, base[changelogPath])
			}
			if err := os.WriteFile(filepath.Join(repo, changelogPath), candidateChangelog, 0o600); err != nil {
				t.Fatal(err)
			}
			app, output, git := testApplication(t, repo, base)
			git.tags[test.candidateVersion] = test.tagExists
			git.headMatchesTag = test.tagMatchesHead
			args := []string{"validate-commit", "--repo", repo, "--base-ref", "BASE", "--commit-message", test.message}
			if test.tagPhase {
				args = append(args, "--tag-phase")
			}
			err := app.run(args, &bytes.Buffer{})
			if (err != nil) != test.wantError {
				t.Fatalf("validate-commit error = %v, wantError %v; output=%s", err, test.wantError, output)
			}
		})
	}
}

func TestValidateCommitRejectsInvalidBaseline(t *testing.T) {
	t.Parallel()
	repo := t.TempDir()
	writeFixture(t, repo, "v4.02.9")
	base := fixtureBaseline("v4.02.8")
	base[versionTargets[0].Path] = append(base[versionTargets[0].Path], []byte("extra = \"v4.02.8\"\n")...)
	app, _, _ := testApplication(t, repo, base)
	if err := app.run([]string{"validate-commit", "--repo", repo, "--base-ref", "BASE", "--commit-message", "Patch : fix"}, &bytes.Buffer{}); err == nil {
		t.Fatal("validate-commit should reject an invalid baseline")
	}
}

func TestValidateCommitProtectsChangelogHistory(t *testing.T) {
	t.Parallel()
	baseline := fixtureBaseline("v4.02.8")
	tests := []struct {
		name      string
		message   string
		candidate func([]byte) []byte
	}{
		{name: "rewritten historical entry", message: "Patch : fix", candidate: func(base []byte) []byte {
			mutated := bytes.Replace(base, []byte("Validate the version contract"), []byte("Rewrite old release history"), 1)
			return prependRelease("v4.02.9", mutated)
		}},
		{name: "removed historical suffix", message: "Patch : fix", candidate: func(_ []byte) []byte {
			return []byte("# Release v4.02.9\n\n### FIXED 🐛\n- Fix versioning.\n\n---\n")
		}},
		{name: "removed separator", message: "Patch : fix", candidate: func(base []byte) []byte {
			return append([]byte("# Release v4.02.9\n\n### FIXED 🐛\n- Fix versioning.\n\n"), base...)
		}},
		{name: "ordinary commit edit", message: "Docs : rewrite history", candidate: func(base []byte) []byte {
			return bytes.Replace(base, []byte("Validate the version contract"), []byte("Edited without a bump"), 1)
		}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			repo := t.TempDir()
			candidateVersion := "v4.02.9"
			if strings.HasPrefix(test.message, "Docs") {
				candidateVersion = "v4.02.8"
			}
			writeFixture(t, repo, candidateVersion)
			if err := os.WriteFile(filepath.Join(repo, changelogPath), test.candidate(baseline[changelogPath]), 0o600); err != nil {
				t.Fatal(err)
			}
			app, _, _ := testApplication(t, repo, baseline)
			if err := app.run([]string{"validate-commit", "--repo", repo, "--base-ref", "BASE", "--commit-message", test.message}, &bytes.Buffer{}); err == nil {
				t.Fatal("validate-commit accepted a changelog history mutation")
			}
		})
	}
}

func TestValidateTag(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		source    string
		changelog string
		tag       string
		exists    bool
		matches   bool
		wantError bool
	}{
		{name: "valid", source: "v4.02.8", changelog: "v4.02.8", tag: "v4.02.8", exists: true, matches: true},
		{name: "source mismatch", source: "v4.02.8", changelog: "v4.02.8", tag: "v4.02.9", exists: true, matches: true, wantError: true},
		{name: "changelog mismatch", source: "v4.02.8", changelog: "v4.02.7", tag: "v4.02.8", exists: true, matches: true, wantError: true},
		{name: "missing tag", source: "v4.02.8", changelog: "v4.02.8", tag: "v4.02.8", exists: false, wantError: true},
		{name: "tag points elsewhere", source: "v4.02.8", changelog: "v4.02.8", tag: "v4.02.8", exists: true, matches: false, wantError: true},
		{name: "invalid tag", source: "v4.02.8", changelog: "v4.02.8", tag: "4.02.8", exists: true, matches: true, wantError: true},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			repo := t.TempDir()
			writeFixture(t, repo, test.source)
			if err := os.WriteFile(filepath.Join(repo, changelogPath), validChangelog(test.changelog), 0o600); err != nil {
				t.Fatal(err)
			}
			app, _, git := testApplication(t, repo, nil)
			git.tags[test.tag] = test.exists
			git.headMatchesTag = test.matches
			err := app.run([]string{"validate-tag", "--repo", repo, "--tag", test.tag}, &bytes.Buffer{})
			if (err != nil) != test.wantError {
				t.Fatalf("validate-tag error = %v, wantError %v", err, test.wantError)
			}
		})
	}
}

func TestCommandUsageErrors(t *testing.T) {
	t.Parallel()
	app := application{git: &fakeGit{}, out: &bytes.Buffer{}}
	for _, args := range [][]string{nil, {"unknown"}, {"dry-run", "--commit-message", "Docs only"}, {"validate-release", "--tag", "bad"}, {"validate-tag", "--tag", "bad"}} {
		if err := app.run(args, &bytes.Buffer{}); err == nil {
			t.Errorf("app.run(%q) unexpectedly succeeded", args)
		}
	}
}
