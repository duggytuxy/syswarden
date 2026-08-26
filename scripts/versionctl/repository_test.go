package main

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestChangelogHistoryResetIsSingleUseAndDigestBound(t *testing.T) {
	t.Parallel()
	base := validChangelog("v4.02.14")
	previous, _ := parseVersion("v4.02.14")
	next, _ := parseVersion("v4.03.0")
	digest := fmt.Sprintf("%x", sha256.Sum256(base))
	suffix := "Archived test changelog SHA-256: " + digest + "\n"
	candidate := []byte("# Release v4.03.0\n\n### CHANGED\n- Reset the public changelog after a sealed archive.\n\n---\n\n" + suffix)
	policy := changelogResetPolicy{From: previous.String(), To: next.String(), BaseSHA256: digest, ArchiveSuffix: suffix}
	if err := validateChangelogHistoryTransitionWithPolicy(base, candidate, previous, next, policy); err != nil {
		t.Fatalf("approved reset rejected: %v", err)
	}
	wrongBase := append([]byte(nil), base...)
	wrongBase = append(wrongBase, '\n')
	if err := validateChangelogHistoryTransitionWithPolicy(wrongBase, candidate, previous, next, policy); err == nil {
		t.Fatal("reset accepted a different baseline digest")
	}
	wrongSuffix := bytes.Replace(candidate, []byte(digest), []byte(strings.Repeat("0", 64)), 1)
	if err := validateChangelogHistoryTransitionWithPolicy(base, wrongSuffix, previous, next, policy); err == nil {
		t.Fatal("reset accepted a different archive suffix")
	}
	otherNext, _ := parseVersion("v4.04.0")
	if err := validateChangelogHistoryTransitionWithPolicy(base, candidate, previous, otherNext, policy); err == nil {
		t.Fatal("reset policy was reusable for another transition")
	}
}

func TestChangelogHistoryRewriteIsSingleUseAndDigestBound(t *testing.T) {
	t.Parallel()
	base := validChangelog("v4.03.2")
	history := bytes.Replace(base, []byte("Validate the version contract"), []byte("Seal the published release status"), 1)
	candidate := prependRelease("v4.03.3", history)
	previous, _ := parseVersion("v4.03.2")
	next, _ := parseVersion("v4.03.3")
	policy := changelogRewritePolicy{
		From:          previous.String(),
		To:            next.String(),
		BaseSHA256:    fmt.Sprintf("%x", sha256.Sum256(base)),
		HistorySHA256: fmt.Sprintf("%x", sha256.Sum256(history)),
	}
	validate := func(base, candidate []byte, previous, next Version) error {
		return validateChangelogHistoryTransitionWithPolicies(
			base,
			candidate,
			previous,
			next,
			changelogResetPolicy{},
			policy,
		)
	}
	if err := validate(base, candidate, previous, next); err != nil {
		t.Fatalf("approved rewrite rejected: %v", err)
	}

	wrongBase := append([]byte(nil), base...)
	wrongBase[0] ^= 1
	if err := validate(wrongBase, candidate, previous, next); err == nil {
		t.Fatal("rewrite accepted a different baseline digest")
	}

	wrongHistory := bytes.Replace(base, []byte("Validate the version contract"), []byte("Apply a different historical rewrite"), 1)
	wrongSuffix := prependRelease("v4.03.3", wrongHistory)
	if err := validate(base, wrongSuffix, previous, next); err == nil {
		t.Fatal("rewrite accepted a different historical suffix digest")
	}

	otherNext, _ := parseVersion("v4.03.4")
	if err := validate(base, candidate, previous, otherNext); err == nil {
		t.Fatal("rewrite policy was reusable for another transition")
	}
	otherPrevious, _ := parseVersion("v4.03.1")
	if err := validate(base, candidate, otherPrevious, next); err == nil {
		t.Fatal("rewrite policy was reusable from another baseline version")
	}

	mutatedCandidate := append([]byte(nil), candidate...)
	mutatedCandidate[len(mutatedCandidate)-2] ^= 1
	if err := validate(base, mutatedCandidate, previous, next); err == nil {
		t.Fatal("rewrite accepted a one-byte historical mutation")
	}
}

func fixtureSnapshot(version string) snapshot {
	contents := make(snapshot, len(versionTargets))
	for _, item := range versionTargets {
		if item.Path == "README.md" {
			contents[item.Path] = []byte("Current source version: **" + version + "**.\n")
			continue
		}
		var value strings.Builder
		for i := 0; i < item.Count; i++ {
			value.WriteString("version = \"")
			value.WriteString(version)
			value.WriteString("\"\n")
		}
		contents[item.Path] = []byte(value.String())
	}
	return contents
}

func validChangelog(version string) []byte {
	return []byte("# Release " + version + "\n\n### FIXED 🐛\n- **CI/CD:** Validate the version contract.\n\n---\n\n# Release v1.00.0\n")
}

func prependRelease(version string, baseline []byte) []byte {
	prefix := []byte("# Release " + version + "\n\n### FIXED 🐛\n- **CI/CD:** Validate the version contract.\n\n---\n\n")
	return append(prefix, baseline...)
}

func fixtureBaseline(version string) snapshot {
	contents := fixtureSnapshot(version)
	contents[changelogPath] = validChangelog(version)
	return contents
}

func writeFixture(t *testing.T, repo, version string) snapshot {
	t.Helper()
	contents := fixtureSnapshot(version)
	for _, item := range versionTargets {
		path := filepath.Join(repo, filepath.FromSlash(item.Path))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, contents[item.Path], 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(repo, changelogPath), validChangelog(version), 0o600); err != nil {
		t.Fatal(err)
	}
	return contents
}

func runTestGit(t *testing.T, repo string, arguments ...string) []byte {
	t.Helper()
	// #nosec G204 -- Git is the fixed executable, repo is a t.TempDir path, and every argument is a literal selected by the test.
	command := exec.Command("git", append([]string{"-C", repo}, arguments...)...)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", arguments, err, output)
	}
	return output
}

func TestInspectSnapshotEnforcesCountsAndConsistency(t *testing.T) {
	t.Parallel()
	contents := fixtureSnapshot("v4.02.8")
	version, err := inspectSnapshot(contents)
	if err != nil || version.String() != "v4.02.8" {
		t.Fatalf("inspectSnapshot = (%s, %v)", version, err)
	}

	missing := fixtureSnapshot("v4.02.8")
	delete(missing, versionTargets[0].Path)
	if _, err := inspectSnapshot(missing); err == nil {
		t.Fatal("inspectSnapshot should reject a missing target")
	}

	wrongCount := fixtureSnapshot("v4.02.8")
	wrongCount[versionTargets[0].Path] = append(wrongCount[versionTargets[0].Path], []byte("other = \"v4.02.8\"\n")...)
	if _, err := inspectSnapshot(wrongCount); err == nil {
		t.Fatal("inspectSnapshot should reject an unexpected occurrence count")
	}

	inconsistent := fixtureSnapshot("v4.02.8")
	inconsistent[versionTargets[1].Path] = []byte("version = \"v4.02.9\"\n")
	if _, err := inspectSnapshot(inconsistent); err == nil {
		t.Fatal("inspectSnapshot should reject inconsistent versions")
	}
}

func TestBaselineInspectionAllowsOnlyTheREADMEBootstrap(t *testing.T) {
	t.Parallel()
	baseline := fixtureSnapshot("v4.02.8")
	baseline["README.md"] = []byte("# Historical README without a scoped current-version statement\n")
	version, err := inspectBaselineSnapshot(baseline)
	if err != nil || version.String() != "v4.02.8" {
		t.Fatalf("inspectBaselineSnapshot bootstrap = (%s, %v)", version, err)
	}
	if _, err := inspectSnapshot(baseline); err == nil {
		t.Fatal("candidate inspection accepted a missing scoped README version")
	}

	missingSource := fixtureSnapshot("v4.02.8")
	missingSource[versionTargets[0].Path] = []byte("no version here\n")
	if _, err := inspectBaselineSnapshot(missingSource); err == nil {
		t.Fatal("baseline inspection accepted a missing non-bootstrap source version")
	}
}

func TestReplaceVersionTokensIsExact(t *testing.T) {
	t.Parallel()
	contents := fixtureSnapshot("v4.02.8")
	contents["README.md"] = append(
		contents["README.md"],
		[]byte("Historical release v3.00.0 remains archived.\n")...,
	)
	oldVersion, _ := parseVersion("v4.02.8")
	newVersion, _ := parseVersion("v4.02.9")
	updated, err := replaceVersionTokens(contents, oldVersion, newVersion)
	if err != nil {
		t.Fatal(err)
	}
	version, err := inspectSnapshot(updated)
	if err != nil || version != newVersion {
		t.Fatalf("updated snapshot = (%s, %v), want %s", version, err, newVersion)
	}
	for _, item := range versionTargets {
		if bytes.Contains(updated[item.Path], []byte(oldVersion.String())) {
			t.Fatalf("%s still contains %s", item.Path, oldVersion)
		}
	}
	if !bytes.Contains(updated["README.md"], []byte("Historical release v3.00.0 remains archived.")) {
		t.Fatal("README historical version reference was not preserved")
	}

	unexpected := fixtureSnapshot("v4.02.80")
	if _, err := replaceVersionTokens(unexpected, oldVersion, newVersion); err == nil {
		t.Fatal("replacement must not rewrite a version that merely shares a prefix")
	}
}

func TestValidateChangelogContract(t *testing.T) {
	t.Parallel()
	version, _ := parseVersion("v4.02.9")
	tests := []struct {
		name      string
		data      []byte
		wantError bool
	}{
		{name: "valid", data: validChangelog("v4.02.9")},
		{name: "valid CRLF and BOM", data: append([]byte("\xef\xbb\xbf"), bytes.ReplaceAll(validChangelog("v4.02.9"), []byte("\n"), []byte("\r\n"))...)},
		{name: "wrong version", data: validChangelog("v4.02.8"), wantError: true},
		{name: "leading blank", data: append([]byte("\n"), validChangelog("v4.02.9")...), wantError: true},
		{name: "missing separator", data: []byte("# Release v4.02.9\n### FIXED\n- Fix\n"), wantError: true},
		{name: "indented separator", data: []byte("# Release v4.02.9\n### FIXED\n- Fix\n ---\n"), wantError: true},
		{name: "missing section", data: []byte("# Release v4.02.9\n- Fix\n---\n"), wantError: true},
		{name: "empty section", data: []byte("# Release v4.02.9\n### \n- Fix\n---\n"), wantError: true},
		{name: "missing bullet", data: []byte("# Release v4.02.9\n### FIXED\nText\n---\n"), wantError: true},
		{name: "empty bullet", data: []byte("# Release v4.02.9\n### FIXED\n- \n---\n"), wantError: true},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			err := validateChangelog(test.data, version)
			if (err != nil) != test.wantError {
				t.Fatalf("validateChangelog error = %v, wantError %v", err, test.wantError)
			}
		})
	}
}

func TestChangelogHistoryPreservesBaselineBytes(t *testing.T) {
	t.Parallel()
	baseline := validChangelog("v4.02.8")
	candidate := prependRelease("v4.02.9", baseline)
	history, err := changelogHistory(candidate)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(history, baseline) {
		t.Fatal("changelogHistory did not return the exact baseline bytes")
	}

	for _, candidate := range [][]byte{
		[]byte("# Release v4.02.9\n### FIXED\n- Fix\n"),
		[]byte("# Release v4.02.9\n### FIXED\n- Fix\n---\n"),
		[]byte("# Release v4.02.9\n### FIXED\n- Fix\n---\n\n"),
	} {
		if _, err := changelogHistory(candidate); err == nil {
			t.Fatalf("changelogHistory unexpectedly accepted missing history: %q", candidate)
		}
	}
}

func TestWriteSnapshotAtomicallyPreservesModes(t *testing.T) {
	t.Parallel()
	repo := t.TempDir()
	original := writeFixture(t, repo, "v4.02.8")
	oldVersion, _ := parseVersion("v4.02.8")
	newVersion, _ := parseVersion("v4.02.9")
	updated, err := replaceVersionTokens(original, oldVersion, newVersion)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeSnapshotAtomically(repo, original, updated); err != nil {
		t.Fatal(err)
	}
	actual, err := readWorktree(repo)
	if err != nil {
		t.Fatal(err)
	}
	version, err := inspectSnapshot(actual)
	if err != nil || version != newVersion {
		t.Fatalf("written snapshot = (%s, %v), want %s", version, err, newVersion)
	}
	for _, item := range versionTargets {
		info, err := os.Stat(filepath.Join(repo, filepath.FromSlash(item.Path)))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("mode for %s = %o, want 600", item.Path, info.Mode().Perm())
		}
	}
}

func TestWriteSnapshotRollbackOnCommitFailure(t *testing.T) {
	t.Parallel()
	repo := t.TempDir()
	original := writeFixture(t, repo, "v4.02.8")
	oldVersion, _ := parseVersion("v4.02.8")
	newVersion, _ := parseVersion("v4.02.9")
	updated, err := replaceVersionTokens(original, oldVersion, newVersion)
	if err != nil {
		t.Fatal(err)
	}
	renames := 0
	injected := errors.New("injected rename failure")
	err = writeSnapshotWithRename(repo, original, updated, func(root *os.Root, oldPath, newPath string) error {
		renames++
		if renames == 3 {
			return injected
		}
		return root.Rename(oldPath, newPath)
	})
	if !errors.Is(err, injected) {
		t.Fatalf("writeSnapshotWithRename error = %v, want injected failure", err)
	}
	actual, readErr := readWorktree(repo)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if !snapshotsEqual(original, actual) {
		t.Fatal("transaction failure did not restore every original target")
	}
	for _, item := range versionTargets {
		matches, globErr := filepath.Glob(filepath.Join(filepath.Dir(filepath.Join(repo, filepath.FromSlash(item.Path))), ".versionctl-*"))
		if globErr != nil {
			t.Fatal(globErr)
		}
		if len(matches) != 0 {
			t.Fatalf("transaction failure left temporary files for %s: %v", item.Path, matches)
		}
	}
}

func TestRollbackFilesReportsUnrecoverableTarget(t *testing.T) {
	t.Parallel()
	repo := t.TempDir()
	root, openErr := openRepositoryRoot(repo)
	if openErr != nil {
		t.Fatal(openErr)
	}
	defer root.Close()
	err := rollbackFiles(root, []stagedFile{{targetPath: "missing/target.go", original: []byte("original"), mode: 0o600}})
	if err == nil {
		t.Fatal("rollbackFiles should report an unrecoverable target")
	}
}

func TestRealGitReadOnlyOperations(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	repo := t.TempDir()
	writeFixture(t, repo, "v4.02.8")
	commands := [][]string{
		{"init", "-q"},
		{"config", "user.name", "Version Test"},
		{"config", "user.email", "version-test@example.invalid"},
		{"add", "."},
		{"commit", "-qm", "Initial fixture"},
		{"tag", "-am", "Version v4.02.8", "v4.02.8"},
	}
	for _, args := range commands {
		runTestGit(t, repo, args...)
	}
	git := realGit{}
	data, err := git.fileAtRef(repo, "HEAD", versionTargets[0].Path)
	if err != nil || !bytes.Contains(data, []byte("v4.02.8")) {
		t.Fatalf("fileAtRef = (%q, %v)", data, err)
	}
	if exists, err := git.tagExists(repo, "v4.02.8"); err != nil || !exists {
		t.Fatalf("tagExists(existing) = (%v, %v)", exists, err)
	}
	if exists, err := git.tagExists(repo, "v4.02.9"); err != nil || exists {
		t.Fatalf("tagExists(missing) = (%v, %v)", exists, err)
	}
	if matches, err := git.tagMatchesHead(repo, "v4.02.8"); err != nil || !matches {
		t.Fatalf("tagMatchesHead(at tagged commit) = (%v, %v)", matches, err)
	}
	if err := os.WriteFile(filepath.Join(repo, "post-tag.txt"), []byte("new commit\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"add", "post-tag.txt"}, {"commit", "-qm", "Post-tag commit"}} {
		runTestGit(t, repo, args...)
	}
	if matches, err := git.tagMatchesHead(repo, "v4.02.8"); err != nil || matches {
		t.Fatalf("tagMatchesHead(after HEAD advanced) = (%v, %v)", matches, err)
	}
	lockPath, err := git.lockPath(repo)
	if err != nil || filepath.Base(lockPath) != "versionctl.lock" {
		t.Fatalf("lockPath = (%q, %v)", lockPath, err)
	}
	status := runTestGit(t, repo, "status", "--porcelain=v1")
	if len(status) != 0 {
		t.Fatalf("read-only Git operations changed repository: %q", status)
	}
}

func TestValidateGitRef(t *testing.T) {
	t.Parallel()
	for _, ref := range []string{"HEAD", "HEAD^", "main", "origin/main", "371d353e871fedb410b08f0618a1ae6aa2f7fedc"} {
		if err := validateGitRef(ref); err != nil {
			t.Errorf("validateGitRef(%q): %v", ref, err)
		}
	}
	for _, ref := range []string{"", "-n", "HEAD:evil", "main..other", "HEAD@{1}", "refs//heads/main", "main path", "$(touch bad)"} {
		if err := validateGitRef(ref); err == nil {
			t.Errorf("validateGitRef(%q) unexpectedly succeeded", ref)
		}
	}
}

func TestRealGitPrepareStateAllowsDirtyWorktreeButRejectsUnsafeGitState(t *testing.T) {
	t.Parallel()
	repo := t.TempDir()
	writeFixture(t, repo, "v4.02.8")
	commands := [][]string{
		{"init", "-q", "-b", "main"},
		{"config", "user.name", "Version Test"},
		{"config", "user.email", "version-test@example.invalid"},
		{"add", "."},
		{"commit", "-qm", "Initial fixture"},
	}
	for _, args := range commands {
		runTestGit(t, repo, args...)
	}
	git := realGit{}
	state, err := git.capturePrepareState(repo, "")
	if err != nil {
		t.Fatalf("capture safe state: %v", err)
	}
	if state.Branch != "main" || !fullGitSHA.MatchString(state.Head) {
		t.Fatalf("unexpected prepare state: %#v", state)
	}
	if err := os.WriteFile(filepath.Join(repo, "untracked-candidate.txt"), []byte("candidate\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := git.capturePrepareState(repo, state.Head); err != nil {
		t.Fatalf("dirty unstaged worktree must remain allowed: %v", err)
	}
	runTestGit(t, repo, "add", "untracked-candidate.txt")
	if _, err := git.capturePrepareState(repo, ""); err == nil || !strings.Contains(err.Error(), "empty Git index") {
		t.Fatalf("staged index error = %v", err)
	}
}

func TestRealGitPrepareStateRejectsDetachedHeadAndNonDescendantBranch(t *testing.T) {
	t.Parallel()
	newRepo := func(t *testing.T) string {
		t.Helper()
		repo := t.TempDir()
		writeFixture(t, repo, "v4.02.8")
		for _, args := range [][]string{
			{"init", "-q", "-b", "main"},
			{"config", "user.name", "Version Test"},
			{"config", "user.email", "version-test@example.invalid"},
			{"add", "."},
			{"commit", "-qm", "Initial fixture"},
		} {
			runTestGit(t, repo, args...)
		}
		return repo
	}
	git := realGit{}
	detached := newRepo(t)
	runTestGit(t, detached, "checkout", "--detach", "-q")
	if _, err := git.capturePrepareState(detached, ""); err == nil || !strings.Contains(err.Error(), "detached") {
		t.Fatalf("detached HEAD error = %v", err)
	}

	unrelated := newRepo(t)
	runTestGit(t, unrelated, "checkout", "--orphan", "unrelated", "-q")
	if err := os.WriteFile(filepath.Join(unrelated, "orphan.txt"), []byte("orphan\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"add", "."}, {"commit", "-qm", "Unrelated fixture"}} {
		runTestGit(t, unrelated, args...)
	}
	if _, err := git.capturePrepareState(unrelated, ""); err == nil || !strings.Contains(err.Error(), "ancestor") {
		t.Fatalf("unrelated branch error = %v", err)
	}
}

func TestWorktreeOutsideTargetsDigestTracksAllOtherCandidateFiles(t *testing.T) {
	t.Parallel()
	repo := t.TempDir()
	writeFixture(t, repo, "v4.02.8")
	before, err := filesystemOutsideTargetsDigest(repo)
	if err != nil {
		t.Fatal(err)
	}
	firstTarget := filepath.Join(repo, filepath.FromSlash(versionTargets[0].Path))
	if err := os.WriteFile(firstTarget, []byte("version = \"v4.02.9\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	afterTarget, err := filesystemOutsideTargetsDigest(repo)
	if err != nil || afterTarget != before {
		t.Fatalf("target-only digest = (%s, %v), want %s", afterTarget, err, before)
	}
	if err := os.WriteFile(filepath.Join(repo, "unrelated.txt"), []byte("changed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	afterOther, err := filesystemOutsideTargetsDigest(repo)
	if err != nil {
		t.Fatal(err)
	}
	if afterOther == before {
		t.Fatal("non-target worktree change was not detected")
	}
}

func TestRealGitWorktreeDigestIncludesCandidateAndIgnoresBuildArtifacts(t *testing.T) {
	t.Parallel()
	repo := t.TempDir()
	writeFixture(t, repo, "v4.02.8")
	if err := os.WriteFile(filepath.Join(repo, ".gitignore"), []byte("dist/\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"init", "-q", "-b", "main"},
		{"config", "user.name", "Version Test"},
		{"config", "user.email", "version-test@example.invalid"},
		{"add", "."},
		{"commit", "-qm", "Initial fixture"},
	} {
		runTestGit(t, repo, args...)
	}
	git := realGit{}
	before, err := git.worktreeOutsideTargetsDigest(repo)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(repo, "dist"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "dist", "ignored.bin"), []byte("build\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	afterIgnored, err := git.worktreeOutsideTargetsDigest(repo)
	if err != nil || afterIgnored != before {
		t.Fatalf("ignored artifact digest = (%s, %v), want %s", afterIgnored, err, before)
	}
	if err := os.WriteFile(filepath.Join(repo, "candidate.txt"), []byte("candidate\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	afterCandidate, err := git.worktreeOutsideTargetsDigest(repo)
	if err != nil {
		t.Fatal(err)
	}
	if afterCandidate == before {
		t.Fatal("untracked candidate file was not included in the worktree digest")
	}
}

func TestRealGitWorktreeDigestRepresentsTrackedDeletion(t *testing.T) {
	t.Parallel()
	repo := t.TempDir()
	writeFixture(t, repo, "v4.02.8")
	deletedPath := filepath.Join(repo, "tracked-candidate.txt")
	if err := os.WriteFile(deletedPath, []byte("tracked\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"init", "-q", "-b", "main"},
		{"config", "user.name", "Version Test"},
		{"config", "user.email", "version-test@example.invalid"},
		{"add", "."},
		{"commit", "-qm", "Initial fixture"},
	} {
		runTestGit(t, repo, args...)
	}
	git := realGit{}
	before, err := git.worktreeOutsideTargetsDigest(repo)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(deletedPath); err != nil {
		t.Fatal(err)
	}
	deleted, err := git.worktreeOutsideTargetsDigest(repo)
	if err != nil {
		t.Fatalf("digest tracked deletion: %v", err)
	}
	if deleted == before {
		t.Fatal("tracked deletion was not represented in the worktree digest")
	}
	repeated, err := git.worktreeOutsideTargetsDigest(repo)
	if err != nil || repeated != deleted {
		t.Fatalf("stable tracked deletion digest = (%s, %v), want %s", repeated, err, deleted)
	}
}
