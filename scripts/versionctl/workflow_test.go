package main

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve test source path")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(source), "..", ".."))
}

func TestAutoVersioningWorkflowIsReadOnly(t *testing.T) {
	t.Parallel()
	root := repositoryRoot(t)
	data, err := readRepoFile(root, ".github/workflows/auto-versioning.yml")
	if err != nil {
		t.Fatal(err)
	}
	workflow := string(data)

	required := []string{
		"permissions:\n  contents: read",
		"concurrency:",
		"cancel-in-progress: false",
		"persist-credentials: false",
		"./scripts/versioning.sh validate-commit",
		"git diff --exit-code",
		"git diff --cached --exit-code",
		"git ls-files --others --exclude-standard",
	}
	for _, text := range required {
		if !strings.Contains(workflow, text) {
			t.Errorf("workflow is missing required read-only control %q", text)
		}
	}

	forbidden := []*regexp.Regexp{
		regexp.MustCompile(`(?m)contents:[[:space:]]*write`),
		regexp.MustCompile(`GH_RELEASE_PAT`),
		regexp.MustCompile(`(?m)[[:space:]]git[[:space:]]+(add|commit|tag|push)([[:space:]]|$)`),
		regexp.MustCompile(`Set-Content`),
		regexp.MustCompile(`(?m)^[[:space:]]*token:`),
		regexp.MustCompile(`versioning\.sh[[:space:]]+apply`),
	}
	for _, pattern := range forbidden {
		if pattern.MatchString(workflow) {
			t.Errorf("workflow contains forbidden mutating capability matching %s", pattern)
		}
	}

	actionPattern := regexp.MustCompile(`(?m)^[[:space:]]*uses:[[:space:]]*[^@[:space:]]+@([^[:space:]#]+)`)
	actions := actionPattern.FindAllStringSubmatch(workflow, -1)
	if len(actions) == 0 {
		t.Fatal("workflow contains no actions to validate")
	}
	shaPattern := regexp.MustCompile(`^[0-9a-f]{40}$`)
	for _, action := range actions {
		if !shaPattern.MatchString(action[1]) {
			t.Errorf("workflow action is not pinned to a full commit SHA: %s", action[0])
		}
	}
}

func TestVersioningWrapperIsExecutableAndContainsNoGitMutation(t *testing.T) {
	t.Parallel()
	root := repositoryRoot(t)
	path := filepath.Join(root, "scripts", "versioning.sh")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o111 == 0 {
		t.Fatalf("%s is not executable", path)
	}
	data, err := readRepoFile(root, "scripts/versioning.sh")
	if err != nil {
		t.Fatal(err)
	}
	if regexp.MustCompile(`(?m)[[:space:]]git[[:space:]]+(add|commit|tag|push)([[:space:]]|$)`).Match(data) {
		t.Fatal("versioning wrapper contains a mutating Git command")
	}
}
