package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type application struct {
	git    gitClient
	out    io.Writer
	getenv func(string) string
}

func run(args []string, stdout, stderr io.Writer) error {
	app := application{git: realGit{}, out: stdout, getenv: os.Getenv}
	return app.run(args, stderr)
}

func (app application) run(args []string, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: versionctl <inspect|dry-run|apply|validate-commit|validate-tag> [options]")
	}
	switch args[0] {
	case "inspect":
		return app.runInspect(args[1:], stderr)
	case "dry-run", "apply":
		return app.runPrepare(args[0], args[1:], stderr)
	case "validate-commit":
		return app.runValidateCommit(args[1:], stderr)
	case "validate-tag":
		return app.runValidateTag(args[1:], stderr)
	case "help", "--help", "-h":
		fmt.Fprintln(app.out, "usage: versionctl <inspect|dry-run|apply|validate-commit|validate-tag> [options]")
		return nil
	default:
		return fmt.Errorf("unknown mode %q", args[0])
	}
}

func (app application) runInspect(args []string, stderr io.Writer) error {
	set := newFlagSet("inspect", stderr)
	repoFlag := set.String("repo", ".", "repository root")
	if err := set.Parse(args); err != nil {
		return err
	}
	if set.NArg() != 0 {
		return errors.New("inspect accepts options only")
	}
	repo, err := cleanRepoPath(*repoFlag)
	if err != nil {
		return err
	}
	contents, err := readWorktree(repo)
	if err != nil {
		return err
	}
	current, err := inspectSnapshot(contents)
	if err != nil {
		return err
	}
	if err := readAndValidateChangelog(repo, current); err != nil {
		return err
	}
	fmt.Fprintln(app.out, current)
	return nil
}

func newFlagSet(name string, stderr io.Writer) *flag.FlagSet {
	set := flag.NewFlagSet(name, flag.ContinueOnError)
	set.SetOutput(stderr)
	return set
}

func cleanRepoPath(raw string) (string, error) {
	abs, err := filepath.Abs(raw)
	if err != nil {
		return "", fmt.Errorf("resolve repository path: %w", err)
	}
	info, err := os.Stat(abs)
	if err != nil {
		return "", fmt.Errorf("inspect repository path: %w", err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("repository path %s is not a directory", abs)
	}
	return abs, nil
}

func (app application) runPrepare(mode string, args []string, stderr io.Writer) error {
	set := newFlagSet(mode, stderr)
	repoFlag := set.String("repo", ".", "repository root")
	message := set.String("commit-message", "", "proposed versioning commit message")
	expectedHead := set.String("expected-head", "", "optional full Git HEAD SHA to require")
	if err := set.Parse(args); err != nil {
		return err
	}
	if set.NArg() != 0 {
		return fmt.Errorf("%s accepts options only", mode)
	}
	if mode == "apply" {
		for _, name := range []string{"CI", "GITHUB_ACTIONS", "ACT"} {
			if isTruthy(app.environment(name)) {
				return fmt.Errorf("apply is disabled when %s is truthy; use dry-run or a validation mode in automation", name)
			}
		}
	}
	bump, recognized, err := parseCommitMessage(*message)
	if err != nil {
		return err
	}
	if !recognized {
		return errors.New("dry-run and apply require a Patch, Minor, Major, or Upgrade commit prefix")
	}
	repo, err := cleanRepoPath(*repoFlag)
	if err != nil {
		return err
	}
	lockPath, err := app.git.lockPath(repo)
	if err != nil {
		return err
	}
	lockRoot, lockName, err := openVersionLockRoot(lockPath)
	if err != nil {
		return err
	}
	defer lockRoot.Close()
	if _, err := lockRoot.Stat(lockName); err == nil {
		return fmt.Errorf("another versionctl operation owns %s", lockPath)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect versionctl lock: %w", err)
	}
	if mode == "apply" {
		lock, err := lockRoot.OpenFile(lockName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return fmt.Errorf("acquire versionctl lock: %w", err)
		}
		if _, err := fmt.Fprintf(lock, "pid=%d\n", os.Getpid()); err != nil {
			_ = lock.Close()
			_ = lockRoot.Remove(lockName)
			return fmt.Errorf("write versionctl lock: %w", err)
		}
		if err := lock.Close(); err != nil {
			_ = lockRoot.Remove(lockName)
			return fmt.Errorf("close versionctl lock: %w", err)
		}
		defer func() {
			if err := lockRoot.Remove(lockName); err != nil && !errors.Is(err, os.ErrNotExist) {
				fmt.Fprintf(stderr, "WARNING: remove versionctl lock %s: %v\n", lockPath, err)
			}
		}()
	}
	gitState, err := app.git.capturePrepareState(repo, *expectedHead)
	if err != nil {
		return err
	}
	outsideBefore, err := app.git.worktreeOutsideTargetsDigest(repo)
	if err != nil {
		return err
	}

	contents, err := readWorktree(repo)
	if err != nil {
		return err
	}
	current, err := inspectSnapshot(contents)
	if err != nil {
		return err
	}
	headContents := make(snapshot, len(versionTargets))
	for _, item := range versionTargets {
		data, err := app.git.fileAtRef(repo, "HEAD", item.Path)
		if err != nil {
			return err
		}
		headContents[item.Path] = data
	}
	headVersion, err := inspectBaselineSnapshot(headContents)
	if err != nil {
		return fmt.Errorf("invalid version baseline at HEAD: %w", err)
	}
	if current != headVersion {
		return fmt.Errorf("worktree version %s does not match HEAD version %s", current, headVersion)
	}
	next, err := nextVersion(current, bump)
	if err != nil {
		return err
	}
	if err := readAndValidateChangelog(repo, next); err != nil {
		return err
	}
	headChangelog, err := app.git.fileAtRef(repo, "HEAD", changelogPath)
	if err != nil {
		return err
	}
	if err := validateChangelog(headChangelog, headVersion); err != nil {
		return fmt.Errorf("invalid changelog baseline at HEAD: %w", err)
	}
	candidateChangelog, err := readRepoFile(repo, changelogPath)
	if err != nil {
		return fmt.Errorf("read %s: %w", changelogPath, err)
	}
	history, err := changelogHistory(candidateChangelog)
	if err != nil {
		return err
	}
	if !bytes.Equal(history, headChangelog) {
		return errors.New("candidate changelog must preserve the complete HEAD changelog byte-for-byte after the new release separator")
	}
	exists, err := app.git.tagExists(repo, next.String())
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("Git tag %s already exists", next)
	}
	updated, err := replaceVersionTokens(contents, current, next)
	if err != nil {
		return err
	}
	latestContents, err := readWorktree(repo)
	if err != nil {
		return err
	}
	if !snapshotEqual(latestContents, contents) {
		return errors.New("a version target changed concurrently during preparation")
	}
	outsideNow, err := app.git.worktreeOutsideTargetsDigest(repo)
	if err != nil {
		return err
	}
	if outsideNow != outsideBefore {
		return errors.New("a non-version target changed concurrently during preparation")
	}
	if err := app.git.verifyPrepareState(repo, gitState); err != nil {
		return fmt.Errorf("verify Git safety state before mutation: %w", err)
	}

	if mode == "dry-run" {
		app.printPlan(mode, bump, current, next)
		return nil
	}

	if err := writeSnapshotAtomically(repo, contents, updated); err != nil {
		return err
	}
	verification, err := readWorktree(repo)
	if err != nil {
		return rollbackAfterVerificationFailure(repo, updated, contents, fmt.Errorf("verify applied version: %w", err))
	}
	applied, err := inspectSnapshot(verification)
	if err != nil {
		return rollbackAfterVerificationFailure(repo, updated, contents, fmt.Errorf("verify applied version: %w", err))
	}
	if applied != next {
		return rollbackAfterVerificationFailure(repo, updated, contents, fmt.Errorf("applied version is %s; expected %s", applied, next))
	}
	outsideAfter, err := app.git.worktreeOutsideTargetsDigest(repo)
	if err != nil {
		return rollbackAfterVerificationFailure(repo, updated, contents, fmt.Errorf("verify worktree isolation: %w", err))
	}
	if outsideAfter != outsideBefore {
		return rollbackAfterVerificationFailure(repo, updated, contents, errors.New("a non-version target changed during version preparation"))
	}
	if err := app.git.verifyPrepareState(repo, gitState); err != nil {
		return rollbackAfterVerificationFailure(repo, updated, contents, fmt.Errorf("verify Git safety state: %w", err))
	}
	app.printPlan(mode, bump, current, next)
	return nil
}

func (app application) environment(name string) string {
	if app.getenv == nil {
		return os.Getenv(name)
	}
	return app.getenv(name)
}

func isTruthy(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func rollbackAfterVerificationFailure(repo string, applied, original snapshot, verificationErr error) error {
	if rollbackErr := writeSnapshotAtomically(repo, applied, original); rollbackErr != nil {
		return fmt.Errorf("%v; rollback also failed: %w", verificationErr, rollbackErr)
	}
	return fmt.Errorf("%v; original version targets restored", verificationErr)
}

func (app application) printPlan(mode string, bump BumpType, current, next Version) {
	fmt.Fprintf(app.out, "Mode: %s\nBump: %s\nCurrent version: %s\nExpected version: %s\n", mode, bump, current, next)
	for _, item := range versionTargets {
		fmt.Fprintf(app.out, "%s: %d exact occurrence(s)\n", item.Path, item.Count)
	}
}

func (app application) runValidateCommit(args []string, stderr io.Writer) error {
	set := newFlagSet("validate-commit", stderr)
	repoFlag := set.String("repo", ".", "repository root")
	message := set.String("commit-message", "", "candidate commit message")
	baseRef := set.String("base-ref", "HEAD^", "Git commit used as the version baseline")
	tagPhase := set.Bool("tag-phase", false, "require the expected tag to exist and resolve to HEAD")
	if err := set.Parse(args); err != nil {
		return err
	}
	if set.NArg() != 0 {
		return errors.New("validate-commit accepts options only")
	}
	repo, err := cleanRepoPath(*repoFlag)
	if err != nil {
		return err
	}
	if err := validateGitRef(*baseRef); err != nil {
		return err
	}
	bump, recognized, err := parseCommitMessage(*message)
	if err != nil {
		return err
	}

	base := make(snapshot, len(versionTargets))
	for _, item := range versionTargets {
		data, err := app.git.fileAtRef(repo, *baseRef, item.Path)
		if err != nil {
			return err
		}
		base[item.Path] = data
	}
	previous, err := inspectBaselineSnapshot(base)
	if err != nil {
		return fmt.Errorf("invalid version baseline at %s: %w", *baseRef, err)
	}
	baseChangelog, err := app.git.fileAtRef(repo, *baseRef, changelogPath)
	if err != nil {
		return err
	}
	if err := validateChangelog(baseChangelog, previous); err != nil {
		return fmt.Errorf("invalid changelog baseline at %s: %w", *baseRef, err)
	}
	candidateChangelog, err := readRepoFile(repo, changelogPath)
	if err != nil {
		return fmt.Errorf("read %s: %w", changelogPath, err)
	}
	candidateContents, err := readWorktree(repo)
	if err != nil {
		return err
	}
	candidate, err := inspectSnapshot(candidateContents)
	if err != nil {
		return fmt.Errorf("invalid candidate version: %w", err)
	}

	if !recognized {
		if *tagPhase {
			return errors.New("tag-phase validation requires a Patch, Minor, Major, or Upgrade commit")
		}
		if candidate != previous {
			return fmt.Errorf("version changed from %s to %s without a recognized commit prefix", previous, candidate)
		}
		if !bytes.Equal(candidateChangelog, baseChangelog) {
			return errors.New("non-versioning commit must preserve changelog.md byte-for-byte")
		}
		if err := validateChangelog(candidateChangelog, candidate); err != nil {
			return err
		}
		fmt.Fprintf(app.out, "Commit validation passed: non-versioning commit preserves %s\n", candidate)
		return nil
	}

	expected, err := nextVersion(previous, bump)
	if err != nil {
		return err
	}
	if candidate != expected {
		return fmt.Errorf("%s commit requires %s from %s; candidate contains %s", bump, expected, previous, candidate)
	}
	if err := validateChangelog(candidateChangelog, expected); err != nil {
		return err
	}
	history, err := changelogHistory(candidateChangelog)
	if err != nil {
		return err
	}
	if !bytes.Equal(history, baseChangelog) {
		return errors.New("versioning commit must preserve the complete baseline changelog byte-for-byte after the new release separator")
	}
	exists, err := app.git.tagExists(repo, expected.String())
	if err != nil {
		return err
	}
	if exists && !*tagPhase {
		return fmt.Errorf("Git tag %s already exists before commit validation", expected)
	}
	if *tagPhase {
		if !exists {
			return fmt.Errorf("Git tag %s must exist during tag-phase commit validation", expected)
		}
		matchesHead, err := app.git.tagMatchesHead(repo, expected.String())
		if err != nil {
			return err
		}
		if !matchesHead {
			return fmt.Errorf("Git tag %s does not resolve to HEAD during tag-phase commit validation", expected)
		}
	}
	fmt.Fprintf(app.out, "Commit validation passed: %s -> %s (%s)\n", previous, expected, bump)
	return nil
}

func (app application) runValidateTag(args []string, stderr io.Writer) error {
	set := newFlagSet("validate-tag", stderr)
	repoFlag := set.String("repo", ".", "repository root")
	tag := set.String("tag", "", "candidate Git tag")
	if err := set.Parse(args); err != nil {
		return err
	}
	if set.NArg() != 0 {
		return errors.New("validate-tag accepts options only")
	}
	repo, err := cleanRepoPath(*repoFlag)
	if err != nil {
		return err
	}
	expected, err := parseVersion(*tag)
	if err != nil {
		return err
	}
	contents, err := readWorktree(repo)
	if err != nil {
		return err
	}
	candidate, err := inspectSnapshot(contents)
	if err != nil {
		return err
	}
	if candidate != expected {
		return fmt.Errorf("tag %s does not match source version %s", expected, candidate)
	}
	if err := readAndValidateChangelog(repo, expected); err != nil {
		return err
	}
	exists, err := app.git.tagExists(repo, expected.String())
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("Git tag %s does not exist in the checked-out repository", expected)
	}
	matchesHead, err := app.git.tagMatchesHead(repo, expected.String())
	if err != nil {
		return err
	}
	if !matchesHead {
		return fmt.Errorf("Git tag %s does not resolve to the checked-out HEAD commit", expected)
	}
	fmt.Fprintf(app.out, "Tag validation passed: %s matches all version targets and changelog.md\n", expected)
	return nil
}
