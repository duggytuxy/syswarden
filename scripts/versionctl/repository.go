package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

type target struct {
	Path          string
	Count         int
	ScopedPattern *regexp.Regexp
	HeadOptional  bool
}

var versionTargets = []target{
	{Path: "src/core/syswarden-cli/pkg/system/upgrade.go", Count: 1},
	{Path: "src/core/syswarden-tui/main.go", Count: 1},
	{Path: "src/core/syswarden-cli/cmd/install.go", Count: 1},
	{Path: "src/core/syswarden-cli/config/default.go", Count: 1},
	{Path: "src/core/syswarden-cli/pkg/integration/webhook.go", Count: 1},
	{Path: "src/core/syswarden-core/webhook/discord.go", Count: 3},
	{
		Path:          "README.md",
		Count:         1,
		ScopedPattern: regexp.MustCompile(`(?m)^Current source version: \*\*(v[0-9]+\.[0-9]{2}\.[0-9]+)\*\*\.$`),
		HeadOptional:  true,
	},
}

const changelogPath = "changelog.md"

type snapshot map[string][]byte

func snapshotEqual(left, right snapshot) bool {
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

func readWorktree(repo string) (snapshot, error) {
	root, err := openRepositoryRoot(repo)
	if err != nil {
		return nil, err
	}
	defer root.Close()

	contents := make(snapshot, len(versionTargets))
	for _, item := range versionTargets {
		data, err := root.ReadFile(filepath.FromSlash(item.Path))
		if err != nil {
			return nil, fmt.Errorf("read version target %s: %w", item.Path, err)
		}
		contents[item.Path] = data
	}
	return contents, nil
}

func openRepositoryRoot(repo string) (*os.Root, error) {
	root, err := os.OpenRoot(repo)
	if err != nil {
		return nil, fmt.Errorf("open repository root: %w", err)
	}
	return root, nil
}

func readRepoFile(repo, path string) ([]byte, error) {
	root, err := openRepositoryRoot(repo)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	return root.ReadFile(filepath.FromSlash(path))
}

func openVersionLockRoot(lockPath string) (*os.Root, string, error) {
	const lockName = "versionctl.lock"
	if filepath.Base(lockPath) != lockName {
		return nil, "", fmt.Errorf("Git returned an unexpected versionctl lock name: %s", lockPath)
	}
	// #nosec G703 -- The parent is resolved by `git rev-parse --git-path` with the fixed lock name and the basename is checked above.
	root, err := os.OpenRoot(filepath.Dir(lockPath))
	if err != nil {
		return nil, "", fmt.Errorf("open versionctl lock directory: %w", err)
	}
	return root, lockName, nil
}

func inspectSnapshot(contents snapshot) (Version, error) {
	return inspectSnapshotWithOptionalHeadTargets(contents, false)
}

func inspectBaselineSnapshot(contents snapshot) (Version, error) {
	return inspectSnapshotWithOptionalHeadTargets(contents, true)
}

func inspectSnapshotWithOptionalHeadTargets(contents snapshot, allowOptional bool) (Version, error) {
	var common Version
	commonSet := false
	for _, item := range versionTargets {
		data, ok := contents[item.Path]
		if !ok {
			return Version{}, fmt.Errorf("missing version target %s", item.Path)
		}
		matches := targetVersionMatches(item, data)
		if allowOptional && item.HeadOptional && len(matches) == 0 {
			continue
		}
		if len(matches) != item.Count {
			return Version{}, fmt.Errorf("version target %s contains %d version occurrence(s); expected exactly %d", item.Path, len(matches), item.Count)
		}
		for _, match := range matches {
			version, err := parseVersion(string(match))
			if err != nil {
				return Version{}, fmt.Errorf("version target %s: %w", item.Path, err)
			}
			if !commonSet {
				common = version
				commonSet = true
			} else if version != common {
				return Version{}, fmt.Errorf("version target %s contains %s; expected %s", item.Path, version, common)
			}
		}
	}
	if !commonSet {
		return Version{}, errors.New("no version occurrence found")
	}
	return common, nil
}

func replaceVersionTokens(contents snapshot, oldVersion, newVersion Version) (snapshot, error) {
	updated := make(snapshot, len(contents))
	oldText := oldVersion.String()
	newText := newVersion.String()
	for _, item := range versionTargets {
		data := contents[item.Path]
		replacements := 0
		var replaced []byte
		if item.ScopedPattern == nil {
			replaced = versionToken.ReplaceAllFunc(data, func(match []byte) []byte {
				if string(match) != oldText {
					return match
				}
				replacements++
				return []byte(newText)
			})
		} else {
			replaced = item.ScopedPattern.ReplaceAllFunc(data, func(match []byte) []byte {
				parts := item.ScopedPattern.FindSubmatch(match)
				if len(parts) != 2 || string(parts[1]) != oldText {
					return match
				}
				replacements++
				return bytes.Replace(match, parts[1], []byte(newText), 1)
			})
		}
		if replacements != item.Count {
			return nil, fmt.Errorf("version target %s would replace %d occurrence(s); expected exactly %d", item.Path, replacements, item.Count)
		}
		updated[item.Path] = replaced
	}
	return updated, nil
}

func targetVersionMatches(item target, data []byte) [][]byte {
	if item.ScopedPattern == nil {
		return versionToken.FindAll(data, -1)
	}
	records := item.ScopedPattern.FindAllSubmatch(data, -1)
	matches := make([][]byte, 0, len(records))
	for _, record := range records {
		if len(record) == 2 {
			matches = append(matches, record[1])
		}
	}
	return matches
}

func validateChangelog(data []byte, expected Version) error {
	normalized := strings.ReplaceAll(string(bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))), "\r\n", "\n")
	lines := strings.Split(normalized, "\n")
	if len(lines) == 0 || lines[0] != "# Release "+expected.String() {
		actual := ""
		if len(lines) > 0 {
			actual = lines[0]
		}
		return fmt.Errorf("changelog first heading is %q; expected %q", actual, "# Release "+expected.String())
	}

	separator := -1
	for i := 1; i < len(lines); i++ {
		if lines[i] == "---" {
			separator = i
			break
		}
	}
	if separator < 0 {
		return errors.New("changelog first release block has no exact --- separator")
	}

	hasSection := false
	hasBullet := false
	for _, line := range lines[1:separator] {
		if strings.HasPrefix(line, "### ") && strings.TrimSpace(strings.TrimPrefix(line, "### ")) != "" {
			hasSection = true
		}
		if strings.HasPrefix(line, "- ") && strings.TrimSpace(strings.TrimPrefix(line, "- ")) != "" {
			hasBullet = true
		}
	}
	if !hasSection || !hasBullet {
		return errors.New("changelog first release block must contain at least one ### section and one non-empty - bullet")
	}
	return nil
}

func changelogHistory(data []byte) ([]byte, error) {
	lineStart := 0
	for lineStart <= len(data) {
		lineEnd := bytes.IndexByte(data[lineStart:], '\n')
		nextLine := len(data)
		if lineEnd >= 0 {
			lineEnd += lineStart
			nextLine = lineEnd + 1
		} else {
			lineEnd = len(data)
		}
		line := data[lineStart:lineEnd]
		line = bytes.TrimSuffix(line, []byte{'\r'})
		if bytes.Equal(line, []byte("---")) {
			historyStart := nextLine
			if historyStart < len(data) && data[historyStart] == '\n' {
				historyStart++
			} else if historyStart+1 < len(data) && data[historyStart] == '\r' && data[historyStart+1] == '\n' {
				historyStart += 2
			}
			if historyStart >= len(data) {
				return nil, errors.New("changelog release separator has no historical suffix")
			}
			return data[historyStart:], nil
		}
		if nextLine >= len(data) {
			break
		}
		lineStart = nextLine
	}
	return nil, errors.New("changelog first release block has no exact --- separator")
}

func readAndValidateChangelog(repo string, expected Version) error {
	data, err := readRepoFile(repo, changelogPath)
	if err != nil {
		return fmt.Errorf("read %s: %w", changelogPath, err)
	}
	return validateChangelog(data, expected)
}

type stagedFile struct {
	targetPath string
	tempPath   string
	original   []byte
	mode       fs.FileMode
}

func writeSnapshotAtomically(repo string, original, updated snapshot) (err error) {
	return writeSnapshotWithRename(repo, original, updated, func(root *os.Root, oldPath, newPath string) error {
		return root.Rename(oldPath, newPath)
	})
}

func writeSnapshotWithRename(
	repo string,
	original, updated snapshot,
	rename func(*os.Root, string, string) error,
) (err error) {
	root, err := openRepositoryRoot(repo)
	if err != nil {
		return err
	}
	defer root.Close()

	staged := make([]stagedFile, 0, len(versionTargets))
	defer func() {
		for _, file := range staged {
			if file.tempPath != "" {
				_ = root.Remove(file.tempPath)
			}
		}
	}()

	for _, item := range versionTargets {
		targetPath := filepath.FromSlash(item.Path)
		info, statErr := root.Lstat(targetPath)
		if statErr != nil {
			return fmt.Errorf("stat version target %s: %w", item.Path, statErr)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("version target %s is not a regular file", item.Path)
		}
		temp, tempPath, createErr := createRootTemp(root, filepath.Dir(targetPath), ".versionctl-")
		if createErr != nil {
			return fmt.Errorf("stage version target %s: %w", item.Path, createErr)
		}
		entry := stagedFile{targetPath: targetPath, tempPath: tempPath, original: original[item.Path], mode: info.Mode().Perm()}
		staged = append(staged, entry)
		if chmodErr := temp.Chmod(info.Mode()); chmodErr != nil {
			_ = temp.Close()
			return fmt.Errorf("preserve mode for %s: %w", item.Path, chmodErr)
		}
		if _, writeErr := temp.Write(updated[item.Path]); writeErr != nil {
			_ = temp.Close()
			return fmt.Errorf("stage version target %s: %w", item.Path, writeErr)
		}
		if syncErr := temp.Sync(); syncErr != nil {
			_ = temp.Close()
			return fmt.Errorf("sync staged version target %s: %w", item.Path, syncErr)
		}
		if closeErr := temp.Close(); closeErr != nil {
			return fmt.Errorf("close staged version target %s: %w", item.Path, closeErr)
		}
	}

	committed := 0
	for i := range staged {
		if renameErr := rename(root, staged[i].tempPath, staged[i].targetPath); renameErr != nil {
			rollbackErr := rollbackFiles(root, staged[:committed])
			if rollbackErr != nil {
				return fmt.Errorf("commit version target %s: %w; rollback also failed: %v", versionTargets[i].Path, renameErr, rollbackErr)
			}
			return fmt.Errorf("commit version target %s: %w", versionTargets[i].Path, renameErr)
		}
		staged[i].tempPath = ""
		committed++
	}
	return nil
}

func createRootTemp(root *os.Root, directory, prefix string) (*os.File, string, error) {
	for range 100 {
		random := make([]byte, 16)
		if _, err := rand.Read(random); err != nil {
			return nil, "", fmt.Errorf("generate temporary file name: %w", err)
		}
		path := filepath.Join(directory, prefix+hex.EncodeToString(random))
		file, err := root.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
		if err == nil {
			return file, path, nil
		}
		if !errors.Is(err, fs.ErrExist) {
			return nil, "", err
		}
	}
	return nil, "", errors.New("cannot allocate a unique temporary file")
}

func rollbackFiles(root *os.Root, files []stagedFile) error {
	var failures []string
	for i := len(files) - 1; i >= 0; i-- {
		file := files[i]
		temp, tempPath, err := createRootTemp(root, filepath.Dir(file.targetPath), ".versionctl-rollback-")
		if err == nil {
			err = temp.Chmod(file.mode)
		}
		if err == nil {
			_, err = temp.Write(file.original)
		}
		if err == nil {
			err = temp.Sync()
		}
		closeErr := error(nil)
		if temp != nil {
			closeErr = temp.Close()
		}
		if err == nil {
			err = closeErr
		}
		if err == nil {
			err = root.Rename(tempPath, file.targetPath)
		}
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", file.targetPath, err))
			if temp != nil {
				_ = root.Remove(tempPath)
			}
		}
	}
	if len(failures) > 0 {
		return errors.New(strings.Join(failures, "; "))
	}
	return nil
}

type gitClient interface {
	fileAtRef(repo, ref, path string) ([]byte, error)
	tagExists(repo, tag string) (bool, error)
	tagMatchesHead(repo, tag string) (bool, error)
	lockPath(repo string) (string, error)
	capturePrepareState(repo, expectedHead string) (gitPrepareState, error)
	verifyPrepareState(repo string, expected gitPrepareState) error
	worktreeOutsideTargetsDigest(repo string) (string, error)
}

type gitPrepareState struct {
	Head   string
	Branch string
	Refs   string
}

type realGit struct{}

var safeGitRef = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z._/-]*\^?$`)
var fullGitSHA = regexp.MustCompile(`^[0-9a-f]{40}$`)

func validateGitRef(ref string) error {
	if !safeGitRef.MatchString(ref) || strings.Contains(ref, "..") || strings.Contains(ref, "@{") || strings.Contains(ref, "//") {
		return fmt.Errorf("unsafe or invalid Git ref %q", ref)
	}
	return nil
}

func validateManagedPath(path string) error {
	if path == changelogPath {
		return nil
	}
	for _, item := range versionTargets {
		if path == item.Path {
			return nil
		}
	}
	return fmt.Errorf("path %q is outside the managed version contract", path)
}

func (realGit) fileAtRef(repo, ref, path string) ([]byte, error) {
	if err := validateGitRef(ref); err != nil {
		return nil, err
	}
	if err := validateManagedPath(path); err != nil {
		return nil, err
	}
	// #nosec G204 -- Git is the fixed executable and both the ref and managed repository path are validated above; exec.Command does not invoke a shell.
	command := exec.Command("git", "-C", repo, "show", ref+":"+path)
	output, err := command.Output()
	if err != nil {
		return nil, fmt.Errorf("read %s at Git ref %s: %w", path, ref, err)
	}
	return output, nil
}

func (realGit) tagExists(repo, tag string) (bool, error) {
	if _, err := parseVersion(tag); err != nil {
		return false, err
	}
	// #nosec G204 G702 -- Git is the fixed executable and tag is a canonical SysWarden version validated above; exec.Command does not invoke a shell.
	command := exec.Command("git", "-C", repo, "show-ref", "--verify", "--quiet", "refs/tags/"+tag)
	err := command.Run()
	if err == nil {
		return true, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && exitErr.ExitCode() == 1 {
		return false, nil
	}
	return false, fmt.Errorf("check Git tag %s: %w", tag, err)
}

func (realGit) tagMatchesHead(repo, tag string) (bool, error) {
	if _, err := parseVersion(tag); err != nil {
		return false, err
	}
	resolve := func(ref string) (string, error) {
		// #nosec G204 -- Git is the fixed executable and ref is selected only from HEAD or the canonical version tag validated above.
		command := exec.Command("git", "-C", repo, "rev-parse", "--verify", ref+"^{commit}")
		output, err := command.Output()
		if err != nil {
			return "", fmt.Errorf("resolve Git ref %s: %w", ref, err)
		}
		return strings.TrimSpace(string(output)), nil
	}
	head, err := resolve("HEAD")
	if err != nil {
		return false, err
	}
	tagCommit, err := resolve("refs/tags/" + tag)
	if err != nil {
		return false, err
	}
	return head == tagCommit, nil
}

func (realGit) lockPath(repo string) (string, error) {
	// #nosec G204 -- Git is the fixed executable and all options, including the lock name, are constants; repo is passed as the value of -C without a shell.
	command := exec.Command("git", "-C", repo, "rev-parse", "--git-path", "versionctl.lock")
	output, err := command.Output()
	if err != nil {
		return "", fmt.Errorf("resolve versionctl lock path: %w", err)
	}
	path := strings.TrimSpace(string(output))
	if !filepath.IsAbs(path) {
		path = filepath.Join(repo, path)
	}
	return filepath.Clean(path), nil
}

func gitCommandOutput(repo string, arguments ...string) (string, error) {
	// #nosec G204 G702 -- Git is the fixed executable, this private helper has constant-only call sites, and exec.Command passes arguments without a shell.
	command := exec.Command("git", append([]string{"-C", repo}, arguments...)...)
	output, err := command.Output()
	if err != nil {
		return "", fmt.Errorf("git %s: %w", strings.Join(arguments, " "), err)
	}
	return strings.TrimSpace(string(output)), nil
}

func gitCommandQuiet(repo string, arguments ...string) error {
	// #nosec G204 G702 -- Git is the fixed executable, this private helper has constant-only call sites, and exec.Command passes arguments without a shell.
	command := exec.Command("git", append([]string{"-C", repo}, arguments...)...)
	if err := command.Run(); err != nil {
		return fmt.Errorf("git %s: %w", strings.Join(arguments, " "), err)
	}
	return nil
}

func (realGit) capturePrepareState(repo, expectedHead string) (gitPrepareState, error) {
	inside, err := gitCommandOutput(repo, "rev-parse", "--is-inside-work-tree")
	if err != nil || inside != "true" {
		return gitPrepareState{}, errors.New("version preparation requires a valid Git worktree")
	}
	branch, err := gitCommandOutput(repo, "symbolic-ref", "--quiet", "--short", "HEAD")
	if err != nil || branch == "" {
		return gitPrepareState{}, errors.New("version preparation refuses a detached Git HEAD")
	}
	head, err := gitCommandOutput(repo, "rev-parse", "--verify", "HEAD^{commit}")
	if err != nil || !fullGitSHA.MatchString(head) {
		return gitPrepareState{}, errors.New("cannot resolve the candidate Git HEAD")
	}
	if expectedHead != "" {
		if !fullGitSHA.MatchString(expectedHead) {
			return gitPrepareState{}, fmt.Errorf("expected HEAD must be a full lowercase Git SHA, got %q", expectedHead)
		}
		if head != expectedHead {
			return gitPrepareState{}, fmt.Errorf("Git HEAD is %s; expected %s", head, expectedHead)
		}
	}
	if err := gitCommandQuiet(repo, "show-ref", "--verify", "--quiet", "refs/heads/main"); err != nil {
		return gitPrepareState{}, errors.New("local refs/heads/main is required for version preparation")
	}
	if err := gitCommandQuiet(repo, "merge-base", "--is-ancestor", "refs/heads/main", "HEAD"); err != nil {
		return gitPrepareState{}, errors.New("local main must be an ancestor of the candidate HEAD")
	}
	if err := gitCommandQuiet(repo, "diff", "--cached", "--quiet", "--exit-code", "--"); err != nil {
		return gitPrepareState{}, errors.New("version preparation requires an empty Git index; unstage the candidate before applying the bump")
	}
	refs, err := gitCommandOutput(repo, "for-each-ref", "--format=%(refname)%00%(objectname)")
	if err != nil {
		return gitPrepareState{}, err
	}
	return gitPrepareState{Head: head, Branch: branch, Refs: refs}, nil
}

func (git realGit) verifyPrepareState(repo string, expected gitPrepareState) error {
	current, err := git.capturePrepareState(repo, expected.Head)
	if err != nil {
		return err
	}
	if current.Branch != expected.Branch {
		return fmt.Errorf("Git branch changed during version preparation: %s -> %s", expected.Branch, current.Branch)
	}
	if current.Refs != expected.Refs {
		return errors.New("Git refs changed during version preparation")
	}
	return nil
}

func filesystemOutsideTargetsDigest(repo string) (string, error) {
	root, err := openRepositoryRoot(repo)
	if err != nil {
		return "", err
	}
	defer root.Close()

	excluded := make(map[string]struct{}, len(versionTargets))
	for _, item := range versionTargets {
		excluded[filepath.ToSlash(item.Path)] = struct{}{}
	}
	type entry struct {
		path string
		mode fs.FileMode
		data []byte
	}
	entries := make([]entry, 0)
	err = fs.WalkDir(root.FS(), ".", func(path string, item fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative := filepath.ToSlash(path)
		if relative == ".git" && item.IsDir() {
			return filepath.SkipDir
		}
		if relative == "." || item.IsDir() {
			return nil
		}
		if _, skip := excluded[relative]; skip {
			return nil
		}
		info, err := item.Info()
		if err != nil {
			return err
		}
		var data []byte
		if info.Mode().IsRegular() {
			data, err = root.ReadFile(filepath.FromSlash(relative))
		} else if info.Mode()&os.ModeSymlink != 0 {
			var target string
			target, err = root.Readlink(filepath.FromSlash(relative))
			data = []byte(target)
		} else {
			return fmt.Errorf("unsupported worktree entry during version preparation: %s", relative)
		}
		if err != nil {
			return err
		}
		entries = append(entries, entry{path: relative, mode: info.Mode(), data: data})
		return nil
	})
	if err != nil {
		return "", fmt.Errorf("snapshot candidate worktree: %w", err)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].path < entries[j].path })
	digest := sha256.New()
	for _, item := range entries {
		_, _ = digest.Write([]byte(item.path))
		_, _ = digest.Write([]byte{0})
		_, _ = digest.Write([]byte(item.mode.String()))
		_, _ = digest.Write([]byte{0})
		contentDigest := sha256.Sum256(item.data)
		_, _ = digest.Write(contentDigest[:])
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

func (realGit) worktreeOutsideTargetsDigest(repo string) (string, error) {
	root, err := openRepositoryRoot(repo)
	if err != nil {
		return "", err
	}
	defer root.Close()

	// #nosec G204 -- The executable and every Git option are fixed constants; repo is a validated absolute directory argument, not shell input.
	command := exec.Command(
		"git", "-C", repo, "ls-files", "-z", "--cached", "--others", "--exclude-standard",
	)
	output, err := command.Output()
	if err != nil {
		return "", fmt.Errorf("inventory candidate worktree: %w", err)
	}
	excluded := make(map[string]struct{}, len(versionTargets))
	for _, item := range versionTargets {
		excluded[item.Path] = struct{}{}
	}
	paths := bytes.Split(output, []byte{0})
	type entry struct {
		path    string
		mode    fs.FileMode
		data    []byte
		missing bool
	}
	entries := make([]entry, 0, len(paths))
	for _, raw := range paths {
		if len(raw) == 0 {
			continue
		}
		relative := filepath.ToSlash(string(raw))
		if _, skip := excluded[relative]; skip {
			continue
		}
		path := filepath.FromSlash(relative)
		info, err := root.Lstat(path)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				entries = append(entries, entry{path: relative, missing: true})
				continue
			}
			return "", fmt.Errorf("inspect candidate worktree file %s: %w", relative, err)
		}
		var data []byte
		if info.Mode().IsRegular() {
			data, err = root.ReadFile(path)
		} else if info.Mode()&os.ModeSymlink != 0 {
			var target string
			target, err = root.Readlink(path)
			data = []byte(target)
		} else {
			return "", fmt.Errorf("unsupported candidate worktree entry: %s", relative)
		}
		if err != nil {
			return "", err
		}
		entries = append(entries, entry{path: relative, mode: info.Mode(), data: data})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].path < entries[j].path })
	digest := sha256.New()
	for _, item := range entries {
		_, _ = digest.Write([]byte(item.path))
		_, _ = digest.Write([]byte{0})
		if item.missing {
			_, _ = digest.Write([]byte("missing"))
			_, _ = digest.Write([]byte{0})
			continue
		}
		_, _ = digest.Write([]byte("present"))
		_, _ = digest.Write([]byte{0})
		_, _ = digest.Write([]byte(item.mode.String()))
		_, _ = digest.Write([]byte{0})
		contentDigest := sha256.Sum256(item.data)
		_, _ = digest.Write(contentDigest[:])
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}
