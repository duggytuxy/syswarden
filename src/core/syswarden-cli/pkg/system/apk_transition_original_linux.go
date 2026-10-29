//go:build linux

package system

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"syscall"
)

const apkOriginalPayloadSchema = "syswarden-apk-original-runtime/v1"

// These bytes are retained evidence, never an executable rollback authority.
// The enclosing native plan separately authenticates the installed CLI/core.
// Administrator files outside this closed runtime set are left untouched.
type apkOriginalPayloadEntry struct {
	Path     string                `json:"path"`
	Identity apkTransitionIdentity `json:"identity"`
	SHA256   string                `json:"sha256"`
}
type apkOriginalPayloadProposal struct {
	Schema        string                    `json:"schema"`
	Purpose       string                    `json:"purpose"`
	Parents       []apkOriginalPayloadEntry `json:"parents"`
	Files         []apkOriginalPayloadEntry `json:"files"`
	PayloadSHA256 string                    `json:"payload_sha256"`
}

type apkOriginalPayloadRecord struct {
	Schema             string                    `json:"schema"`
	ProposalSHA256     string                    `json:"proposal_sha256"`
	PayloadSHA256      string                    `json:"payload_sha256"`
	Parent             apkTransitionIdentity     `json:"retained_parent"`
	Files              []apkOriginalPayloadEntry `json:"retained_files"`
	RecoveryAuthorized bool                      `json:"recovery_authorized"`
}

type apkOriginalPayloadCustody struct {
	receipt         []byte
	receiptIdentity removalArtifactIdentity
	ancestry        []apkOriginalAncestor
	hostRoot        string
	executionPath   string
	proposal        *apkOriginalPayloadProposal
	proposalSHA256  string
	execution       *pinnedServiceDirectory
	saved           *pinnedServiceDirectory
	snapshot        retainedDirectorySnapshot
}

// Pin every path component, including ancestors outside the execution root.
// Mutable directory timestamps are not authority, because owned journal writes
// change them. Replacement, links, ownership or permission drift are refused.
type apkOriginalAncestor struct {
	path     string
	root     *os.Root
	identity removalArtifactIdentity
}

func pinAPKOriginalAncestry(path string) (_ []apkOriginalAncestor, result error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("original APK custody ancestry is not absolute")
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(parts) > 128 {
		return nil, errors.New("original APK custody ancestry exceeds its bound")
	}
	var ancestors []apkOriginalAncestor
	defer func() {
		if result != nil {
			result = errors.Join(result, closeAPKOriginalAncestry(ancestors))
		}
	}()
	current := "/"
	for index := -1; index < len(parts); index++ {
		if index >= 0 {
			if parts[index] == "" {
				continue
			}
			current = filepath.Join(current, parts[index])
		}
		before, err := os.Lstat(current)
		identity, identityErr := exactRemovalArtifactIdentity(before)
		if err != nil || identityErr != nil || !before.IsDir() || before.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("original APK custody ancestor is not a real directory")
		}
		root, err := os.OpenRoot(current)
		if err != nil {
			return nil, err
		}
		ancestors = append(ancestors, apkOriginalAncestor{current, root, identity})
	}
	if err := revalidateAPKOriginalAncestry(ancestors); err != nil {
		return nil, err
	}
	return ancestors, nil
}
func revalidateAPKOriginalAncestry(ancestors []apkOriginalAncestor) error {
	if len(ancestors) == 0 {
		return errors.New("original APK custody ancestry is unavailable")
	}
	for index, ancestor := range ancestors {
		var info os.FileInfo
		var err error
		if index == 0 {
			info, err = os.Lstat("/")
		} else {
			info, err = ancestors[index-1].root.Lstat(filepath.Base(ancestor.path))
		}
		actual, identityErr := exactRemovalArtifactIdentity(info)
		opened, openErr := ancestor.root.Stat(".")
		pinned, pinnedErr := exactRemovalArtifactIdentity(opened)
		same := func(value removalArtifactIdentity) bool {
			want := ancestor.identity
			return value.dev == want.dev && value.ino == want.ino && value.mode == want.mode && value.uid == want.uid && value.gid == want.gid
		}
		if err != nil || identityErr != nil || openErr != nil || pinnedErr != nil || !same(actual) || !same(pinned) {
			return errors.New("original APK custody ancestry changed")
		}
	}
	return nil
}
func closeAPKOriginalAncestry(ancestors []apkOriginalAncestor) error {
	var result error
	for _, ancestor := range ancestors {
		result = errors.Join(result, ancestor.root.Close())
	}
	return result
}

func apkOriginalIdentity(value removalArtifactIdentity) apkTransitionIdentity {
	return apkTransitionIdentity{Device: value.dev, Inode: value.ino, Mode: value.mode,
		UID: value.uid, GID: value.gid, Links: value.nlink, Size: value.size,
		ModifiedSec: value.mtime.Sec, ModifiedNS: value.mtime.Nsec,
		ChangedSec: value.ctime.Sec, ChangedNS: value.ctime.Nsec}
}

func apkOriginalExpected(proposal *apkOriginalPayloadProposal) (map[string]string, error) {
	if proposal == nil || proposal.Schema != apkOriginalPayloadSchema || proposal.Purpose != "retained-original-runtime-evidence-only" || !validSHA256(proposal.PayloadSHA256) {
		return nil, errors.New("original APK runtime proposal is unavailable or malformed")
	}
	expected := map[string]string{}
	for _, entry := range proposal.Files {
		switch entry.Path {
		case "bin/syswarden-cli", "bin/syswarden-core", "bin/syswarden-tui", "signatures.json":
			if _, present := expected[entry.Path]; present || !validSHA256(entry.SHA256) {
				return nil, errors.New("original APK runtime bindings are duplicated or invalid")
			}
			expected[entry.Path] = entry.SHA256
		case "activation-contract-v1.json":
		default:
			return nil, errors.New("original APK runtime proposal includes unrelated data")
		}
	}
	if len(expected) != 4 {
		return nil, errors.New("original APK runtime proposal is incomplete")
	}
	return expected, nil
}

func captureAPKOriginalPayloadProposalAt(ctx context.Context, hostRoot string) (_ *apkOriginalPayloadProposal, result error) {
	if ctx == nil || !filepath.IsAbs(hostRoot) || filepath.Clean(hostRoot) != hostRoot {
		return nil, errors.New("original APK runtime capture requires a context and fixed host root")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	proposal := &apkOriginalPayloadProposal{Schema: apkOriginalPayloadSchema, Purpose: "retained-original-runtime-evidence-only"}
	var parents []*pinnedServiceDirectory
	defer func() {
		for _, parent := range parents {
			result = errors.Join(result, parent.file.Close(), parent.root.Close())
		}
	}()
	for _, name := range []string{".", "opt", "opt/syswarden", "opt/syswarden/bin"} {
		parent, err := openExistingPinnedServiceDirectory(filepath.Join(hostRoot, name))
		if err != nil {
			return nil, err
		}
		parents = append(parents, parent)
		info, err := parent.file.Stat()
		if err != nil {
			return nil, err
		}
		status, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return nil, errors.New("original APK parent identity unavailable")
		}
		proposal.Parents = append(proposal.Parents, apkOriginalPayloadEntry{Path: name, Identity: apkTransitionStat(status)})
	}
	source := parents[2]
	expected := map[string]string{}
	for _, name := range []string{"bin/syswarden-cli", "bin/syswarden-core", "bin/syswarden-tui", "signatures.json"} {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		file, err := source.root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if err != nil {
			return nil, err
		}
		mode := os.FileMode(0750)
		if name == "signatures.json" {
			mode = 0640
		}
		_, digest, readErr := hashStandalonePayload(file, mode)
		closeErr := file.Close()
		if err := errors.Join(readErr, closeErr); err != nil {
			return nil, err
		}
		expected[name] = digest
	}
	snapshot, err := inspectBoundPayload(source, expected, true)
	if err != nil {
		return nil, err
	}
	proposal.PayloadSHA256 = snapshot.digest
	for name, digest := range snapshot.content {
		proposal.Files = append(proposal.Files, apkOriginalPayloadEntry{Path: name, Identity: apkOriginalIdentity(snapshot.files[name]), SHA256: string(digest)})
	}
	sort.Slice(proposal.Files, func(i, j int) bool { return proposal.Files[i].Path < proposal.Files[j].Path })
	for index, parent := range parents {
		if err := attestRetainedDirectoryParent(filepath.Join(hostRoot, proposal.Parents[index].Path), parent, false); err != nil {
			return nil, err
		}
		info, err := parent.file.Stat()
		if err != nil {
			return nil, err
		}
		status, ok := info.Sys().(*syscall.Stat_t)
		if !ok || apkTransitionStat(status) != proposal.Parents[index].Identity {
			return nil, errors.New("original APK runtime ancestry changed during capture")
		}
	}
	return proposal, ctx.Err()
}

func retainAPKOriginalPayloadAt(ctx context.Context, hostRoot, executionPath string, proposal *apkOriginalPayloadProposal, proposalSHA256 string) (_ *apkOriginalPayloadCustody, result error) {
	if ctx == nil || !validSHA256(proposalSHA256) || !filepath.IsAbs(executionPath) || filepath.Clean(executionPath) != executionPath {
		return nil, errors.New("original APK retention lacks exact approved custody")
	}
	raw, err := apkExecutionJSON(proposal)
	if err != nil || apkTransitionDigest(raw) != proposalSHA256 {
		return nil, errors.New("original APK retention proposal differs from approval")
	}
	expected, err := apkOriginalExpected(proposal)
	if err != nil {
		return nil, err
	}
	current, err := captureAPKOriginalPayloadProposalAt(ctx, hostRoot)
	if err != nil || !reflect.DeepEqual(current, proposal) {
		return nil, errors.Join(errors.New("original APK runtime changed before retention"), err)
	}
	source, err := openExistingPinnedServiceDirectory(filepath.Join(hostRoot, "opt/syswarden"))
	if err != nil {
		return nil, err
	}
	defer func() { result = errors.Join(result, source.file.Close(), source.root.Close()) }()
	ancestry, err := pinAPKOriginalAncestry(executionPath)
	if err != nil {
		return nil, err
	}
	ancestryRetained := false
	defer func() {
		if !ancestryRetained {
			result = errors.Join(result, closeAPKOriginalAncestry(ancestry))
		}
	}()
	execution, err := openExistingPinnedServiceDirectory(executionPath)
	if err != nil {
		return nil, err
	}
	executionRetained := false
	defer func() {
		if !executionRetained {
			result = errors.Join(result, execution.file.Close(), execution.root.Close())
		}
	}()
	info, err := execution.file.Stat()
	if err != nil || info.Mode() != os.ModeDir|0700 {
		return nil, errors.New("original APK retention needs a private execution directory")
	}
	// Interrupted or preexisting directories are preserved and never replayed.
	if err := execution.root.Mkdir("original-runtime", 0750); err != nil {
		return nil, err
	}
	savedPath := filepath.Join(executionPath, "original-runtime")
	saved, err := openExistingPinnedServiceDirectory(savedPath)
	if err != nil {
		return nil, err
	}
	success := false
	defer func() {
		if !success {
			result = errors.Join(result, saved.file.Close(), saved.root.Close())
		}
	}()
	if err := saved.root.Mkdir("bin", 0750); err != nil {
		return nil, err
	}
	for _, entry := range proposal.Files {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		mode := os.FileMode(0750)
		if entry.Path == "signatures.json" {
			mode = 0640
		} else if entry.Path == "activation-contract-v1.json" {
			mode = 0644
		}
		if err := copyAPKRecoveryFile(source.root, saved.root, entry.Path, mode, entry.SHA256); err != nil {
			return nil, err
		}
	}
	bin, err := openExistingPinnedServiceDirectory(filepath.Join(savedPath, "bin"))
	if err != nil {
		return nil, err
	}
	if err := errors.Join(bin.sync(), bin.file.Close(), bin.root.Close()); err != nil {
		return nil, err
	}
	if err := errors.Join(saved.sync(), execution.sync()); err != nil {
		return nil, err
	}
	snapshot, err := inspectStandalonePayload(saved, expected)
	if err != nil || snapshot.digest != proposal.PayloadSHA256 {
		return nil, errors.Join(errors.New("original APK retained payload did not verify"), err)
	}
	// Deep-copy the public proposal so a caller cannot mutate the approved set.
	var immutable apkOriginalPayloadProposal
	if err := decodeAPKTransitionJSON(raw, &immutable); err != nil {
		return nil, err
	}
	custody := &apkOriginalPayloadCustody{ancestry: ancestry, hostRoot: hostRoot, executionPath: executionPath, proposal: &immutable, proposalSHA256: proposalSHA256, saved: saved, execution: execution, snapshot: snapshot}
	if err := custody.RevalidateSource(ctx); err != nil {
		return nil, err
	}
	if err := custody.RevalidateRetained(ctx); err != nil {
		return nil, err
	}
	var retained []apkOriginalPayloadEntry
	for name, digest := range snapshot.content {
		retained = append(retained, apkOriginalPayloadEntry{Path: name, Identity: apkOriginalIdentity(snapshot.files[name]), SHA256: string(digest)})
	}
	sort.Slice(retained, func(i, j int) bool { return retained[i].Path < retained[j].Path })
	receipt, err := apkExecutionJSON(apkOriginalPayloadRecord{Schema: apkOriginalPayloadSchema, ProposalSHA256: proposalSHA256, PayloadSHA256: snapshot.digest, Parent: apkOriginalIdentity(snapshot.directory), Files: retained})
	if err != nil {
		return nil, err
	}
	if err := writeAPKTransitionBytes(execution, "original-runtime.json", receipt); err != nil {
		return nil, err
	}
	custody.receipt = bytes.Clone(receipt)
	receiptInfo, err := execution.root.Lstat("original-runtime.json")
	if err != nil {
		return nil, err
	}
	custody.receiptIdentity, err = exactRemovalArtifactIdentity(receiptInfo)
	if err != nil {
		return nil, err
	}
	if err := custody.RevalidateRetained(ctx); err != nil {
		return nil, err
	}
	success = true
	executionRetained = true
	ancestryRetained = true
	return custody, nil
}

func (custody *apkOriginalPayloadCustody) RevalidateSource(ctx context.Context) error {
	if custody == nil || custody.proposal == nil || custody.saved == nil {
		return errors.New("original APK runtime custody is closed or missing")
	}
	current, err := captureAPKOriginalPayloadProposalAt(ctx, custody.hostRoot)
	if err != nil || !reflect.DeepEqual(current, custody.proposal) {
		return errors.Join(errors.New("original APK runtime changed before native dispatch"), err)
	}
	return nil
}
func (custody *apkOriginalPayloadCustody) RevalidateRetained(ctx context.Context) error {
	if ctx == nil || custody == nil || custody.saved == nil {
		return errors.New("original APK retained custody is closed or missing")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := revalidateAPKOriginalAncestry(custody.ancestry); err != nil {
		return err
	}
	if custody.execution == nil {
		return errors.New("original APK execution custody is unavailable")
	}
	if err := attestRetainedDirectoryParent(custody.executionPath, custody.execution, false); err != nil {
		return err
	}
	info, err := custody.execution.file.Stat()
	if err != nil || info.Mode() != os.ModeDir|0700 {
		return errors.New("original APK execution custody lost private permissions")
	}
	expected, err := apkOriginalExpected(custody.proposal)
	if err != nil {
		return err
	}
	raw, err := apkExecutionJSON(custody.proposal)
	if err != nil || apkTransitionDigest(raw) != custody.proposalSHA256 {
		return errors.New("original APK retained proposal changed")
	}
	current, err := inspectStandalonePayload(custody.saved, expected)
	if err != nil || !sameRetainedDirectorySnapshot(custody.snapshot, current, false) {
		return errors.Join(errors.New("original APK retained runtime changed"), err)
	}
	if err := attestRetainedDirectoryParent(filepath.Join(custody.executionPath, "original-runtime"), custody.saved, false); err != nil {
		return err
	}
	if custody.receipt != nil {
		before, err := custody.execution.root.Lstat("original-runtime.json")
		identity, identityErr := exactRemovalArtifactIdentity(before)
		if err != nil || identityErr != nil || identity != custody.receiptIdentity {
			return errors.New("original APK retention receipt identity changed")
		}
		receipt, err := readAPKTransitionBytes(custody.execution, "original-runtime.json", 64<<10)
		after, afterErr := custody.execution.root.Lstat("original-runtime.json")
		afterIdentity, identityErr := exactRemovalArtifactIdentity(after)
		if err != nil || afterErr != nil || identityErr != nil || afterIdentity != custody.receiptIdentity || !bytes.Equal(receipt, custody.receipt) {
			return errors.Join(errors.New("original APK retention receipt changed"), err, afterErr, identityErr)
		}
	}
	return ctx.Err()
}
func (custody *apkOriginalPayloadCustody) Close() error {
	if custody == nil || custody.saved == nil {
		return nil
	}
	result := errors.Join(custody.saved.file.Close(), custody.saved.root.Close())
	if custody.execution != nil {
		result = errors.Join(result, custody.execution.file.Close(), custody.execution.root.Close())
		custody.execution = nil
	}
	custody.saved = nil
	result = errors.Join(result, closeAPKOriginalAncestry(custody.ancestry))
	custody.ancestry = nil
	return result
}

func bindAPKOriginalRuntime(proposal *apkOriginalPayloadProposal, cliSHA256, coreSHA256 string) error {
	expected, err := apkOriginalExpected(proposal)
	if err != nil {
		return err
	}
	if !validSHA256(cliSHA256) || !validSHA256(coreSHA256) || expected["bin/syswarden-cli"] != cliSHA256 || expected["bin/syswarden-core"] != coreSHA256 {
		return fmt.Errorf("original APK runtime does not match the authenticated installed binary pair")
	}
	return nil
}

// reopenAPKOriginalPayloadAt verifies retained evidence without treating the
// current installed payload as the original source. It never restores bytes.
func reopenAPKOriginalPayloadAt(ctx context.Context, hostRoot, executionPath string, proposal *apkOriginalPayloadProposal, proposalSHA256 string) (_ *apkOriginalPayloadCustody, result error) {
	if ctx == nil || !validSHA256(proposalSHA256) {
		return nil, errors.New("original APK inspection lacks an exact proposal")
	}
	raw, err := apkExecutionJSON(proposal)
	if err != nil || apkTransitionDigest(raw) != proposalSHA256 {
		return nil, errors.New("original APK inspection proposal changed")
	}
	expected, err := apkOriginalExpected(proposal)
	if err != nil {
		return nil, err
	}
	custody := &apkOriginalPayloadCustody{hostRoot: hostRoot, executionPath: executionPath, proposalSHA256: proposalSHA256}
	defer func() {
		if result != nil {
			result = errors.Join(result, custody.Close())
			if custody.execution != nil {
				result = errors.Join(result, custody.execution.file.Close(), custody.execution.root.Close())
			}
			result = errors.Join(result, closeAPKOriginalAncestry(custody.ancestry))
		}
	}()
	var immutable apkOriginalPayloadProposal
	if err := decodeAPKTransitionJSON(raw, &immutable); err != nil {
		return nil, err
	}
	custody.proposal = &immutable
	custody.ancestry, err = pinAPKOriginalAncestry(executionPath)
	if err != nil {
		return nil, err
	}
	custody.execution, err = openExistingPinnedServiceDirectory(executionPath)
	if err != nil {
		return nil, err
	}
	before, err := custody.execution.root.Lstat("original-runtime.json")
	if err != nil {
		return nil, err
	}
	custody.receiptIdentity, err = exactRemovalArtifactIdentity(before)
	if err != nil {
		return nil, err
	}
	custody.receipt, err = readAPKTransitionBytes(custody.execution, "original-runtime.json", 64<<10)
	if err != nil {
		return nil, err
	}
	var record apkOriginalPayloadRecord
	if err := decodeAPKTransitionJSON(custody.receipt, &record); err != nil {
		return nil, err
	}
	if record.Schema != apkOriginalPayloadSchema || record.ProposalSHA256 != proposalSHA256 || record.PayloadSHA256 != proposal.PayloadSHA256 || record.RecoveryAuthorized {
		return nil, errors.New("original APK retained receipt is inconsistent")
	}
	custody.saved, err = openExistingPinnedServiceDirectory(filepath.Join(executionPath, "original-runtime"))
	if err != nil {
		return nil, err
	}
	custody.snapshot, err = inspectStandalonePayload(custody.saved, expected)
	if err != nil {
		return nil, err
	}
	if custody.snapshot.digest != record.PayloadSHA256 || apkOriginalIdentity(custody.snapshot.directory) != record.Parent || len(record.Files) != len(custody.snapshot.content) {
		return nil, errors.New("original APK saved inventory differs from its receipt")
	}
	previous := ""
	for _, entry := range record.Files {
		if entry.Path <= previous || string(custody.snapshot.content[entry.Path]) != entry.SHA256 || apkOriginalIdentity(custody.snapshot.files[entry.Path]) != entry.Identity {
			return nil, errors.New("original APK saved file identity or bytes changed")
		}
		previous = entry.Path
	}
	return custody, custody.RevalidateRetained(ctx)
}
