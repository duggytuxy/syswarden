//go:build linux

package security

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

type cisRemovalPolicy struct {
	path            string
	quarantinePath  string
	expectedContent [][]byte
}

type cisRemovalDisposition uint8

const (
	cisRemovalAbsent cisRemovalDisposition = iota
	cisRemovalExact
	cisRemovalPreserved
	cisRemovalPending
)

func cisSysctlRemovalContent() [][]byte {
	content := make([][]byte, 0, 12)
	for _, includeBPFJITHardening := range []bool{true, false} {
		for _, unprivilegedBPF := range []string{"1", "2"} {
			for _, ptraceScope := range []string{"1", "2", "3"} {
				policy := cisSysctlPolicy
				if !includeBPFJITHardening {
					policy = strings.Replace(policy, "net.core.bpf_jit_harden = 2\n", "", 1)
				}
				if unprivilegedBPF != "1" {
					policy = strings.Replace(
						policy,
						"kernel.unprivileged_bpf_disabled = 1",
						"kernel.unprivileged_bpf_disabled = "+unprivilegedBPF,
						1,
					)
				}
				if ptraceScope != "1" {
					policy = strings.Replace(
						policy,
						"kernel.yama.ptrace_scope = 1",
						"kernel.yama.ptrace_scope = "+ptraceScope,
						1,
					)
				}
				content = append(content, []byte(policy))
			}
		}
	}
	return content
}

func cisRemovalPolicies() []cisRemovalPolicy {
	return []cisRemovalPolicy{
		{
			path:            cisFilesystemPolicyPath,
			quarantinePath:  cisRemovalQuarantinePath(cisFilesystemPolicyPath),
			expectedContent: [][]byte{[]byte(cisFilesystemPolicy)},
		},
		{
			path:            cisNetworkPolicyPath,
			quarantinePath:  cisRemovalQuarantinePath(cisNetworkPolicyPath),
			expectedContent: [][]byte{[]byte(cisNetworkPolicy)},
		},
		{
			path:            cisSysctlPolicyPath,
			quarantinePath:  cisRemovalQuarantinePath(cisSysctlPolicyPath),
			expectedContent: cisSysctlRemovalContent(),
		},
		{
			path:            cisLimitsPolicyPath,
			quarantinePath:  cisRemovalQuarantinePath(cisLimitsPolicyPath),
			expectedContent: [][]byte{[]byte(cisLimitsPolicy)},
		},
		{
			path:            cisCoredumpPolicyPath,
			quarantinePath:  cisRemovalQuarantinePath(cisCoredumpPolicyPath),
			expectedContent: [][]byte{[]byte(cisCoredumpPolicy)},
		},
	}
}

func cisRemovalQuarantinePath(logical string) string {
	return filepath.Join(
		filepath.Dir(logical),
		"."+filepath.Base(logical)+".syswarden-removal-v1",
	)
}

func cisRemovalContentIsExact(content []byte, expected [][]byte) bool {
	for _, candidate := range expected {
		if bytes.Equal(content, candidate) {
			return true
		}
	}
	return false
}

func cisRemovalMetadataIsExact(host hardeningHost, info fs.FileInfo) bool {
	if info == nil || !info.Mode().IsRegular() || info.Mode() != 0600 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Nlink == 1 && int(stat.Uid) == host.expectedRootUID &&
		int(stat.Gid) == host.expectedRootGID
}

func inspectCISRemovalArtifact(
	host hardeningHost,
	logical string,
	expectedContent [][]byte,
) (cisRemovalDisposition, hardeningFileSnapshot, string, error) {
	physical, err := host.path(logical)
	if err != nil {
		return cisRemovalAbsent, hardeningFileSnapshot{}, "", err
	}
	if _, err := os.Lstat(physical); errors.Is(err, fs.ErrNotExist) {
		return cisRemovalAbsent, hardeningFileSnapshot{}, "", nil
	} else if err != nil {
		return cisRemovalAbsent, hardeningFileSnapshot{}, "", fmt.Errorf("inspect CIS hardening policy artifact %s: %w", logical, err)
	}

	if err := host.verifyHardeningPolicyParent(logical); err != nil {
		return cisRemovalAbsent, hardeningFileSnapshot{}, "", fmt.Errorf("attest CIS hardening policy parent %s: %w", logical, err)
	}
	target, err := host.target(logical, false)
	if err != nil {
		return cisRemovalAbsent, hardeningFileSnapshot{}, "", err
	}
	root, err := openSecurityDirectory(target)
	if err != nil {
		return cisRemovalAbsent, hardeningFileSnapshot{}, "", fmt.Errorf("open CIS hardening policy parent %s: %w", logical, err)
	}
	pathInfo, inspectErr := root.Lstat(target.name)
	closeErr := root.Close()
	if inspectErr != nil {
		return cisRemovalAbsent, hardeningFileSnapshot{}, "", errors.Join(
			fmt.Errorf("reinspect CIS hardening policy artifact %s: %w", logical, inspectErr),
			closeErr,
		)
	}
	if closeErr != nil {
		return cisRemovalAbsent, hardeningFileSnapshot{}, "", fmt.Errorf("close CIS hardening policy parent %s: %w", logical, closeErr)
	}
	if !cisRemovalMetadataIsExact(host, pathInfo) {
		return cisRemovalPreserved, hardeningFileSnapshot{}, "metadata is not the exact managed state", nil
	}

	snapshot, err := host.snapshot(logical)
	if err != nil {
		return cisRemovalAbsent, hardeningFileSnapshot{}, "", fmt.Errorf("snapshot CIS hardening policy artifact %s: %w", logical, err)
	}
	if !snapshot.existed || !sameHardeningArtifactIdentity(pathInfo, snapshot.identity.info) {
		return cisRemovalAbsent, hardeningFileSnapshot{}, "", fmt.Errorf("CIS hardening policy artifact changed during attestation: %s", logical)
	}
	if !cisRemovalMetadataIsExact(host, snapshot.identity.info) {
		return cisRemovalAbsent, hardeningFileSnapshot{}, "", fmt.Errorf("CIS hardening policy artifact metadata changed during attestation: %s", logical)
	}
	if !cisRemovalContentIsExact(snapshot.content, expectedContent) {
		return cisRemovalPreserved, hardeningFileSnapshot{}, "content is not an exact managed variant", nil
	}
	return cisRemovalExact, snapshot, "", nil
}

type cisRemovalPlan struct {
	policy      cisRemovalPolicy
	disposition cisRemovalDisposition
	snapshot    hardeningFileSnapshot
	reason      string
}

func inspectCISRemovalPolicy(host hardeningHost, policy cisRemovalPolicy) (cisRemovalPlan, error) {
	disposition, snapshot, reason, err := inspectCISRemovalArtifact(
		host,
		policy.path,
		policy.expectedContent,
	)
	if err != nil {
		return cisRemovalPlan{}, err
	}
	quarantineDisposition, quarantineSnapshot, quarantineReason, err := inspectCISRemovalArtifact(
		host,
		policy.quarantinePath,
		policy.expectedContent,
	)
	if err != nil {
		return cisRemovalPlan{}, err
	}
	if quarantineDisposition != cisRemovalAbsent {
		if disposition != cisRemovalAbsent {
			return cisRemovalPlan{}, fmt.Errorf(
				"both canonical and deterministic-quarantine CIS hardening policy artifacts are present: %s and %s",
				policy.path,
				policy.quarantinePath,
			)
		}
		if quarantineDisposition != cisRemovalExact {
			return cisRemovalPlan{}, fmt.Errorf(
				"refusing ambiguous deterministic CIS hardening policy quarantine %s: %s",
				policy.quarantinePath,
				quarantineReason,
			)
		}
		return cisRemovalPlan{
			policy:      policy,
			disposition: cisRemovalPending,
			snapshot:    quarantineSnapshot,
		}, nil
	}
	return cisRemovalPlan{
		policy:      policy,
		disposition: disposition,
		snapshot:    snapshot,
		reason:      reason,
	}, nil
}

func removeAttestedCISPolicyUsing(
	host hardeningHost,
	policy cisRemovalPolicy,
	snapshot hardeningFileSnapshot,
	rename hardeningArtifactRename,
) error {
	if err := host.verifyHardeningPolicyParent(policy.path); err != nil {
		return fmt.Errorf("reattest CIS hardening policy parent %s: %w", policy.path, err)
	}
	target, err := host.target(policy.path, false)
	if err != nil {
		return err
	}
	quarantineTarget, err := host.target(policy.quarantinePath, false)
	if err != nil {
		return err
	}
	if quarantineTarget.directory != target.directory || quarantineTarget.name == target.name {
		return fmt.Errorf("invalid deterministic CIS hardening policy quarantine for %s", policy.path)
	}
	root, err := openSecurityDirectory(target)
	if err != nil {
		return fmt.Errorf("open CIS hardening policy parent %s for removal: %w", policy.path, err)
	}
	defer func() { _ = root.Close() }()

	expectedIdentity := snapshot.identity
	attest := func(root *os.Root, name string) (fs.FileInfo, error) {
		candidate := target
		candidate.name = name
		identity, existed, inspectErr := inspectSecurityDestination(root, candidate)
		if inspectErr != nil {
			return nil, inspectErr
		}
		if !existed {
			return nil, fs.ErrNotExist
		}
		if !cisRemovalMetadataIsExact(host, identity.info) ||
			!sameSecurityFileState(expectedIdentity, identity.info, identity.digest) {
			return identity.info, fmt.Errorf("CIS hardening policy changed before removal: %s", policy.path)
		}
		return identity.info, nil
	}
	if _, err := attest(root, target.name); err != nil {
		return fmt.Errorf("reattest exact CIS hardening policy %s before quarantine: %w", policy.path, err)
	}
	if _, err := root.Lstat(quarantineTarget.name); err == nil {
		return fmt.Errorf("deterministic CIS hardening policy quarantine already exists: %s", policy.quarantinePath)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("inspect deterministic CIS hardening policy quarantine %s: %w", policy.quarantinePath, err)
	}
	directory, err := root.Open(".")
	if err != nil {
		return fmt.Errorf("open CIS hardening policy parent for quarantine: %w", err)
	}
	defer func() { _ = directory.Close() }()
	directoryFD := int(directory.Fd())
	if err := rename(
		directoryFD,
		target.name,
		directoryFD,
		quarantineTarget.name,
		unix.RENAME_NOREPLACE,
	); err != nil {
		return fmt.Errorf("quarantine exact CIS hardening policy %s atomically: %w", policy.path, err)
	}
	moved, attestErr := attest(root, quarantineTarget.name)
	canonicalInfo, canonicalErr := root.Lstat(target.name)
	canonicalAbsent := errors.Is(canonicalErr, fs.ErrNotExist)
	syncErr := host.directorySync(root)
	if attestErr != nil || !sameHardeningArtifactIdentity(snapshot.identity.info, moved) ||
		!canonicalAbsent || syncErr != nil {
		if canonicalAbsent {
			canonicalErr = nil
		} else if canonicalErr == nil && canonicalInfo != nil {
			canonicalErr = fmt.Errorf("a concurrent canonical artifact appeared")
		}
		restoreErr := restoreHardeningQuarantine(
			root,
			directoryFD,
			target.name,
			quarantineTarget.name,
			rename,
			host.directorySync,
		)
		return errors.Join(
			fmt.Errorf("CIS hardening policy %s changed before deterministic quarantine", policy.path),
			attestErr,
			canonicalErr,
			syncErr,
			restoreErr,
		)
	}
	committed, commitErr := attest(root, quarantineTarget.name)
	_, canonicalErr = root.Lstat(target.name)
	canonicalAbsent = errors.Is(canonicalErr, fs.ErrNotExist)
	if commitErr != nil || !sameHardeningArtifactIdentity(snapshot.identity.info, committed) || !canonicalAbsent {
		if canonicalAbsent {
			canonicalErr = nil
		} else if canonicalErr == nil {
			canonicalErr = fmt.Errorf("a concurrent canonical artifact appeared")
		}
		restoreErr := restoreHardeningQuarantine(
			root,
			directoryFD,
			target.name,
			quarantineTarget.name,
			rename,
			host.directorySync,
		)
		return errors.Join(
			fmt.Errorf("CIS hardening policy %s changed before quarantine commit", policy.path),
			commitErr,
			canonicalErr,
			restoreErr,
		)
	}
	if err := unix.Unlinkat(directoryFD, quarantineTarget.name, 0); err != nil {
		restoreErr := restoreHardeningQuarantine(
			root,
			directoryFD,
			target.name,
			quarantineTarget.name,
			rename,
			host.directorySync,
		)
		return errors.Join(
			fmt.Errorf("remove deterministic CIS hardening policy quarantine %s: %w", policy.quarantinePath, err),
			restoreErr,
		)
	}
	if err := host.directorySync(root); err != nil {
		recreateErr := host.writeExpected(
			policy.path,
			snapshot.content,
			0600,
			hardeningFileSnapshot{},
		)
		return errors.Join(
			fmt.Errorf("sync removal of deterministic CIS hardening policy quarantine %s: %w", policy.quarantinePath, err),
			recreateErr,
		)
	}
	if _, err := root.Lstat(target.name); !errors.Is(err, fs.ErrNotExist) {
		if err == nil {
			err = fmt.Errorf("a replacement appeared after removal")
		}
		return fmt.Errorf("verify removal of CIS hardening policy %s: %w", policy.path, err)
	}
	if _, err := root.Lstat(quarantineTarget.name); !errors.Is(err, fs.ErrNotExist) {
		if err == nil {
			err = fmt.Errorf("the deterministic quarantine remains after removal")
		}
		return fmt.Errorf("verify deterministic CIS hardening policy quarantine removal %s: %w", policy.quarantinePath, err)
	}
	return nil
}

func finishPendingCISPolicyRemovalUsing(
	host hardeningHost,
	plan cisRemovalPlan,
	rename hardeningArtifactRename,
) error {
	policy := plan.policy
	if err := host.verifyHardeningPolicyParent(policy.path); err != nil {
		return fmt.Errorf("reattest pending CIS hardening policy parent %s: %w", policy.path, err)
	}
	target, err := host.target(policy.path, false)
	if err != nil {
		return err
	}
	quarantineTarget, err := host.target(policy.quarantinePath, false)
	if err != nil {
		return err
	}
	if quarantineTarget.directory != target.directory || quarantineTarget.name == target.name {
		return fmt.Errorf("invalid deterministic CIS hardening policy quarantine for %s", policy.path)
	}
	root, err := openSecurityDirectory(target)
	if err != nil {
		return fmt.Errorf("open pending CIS hardening policy parent %s: %w", policy.path, err)
	}
	defer func() { _ = root.Close() }()
	directory, err := root.Open(".")
	if err != nil {
		return fmt.Errorf("open pending CIS hardening policy directory: %w", err)
	}
	defer func() { _ = directory.Close() }()
	if _, err := root.Lstat(target.name); err == nil {
		return fmt.Errorf("canonical CIS hardening policy appeared beside its deterministic quarantine: %s", policy.path)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("inspect canonical CIS hardening policy before retry recovery %s: %w", policy.path, err)
	}
	expectedIdentity := plan.snapshot.identity
	identity, existed, err := inspectSecurityDestination(root, quarantineTarget)
	if err != nil {
		return fmt.Errorf("reattest pending CIS hardening policy quarantine %s: %w", policy.quarantinePath, err)
	}
	if !existed || !cisRemovalMetadataIsExact(host, identity.info) ||
		!sameSecurityFileState(expectedIdentity, identity.info, identity.digest) {
		return fmt.Errorf("pending CIS hardening policy quarantine changed before retry recovery: %s", policy.quarantinePath)
	}
	if _, err := root.Lstat(target.name); err == nil {
		return fmt.Errorf("canonical CIS hardening policy appeared before pending removal: %s", policy.path)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("reattest canonical CIS hardening policy absence %s: %w", policy.path, err)
	}
	identity, existed, err = inspectSecurityDestination(root, quarantineTarget)
	if err != nil {
		return fmt.Errorf("final reattestation of pending CIS hardening policy quarantine %s: %w", policy.quarantinePath, err)
	}
	if !existed || !cisRemovalMetadataIsExact(host, identity.info) ||
		!sameSecurityFileState(expectedIdentity, identity.info, identity.digest) {
		return fmt.Errorf("pending CIS hardening policy quarantine changed before removal: %s", policy.quarantinePath)
	}
	if _, err := root.Lstat(target.name); err == nil {
		return fmt.Errorf("canonical CIS hardening policy appeared at pending removal commit: %s", policy.path)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("final canonical CIS hardening policy absence reattestation %s: %w", policy.path, err)
	}
	if err := unix.Unlinkat(int(directory.Fd()), quarantineTarget.name, 0); err != nil {
		restoreErr := restoreHardeningQuarantine(
			root,
			int(directory.Fd()),
			target.name,
			quarantineTarget.name,
			rename,
			host.directorySync,
		)
		return errors.Join(
			fmt.Errorf("remove pending CIS hardening policy quarantine %s: %w", policy.quarantinePath, err),
			restoreErr,
		)
	}
	if err := host.directorySync(root); err != nil {
		recreateErr := host.writeExpected(
			policy.path,
			plan.snapshot.content,
			0600,
			hardeningFileSnapshot{},
		)
		return errors.Join(
			fmt.Errorf("sync pending CIS hardening policy removal %s: %w", policy.quarantinePath, err),
			recreateErr,
		)
	}
	for _, candidate := range []struct {
		name  string
		label string
	}{
		{name: target.name, label: policy.path},
		{name: quarantineTarget.name, label: policy.quarantinePath},
	} {
		if _, err := root.Lstat(candidate.name); !errors.Is(err, fs.ErrNotExist) {
			if err == nil {
				err = fmt.Errorf("artifact remains present")
			}
			return fmt.Errorf("verify pending CIS hardening policy removal %s: %w", candidate.label, err)
		}
	}
	return nil
}

func removeExactCISHardeningPoliciesForRemovalOn(
	host hardeningHost,
	rename hardeningArtifactRename,
) error {
	plans := make([]cisRemovalPlan, 0, len(cisRemovalPolicies()))
	for _, policy := range cisRemovalPolicies() {
		plan, err := inspectCISRemovalPolicy(host, policy)
		if err != nil {
			return err
		}
		plans = append(plans, plan)
	}

	for _, plan := range plans {
		switch plan.disposition {
		case cisRemovalAbsent:
			continue
		case cisRemovalPreserved:
			fmt.Printf("[WARN] Preserving modified or ambiguous SysWarden CIS hardening policy %s: %s.\n", plan.policy.path, plan.reason)
			continue
		case cisRemovalPending:
			if err := finishPendingCISPolicyRemovalUsing(host, plan, rename); err != nil {
				return err
			}
			fmt.Printf("[INFO] Finished pending removal of exact SysWarden CIS hardening policy: %s\n", plan.policy.path)
		case cisRemovalExact:
			if err := removeAttestedCISPolicyUsing(host, plan.policy, plan.snapshot, rename); err != nil {
				return err
			}
			fmt.Printf("[INFO] Removed exact SysWarden CIS hardening policy: %s\n", plan.policy.path)
		default:
			return fmt.Errorf("unknown CIS hardening removal disposition for %s", plan.policy.path)
		}
	}
	return nil
}

// RemoveExactCISHardeningPoliciesForRemoval removes only exact SysWarden CIS
// policy artifacts. Modified or ambiguous host policy is preserved.
func RemoveExactCISHardeningPoliciesForRemoval() error {
	return removeExactCISHardeningPoliciesForRemovalOn(productionHardeningHost(), unix.Renameat2)
}
