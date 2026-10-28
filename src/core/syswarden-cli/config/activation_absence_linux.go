//go:build linux

package config

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// ActivationAbsence retains publication exclusion for an exact unapproved
// policy. It proves neither runtime inactivity nor permission to update a
// package. A native coordinator must establish those independently, retain this
// custody through its outcome checks and preserve its own crash recovery gate.
// This single-owner handle must not be used concurrently with Close.
type ActivationAbsence struct {
	policy  *ActivationPolicy
	store   activationApprovalStore
	lease   *activationPolicyLease
	anchor  *os.Root
	witness activationAbsenceWitness
	digest  string
	closed  bool
}

type activationAbsenceWitness struct {
	Schema       string                      `json:"schema"`
	PolicySHA256 string                      `json:"policy_sha256"`
	HostSHA256   string                      `json:"host_sha256"`
	StorePath    string                      `json:"store_path"`
	AnchorPath   string                      `json:"anchor_path"`
	Anchor       activationDirectoryIdentity `json:"anchor"`
}

type activationPolicyLease struct {
	root *os.Root
	file *os.File
}

// HoldActivationAbsent reads without creating activation state or changing
// configuration. Only an absent activation directory is supported; even an
// empty existing directory is unresolved history, not a fresh-state receipt.
// Approval publication uses the same existing configuration-directory inode.
// No new approval can be published by that ingress until Close releases it.
func (policy *ActivationPolicy) HoldActivationAbsent(ctx context.Context) (*ActivationAbsence, error) {
	store, err := productionActivationStore()
	if err != nil {
		return nil, err
	}
	if policy == nil || policy.root != "/etc/syswarden/config" {
		return nil, errors.New("production activation absence requires the fixed configuration root")
	}
	return policy.holdActivationAbsentAt(ctx, store)
}

func (policy *ActivationPolicy) holdActivationAbsentAt(ctx context.Context, store activationApprovalStore) (_ *ActivationAbsence, result error) {
	lease, err := policy.lockActivationPolicy(ctx, store.uid, unix.LOCK_EX)
	if err != nil {
		return nil, err
	}
	absence := &ActivationAbsence{policy: policy, store: store, lease: lease}
	defer func() {
		if result != nil {
			result = errors.Join(result, absence.Close())
		}
	}()
	anchor, path, identity, err := observeAbsentActivationStore(store)
	if err != nil {
		return nil, err
	}
	absence.anchor = anchor
	host, err := policy.HostSHA256()
	if err != nil {
		return nil, err
	}
	absence.witness = activationAbsenceWitness{
		Schema: "syswarden-activation-absence-v1", PolicySHA256: policy.Review().Digest,
		HostSHA256: host, StorePath: store.path, AnchorPath: path, Anchor: identity,
	}
	raw, err := activationCanonical(absence.witness)
	if err != nil {
		return nil, err
	}
	absence.digest = activationDigest(raw)
	if err := absence.Revalidate(ctx); err != nil {
		return nil, err
	}
	return absence, nil
}

// SHA256 binds exact TOML, its source scope, the absent state path and the
// nearest protected existing ancestor. It is an observation, never consent.
func (absence *ActivationAbsence) SHA256() string {
	if absence == nil || absence.closed {
		return ""
	}
	return absence.digest
}

func (absence *ActivationAbsence) Revalidate(ctx context.Context) error {
	if absence == nil || absence.closed || absence.lease == nil || absence.anchor == nil || absence.digest == "" {
		return errors.New("activation absence custody is unavailable")
	}
	if err := absence.policy.Revalidate(ctx); err != nil {
		return err
	}
	root, path, identity, err := observeAbsentActivationStore(absence.store)
	if err != nil {
		return err
	}
	if err := root.Close(); err != nil {
		return err
	}
	if path != absence.witness.AnchorPath || identity != absence.witness.Anchor {
		return errors.New("activation absence ancestor changed after capture")
	}
	return absence.policy.Revalidate(ctx)
}

// Close releases descriptors only. It never removes files or claims native
// completion. The original anchor stays open until then to prevent inode reuse.
func (absence *ActivationAbsence) Close() error {
	if absence == nil || absence.closed {
		return nil
	}
	absence.closed = true
	var err error
	if absence.anchor != nil {
		err = absence.anchor.Close()
	}
	return errors.Join(err, absence.lease.Close())
}

func observeAbsentActivationStore(store activationApprovalStore) (*os.Root, string, activationDirectoryIdentity, error) {
	empty := activationDirectoryIdentity{}
	if !filepath.IsAbs(store.path) || filepath.Clean(store.path) != store.path || store.path == "/" {
		return nil, "", empty, errors.New("activation absence path is not canonical")
	}
	if err := refuseActivationRetirement(store.path, store.uid); err != nil {
		return nil, "", empty, err
	}
	root, _, err := openActivationDirectory(store.path, store.uid)
	if err == nil {
		return nil, "", empty, errors.Join(errors.New("activation state already exists; inactive authority cannot be inferred"), root.Close())
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, "", empty, err
	}
	for path := filepath.Dir(store.path); ; path = filepath.Dir(path) {
		root, identity, err := openActivationDirectory(path, store.uid)
		if err == nil {
			return root, path, identity, nil
		}
		if !errors.Is(err, os.ErrNotExist) || path == "/" {
			return nil, "", empty, err
		}
	}
}

func (policy *ActivationPolicy) lockActivationPolicy(ctx context.Context, uid uint32, mode int) (_ *activationPolicyLease, result error) {
	if mode != unix.LOCK_SH && mode != unix.LOCK_EX {
		return nil, errors.New("activation publication lease mode is unsupported")
	}
	if err := policy.Revalidate(ctx); err != nil {
		return nil, err
	}
	root, _, err := openActivationDirectory(policy.root, uid)
	if err != nil {
		return nil, err
	}
	lease := &activationPolicyLease{root: root}
	defer func() {
		if result != nil {
			result = errors.Join(result, lease.Close())
		}
	}()
	file, err := root.Open(".")
	if err != nil {
		return nil, err
	}
	lease.file = file
	if err := unix.Flock(int(file.Fd()), mode|unix.LOCK_NB); err != nil {
		return nil, fmt.Errorf("activation publication or inactive-preservation custody is already held: %w", err)
	}
	// Revalidate after acquiring the retained inode, before any approval write.
	// A replacement configuration root must not split the lock namespace.
	info, err := file.Stat()
	if err != nil || !os.SameFile(info, policy.snapshot.configRootInfo) {
		return nil, errors.New("activation policy directory changed while acquiring custody")
	}
	if err := policy.Revalidate(ctx); err != nil {
		return nil, err
	}
	return lease, nil
}

func (lease *activationPolicyLease) Close() error {
	if lease == nil {
		return nil
	}
	var err error
	if lease.file != nil {
		err = lease.file.Close()
		lease.file = nil
	}
	if lease.root != nil {
		err = errors.Join(err, lease.root.Close())
		lease.root = nil
	}
	return err
}
