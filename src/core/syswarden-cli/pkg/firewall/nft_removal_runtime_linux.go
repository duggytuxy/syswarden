//go:build linux

package firewall

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"reflect"
	"strings"
	"syscall"
	"time"
)

type nftRemovalEpoch struct {
	BootID string `json:"boot_id"`
	Device uint64 `json:"namespace_device"`
	Inode  uint64 `json:"namespace_inode"`
}

type nftRemovalKernelIntent struct {
	Schema  string          `json:"schema"`
	Plan    string          `json:"persistence_plan_sha256"`
	Source  string          `json:"source_sha256"`
	Inputs  string          `json:"inputs_sha256"`
	Epoch   nftRemovalEpoch `json:"epoch"`
	Targets []string        `json:"targets"`
	History string          `json:"runtime_history_sha256,omitempty"`
}

type nftRemovalFence interface {
	apply(context.Context, func() error) error
	close()
}

func verifyExistingNFTRemovalKernelIntent(host nftPersistenceFilesystem, plan nftHistoricalPersistencePlan, targets []nftTableTarget, history string) error {
	snapshot, err := host.snapshot(legacyFail2banPlanPath(plan.sha256) + "/kernel-retirement.json")
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var intent nftRemovalKernelIntent
	if snapshot.identity.Mode().Perm() != 0600 || len(snapshot.content) > 16384 || json.Unmarshal(snapshot.content, &intent) != nil {
		return fmt.Errorf("kernel retirement intent is not a private bounded record")
	}
	canonical, err := json.Marshal(intent)
	if err != nil || !bytes.Equal(canonical, snapshot.content) {
		return fmt.Errorf("kernel retirement intent is not canonical")
	}
	inputs, err := json.Marshal(plan.binding.Current)
	if err != nil {
		return err
	}
	wanted := make([]string, len(targets))
	for index, target := range targets {
		wanted[index] = target.family + " " + target.name
	}
	if intent.Schema != "syswarden-nft-kernel-retirement-v1" || intent.Plan != plan.sha256 || intent.Source != plan.binding.Source.Artifact.SHA256 || intent.Inputs != fmt.Sprintf("%x", sha256.Sum256(inputs)) || intent.History != history || !reflect.DeepEqual(intent.Targets, wanted) || intent.Epoch.Inode == 0 || len(intent.Epoch.BootID) != 36 {
		return fmt.Errorf("kernel retirement intent differs from its independent source bindings")
	}
	return nil
}

func currentNFTRemovalEpoch() (nftRemovalEpoch, error) {
	var empty nftRemovalEpoch
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil || len(boot) != 37 || boot[36] != '\n' {
		return empty, fmt.Errorf("cannot bind nftables retirement to the current boot")
	}
	for index, character := range string(boot[:36]) {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			if character != '-' {
				return empty, fmt.Errorf("invalid retirement boot identity")
			}
		} else if !strings.ContainsRune("0123456789abcdef", character) {
			return empty, fmt.Errorf("invalid retirement boot identity")
		}
	}
	info, err := os.Stat("/proc/thread-self/ns/net")
	if err != nil {
		return empty, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Ino == 0 {
		return empty, fmt.Errorf("cannot bind nftables retirement to its network namespace")
	}
	return nftRemovalEpoch{string(boot[:36]), uint64(stat.Dev), stat.Ino}, nil
}

func observeNFTRemovalTargets(ctx context.Context, runner nftCommandRunner) (map[nftTableTarget]bool, error) {
	output, err := runner.Run(ctx, nil, "-j", "list", "tables")
	if err != nil {
		return nil, fmt.Errorf("inspect tables before verified retirement: %w", err)
	}
	document, err := decodeLegacyFail2banNFTJSON(output)
	if err != nil {
		return nil, err
	}
	objects, ok := document["nftables"].([]any)
	if !ok || len(document) != 1 || len(objects) > 4096 {
		return nil, fmt.Errorf("unbounded or ambiguous nftables table inventory")
	}
	seen := make(map[nftTableTarget]bool)
	reserved := make(map[nftTableTarget]bool)
	for _, raw := range objects {
		wrapper, ok := raw.(map[string]any)
		if !ok || len(wrapper) != 1 {
			return nil, fmt.Errorf("ambiguous nftables inventory object")
		}
		if _, meta := wrapper["metainfo"]; meta {
			continue
		}
		table, ok := wrapper["table"].(map[string]any)
		if !ok {
			return nil, fmt.Errorf("unexpected nftables table inventory object")
		}
		family, familyOK := table["family"].(string)
		name, nameOK := table["name"].(string)
		if !familyOK || !nameOK || family == "" || name == "" || len(name) > 256 {
			return nil, fmt.Errorf("invalid nftables table inventory identity")
		}
		target := nftTableTarget{family: family, name: name}
		if seen[target] {
			return nil, fmt.Errorf("duplicate nftables table inventory identity")
		}
		seen[target] = true
		if isReservedNFTTableForUninstall(target) {
			reserved[target] = true
		}
	}
	return reserved, nil
}

// The immutable file plan must already be durable and fully retired. A live
// match cannot authorize deleting its source or skipping producer attestation.
func currentNFTRetiredSource(host nftPersistenceFilesystem, plan nftHistoricalPersistencePlan) ([]byte, error) {
	if plan.binding.Current == nil {
		return nil, fmt.Errorf("current runtime retirement requires its current-generation source binding")
	}
	durable, err := readNFTHistoricalPersistencePlan(host, plan.sha256)
	if err != nil || !reflect.DeepEqual(durable, plan) {
		return nil, fmt.Errorf("runtime retirement differs from durable source evidence")
	}
	state, err := inspectNFTPersistenceGraphState(host, plan.graph)
	if err != nil {
		return nil, err
	}
	for _, source := range plan.graph.Sources {
		if source.Artifact.Path == legacyNFTIncludePath {
			if !state.retired[source.Artifact.Path] {
				return nil, fmt.Errorf("runtime retirement requires its active source to be retired first")
			}
		} else if source.EditedSHA256 != source.Artifact.SHA256 && !state.edited[source.Artifact.Path] {
			return nil, fmt.Errorf("runtime retirement requires complete persistent include retirement")
		}
	}
	path := legacyRetirementBackupDirectory(nftPersistenceGraphFileRecord(plan.binding.Source, plan.sha256)) + "/original"
	return host.read(path)
}

func bindNFTRemovalKernelIntent(host nftPersistenceFilesystem, plan string, intent nftRemovalKernelIntent, guard func() error, ops legacyRetirementFileOps) error {
	if intent.Schema != "syswarden-nft-kernel-retirement-v1" || intent.Plan != plan || !validLegacyRetirementDigest(plan) || !validLegacyRetirementDigest(intent.Source) || !validLegacyRetirementDigest(intent.Inputs) || len(intent.Targets) < 2 || len(intent.Targets) > 3 || !validLegacyRetirementOperations(guard, ops) {
		return fmt.Errorf("incomplete nftables kernel retirement intent")
	}
	if intent.History != "" && !validLegacyRetirementDigest(intent.History) {
		return fmt.Errorf("invalid native runtime history binding")
	}
	content, err := json.Marshal(intent)
	if err != nil {
		return err
	}
	path := legacyFail2banPlanPath(plan) + "/kernel-retirement.json"
	if err := guard(); err != nil {
		return err
	}
	before, err := host.snapshot(path)
	if errors.Is(err, fs.ErrNotExist) {
		directory, err := openLegacyFail2banPlanDirectory(host, plan)
		if err != nil {
			return err
		}
		defer func() { _ = directory.Close() }()
		fd, err := directory.Open(".")
		if err != nil {
			return err
		}
		defer func() { _ = fd.Close() }()
		if err := guard(); err != nil {
			return err
		}
		if err := publishLegacyRetirementJSON(directory, fd, "kernel-retirement", content, ops); err != nil {
			return err
		}
	} else if err != nil || before.identity.Mode().Perm() != 0600 || !bytes.Equal(before.content, content) {
		return fmt.Errorf("nftables kernel retirement intent differs from the reviewed source or current boot and namespace")
	}
	// Repeat both fsync operations even when a previous invocation published
	// the record and failed before durability could be confirmed.
	before, err = host.snapshot(path)
	if err != nil || before.identity.Mode().Perm() != 0600 || !bytes.Equal(before.content, content) {
		return fmt.Errorf("nftables kernel retirement intent is unavailable or changed")
	}
	directory, err := openLegacyFail2banPlanDirectory(host, plan)
	if err != nil {
		return err
	}
	defer func() { _ = directory.Close() }()
	file, err := directory.OpenFile("kernel-retirement.json", os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	info, statErr := file.Stat()
	if statErr != nil || !sameNFTPersistenceIdentity(before.identity, info) {
		_ = file.Close()
		return fmt.Errorf("kernel retirement journal changed before synchronization")
	}
	fileErr := errors.Join(ops.sync(file), file.Close())
	fd, err := directory.Open(".")
	if err != nil {
		return errors.Join(fileErr, err)
	}
	identity, statErr := fd.Stat()
	if err := errors.Join(fileErr, statErr, ops.sync(fd), fd.Close()); err != nil {
		return err
	}
	after, err := host.snapshot(path)
	if err != nil || !sameLegacyFail2banSource(before, after) {
		return fmt.Errorf("kernel retirement journal changed during synchronization")
	}
	if err := attestLegacyRetirementDirectory(host, legacyFail2banPlanPath(plan), identity); err != nil {
		return err
	}
	return guard()
}

func retireNFTCurrentRuntime(ctx context.Context, host nftPersistenceFilesystem, plan nftHistoricalPersistencePlan, reviewed string, guard func(string, string) error, runner nftCommandRunner, ops legacyRetirementFileOps, history *nftRuntimeHistoryLease) error {
	return retireNFTCurrentRuntimeUsing(ctx, host, plan, reviewed, guard, runner, ops, func(ctx context.Context, inspect func(context.Context) ([]nftTableTarget, error)) (nftRemovalFence, error) {
		return newNFTGenerationFence(ctx, inspect)
	}, history)
}

// The production caller must hold the removal and firewall locks and attest
// all originating inputs and quiescent producers. Persist intent before an
// atomic generation-bound deletion; never retry a rejected batch implicitly.
func retireNFTCurrentRuntimeUsing(ctx context.Context, host nftPersistenceFilesystem, plan nftHistoricalPersistencePlan, reviewed string, guard func(string, string) error, runner nftCommandRunner, ops legacyRetirementFileOps, newFence func(context.Context, func(context.Context) ([]nftTableTarget, error)) (nftRemovalFence, error), histories ...*nftRuntimeHistoryLease) error {
	var history *nftRuntimeHistoryLease
	if len(histories) > 1 {
		return fmt.Errorf("runtime retirement accepts one history authority")
	}
	if len(histories) == 1 {
		history = histories[0]
	}
	if guard == nil || runner == nil || newFence == nil || reviewed != plan.sha256 || plan.binding.Current == nil || !validLegacyRetirementOperations(func() error { return nil }, ops) {
		return fmt.Errorf("current runtime retirement lacks exact reviewed evidence and complete guards")
	}
	check := func() error {
		if err := history.verify(); err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := guard(plan.binding.Origins, plan.binding.Producers); err != nil {
			return err
		}
		_, err := currentNFTRetiredSource(host, plan)
		return err
	}
	if err := check(); err != nil {
		return err
	}
	input := *plan.binding.Current
	targets := []nftTableTarget{{family: "inet", name: "syswarden"}, {family: "netdev", name: "syswarden_hw_drop"}}
	if input.Base.ARP {
		targets = append(targets, nftTableTarget{family: "arp", name: "syswarden_arp"})
	}
	if err := verifyExistingNFTRemovalKernelIntent(host, plan, targets, history.digest()); err != nil {
		return err
	}
	existing, err := observeNFTRemovalTargets(ctx, runner)
	if err != nil {
		return err
	}
	if len(existing) == 0 {
		return check()
	}
	wanted := make(map[nftTableTarget]bool, len(targets))
	for _, target := range targets {
		wanted[target] = true
	}
	if !reflect.DeepEqual(existing, wanted) {
		return fmt.Errorf("runtime table coverage is incomplete or includes unproven historical or WireGuard state")
	}
	epoch, err := currentNFTRemovalEpoch()
	if err != nil {
		return err
	}
	var evidence nftCurrentPersistenceEvidence
	fence, err := newFence(ctx, func(ctx context.Context) ([]nftTableTarget, error) {
		if err := check(); err != nil {
			return nil, err
		}
		source, err := currentNFTRetiredSource(host, plan)
		if err != nil {
			return nil, err
		}
		observations := make([][]byte, len(targets))
		windows := map[string]nftRuntimeCapture{}
		for index, target := range targets {
			start := time.Now().UTC()
			observations[index], err = runner.Run(ctx, nil, "-j", "list", "table", target.family, target.name)
			windows[target.family] = nftRuntimeCapture{start, time.Now().UTC()}
			if err != nil {
				return nil, fmt.Errorf("observe current table before retirement: %w", err)
			}
		}
		var arp []byte
		if input.Base.ARP {
			arp = observations[2]
		}
		claims, err := newNFTRuntimeClaimProof(history, windows)
		if err != nil {
			return nil, err
		}
		evidence, err = inspectNFTCurrentRuntimeWithClaims(source, observations[0], observations[1], arp, input, claims)
		if err != nil {
			return nil, err
		}
		if err := check(); err != nil {
			return nil, err
		}
		return targets, nil
	})
	if err != nil {
		return err
	}
	if fence == nil {
		return fmt.Errorf("kernel retirement fence is unavailable")
	}
	defer fence.close()
	intent := nftRemovalKernelIntent{Schema: "syswarden-nft-kernel-retirement-v1", Plan: reviewed, Source: evidence.sourceSHA256, Inputs: evidence.inputSHA256, Epoch: epoch, History: history.digest()}
	for _, target := range targets {
		intent.Targets = append(intent.Targets, target.family+" "+target.name)
	}
	if err := bindNFTRemovalKernelIntent(host, reviewed, intent, check, ops); err != nil {
		return err
	}
	if err := ops.checkpoint("kernel-retirement-intent-durable"); err != nil {
		return err
	}
	final := func() error {
		if err := check(); err != nil {
			return err
		}
		current, err := currentNFTRemovalEpoch()
		if err != nil || current != epoch {
			return fmt.Errorf("kernel retirement boot or network namespace changed")
		}
		return bindNFTRemovalKernelIntent(host, reviewed, intent, check, ops)
	}
	if err := fence.apply(ctx, final); err != nil {
		return err
	}
	if err := ops.checkpoint("kernel-retirement-applied"); err != nil {
		return err
	}
	remaining, err := observeNFTRemovalTargets(ctx, runner)
	if err != nil || len(remaining) != 0 {
		return errors.Join(fmt.Errorf("verified nftables runtime retirement remains incomplete"), err)
	}
	return check()
}
