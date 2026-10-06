//go:build linux

package firewall

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"sort"
	"strings"
	"syscall"
	"time"
)

// This file-only path cannot stop a jail or issue a runtime mutation. The
// caller still holds the removal lock and independently guards producers and
// external consumers. Equality of parser views alone cannot attest those.
type legacyFail2banUnusedAdapter struct {
	guard       func(context.Context, bool) error
	read        func(context.Context, bool) (legacyFail2banRuntimeSnapshot, error)
	actions     legacyFail2banConfiguredActions
	bindRuntime func(nftPersistenceFilesystem, legacyFail2banRetirementPlan, legacyFail2banRuntimeSnapshot, func() error, legacyRetirementFileOps) (func() error, error)
}

func newLegacyFail2banUnusedAdapter(host nftPersistenceFilesystem, record legacyFail2banPlanRecord, inspection *legacyFail2banServiceInspection, liveGuard func(context.Context) error) (legacyFail2banUnusedAdapter, error) {
	var empty legacyFail2banUnusedAdapter
	if inspection == nil || inspection.process == nil || liveGuard == nil || inspection.parser.digest != record.ParserSHA256 || host.root == nil || inspection.host.root == nil {
		return empty, fmt.Errorf("unused Fail2ban retirement requires an inspected service and independent removal guards")
	}
	root, rootErr := host.root.Stat(".")
	inspected, inspectedErr := inspection.host.root.Stat(".")
	if rootErr != nil || inspectedErr != nil || !os.SameFile(root, inspected) || host.expectedUID != inspection.host.expectedUID || host.expectedGID != inspection.host.expectedGID {
		return empty, fmt.Errorf("unused Fail2ban retirement differs from the inspected host root")
	}
	view, err := legacyFail2banConfigurationProbeUsingParser(host, inspection.parser)(cloneLegacyFail2banInventory(inspection.inventory), nil)
	if err != nil || sha256.Sum256(view.enabled) != record.Views[0] || sha256.Sum256(view.allJails) != record.Views[1] {
		return empty, fmt.Errorf("unused Fail2ban retirement service differs from the reviewed configuration")
	}
	actions, err := decodeLegacyFail2banConfiguredActions(view.actionsEnabled)
	if err != nil || !reflect.DeepEqual(actions, inspection.actions) {
		return empty, fmt.Errorf("unused Fail2ban retirement actions differ from the inspected service")
	}
	return legacyFail2banUnusedAdapter{
		actions: actions,
		guard: func(ctx context.Context, published bool) error {
			if err := liveGuard(ctx); err != nil {
				return err
			}
			if published {
				return inspection.verifyFileRetirement(ctx, record)
			}
			return inspection.verify(ctx)
		},
		read: func(ctx context.Context, published bool) (legacyFail2banRuntimeSnapshot, error) {
			if published {
				return inspection.readRuntimeFileRetirement(ctx, record)
			}
			return inspection.readRuntime(ctx)
		},
	}, nil
}

func inspectUnusedLegacyFail2banPlan(host nftPersistenceFilesystem, record legacyFail2banPlanRecord) (string, error) {
	if record.Views[0] == ([sha256.Size]byte{}) || record.Views[1] == ([sha256.Size]byte{}) ||
		record.Views[0] != record.Views[2] || record.Views[1] != record.Views[3] {
		return "", fmt.Errorf("unused Fail2ban retirement must preserve enabled and disabled configuration exactly")
	}
	state, err := inspectLegacyFail2banPlanState(host, record)
	if err != nil {
		return "", err
	}
	selected := make(map[string]bool, len(record.Targets))
	for _, path := range record.Targets {
		selected[path] = true
	}
	for _, source := range state.baseline.sources {
		if !selected[source.path] {
			continue
		}
		match, exact := matchLegacyFail2banTemplate(source.path, source.snapshot.content)
		if !exact || (match.kind != "action" && match.kind != "filter") {
			return "", fmt.Errorf("unused Fail2ban retirement accepts only complete generated action and filter definitions")
		}
		delete(selected, source.path)
	}
	if len(selected) != 0 {
		return "", fmt.Errorf("unused Fail2ban retirement lacks complete source evidence")
	}
	var retired []string
	for path := range state.retired {
		retired = append(retired, path)
	}
	sort.Strings(retired)
	return strings.Join(retired, "\n"), nil
}

// Live actions are checked against the recorded parser views. Persist the
// initial jail membership and ban-expiration fingerprint as well: a new
// invocation must not silently accept a lost ban as its new baseline. Only
// the digest is stored here; raw addresses are not diagnostic output.
type legacyFail2banUnusedRuntimeRecord struct {
	Schema   string `json:"schema"`
	FilePlan string `json:"file_plan_sha256"`
	Bans     string `json:"runtime_bans_sha256"`
}

func encodeUnusedLegacyFail2banRuntime(digest string, live legacyFail2banRuntimeSnapshot) ([]byte, error) {
	type jailRecord struct {
		Name string   `json:"name"`
		Bans []string `json:"bans"`
	}
	if !validLegacyRetirementDigest(digest) || len(live.jails) > 128 || live.jails == nil {
		return nil, fmt.Errorf("unused Fail2ban retirement lacks a bounded runtime observation")
	}
	jails := make([]jailRecord, 0, len(live.jails))
	total := 0
	for name, jail := range live.jails {
		if !validLegacyFail2banJailName(name) || len(jail.bans) > 32768 {
			return nil, fmt.Errorf("unused Fail2ban runtime evidence has unsupported jail or ban data")
		}
		bans := append([]string{}, jail.bans...)
		sort.Strings(bans)
		total += len(name)
		for index, ban := range bans {
			total += len(ban)
			if total > 8<<20 {
				return nil, fmt.Errorf("unused Fail2ban runtime evidence exceeds its bound")
			}
			if len(ban) > 256 || !strings.Contains(ban, "\t") || strings.ContainsAny(ban, "\n\r\x00") || (index > 0 && bans[index-1] == ban) {
				return nil, fmt.Errorf("unused Fail2ban runtime evidence has unsupported ban data")
			}
		}
		jails = append(jails, jailRecord{name, bans})
	}
	sort.Slice(jails, func(i, j int) bool { return jails[i].Name < jails[j].Name })
	content, err := json.Marshal(jails)
	if err != nil || len(content) > 8<<20 {
		return nil, fmt.Errorf("unused Fail2ban runtime evidence exceeds its bound")
	}
	record := legacyFail2banUnusedRuntimeRecord{"syswarden-unused-fail2ban-runtime-v1", digest, fmt.Sprintf("%x", sha256.Sum256(content))}
	return json.Marshal(record)
}

func bindUnusedLegacyFail2banRuntime(host nftPersistenceFilesystem, plan legacyFail2banRetirementPlan, live legacyFail2banRuntimeSnapshot, guard func() error, ops legacyRetirementFileOps) (func() error, error) {
	content, err := encodeUnusedLegacyFail2banRuntime(plan.sha256, live)
	if err != nil {
		return nil, err
	}
	if !validLegacyRetirementOperations(guard, ops) {
		return nil, fmt.Errorf("unused Fail2ban runtime evidence requires complete guards")
	}
	if err := guard(); err != nil {
		return nil, err
	}
	directory, err := openLegacyFail2banPlanDirectory(host, plan.sha256)
	if err != nil {
		return nil, err
	}
	defer func() { _ = directory.Close() }()
	descriptor, err := directory.Open(".")
	if err != nil {
		return nil, err
	}
	defer func() { _ = descriptor.Close() }()
	directoryIdentity, err := descriptor.Stat()
	if err != nil {
		return nil, err
	}
	path := legacyFail2banPlanPath(plan.sha256) + "/unused-runtime.json"
	original, err := host.snapshot(path)
	if errors.Is(err, os.ErrNotExist) {
		state, stateErr := inspectLegacyFail2banPlanState(host, plan.binding)
		if stateErr != nil || len(state.retired) != 0 {
			return nil, fmt.Errorf("unused Fail2ban retirement cannot recreate missing runtime evidence after file movement")
		}
		if err := guard(); err != nil {
			return nil, err
		}
		if err := attestLegacyRetirementDirectory(host, legacyFail2banPlanPath(plan.sha256), directoryIdentity); err != nil {
			return nil, err
		}
		if err := publishLegacyRetirementJSON(directory, descriptor, "unused-runtime", content, ops); err != nil {
			return nil, err
		}
		original, err = host.snapshot(path)
	}
	if err != nil || original.identity == nil || original.identity.Mode().Perm() != 0600 || !bytes.Equal(original.content, content) {
		return nil, fmt.Errorf("unused Fail2ban runtime protection differs from its retained private evidence")
	}
	file, err := directory.OpenFile("unused-runtime.json", os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	identity, err := file.Stat()
	if err != nil || !sameNFTPersistenceIdentity(original.identity, identity) {
		return nil, fmt.Errorf("unused Fail2ban runtime evidence changed before synchronization")
	}
	if err := errors.Join(ops.sync(file), ops.sync(descriptor)); err != nil {
		return nil, err
	}
	verify := func() error {
		if err := attestLegacyRetirementDirectory(host, legacyFail2banPlanPath(plan.sha256), directoryIdentity); err != nil {
			return err
		}
		durable, err := readLegacyFail2banPlan(host, plan.sha256)
		if err != nil || !reflect.DeepEqual(durable, plan.binding) {
			return fmt.Errorf("unused Fail2ban runtime evidence lost its original file plan")
		}
		current, err := host.snapshot(path)
		if err != nil || !sameLegacyFail2banSource(original, current) {
			return fmt.Errorf("unused Fail2ban runtime evidence changed or disappeared")
		}
		return nil
	}
	if err := guard(); err != nil {
		return nil, err
	}
	if err := verify(); err != nil {
		return nil, err
	}
	if err := ops.checkpoint("unused-runtime-durable"); err != nil {
		return nil, err
	}
	return verify, nil
}

// Current, intermediate and final views must all preserve the same effective
// configuration. A fresh service inspection may resume this file-only path
// after a restart; the separate active-jail path still requires its original
// invocation and its quiescence and kernel journals.
func retireUnusedLegacyFail2banFiles(ctx context.Context, host nftPersistenceFilesystem, plan legacyFail2banRetirementPlan, reviewedDigest string, adapter legacyFail2banUnusedAdapter, ops legacyRetirementFileOps) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()
	_, digest, err := encodeLegacyFail2banPlan(plan.binding, host.expectedUID, host.expectedGID)
	if err != nil || digest != plan.sha256 || digest != reviewedDigest {
		return fmt.Errorf("unused Fail2ban retirement differs from the exact reviewed plan")
	}
	if adapter.guard == nil || adapter.read == nil || adapter.actions == nil || !validLegacyRetirementOperations(func() error { return nil }, ops) {
		return fmt.Errorf("unused Fail2ban retirement lacks complete live protection guards")
	}
	if _, err := inspectUnusedLegacyFail2banPlan(host, plan.binding); err != nil {
		return err
	}
	published := false
	durable, err := readLegacyFail2banPlan(host, digest)
	if err == nil {
		if !reflect.DeepEqual(durable, plan.binding) {
			return fmt.Errorf("unused Fail2ban retirement differs from durable evidence")
		}
		published = true
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := adapter.guard(ctx, published); err != nil {
		return err
	}
	before, err := adapter.read(ctx, published)
	if err != nil {
		return err
	}
	if err := verifyLegacyFail2banConfiguredRuntime(adapter.actions, before); err != nil {
		return err
	}
	parser, err := captureLegacyFail2banParser(host)
	if err != nil || parser.digest != plan.binding.ParserSHA256 {
		return fmt.Errorf("unused Fail2ban retirement lost its inspected parser")
	}
	probe := legacyFail2banConfigurationProbeUsingParser(host, parser)
	lastView, checkedView := "", false
	var runtimeEvidence func() error
	guard := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := adapter.guard(ctx, published); err != nil {
			return err
		}
		state, err := inspectUnusedLegacyFail2banPlan(host, plan.binding)
		if err != nil {
			return err
		}
		if !checkedView || state != lastView {
			inventory, err := inspectLegacyFail2banInventory(host)
			if err != nil {
				return err
			}
			view, err := probe(inventory, nil)
			if err != nil || sha256.Sum256(view.enabled) != plan.binding.Views[0] || sha256.Sum256(view.allJails) != plan.binding.Views[1] {
				return fmt.Errorf("unused Fail2ban retirement changes an intermediate configuration")
			}
			if err := reattestLegacyFail2banPlanInventory(host, inventory); err != nil {
				return err
			}
			lastView, checkedView = state, true
		}
		if err := parser.reattest(host); err != nil {
			return err
		}
		current, err := adapter.read(ctx, published)
		if err != nil {
			return err
		}
		if err := verifyLegacyFail2banConfiguredRuntime(adapter.actions, current); err != nil {
			return err
		}
		if err := verifyLegacyFail2banRuntimePreservation(before, current, nil); err != nil {
			return err
		}
		if runtimeEvidence != nil {
			if err := runtimeEvidence(); err != nil {
				return err
			}
		}
		return adapter.guard(ctx, published)
	}
	if err := publishVerifiedLegacyFail2banFilePlan(host, plan, guard, ops); err != nil {
		return err
	}
	published = true
	bindRuntime := adapter.bindRuntime
	if bindRuntime == nil {
		bindRuntime = bindUnusedLegacyFail2banRuntime
	}
	runtimeEvidence, err = bindRuntime(host, plan, before, guard, ops)
	if err != nil {
		return err
	}
	if err := resumeVerifiedLegacyFail2banFilePlan(host, digest, guard, ops); err != nil {
		return err
	}
	return guard()
}
