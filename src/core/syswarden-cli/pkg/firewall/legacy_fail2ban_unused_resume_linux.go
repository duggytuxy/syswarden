//go:build linux

package firewall

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"reflect"
	"slices"
	"sort"
	"syscall"
)

const legacyUnusedResumeSchema = "syswarden-unused-fail2ban-resume-v1"
const legacyUnusedResumePrefix = "unused-resume-"

// A new operator review never replaces the original runtime evidence. It
// authorizes only the remaining moves of already proven unused definitions.
// It makes no claim about protection continuity between separate attempts.
type legacyUnusedResumeRecord struct {
	Schema         string   `json:"schema"`
	FilePlan       string   `json:"file_plan_sha256"`
	OriginalIntent string   `json:"original_runtime_intent_sha256"`
	CurrentBans    string   `json:"reviewed_current_bans_sha256"`
	Retired        []string `json:"already_retired_files"`
}

type legacyUnusedResumeIntent struct {
	record   legacyUnusedResumeRecord
	digest   string
	original nftPersistenceRead
}

func readOriginalUnusedLegacyRuntime(host nftPersistenceFilesystem, plan string) (nftPersistenceRead, legacyFail2banUnusedRuntimeRecord, error) {
	var record legacyFail2banUnusedRuntimeRecord
	original, err := host.snapshot(legacyFail2banPlanPath(plan) + "/unused-runtime.json")
	if err != nil || original.identity == nil || original.identity.Mode().Perm() != 0600 || len(original.content) > 512 {
		return original, record, fmt.Errorf("unused Fail2ban resumption requires the original private runtime evidence")
	}
	if json.Unmarshal(original.content, &record) != nil || record.Schema != "syswarden-unused-fail2ban-runtime-v1" || record.FilePlan != plan || !validLegacyRetirementDigest(record.Bans) {
		return original, record, fmt.Errorf("original unused Fail2ban runtime evidence is invalid")
	}
	canonical, err := json.Marshal(record)
	if err != nil || !bytes.Equal(canonical, original.content) {
		return original, record, fmt.Errorf("original unused Fail2ban runtime evidence is not canonical")
	}
	return original, record, nil
}

func encodeLegacyUnusedResume(record legacyUnusedResumeRecord, plan legacyFail2banPlanRecord) ([]byte, string, error) {
	if record.Schema != legacyUnusedResumeSchema || !validLegacyRetirementDigest(record.FilePlan) ||
		!validLegacyRetirementDigest(record.OriginalIntent) || !validLegacyRetirementDigest(record.CurrentBans) ||
		record.Retired == nil || len(record.Retired) >= len(plan.Targets) {
		return nil, "", fmt.Errorf("unused Fail2ban resumption has incomplete or unbounded review evidence")
	}
	for index, path := range record.Retired {
		if !slices.Contains(plan.Targets, path) || index > 0 && record.Retired[index-1] >= path {
			return nil, "", fmt.Errorf("unused Fail2ban resumption contains an unreviewed retired source")
		}
	}
	content, err := json.Marshal(record)
	if err != nil || len(content) > 64<<10 {
		return nil, "", fmt.Errorf("unused Fail2ban resumption exceeds its record bound")
	}
	return content, nftSHA256Hex(content), nil
}

func verifyLegacyUnusedResumeProgress(record legacyUnusedResumeRecord, retired map[string]bool) error {
	for _, path := range record.Retired {
		if !retired[path] {
			return fmt.Errorf("a source retired before the reviewed resumption reappeared")
		}
	}
	return nil
}

// A nil live observation is accepted only when the exact immutable resume
// intent already exists and every original file is fully retired. This is a
// read-only acknowledgement and never authorizes another preparation step.
func inspectLegacyUnusedResume(host nftPersistenceFilesystem, plan legacyFail2banRetirementPlan, live *legacyFail2banRuntimeSnapshot, reviewed string) (legacyUnusedResumeIntent, bool, error) {
	var empty legacyUnusedResumeIntent
	if !validLegacyRetirementDigest(plan.sha256) || reviewed != "" && !validLegacyRetirementDigest(reviewed) {
		return empty, false, fmt.Errorf("unused Fail2ban resumption requires exact lowercase reviewed digests")
	}
	if _, err := inspectUnusedLegacyFail2banPlan(host, plan.binding); err != nil {
		return empty, false, err
	}
	durable, err := readLegacyFail2banPlan(host, plan.sha256)
	if err != nil || !reflect.DeepEqual(durable, plan.binding) {
		return empty, false, fmt.Errorf("unused Fail2ban resumption lacks its original durable file plan")
	}
	state, err := inspectLegacyFail2banPlanState(host, plan.binding)
	if err != nil {
		return empty, false, err
	}
	original, baseline, err := readOriginalUnusedLegacyRuntime(host, plan.sha256)
	if err != nil {
		return empty, false, err
	}
	originalDigest := nftSHA256Hex(original.content)
	complete := len(state.retired) == len(plan.binding.Targets)
	var current legacyFail2banUnusedRuntimeRecord
	if live != nil {
		wire, err := encodeUnusedLegacyFail2banRuntime(plan.sha256, *live)
		if err != nil || json.Unmarshal(wire, &current) != nil {
			return empty, false, fmt.Errorf("unused Fail2ban resumption lacks a bounded current runtime observation")
		}
	} else if !complete {
		return empty, false, fmt.Errorf("unfinished unused Fail2ban resumption requires current runtime evidence")
	}
	if reviewed != "" {
		retained, readErr := host.snapshot(legacyFail2banPlanPath(plan.sha256) + "/" + legacyUnusedResumePrefix + reviewed + ".json")
		if readErr == nil {
			var record legacyUnusedResumeRecord
			if retained.identity.Mode().Perm() != 0600 || len(retained.content) > 64<<10 || json.Unmarshal(retained.content, &record) != nil {
				return empty, false, fmt.Errorf("retained unused Fail2ban resumption evidence is unsafe")
			}
			canonical, digest, err := encodeLegacyUnusedResume(record, plan.binding)
			if err != nil || digest != reviewed || !bytes.Equal(canonical, retained.content) || record.FilePlan != plan.sha256 || record.OriginalIntent != originalDigest || record.CurrentBans == baseline.Bans {
				return empty, false, fmt.Errorf("retained unused Fail2ban resumption differs from the exact reviewed authority")
			}
			if err := verifyLegacyUnusedResumeProgress(record, state.retired); err != nil {
				return empty, false, err
			}
			if !complete && record.CurrentBans != current.Bans {
				return empty, false, fmt.Errorf("current Fail2ban protection changed since this resumption was reviewed")
			}
			return legacyUnusedResumeIntent{record, digest, original}, complete, nil
		}
		if !errors.Is(readErr, fs.ErrNotExist) {
			return empty, false, readErr
		}
	}
	if complete || live == nil {
		return empty, false, fmt.Errorf("completed unused Fail2ban retirement has no matching prior resumption intent")
	}
	if current.Bans == baseline.Bans {
		return empty, false, fmt.Errorf("unused Fail2ban runtime is unchanged; resume the original reviewed recovery")
	}
	retired := make([]string, 0, len(state.retired))
	for path := range state.retired {
		retired = append(retired, path)
	}
	sort.Strings(retired)
	record := legacyUnusedResumeRecord{legacyUnusedResumeSchema, plan.sha256, originalDigest, current.Bans, retired}
	_, digest, err := encodeLegacyUnusedResume(record, plan.binding)
	if err != nil || reviewed != "" && reviewed != digest {
		return empty, false, fmt.Errorf("unused Fail2ban state changed since the new operator review")
	}
	return legacyUnusedResumeIntent{record, digest, original}, false, nil
}

func bindLegacyUnusedResume(host nftPersistenceFilesystem, plan legacyFail2banRetirementPlan, live legacyFail2banRuntimeSnapshot, intent legacyUnusedResumeIntent, guard func() error, ops legacyRetirementFileOps) (func() error, error) {
	if !validLegacyRetirementOperations(guard, ops) {
		return nil, fmt.Errorf("unused Fail2ban resumption requires complete independent guards")
	}
	actual, complete, err := inspectLegacyUnusedResume(host, plan, &live, intent.digest)
	if err != nil || complete || !reflect.DeepEqual(actual.record, intent.record) || !sameLegacyFail2banSource(actual.original, intent.original) {
		return nil, fmt.Errorf("unused Fail2ban resumption changed before publishing its reviewed intent")
	}
	content, digest, err := encodeLegacyUnusedResume(intent.record, plan.binding)
	if err != nil || digest != intent.digest {
		return nil, fmt.Errorf("unused Fail2ban resumption lacks exact reviewed authority")
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
	identity, err := descriptor.Stat()
	if err != nil {
		return nil, err
	}
	kind := legacyUnusedResumePrefix + digest
	path := legacyFail2banPlanPath(plan.sha256) + "/" + kind + ".json"
	retained, err := host.snapshot(path)
	if errors.Is(err, fs.ErrNotExist) {
		if err := guard(); err != nil {
			return nil, err
		}
		if err := attestLegacyRetirementDirectory(host, legacyFail2banPlanPath(plan.sha256), identity); err != nil {
			return nil, err
		}
		if err := publishLegacyRetirementJSON(directory, descriptor, kind, content, ops); err != nil {
			return nil, err
		}
		retained, err = host.snapshot(path)
	}
	if err != nil || retained.identity.Mode().Perm() != 0600 || !bytes.Equal(retained.content, content) {
		return nil, fmt.Errorf("unused Fail2ban resumption differs from its immutable private record")
	}
	file, err := directory.OpenFile(kind+".json", os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	currentIdentity, err := file.Stat()
	if err != nil || !sameNFTPersistenceIdentity(retained.identity, currentIdentity) {
		return nil, fmt.Errorf("unused Fail2ban resumption changed before synchronization")
	}
	if err := errors.Join(ops.sync(file), ops.sync(descriptor)); err != nil {
		return nil, err
	}
	verify := func() error {
		if err := attestLegacyRetirementDirectory(host, legacyFail2banPlanPath(plan.sha256), identity); err != nil {
			return err
		}
		original, _, err := readOriginalUnusedLegacyRuntime(host, plan.sha256)
		if err != nil || !sameLegacyFail2banSource(original, intent.original) {
			return fmt.Errorf("original unused Fail2ban runtime evidence changed during resumption")
		}
		current, err := host.snapshot(path)
		if err != nil || !sameLegacyFail2banSource(current, retained) {
			return fmt.Errorf("reviewed unused Fail2ban resumption evidence changed or disappeared")
		}
		durable, err := readLegacyFail2banPlan(host, plan.sha256)
		if err != nil || !reflect.DeepEqual(durable, plan.binding) {
			return fmt.Errorf("unused Fail2ban resumption lost the exact original file plan")
		}
		return nil
	}
	if err := guard(); err != nil {
		return nil, err
	}
	if err := verify(); err != nil {
		return nil, err
	}
	if err := ops.checkpoint("unused-resume-durable"); err != nil {
		return nil, err
	}
	return verify, nil
}

// Keep the new intent immutable throughout the remaining file-only moves.
func legacyUnusedResumeBinder(intent legacyUnusedResumeIntent) func(nftPersistenceFilesystem, legacyFail2banRetirementPlan, legacyFail2banRuntimeSnapshot, func() error, legacyRetirementFileOps) (func() error, error) {
	return func(host nftPersistenceFilesystem, plan legacyFail2banRetirementPlan, live legacyFail2banRuntimeSnapshot, guard func() error, ops legacyRetirementFileOps) (func() error, error) {
		return bindLegacyUnusedResume(host, plan, live, intent, guard, ops)
	}
}

// The public adapter still verifies the exact live service, parser and all
// configuration views before and after this read-only observation.
func verifyLegacyUnusedResumeRuntime(ctx context.Context, plan string, intent legacyUnusedResumeIntent, live legacyFail2banRuntimeSnapshot) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	wire, err := encodeUnusedLegacyFail2banRuntime(plan, live)
	var record legacyFail2banUnusedRuntimeRecord
	if err != nil || json.Unmarshal(wire, &record) != nil || record.Bans != intent.record.CurrentBans {
		return fmt.Errorf("unused Fail2ban runtime changed after the explicit resumption review")
	}
	return nil
}
