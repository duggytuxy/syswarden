//go:build linux

package config

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/spf13/viper"
)

type coreActivationApproval struct {
	record    *activationApprovalRecord
	raw       []byte
	file      activationFileIdentity
	directory activationDirectoryIdentity
}

func readCoreActivationApproval(path string, uid uint32) (*coreActivationApproval, error) {
	if err := refuseActivationRetirement(path, uid); err != nil {
		return nil, err
	}
	root, directory, err := openActivationDirectory(path, uid)
	if err != nil {
		return nil, fmt.Errorf("explicit core activation approval is unavailable: %w", err)
	}
	defer func() { _ = root.Close() }()
	if directory.Mode != 0700 {
		return nil, errors.New("core activation state directory is not private")
	}
	opened, err := root.Open(".")
	if err != nil {
		return nil, err
	}
	entries, readErr := opened.ReadDir(4)
	_ = opened.Close()
	if readErr != nil && readErr != io.EOF {
		return nil, readErr
	}
	if len(entries) > 3 {
		return nil, errors.New("core activation state contains unrecognized artifacts")
	}
	for _, entry := range entries {
		if entry.Name() != activationApprovedName && entry.Name() != activationAppliedName && entry.Name() != activationLockName {
			return nil, errors.New("core activation state contains unresolved or unrecognized artifacts")
		}
	}
	raw, identity, err := readActivationFile(root, activationApprovedName, uid, maximumActivationRecordBytes)
	if err != nil {
		return nil, fmt.Errorf("explicit core activation approval is absent or unsafe: %w", err)
	}
	if identity.Mode != 0600 {
		return nil, errors.New("core activation approval is not private")
	}
	record, err := decodeActivationApproval(raw, uid)
	if err != nil {
		return nil, err
	}
	// Application success is independent from authority. An approved install
	// must permit its nested firewall/core start before the parent can finish.
	if applied, witness, err := readActivationFile(root, activationAppliedName, uid, maximumActivationRecordBytes); err == nil {
		if witness.Mode != 0600 {
			return nil, errors.New("core application record is not private")
		}
		state, err := decodeActivationApplied(applied)
		if err != nil {
			return nil, err
		}
		if state.ApprovalSHA256 != activationDigest(raw) && activationDigest(applied) != record.RetainedAppliedSHA256 {
			return nil, errors.New("core application record has no matching approval lineage")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if _, witness, err := readActivationFile(root, activationLockName, uid, 0); err == nil {
		if witness.Mode != 0600 {
			return nil, errors.New("core activation lock is not private")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return &coreActivationApproval{record: record, raw: raw, file: identity, directory: directory}, nil
}

// The production loader consumes only the exact approved TOML bytes. It checks
// the same protected record and source inventory again before publishing any
// runtime settings, independently of the CLI process or service invocation.
func loadApprovedConfigDirectory(ctx context.Context, configPath, statePath string, uid uint32) (Diagnostics, error) {
	diagnostics := Diagnostics{}
	if ctx == nil {
		return diagnostics, errors.New("approved core startup requires a context")
	}
	if err := ctx.Err(); err != nil {
		return diagnostics, err
	}
	if err := rejectActivationContractEnvironment(); err != nil {
		return diagnostics, err
	}
	approval, err := readCoreActivationApproval(statePath, uid)
	if err != nil {
		return diagnostics, err
	}
	if approval.record.Root != configPath {
		return diagnostics, errors.New("core approval belongs to another configuration root")
	}
	inputs, err := readActivationInputs(approval.record, uid)
	if err != nil {
		return diagnostics, err
	}
	loadMu.Lock()
	defer loadMu.Unlock()
	consumed := make(map[string]bool, len(inputs))
	reader := func(_ *os.Root, _ string, display string) ([]byte, error) {
		relative, err := filepath.Rel(configPath, display)
		if err != nil {
			return nil, err
		}
		name := filepath.ToSlash(relative)
		raw, found := inputs[name]
		if !found || consumed[name] {
			return nil, errors.New("core attempted to consume an unapproved or repeated source")
		}
		consumed[name] = true
		return bytes.Clone(raw), nil
	}
	candidate, diagnostics, err := loadCandidateWithEnvironment(configPath, reader, false)
	if err != nil {
		return diagnostics, err
	}
	if len(consumed) != len(inputs) {
		return diagnostics, errors.New("core did not consume the complete approved input inventory")
	}
	confirmed, err := readCoreActivationApproval(statePath, uid)
	if err != nil {
		return diagnostics, err
	}
	if confirmed.directory != approval.directory || confirmed.file != approval.file || !bytes.Equal(confirmed.raw, approval.raw) {
		return diagnostics, errors.New("core activation approval changed during configuration decoding")
	}
	if _, err := readActivationInputs(approval.record, uid); err != nil {
		return diagnostics, err
	}
	if err := rejectActivationContractEnvironment(); err != nil {
		return diagnostics, err
	}
	if err := ctx.Err(); err != nil {
		return diagnostics, err
	}
	settings := candidate.AllSettings()
	viper.Reset()
	// No AutomaticEnv or environment bindings survive this publication.
	// Explicit top-level values also pin all nested maps and slices to the
	// validated candidate rather than looking up environment on runtime reads.
	target := viper.GetViper()
	for name, value := range settings {
		target.Set(name, value)
	}
	return diagnostics, nil
}
