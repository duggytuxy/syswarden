//go:build linux

package sshpolicy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"reflect"
	"time"
	"unicode/utf8"
)

type sshDefaultConfigurationRun func(context.Context) (effective, trace []byte, err error)

// Bind the parser's selected main path to the manager declaration before a
// signal lease exists. This is selection evidence, not daemon-build provenance
// or proof that the running service consumed this configuration.
func bindSSHConfigurationSelection(ctx context.Context, startup StartupSummary, parserDigest string, expected sshEffective,
	run sshDefaultConfigurationRun, guard func() error) (string, error) {
	if ctx == nil || guard == nil || startup.Schema != 1 || !startup.DeclarationVerified ||
		!lowerDigest.MatchString(startup.CommandSHA256) || !lowerDigest.MatchString(parserDigest) || len(expected) == 0 {
		return "", ErrInventoryUnsafe
	}
	if err := errors.Join(ctx.Err(), guard(), ctx.Err()); err != nil {
		return "", err
	}
	if !startup.ExplicitConfiguration {
		if run == nil {
			return "", ErrInventoryUnsafe
		}
		output, trace, runErr := run(ctx)
		defer clear(output)
		defer clear(trace)
		if err := errors.Join(runErr, ctx.Err(), guard(), ctx.Err()); err != nil {
			return "", err
		}
		if err := verifySSHDefaultConfigurationTrace(trace); err != nil {
			return "", err
		}
		actual, err := parseEffective(output)
		if err != nil || !reflect.DeepEqual(actual["loglevel"], []string{"DEBUG3"}) {
			return "", errors.Join(ErrInventoryUnsafe, err)
		}
		// The fixed -ddd option changes only the parser's diagnostic log level.
		// All remaining effective directives must match the inspected graph.
		if err := compareEffective(expected, actual, map[string]bool{"loglevel": true}); err != nil {
			return "", err
		}
	}
	identity, err := sshActivationDigest([]any{"ssh-configuration-selection-v1", parserDigest, startup, MainPath, expected})
	if err := errors.Join(err, ctx.Err(), guard(), ctx.Err()); err != nil {
		return "", err
	}
	return identity, nil
}

// OpenSSH emits this first load event before reading any configuration line.
// An Include event, equal effective values from a different file, or an
// embedded occurrence in another diagnostic cannot establish the main path.
// Unsupported trace formats are refused; raw output never reaches diagnostics.
func verifySSHDefaultConfigurationTrace(trace []byte) error {
	if len(trace) == 0 || len(trace) > MaxBytes || bytes.IndexByte(trace, 0) >= 0 || !utf8.Valid(trace) {
		return ErrInventoryBounds
	}
	const prefix = "debug2: load_server_config: filename "
	found := false
	for _, line := range bytes.Split(trace, []byte("\n")) {
		line = bytes.TrimSuffix(line, []byte("\r"))
		if len(line) > 2*MaxLineBytes {
			return ErrInventoryBounds
		}
		if found {
			continue
		}
		if bytes.HasPrefix(line, []byte(prefix)) {
			if !bytes.Equal(line, []byte(prefix+MainPath)) {
				return fmt.Errorf("SSH compiled configuration path differs from the inspected graph")
			}
			found = true
		} else if bytes.Contains(line, []byte("load_server_config")) {
			return fmt.Errorf("SSH compiled configuration trace format is unsupported")
		}
	}
	if found {
		return nil
	}
	return fmt.Errorf("SSH compiled configuration path could not be verified")
}

// Test mode exits before listening. Do not add -f: the purpose is to observe
// this pinned executable's default, not replace it with our expected pathname.
func (daemon *pinnedSSHD) runDefaultConfiguration(parent context.Context) ([]byte, []byte, error) {
	if parent == nil || daemon == nil || daemon.file == nil {
		return nil, nil, ErrInventoryUnsafe
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "/proc/self/fd/3", "-T", "-ddd") // #nosec G204 -- Fixed parser-only arguments execute the retained AMD64 daemon descriptor; no shell, caller-selected path or listener mode.
	command.ExtraFiles = []*os.File{daemon.file}
	command.Env = []string{"LC_ALL=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	command.Dir = "/"
	command.WaitDelay = time.Second
	var stdout, stderr parserOutput
	command.Stdout, command.Stderr = &stdout, &stderr
	if err := command.Run(); err != nil {
		clear(stdout.Bytes())
		clear(stderr.Bytes())
		return nil, nil, fmt.Errorf("installed SSH default-configuration probe failed or exceeded execution bounds")
	}
	return stdout.Bytes(), stderr.Bytes(), nil
}
