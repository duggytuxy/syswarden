package system

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	installedRPMExecutablePath       = "/usr/bin/rpm"
	installedRPMPackageName          = "syswarden"
	installedRPMArchitecture         = "x86_64"
	standardRPMPackageRelease        = "1"
	rhelPackageOwnedRPMVersion       = "4.10.0"
	rhelPackageOwnedRPMRelease       = "1.rhelpo"
	rhelPackageOwnedRPMFilename      = "syswarden-4.10.0-1.rhelpo.x86_64.rpm"
	installedRPMQueryFormat          = "%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\n"
	maximumInstalledRPMIdentityBytes = 1024
	installedRPMReleaseTimeout       = 15 * time.Second
	installedRPMCommandWaitDelay     = 2 * time.Second
)

type installedRPMIdentity struct {
	name         string
	epoch        string
	version      string
	release      string
	architecture string
}

type rpmQueryBoundedBuffer struct {
	buffer   bytes.Buffer
	limit    int
	overflow bool
}

func (buffer *rpmQueryBoundedBuffer) Write(data []byte) (int, error) {
	written := len(data)
	remaining := buffer.limit - buffer.buffer.Len()
	if remaining > len(data) {
		remaining = len(data)
	}
	if remaining > 0 {
		_, _ = buffer.buffer.Write(data[:remaining])
	}
	if remaining != len(data) {
		buffer.overflow = true
	}
	return written, nil
}

func (buffer *rpmQueryBoundedBuffer) Bytes() []byte {
	return bytes.Clone(buffer.buffer.Bytes())
}

func installedRPMIdentityCommand(ctx context.Context) *exec.Cmd {
	command := exec.CommandContext(
		ctx,
		installedRPMExecutablePath,
		"--noplugins",
		"--query",
		"--queryformat",
		installedRPMQueryFormat,
		installedRPMPackageName,
	)
	command.Env = []string{
		"HOME=/nonexistent",
		"LANG=C",
		"LC_ALL=C",
		"PATH=/usr/bin:/bin",
		"TZ=UTC",
		"XDG_CONFIG_HOME=/nonexistent",
	}
	command.Dir = "/"
	command.WaitDelay = installedRPMCommandWaitDelay
	return command
}

func queryInstalledRPMIdentity(ctx context.Context) ([]byte, error) {
	stdout := &rpmQueryBoundedBuffer{limit: maximumInstalledRPMIdentityBytes}
	stderr := &rpmQueryBoundedBuffer{limit: maximumInstalledRPMIdentityBytes}
	command := installedRPMIdentityCommand(ctx)
	command.Stdout = stdout
	command.Stderr = stderr
	err := command.Run()
	if stdout.overflow || stderr.overflow {
		return nil, errors.New("installed RPM identity query exceeded its output limit")
	}
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, fmt.Errorf("query installed RPM identity: %w", ctxErr)
		}
		return nil, fmt.Errorf("query installed RPM identity: %w", err)
	}
	return stdout.Bytes(), nil
}

func parseInstalledRPMIdentity(output []byte) (installedRPMIdentity, error) {
	if len(output) == 0 || len(output) > maximumInstalledRPMIdentityBytes {
		return installedRPMIdentity{}, fmt.Errorf("installed RPM identity size %d is outside the accepted range", len(output))
	}
	if !utf8.Valid(output) || output[len(output)-1] != '\n' || bytes.Count(output, []byte{'\n'}) != 1 {
		return installedRPMIdentity{}, errors.New("installed RPM identity output is not canonical")
	}
	fields := strings.Split(string(output[:len(output)-1]), "\t")
	if len(fields) != 5 {
		return installedRPMIdentity{}, fmt.Errorf("installed RPM identity contains %d fields, want 5", len(fields))
	}
	for _, field := range fields {
		if field == "" {
			return installedRPMIdentity{}, errors.New("installed RPM identity contains an empty field")
		}
	}
	return installedRPMIdentity{
		name:         fields[0],
		epoch:        fields[1],
		version:      fields[2],
		release:      fields[3],
		architecture: fields[4],
	}, nil
}

func validateInstalledStandardRPMRelease(output []byte, currentVersion string) error {
	if _, err := parseReleaseVersion(currentVersion); err != nil {
		return fmt.Errorf("validate running SysWarden version: %w", err)
	}
	identity, err := parseInstalledRPMIdentity(output)
	if err != nil {
		return err
	}
	if identity.name != installedRPMPackageName {
		return fmt.Errorf("installed RPM name %q does not match %q", identity.name, installedRPMPackageName)
	}
	if identity.epoch != "0" {
		return fmt.Errorf("installed RPM epoch %q does not match 0", identity.epoch)
	}
	if identity.architecture != installedRPMArchitecture {
		return fmt.Errorf("installed RPM architecture %q does not match %q", identity.architecture, installedRPMArchitecture)
	}
	if identity.release == rhelPackageOwnedRPMRelease {
		if identity.version == rhelPackageOwnedRPMVersion {
			return fmt.Errorf(
				"refusing the standard signed updater on RHEL package-owned RPM %s",
				rhelPackageOwnedRPMFilename,
			)
		}
		return fmt.Errorf("refusing the standard signed updater on unrecognized RHEL package-owned RPM version %q", identity.version)
	}
	if identity.version != strings.TrimPrefix(currentVersion, "v") {
		return fmt.Errorf(
			"installed RPM version %q does not match running SysWarden version %q",
			identity.version,
			strings.TrimPrefix(currentVersion, "v"),
		)
	}
	if identity.release != standardRPMPackageRelease {
		return fmt.Errorf("installed RPM release %q is not the standard release %q", identity.release, standardRPMPackageRelease)
	}
	return nil
}

func attestInstalledStandardRPMRelease(ctx context.Context, currentVersion string) error {
	output, err := queryInstalledRPMIdentity(ctx)
	if err != nil {
		return err
	}
	return validateInstalledStandardRPMRelease(output, currentVersion)
}

func (u *updater) attestStandardRPMChannel(ctx context.Context, target packageTarget, phase string) error {
	if target.format != packageFormatRPM {
		return nil
	}
	if u.attestRPM == nil {
		return errors.New("installed RPM release attestation is unavailable; refusing the standard signed updater")
	}
	attestationCtx, cancel := context.WithTimeout(ctx, installedRPMReleaseTimeout)
	defer cancel()
	if err := u.attestRPM(attestationCtx, u.currentVersion); err != nil {
		return fmt.Errorf("attest installed RPM release %s: %w", phase, err)
	}
	return nil
}
