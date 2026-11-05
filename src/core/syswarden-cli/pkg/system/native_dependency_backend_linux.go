//go:build linux

package system

import (
	"bytes"
	"context"
	"errors"
	"regexp"
	"strings"
)

var dnf4RetentionVersion = regexp.MustCompile(`^4[.][0-9]+[.][0-9]+([.][0-9]+)?$`)
var dnf5RetentionVersion = regexp.MustCompile(`^dnf5 version 5[.][0-9]+[.][0-9]+[.][0-9]+$`)

type nativeRetentionVariantRunner func(context.Context, string, string, []string, int) ([]byte, error)

func nativeRetentionGeneration(data []byte) (int, error) {
	if len(data) == 0 || len(data) > 64<<10 || bytes.ContainsAny(data, "\x00\r") || data[len(data)-1] != '\n' {
		return 0, errors.New("invalid native package manager version observation")
	}
	line := strings.SplitN(string(data), "\n", 2)[0]
	if dnf4RetentionVersion.MatchString(line) {
		return 4, nil
	}
	if dnf5RetentionVersion.MatchString(line) {
		return 5, nil
	}
	return 0, errors.New("native dependency retention requires qualified DNF4 or DNF5")
}

// Bind generation to the selected protected executable's native version output,
// not an OS label, ambient environment, package reason casing or caller summary.
// Recheck before every query/mutation so an observed provider change stops work.
func bindNativeRetentionRunner(ctx context.Context, manager string, execute nativeRetentionVariantRunner) (nativeRetentionRunner, error) {
	if execute == nil || len(retentionEligible(manager)) == 0 {
		return nil, errors.New("native retention provider unavailable")
	}
	if manager == "/usr/bin/apt-get" || manager == "/usr/bin/dpkg" {
		return func(ctx context.Context, got, operation string, names []string) ([]byte, error) {
			if got != manager {
				return nil, errors.New("native retention manager changed")
			}
			return execute(ctx, got, operation, names, 4)
		}, nil
	}
	data, err := execute(ctx, manager, "provider", nil, 4)
	if err != nil {
		return nil, err
	}
	generation, err := nativeRetentionGeneration(data)
	if err != nil {
		return nil, err
	}
	version := bytes.Clone(data)
	return func(ctx context.Context, got, operation string, names []string) ([]byte, error) {
		if got != manager || operation == "provider" {
			return nil, errors.New("native retention manager scope changed")
		}
		current, err := execute(ctx, manager, "provider", nil, 4)
		if err != nil || !bytes.Equal(current, version) {
			return nil, errors.New("native package manager changed or became unavailable during retention")
		}
		return execute(ctx, manager, operation, names, generation)
	}, nil
}

// Keep native selection semantics exact. DNF5 uses a distinct fixed vocabulary;
// unknown values are never treated as an automatic dependency or an approval.
func normalizeDNF5RetentionReasons(data []byte) ([]byte, error) {
	if len(data) == 0 || len(data) > 64<<10 || bytes.ContainsAny(data, "\x00\r") || data[len(data)-1] != '\n' {
		return nil, errors.New("incomplete DNF5 dependency reasons")
	}
	var out strings.Builder
	for _, line := range strings.Split(strings.TrimSuffix(string(data), "\n"), "\n") {
		fields := strings.Split(line, "\t")
		if len(fields) != 2 {
			return nil, errors.New("ambiguous DNF5 dependency reasons")
		}
		var reason string
		switch fields[1] {
		case "User":
			reason = "user"
		case "Group":
			reason = "group"
		case "External User":
			reason = "external-user"
		case "Dependency":
			reason = "dependency"
		case "Weak Dependency":
			reason = "weak-dependency"
		default:
			return nil, errors.New("unknown DNF5 dependency reason")
		}
		out.WriteString(fields[0] + "\t" + reason + "\n")
	}
	return []byte(out.String()), nil
}
