package main

import (
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
)

type Version struct {
	Major int
	Minor int
	Patch int
}

func (v Version) String() string {
	return fmt.Sprintf("v%d.%02d.%d", v.Major, v.Minor, v.Patch)
}

type BumpType string

const (
	BumpPatch   BumpType = "Patch"
	BumpMinor   BumpType = "Minor"
	BumpMajor   BumpType = "Major"
	BumpUpgrade BumpType = "Upgrade"
)

var (
	versionPattern = regexp.MustCompile(`^v([0-9]+)\.([0-9]{2})\.([0-9]+)$`)
	versionToken   = regexp.MustCompile(`v[0-9]+\.[0-9]{2}\.[0-9]+`)
	commitPattern  = regexp.MustCompile(`^(Patch|Minor|Major|Upgrade)[[:space:]]*:[[:space:]]*(.+)$`)
)

func parseVersion(raw string) (Version, error) {
	match := versionPattern.FindStringSubmatch(raw)
	if match == nil {
		return Version{}, fmt.Errorf("invalid SysWarden version %q (expected vMAJOR.MINOR.PATCH with a two-digit minor)", raw)
	}

	parts := [3]int{}
	for i := range parts {
		value, err := strconv.ParseUint(match[i+1], 10, 31)
		if err != nil {
			return Version{}, fmt.Errorf("invalid numeric component in version %q: %w", raw, err)
		}
		parts[i] = int(value)
	}

	version := Version{Major: parts[0], Minor: parts[1], Patch: parts[2]}
	if version.String() != raw {
		return Version{}, fmt.Errorf("non-canonical SysWarden version %q (expected %s)", raw, version)
	}
	return version, nil
}

func nextVersion(current Version, bump BumpType) (Version, error) {
	next := current
	switch bump {
	case BumpPatch:
		if next.Patch == math.MaxInt32 {
			return Version{}, fmt.Errorf("Patch bump from %s exceeds the supported numeric range", current)
		}
		next.Patch++
	case BumpMinor:
		next.Minor++
		next.Patch = 0
	case BumpMajor:
		next.Minor = (next.Minor - next.Minor%10) + 10
		next.Patch = 0
	case BumpUpgrade:
		if next.Major == math.MaxInt32 {
			return Version{}, fmt.Errorf("Upgrade bump from %s exceeds the supported numeric range", current)
		}
		next.Major++
		next.Minor = 0
		next.Patch = 0
	default:
		return Version{}, fmt.Errorf("unsupported bump type %q", bump)
	}

	if next.Minor > 99 {
		return Version{}, fmt.Errorf("%s bump from %s exceeds the two-digit minor range; use Upgrade instead", bump, current)
	}
	return next, nil
}

func parseCommitMessage(message string) (BumpType, bool, error) {
	firstLine := message
	for i, char := range firstLine {
		if char == '\n' || char == '\r' {
			firstLine = firstLine[:i]
			break
		}
	}

	match := commitPattern.FindStringSubmatch(firstLine)
	if match != nil && strings.TrimSpace(match[2]) == "" {
		return "", false, fmt.Errorf("versioning commit %q must include a non-empty description after the colon", firstLine)
	}
	if match == nil {
		for _, prefix := range []string{"Patch", "Minor", "Major", "Upgrade"} {
			if firstLine == prefix || regexp.MustCompile(`^`+prefix+`[[:space:]]*:`).MatchString(firstLine) {
				return "", false, fmt.Errorf("versioning commit %q must include a non-empty description after the colon", firstLine)
			}
		}
		return "", false, nil
	}

	return BumpType(match[1]), true, nil
}
