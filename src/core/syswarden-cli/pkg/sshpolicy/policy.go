// Package sshpolicy prepares an inactive SSH hardening drop-in from a bounded,
// caller-attested configuration inventory. It never edits files or starts sshd.
package sshpolicy

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"path"
	"sort"
	"strings"
)

const (
	MainPath        = "/etc/ssh/sshd_config"
	DropInPath      = "/etc/ssh/sshd_config.d/00-syswarden-hardening.conf"
	MaxFiles        = 128
	MaxBytes        = 1 << 20
	MaxLineBytes    = 16 << 10
	MaxIncludeDepth = 16
	MaxExpansions   = 512
)

// Profile selects a fixed policy. Neither profile changes the port, identities,
// authentication, authorized keys, MFA, listening addresses or access groups.
type Profile uint8

const (
	Forwarding Profile = iota + 1
	CIS
)

type directive struct{ key, value string }

func directives(profile Profile) ([]directive, error) {
	values := []directive{{"AllowTcpForwarding", "no"}}
	switch profile {
	case Forwarding:
	case CIS:
		values = append(values, directive{"X11Forwarding", "no"},
			directive{"MaxAuthTries", "4"}, directive{"ClientAliveInterval", "300"},
			directive{"ClientAliveCountMax", "3"})
	default:
		return nil, fmt.Errorf("unsupported SSH policy profile")
	}
	return values, nil
}

// Candidate is an immutable preparation result, not an ownership receipt,
// migration approval, publication transaction or proof of runtime enforcement.
type Candidate struct {
	profile      Profile
	content      string
	sourceDigest [sha256.Size]byte
}

func (candidate Candidate) Bytes() []byte { return []byte(candidate.content) }

// SourceDigest binds the entire inventory, including files that did not match
// an Include. It does not attest the filesystem or prove inventory completeness.
func (candidate Candidate) SourceDigest() [sha256.Size]byte { return candidate.sourceDigest }

// Prepare requires a complete, independently attested inventory of all files
// reachable by Include, including negative glob results and directory membership.
// The caller must prevent concurrent input mutation. No path is opened here.
// Only first publication into an absent reserved path is supported. Updates and
// legacy migration require independent ownership evidence in the future adapter.
func Prepare(profile Profile, files map[string][]byte) (Candidate, error) {
	policy, err := directives(profile)
	if err != nil {
		return Candidate{}, err
	}
	if len(files) == 0 || len(files) > MaxFiles {
		return Candidate{}, fmt.Errorf("SSH inventory file count exceeds bounds")
	}
	if _, exists := files[MainPath]; !exists {
		return Candidate{}, fmt.Errorf("SSH main configuration is missing")
	}
	if _, exists := files[DropInPath]; exists {
		return Candidate{}, fmt.Errorf("reserved SSH drop-in already exists; independent ownership is required")
	}
	names := make([]string, 0, len(files))
	total := 0
	for name, content := range files {
		if !safePath(name) {
			return Candidate{}, fmt.Errorf("SSH inventory contains a noncanonical path")
		}
		if len(content) > MaxBytes-total {
			return Candidate{}, fmt.Errorf("SSH inventory exceeds byte limit")
		}
		total += len(content)
		names = append(names, name)
	}
	sort.Strings(names)
	hash := sha256.New()
	_, _ = hash.Write([]byte("SYSWARDEN-SSH-INVENTORY-V1\n"))
	for _, name := range names {
		for _, part := range [][]byte{[]byte(name), files[name]} {
			var size [8]byte
			binary.BigEndian.PutUint64(size[:], uint64(len(part)))
			_, _ = hash.Write(size[:])
			_, _ = hash.Write(part)
		}
	}
	var body strings.Builder
	body.WriteString("# SysWarden SSH hardening policy v1\n# Managed publication requires a separate ownership receipt.\n")
	expected := make(map[string]string, len(policy))
	for _, item := range policy {
		expected[strings.ToLower(item.key)] = item.value
		body.WriteString(item.key + " " + item.value + "\n")
	}
	graph := inspector{files: files, names: append(names, DropInPath), expected: expected, active: make(map[string]bool)}
	sort.Strings(graph.names)
	if err := graph.walk(MainPath, 0); err != nil {
		return Candidate{}, err
	}
	if graph.included != 1 {
		return Candidate{}, fmt.Errorf("SSH drop-in must be included exactly once in global scope")
	}
	candidate := Candidate{profile: profile, content: body.String()}
	copy(candidate.sourceDigest[:], hash.Sum(nil))
	return candidate, nil
}

func safePath(name string) bool {
	return len(name) <= 1024 && path.IsAbs(name) && name != "/" && path.Clean(name) == name &&
		printableASCII(name) && !strings.ContainsAny(name, "\\ *?[]\"#")
}

func printableASCII(value string) bool {
	for i := range len(value) {
		if value[i] < 0x20 || value[i] > 0x7e {
			return false
		}
	}
	return true
}

type inspector struct {
	files                                   map[string][]byte
	names                                   []string
	expected                                map[string]string
	active                                  map[string]bool
	conditional                             bool
	included, expansions, patterns, scanned int
}

func (graph *inspector) walk(name string, depth int) error {
	graph.expansions++
	if depth > MaxIncludeDepth || graph.expansions > MaxExpansions {
		return fmt.Errorf("SSH Include graph exceeds bounds")
	}
	if graph.active[name] {
		return fmt.Errorf("cyclic SSH Include graph")
	}
	if name == DropInPath {
		graph.included++
		if graph.conditional || graph.included > 1 {
			return fmt.Errorf("SSH drop-in is conditional or included more than once")
		}
		return nil
	}
	graph.active[name] = true
	defer delete(graph.active, name)
	content := string(graph.files[name])
	if len(content) > 4*MaxBytes-graph.scanned {
		return fmt.Errorf("SSH Include expansion exceeds byte budget")
	}
	graph.scanned += len(content)
	if strings.IndexByte(content, 0) >= 0 {
		return fmt.Errorf("SSH configuration contains NUL")
	}
	for _, line := range strings.Split(content, "\n") {
		if len(line) > MaxLineBytes {
			return fmt.Errorf("SSH configuration line exceeds bounds")
		}
		// Old main-file edits do not carry independently verifiable ownership.
		if strings.Contains(line, "SYSWARDEN OVERRIDE:") || strings.Contains(line, "SYSWARDEN CIS SSH HARDENING") {
			return fmt.Errorf("legacy SSH edits require separate reviewed migration")
		}
		key, rest := splitDirective(line)
		switch key {
		case "":
			continue
		case "match":
			// Conservative across Include returns and Match all: no later
			// inclusion is accepted as an unconditional installation point.
			graph.conditional = true
		case "include":
			patterns, err := arguments(rest)
			if err != nil || len(patterns) == 0 {
				return fmt.Errorf("unsupported SSH Include syntax")
			}
			for _, pattern := range patterns {
				if err := graph.include(pattern, depth+1); err != nil {
					return err
				}
			}
		default:
			want, controlled := graph.expected[key]
			if !controlled {
				continue
			}
			values, err := arguments(rest)
			if err != nil || len(values) != 1 || values[0] != want {
				return fmt.Errorf("administrator SSH directive %s conflicts with the requested policy; preserve it for review", key)
			}
		}
	}
	return nil
}

func (graph *inspector) include(pattern string, depth int) error {
	graph.patterns++
	if graph.patterns > MaxExpansions {
		return fmt.Errorf("SSH Include pattern count exceeds bounds")
	}
	pattern, err := includePattern(pattern)
	if err != nil {
		return err
	}
	for _, name := range graph.names {
		matched, err := path.Match(pattern, name)
		if err != nil {
			return err
		}
		if matched {
			if err := graph.walk(name, depth); err != nil {
				return err
			}
		}
	}
	return nil
}

func includePattern(pattern string) (string, error) {
	if !path.IsAbs(pattern) {
		pattern = "/etc/ssh/" + pattern
	}
	// Restrict globs to * and ?. Go bracket negation and libc glob negation
	// differ, and locale-dependent path matching is not a planning authority.
	if len(pattern) > 1024 || path.Clean(pattern) != pattern || !printableASCII(pattern) || strings.ContainsAny(pattern, "\\ []\"#~") {
		return "", fmt.Errorf("unsupported SSH Include path")
	}
	if _, err := path.Match(pattern, ""); err != nil {
		return "", fmt.Errorf("invalid SSH Include pattern")
	}
	return pattern, nil
}

func splitDirective(line string) (string, string) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return "", ""
	}
	i := strings.IndexAny(line, " \t=")
	if i < 0 {
		return strings.ToLower(line), ""
	}
	key, rest := strings.ToLower(line[:i]), strings.TrimLeft(line[i:], " \t")
	if strings.HasPrefix(rest, "=") {
		rest = strings.TrimLeft(rest[1:], " \t")
	}
	return key, rest
}

// arguments intentionally accepts only simple OpenSSH tokens and complete
// double-quoted tokens. Escapes, continuations and ambiguous spellings refuse
// planning instead of guessing at the daemon's parser behavior.
func arguments(value string) ([]string, error) {
	var result []string
	for {
		value = strings.TrimLeft(value, " \t\r")
		if value == "" || value[0] == '#' {
			return result, nil
		}
		var token string
		if value[0] == '"' {
			end := strings.IndexByte(value[1:], '"')
			if end < 0 {
				return nil, fmt.Errorf("unterminated SSH argument")
			}
			token, value = value[1:end+1], value[end+2:]
			if value != "" && !strings.ContainsRune(" \t\r", rune(value[0])) {
				return nil, fmt.Errorf("ambiguous SSH argument")
			}
		} else {
			end := strings.IndexAny(value, " \t\r")
			if end < 0 {
				token, value = value, ""
			} else {
				token, value = value[:end], value[end:]
			}
		}
		if token == "" || strings.ContainsAny(token, "\\\"\r\n\x00") {
			return nil, fmt.Errorf("unsupported SSH argument")
		}
		result = append(result, token)
	}
}

// CheckEffective validates one bounded sshd -T output against this candidate.
// Success is not activation or evidence for untested Match connection contexts.
// The future adapter must also compare port/authentication state, re-attest the
// full inventory, run sshd -t, test relevant -C contexts and verify activation.
func (candidate Candidate) CheckEffective(output []byte) error {
	if candidate.content == "" {
		return fmt.Errorf("unprepared SSH candidate")
	}
	policy, err := directives(candidate.profile)
	if err != nil {
		return err
	}
	if len(output) == 0 || len(output) > MaxBytes || strings.IndexByte(string(output), 0) >= 0 {
		return fmt.Errorf("SSH effective output exceeds bounds or is malformed")
	}
	wants := make(map[string]string, len(policy))
	for _, item := range policy {
		wants[strings.ToLower(item.key)] = item.value
	}
	seen := make(map[string]bool, len(policy))
	for _, line := range strings.Split(string(output), "\n") {
		if len(line) > MaxLineBytes {
			return fmt.Errorf("SSH effective output line exceeds bounds")
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		key := strings.ToLower(fields[0])
		want, relevant := wants[key]
		if !relevant {
			continue
		}
		if seen[key] || len(fields) != 2 || fields[1] != want {
			return fmt.Errorf("effective SSH directive %s is duplicated or differs from policy", key)
		}
		seen[key] = true
	}
	if len(seen) != len(wants) {
		return fmt.Errorf("effective SSH output omits required policy directives")
	}
	return nil
}
