//go:build linux

package firewall

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

const maximumLegacyFail2banDependencies = 8192

type legacyFail2banConfigDocument map[string]map[string]string

// parseLegacyFail2banConfig reads the INI structure needed for dependency
// inspection, with Fail2ban's semicolon inline comments and indented multiline
// values. It does not interpolate settings, execute actions or replace the
// installed client's configuration validation. Unsupported syntax is refused.
func parseLegacyFail2banConfig(content []byte) (legacyFail2banConfigDocument, error) {
	if len(content) > maximumNFTPersistenceBytes || !utf8.Valid(content) || bytes.Count(content, []byte{'\n'}) > maximumLegacyFail2banDumpLines {
		return nil, fmt.Errorf("Fail2ban configuration is oversized or not valid UTF-8")
	}
	for _, value := range content {
		if value < 0x20 && value != '\t' && value != '\r' && value != '\n' || value == 0x7f {
			return nil, fmt.Errorf("Fail2ban configuration contains an unsupported control byte")
		}
	}
	values := make(map[string]map[string]*strings.Builder)
	section, option, optionIndent, records := "", "", -1, 0
	for _, raw := range strings.Split(string(content), "\n") {
		line := strings.TrimSuffix(raw, "\r")
		if strings.ContainsRune(line, '\r') {
			return nil, fmt.Errorf("Fail2ban configuration uses unsupported line endings")
		}
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") {
			continue
		}
		previous := rune(0)
		for offset, value := range line {
			if value == ';' && (offset == 0 || unicode.IsSpace(previous)) {
				line = line[:offset]
				break
			}
			previous = value
		}
		trimmed = strings.TrimSpace(line)
		if trimmed == "" {
			if section != "" && option != "" {
				_ = values[section][option].WriteByte('\n')
			}
			continue
		}
		indent := 0
		for _, value := range line {
			if !unicode.IsSpace(value) {
				break
			}
			indent++
		}
		if section != "" && option != "" && indent > optionIndent {
			_ = values[section][option].WriteByte('\n')
			_, _ = values[section][option].WriteString(trimmed)
			continue
		}
		records++
		if records > maximumLegacyFail2banDumpLines {
			return nil, fmt.Errorf("Fail2ban configuration exceeds its record limit")
		}
		if strings.HasPrefix(trimmed, "[") {
			end := strings.LastIndexByte(trimmed, ']')
			if end <= 1 || end != len(trimmed)-1 {
				return nil, fmt.Errorf("Fail2ban configuration has an unsupported section header")
			}
			section = trimmed[1:end]
			if _, duplicate := values[section]; duplicate {
				return nil, fmt.Errorf("Fail2ban configuration has a duplicate section")
			}
			values[section] = make(map[string]*strings.Builder)
			option, optionIndent = "", -1
			continue
		}
		separator := strings.IndexAny(trimmed, "=:")
		if section == "" || separator <= 0 {
			return nil, fmt.Errorf("Fail2ban configuration has an unsupported option record")
		}
		option = strings.ToLower(strings.TrimSpace(trimmed[:separator]))
		if option == "" {
			return nil, fmt.Errorf("Fail2ban configuration has an empty option name")
		}
		if _, duplicate := values[section][option]; duplicate {
			return nil, fmt.Errorf("Fail2ban configuration has a duplicate option")
		}
		value := &strings.Builder{}
		value.WriteString(strings.TrimSpace(trimmed[separator+1:]))
		values[section][option] = value
		optionIndent = indent
	}
	document := make(legacyFail2banConfigDocument, len(values))
	for section, options := range values {
		document[section] = make(map[string]string, len(options))
		for name, value := range options {
			document[section][name] = strings.TrimRightFunc(value.String(), unicode.IsSpace)
		}
	}
	return document, nil
}

type legacyFail2banDependency struct {
	source  string
	target  string
	kind    string
	present bool
}

type legacyFail2banDependencies struct {
	sources []string
	edges   []legacyFail2banDependency
}

func legacyFail2banLocalVariant(path string) string {
	base := filepath.Base(path)
	leadingDots := len(base) - len(strings.TrimLeft(base, "."))
	dot := strings.LastIndexByte(base, '.')
	// Match Python splitext: a leading dot by itself is not an extension.
	if dot < leadingDots {
		return path + ".local"
	}
	return path[:len(path)-len(base)+dot] + ".local"
}

func resolveLegacyFail2banInclude(source, value string) (string, error) {
	// Do not approximate interpolated paths, escapes or wildcard semantics.
	// External includes require a separate, attested inventory before any edit.
	if value == "" || strings.ContainsAny(value, "%\\\x00\r\n\t*?[") {
		return "", fmt.Errorf("Fail2ban include requires reviewed path resolution")
	}
	path := value
	if !filepath.IsAbs(path) {
		path = filepath.Join(filepath.Dir(source), path)
	}
	path = filepath.Clean(path)
	if !canonicalNFTPersistencePath(path, false) || !strings.HasPrefix(path, legacyFail2banDirectory+"/") {
		return "", fmt.Errorf("Fail2ban include leaves the attested configuration tree")
	}
	return path, nil
}

// inspectLegacyFail2banDependencies inspects all .conf and .local files, even
// when a jail is disabled, and recursively follows other literal include
// suffixes. Missing optional includes and implicit .local files are retained
// as absence evidence. The source inventory must be reattested before use.
//
// This graph covers file includes only. It does not establish action/filter
// option dependencies, other service roots, Python action imports or live
// commands. Successful inspection is not authorization to remove a file.
func inspectLegacyFail2banDependencies(inventory legacyFail2banInventory) (legacyFail2banDependencies, error) {
	var graph legacyFail2banDependencies
	if !inventory.present || len(inventory.sources) > maximumLegacyFail2banFiles {
		return graph, fmt.Errorf("Fail2ban dependencies require a bounded present inventory")
	}
	sources := make(map[string]legacyFail2banSource, len(inventory.sources))
	directories := make(map[string]bool)
	for _, directory := range inventory.directories {
		directories[directory.path] = true
	}
	for _, source := range inventory.sources {
		if _, duplicate := sources[source.path]; duplicate || !canonicalNFTPersistencePath(source.path, false) ||
			!strings.HasPrefix(source.path, legacyFail2banDirectory+"/") || source.sha256 != sha256.Sum256(source.snapshot.content) {
			return graph, fmt.Errorf("Fail2ban dependency source is duplicate or unbound")
		}
		sources[source.path] = source
	}
	var pending []string
	for path := range sources {
		if suffix := filepath.Ext(path); suffix == ".conf" || suffix == ".local" {
			pending = append(pending, path)
		}
	}
	sort.Strings(pending)
	seen := make(map[string]bool)
	appendEdge := func(source, target, kind string) error {
		if len(graph.edges) >= maximumLegacyFail2banDependencies {
			return fmt.Errorf("Fail2ban include graph exceeds its edge limit")
		}
		if directories[target] {
			return fmt.Errorf("Fail2ban include resolves to a directory")
		}
		_, present := sources[target]
		graph.edges = append(graph.edges, legacyFail2banDependency{source, target, kind, present})
		if present && !seen[target] {
			pending = append(pending, target)
		}
		return nil
	}
	for len(pending) > 0 {
		path := pending[0]
		pending = pending[1:]
		if seen[path] {
			continue
		}
		seen[path] = true
		graph.sources = append(graph.sources, path)
		document, err := parseLegacyFail2banConfig(sources[path].snapshot.content)
		if err != nil {
			return legacyFail2banDependencies{}, fmt.Errorf("inspect Fail2ban include source %q: %w", path, err)
		}
		if local := legacyFail2banLocalVariant(path); local != path {
			if err := appendEdge(path, local, "local"); err != nil {
				return legacyFail2banDependencies{}, err
			}
		}
		includes, found := document["INCLUDES"]
		if !found {
			continue
		}
		for _, kind := range []string{"before", "after"} {
			value, found := includes[kind]
			if !found {
				value = document["DEFAULT"][kind]
			}
			for _, literal := range strings.Split(value, "\n") {
				if literal == "" {
					continue
				}
				target, err := resolveLegacyFail2banInclude(path, literal)
				if err != nil {
					return legacyFail2banDependencies{}, fmt.Errorf("inspect Fail2ban include in %q: %w", path, err)
				}
				if err := appendEdge(path, target, kind); err != nil {
					return legacyFail2banDependencies{}, err
				}
				// Fail2ban probes the local variant even when the base include
				// is absent. It must not disappear from dependency inspection.
				if local := legacyFail2banLocalVariant(target); local != target {
					if err := appendEdge(path, local, kind+"-local"); err != nil {
						return legacyFail2banDependencies{}, err
					}
				}
			}
		}
	}
	sort.Strings(graph.sources)
	sort.Slice(graph.edges, func(i, j int) bool {
		a, b := graph.edges[i], graph.edges[j]
		if a.source != b.source {
			return a.source < b.source
		}
		if a.kind != b.kind {
			return a.kind < b.kind
		}
		return a.target < b.target
	})
	return graph, nil
}

// verifyLegacyFail2banIncludeRetirement refuses to break any retained include,
// including a dormant consumer or a local override. Ownership and effective
// command-stream preservation remain separate mandatory checks.
func verifyLegacyFail2banIncludeRetirement(inventory legacyFail2banInventory, retiring []nftPersistenceRetiredSource) error {
	if len(retiring) > maximumLegacyFail2banFiles {
		return fmt.Errorf("Fail2ban include retirement exceeds its target limit")
	}
	graph, err := inspectLegacyFail2banDependencies(inventory)
	if err != nil {
		return err
	}
	sources := make(map[string][sha256.Size]byte, len(inventory.sources))
	for _, source := range inventory.sources {
		sources[source.path] = source.sha256
	}
	retired := make(map[string]bool)
	for _, source := range retiring {
		expected, found := sources[source.path]
		if !found || expected != source.sha256 || retired[source.path] {
			return fmt.Errorf("Fail2ban include retirement has an unbound or duplicate source")
		}
		retired[source.path] = true
	}
	for _, edge := range graph.edges {
		if !retired[edge.source] && retired[edge.target] {
			return fmt.Errorf("retained Fail2ban configuration %q still includes %q", edge.source, edge.target)
		}
		if retired[edge.source] && edge.kind == "local" && edge.present && !retired[edge.target] {
			return fmt.Errorf("Fail2ban configuration %q has a retained local override %q", edge.source, edge.target)
		}
	}
	// ConfigReader also loads name.d/*.conf and name.d/*.local for an
	// action or filter, even if no currently enabled jail references it.
	// These are option overlays, not INCLUDES edges. Do not strand a custom
	// overlay by removing its exact historical base file.
	for _, target := range retiring {
		if filepath.Ext(target.path) != ".conf" ||
			!strings.HasPrefix(target.path, legacyFail2banDirectory+"/action.d/") &&
				!strings.HasPrefix(target.path, legacyFail2banDirectory+"/filter.d/") {
			continue
		}
		directory := strings.TrimSuffix(target.path, ".conf") + ".d"
		for path := range sources {
			name := filepath.Base(path)
			if filepath.Dir(path) == directory && !strings.HasPrefix(name, ".") &&
				(filepath.Ext(name) == ".conf" || filepath.Ext(name) == ".local") && !retired[path] {
				return fmt.Errorf("Fail2ban configuration %q has a retained option overlay %q", target.path, path)
			}
		}
	}
	return nil
}
