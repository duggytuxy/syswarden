package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"sync"

	"github.com/pelletier/go-toml/v2"
	"github.com/pelletier/go-toml/v2/unstable"
	"github.com/spf13/viper"
)

const (
	maximumRetirementModules  = 1024
	maximumRetirementFileSize = 8 << 20
)

var (
	retiredWebTUIWriteMu sync.Mutex
	publishRetiredWebTUI = replaceSecureFileAtomicallyIfUnchanged
)

type retiredWebTUIRewrite struct {
	directory string
	name      string
	content   []byte
	identity  *secureFileIdentity
}

type retiredWebTUISpan struct {
	start int
	end   int
}

// RemoveRetiredWebTUIConfiguration removes only the retired Web-TUI secret
// assignment from secure modular TOML files. Every changed file is validated
// and replaced through a compare-and-swap transaction. Secret values are never
// included in returned errors.
func RemoveRetiredWebTUIConfiguration(configDir string) error {
	retiredWebTUIWriteMu.Lock()
	defer retiredWebTUIWriteMu.Unlock()

	info, err := os.Lstat(configDir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect configuration root: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("configuration root is not a real directory")
	}

	root, err := openConfigDirectory(configDir, false, 0)
	if err != nil {
		return fmt.Errorf("open configuration root: %w", err)
	}
	defer func() { _ = root.Close() }()

	var rewrites []retiredWebTUIRewrite
	publishRewrites := func() error {
		for _, rewrite := range rewrites {
			if err := publishRetiredWebTUI(rewrite.directory, rewrite.name, rewrite.content, rewrite.identity); err != nil {
				return fmt.Errorf("publish retired configuration cleanup for %s: %w", filepath.Join(rewrite.directory, rewrite.name), err)
			}
		}
		return nil
	}
	master, err := prepareRetiredWebTUIFile(root, configDir, "config.toml")
	if err != nil {
		return err
	}
	if master != nil {
		rewrites = append(rewrites, *master)
	}

	modulesInfo, err := root.Lstat("modules")
	if errors.Is(err, fs.ErrNotExist) {
		return publishRewrites()
	}
	if err != nil {
		return fmt.Errorf("inspect configuration modules: %w", err)
	}
	if modulesInfo.Mode()&os.ModeSymlink != 0 || !modulesInfo.IsDir() {
		return fmt.Errorf("configuration modules path is not a real directory")
	}

	modulesDir := filepath.Join(configDir, "modules")
	modulesRoot, err := openConfigDirectory(modulesDir, false, 0)
	if err != nil {
		return fmt.Errorf("open configuration modules: %w", err)
	}
	defer func() { _ = modulesRoot.Close() }()
	directory, err := modulesRoot.Open(".")
	if err != nil {
		return fmt.Errorf("open configuration modules inventory: %w", err)
	}
	entries, err := directory.ReadDir(maximumRetirementModules + 1)
	_ = directory.Close()
	if err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("read configuration modules inventory: %w", err)
	}
	if len(entries) > maximumRetirementModules {
		return fmt.Errorf("configuration modules inventory exceeds the cleanup limit")
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) != ".toml" {
			continue
		}
		rewrite, err := prepareRetiredWebTUIFile(modulesRoot, modulesDir, entry.Name())
		if err != nil {
			return err
		}
		if rewrite != nil {
			rewrites = append(rewrites, *rewrite)
		}
	}
	// Prove every rewrite before publishing the first one. This prevents an
	// unsupported but valid TOML representation in a later module from leaving
	// a partially cleaned configuration corpus.
	return publishRewrites()
}

func prepareRetiredWebTUIFile(root *os.Root, directory, name string) (*retiredWebTUIRewrite, error) {
	displayPath := filepath.Join(directory, name)
	content, identity, err := readSecureRegularFileIdentity(root, name, displayPath)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read configuration file %s securely: %w", displayPath, err)
	}
	if len(content) > maximumRetirementFileSize {
		return nil, fmt.Errorf("configuration file %s exceeds the cleanup size limit", displayPath)
	}
	updated, changed, err := removeRetiredWebTUIAssignments(content)
	if err != nil {
		return nil, fmt.Errorf("prove retired configuration cleanup for %s: %w", displayPath, err)
	}
	if !changed {
		return nil, nil
	}
	parser := viper.New()
	parser.SetConfigType("toml")
	if err := parser.ReadConfig(bytes.NewReader(updated)); err != nil {
		return nil, fmt.Errorf("retired configuration rewrite produced invalid TOML in %s", displayPath)
	}
	return &retiredWebTUIRewrite{directory: directory, name: name, content: updated, identity: identity}, nil
}

func removeRetiredWebTUIAssignments(content []byte) ([]byte, bool, error) {
	var before map[string]any
	if err := toml.Unmarshal(content, &before); err != nil {
		// Cleanup is not the configuration validator. If the retired key is not
		// even lexically present, leave invalid TOML byte-exact so the normal
		// loader can record and report its canonical degraded state.
		if !bytes.Contains(content, []byte("webtui_password")) {
			return bytes.Clone(content), false, nil
		}
		return nil, false, fmt.Errorf("parse TOML before cleanup: %w", err)
	}
	userValue, exists := before["user"]
	if !exists {
		return bytes.Clone(content), false, nil
	}
	user, ok := userValue.(map[string]any)
	if !ok {
		return bytes.Clone(content), false, nil
	}
	if _, exists := user["webtui_password"]; !exists {
		return bytes.Clone(content), false, nil
	}

	spans, err := locateRetiredWebTUISpans(content)
	if err != nil {
		return nil, false, err
	}
	if len(spans) != 1 {
		return nil, false, fmt.Errorf("retired credential has no unique byte-exact TOML representation")
	}
	span := spans[0]
	if span.start < 0 || span.end <= span.start || span.end > len(content) {
		return nil, false, fmt.Errorf("retired credential rewrite span is invalid")
	}
	updated := make([]byte, 0, len(content)-(span.end-span.start))
	updated = append(updated, content[:span.start]...)
	updated = append(updated, content[span.end:]...)

	delete(user, "webtui_password")
	if len(user) == 0 {
		delete(before, "user")
	}
	var after map[string]any
	if err := toml.Unmarshal(updated, &after); err != nil {
		return nil, false, fmt.Errorf("parse TOML after cleanup: %w", err)
	}
	if afterUser, ok := after["user"].(map[string]any); ok && len(afterUser) == 0 {
		delete(after, "user")
	}
	if !(len(before) == 0 && len(after) == 0) && !reflect.DeepEqual(before, after) {
		return nil, false, fmt.Errorf("retired credential rewrite changed unrelated TOML semantics")
	}
	return updated, true, nil
}

func locateRetiredWebTUISpans(content []byte) ([]retiredWebTUISpan, error) {
	parser := unstable.Parser{}
	parser.Reset(content)
	var table []string
	var spans []retiredWebTUISpan
	for parser.NextExpression() {
		expression := parser.Expression()
		switch expression.Kind {
		case unstable.Table, unstable.ArrayTable:
			table = tomlNodeKey(expression)
		case unstable.KeyValue:
			key := tomlNodeKey(expression)
			full := append(append([]string(nil), table...), key...)
			if equalTOMLPath(full, "user", "webtui_password") {
				start := int(firstTOMLKeyOffset(expression))
				lineStart := bytes.LastIndexByte(content[:start], '\n') + 1
				lineEnd := start + bytes.IndexByte(content[start:], '\n')
				if lineEnd < start {
					lineEnd = len(content)
				} else {
					lineEnd++
				}
				spans = append(spans, retiredWebTUISpan{start: lineStart, end: lineEnd})
				continue
			}
			if len(table) == 0 && equalTOMLPath(key, "user") && expression.Value().Kind == unstable.InlineTable {
				span, found, err := locateRetiredInlineTableSpan(content, expression.Value())
				if err != nil {
					return nil, err
				}
				if found {
					spans = append(spans, span)
				}
			}
		}
	}
	if err := parser.Error(); err != nil {
		return nil, fmt.Errorf("parse TOML syntax tree: %w", err)
	}
	return spans, nil
}

func tomlNodeKey(node *unstable.Node) []string {
	iterator := node.Key()
	var key []string
	for iterator.Next() {
		key = append(key, string(iterator.Node().Data))
	}
	return key
}

func firstTOMLKeyOffset(node *unstable.Node) uint32 {
	iterator := node.Key()
	if !iterator.Next() {
		return 0
	}
	return iterator.Node().Raw.Offset
}

func equalTOMLPath(actual []string, expected ...string) bool {
	return reflect.DeepEqual(actual, expected)
}

func locateRetiredInlineTableSpan(content []byte, table *unstable.Node) (retiredWebTUISpan, bool, error) {
	open := int(table.Raw.Offset)
	close, commas, err := scanTOMLInlineTable(content, open)
	if err != nil {
		return retiredWebTUISpan{}, false, err
	}
	type entry struct {
		start int
		key   []string
	}
	var entries []entry
	children := table.Children()
	for children.Next() {
		child := children.Node()
		if child.Kind != unstable.KeyValue {
			return retiredWebTUISpan{}, false, fmt.Errorf("inline table contains an unsupported syntax node")
		}
		entries = append(entries, entry{start: int(firstTOMLKeyOffset(child)), key: tomlNodeKey(child)})
	}
	for index, current := range entries {
		if !equalTOMLPath(current.key, "webtui_password") {
			continue
		}
		if len(entries) == 1 {
			return retiredWebTUISpan{start: current.start, end: close}, true, nil
		}
		if index < len(entries)-1 {
			next := entries[index+1].start
			for _, comma := range commas {
				if comma >= current.start && comma < next {
					return retiredWebTUISpan{start: current.start, end: comma + 1}, true, nil
				}
			}
			return retiredWebTUISpan{}, false, fmt.Errorf("inline-table credential has no safe following delimiter")
		}
		previous := entries[index-1].start
		for offset := len(commas) - 1; offset >= 0; offset-- {
			comma := commas[offset]
			if comma > previous && comma < current.start {
				return retiredWebTUISpan{start: comma, end: close}, true, nil
			}
		}
		return retiredWebTUISpan{}, false, fmt.Errorf("inline-table credential has no safe preceding delimiter")
	}
	return retiredWebTUISpan{}, false, nil
}

func scanTOMLInlineTable(content []byte, open int) (int, []int, error) {
	if open < 0 || open >= len(content) || content[open] != '{' {
		return 0, nil, fmt.Errorf("inline table opening delimiter is invalid")
	}
	curlyDepth := 1
	squareDepth := 0
	var commas []int
	for index := open + 1; index < len(content); {
		switch content[index] {
		case '"', '\'':
			next, err := skipTOMLString(content, index)
			if err != nil {
				return 0, nil, err
			}
			index = next
			continue
		case '#':
			if newline := bytes.IndexByte(content[index:], '\n'); newline >= 0 {
				index += newline + 1
				continue
			}
			return 0, nil, fmt.Errorf("unterminated inline-table comment")
		case '{':
			curlyDepth++
		case '}':
			curlyDepth--
			if curlyDepth == 0 {
				return index, commas, nil
			}
		case '[':
			squareDepth++
		case ']':
			if squareDepth > 0 {
				squareDepth--
			}
		case ',':
			if curlyDepth == 1 && squareDepth == 0 {
				commas = append(commas, index)
			}
		}
		index++
	}
	return 0, nil, fmt.Errorf("inline table closing delimiter is missing")
}

func skipTOMLString(content []byte, start int) (int, error) {
	quote := content[start]
	triple := start+2 < len(content) && content[start+1] == quote && content[start+2] == quote
	index := start + 1
	if triple {
		index = start + 3
	}
	for index < len(content) {
		if quote == '"' && content[index] == '\\' {
			index += 2
			continue
		}
		if triple {
			if index+2 < len(content) && content[index] == quote && content[index+1] == quote && content[index+2] == quote {
				return index + 3, nil
			}
			index++
			continue
		}
		if content[index] == quote {
			return index + 1, nil
		}
		index++
	}
	return 0, fmt.Errorf("unterminated TOML string while locating retired credential")
}
