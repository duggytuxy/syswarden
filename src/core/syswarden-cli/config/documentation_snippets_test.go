package config

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPublicTOMLSnippetsLoadWithApplicationParser_SW_DOC_001(t *testing.T) {
	repoRoot := filepath.Clean(filepath.Join("..", "..", "..", ".."))
	paths := []string{filepath.Join(repoRoot, "README.md")}
	if wikiRoot := os.Getenv("SYSWARDEN_WIKI_ROOT"); wikiRoot != "" {
		info, err := os.Stat(wikiRoot) // #nosec G703 -- the maintainer explicitly supplies the separate local wiki checkout used only by this test
		if err != nil || !info.IsDir() {
			t.Fatalf("SYSWARDEN_WIKI_ROOT is not a readable directory: %s: %v", wikiRoot, err)
		}
		matches, err := filepath.Glob(filepath.Join(wikiRoot, "*.md"))
		if err != nil || len(matches) == 0 {
			t.Fatalf("discover wiki Markdown under %s: matches=%d error=%v", wikiRoot, len(matches), err)
		}
		paths = append(paths, matches...)
	}

	total := 0
	for _, path := range paths {
		path := path
		blocks := documentationTOMLBlocks(t, path)
		for index, block := range blocks {
			index, block := index, block
			total++
			t.Run(fmt.Sprintf("%s/block-%d", filepath.Base(path), index+1), func(t *testing.T) {
				root := t.TempDir()
				modules := filepath.Join(root, "modules")
				if err := os.MkdirAll(modules, 0o750); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(root, "config.toml"), []byte(minimalModularConfig), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(modules, "99-documentation.toml"), []byte(block), 0o600); err != nil {
					t.Fatal(err)
				}
				previous := GlobalConfig
				t.Cleanup(func() { GlobalConfig = previous })
				if err := loadModularConfig(root); err != nil {
					t.Fatalf("application parser rejected documented TOML from %s block %d: %v\n%s", path, index+1, err, block)
				}
			})
		}
	}
	if total == 0 {
		t.Fatal("public documentation contains no TOML snippet to validate")
	}
}

func documentationTOMLBlocks(t *testing.T, path string) []string {
	t.Helper()
	file, err := os.Open(path) // #nosec G304 G703 -- path is the fixed README or a file discovered inside the explicit maintainer-controlled wiki root
	if err != nil {
		t.Fatalf("open documentation %s: %v", path, err)
	}
	defer file.Close()

	var blocks []string
	var current []string
	inTOML := false
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if !inTOML && strings.TrimSpace(line) == "```toml" {
			inTOML = true
			current = nil
			continue
		}
		if inTOML && strings.HasPrefix(strings.TrimSpace(line), "```") {
			blocks = append(blocks, strings.Join(current, "\n")+"\n")
			inTOML = false
			continue
		}
		if inTOML {
			current = append(current, line)
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("read documentation %s: %v", path, err)
	}
	if inTOML {
		t.Fatalf("unclosed TOML fence in %s", path)
	}
	return blocks
}
