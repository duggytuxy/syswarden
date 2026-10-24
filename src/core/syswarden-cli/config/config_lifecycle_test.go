package config

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// GlobalConfig remains compatible with existing direct readers because every
// production configuration publication is confined to the single-threaded Cobra startup
// and install-preflight lifecycle. Adding a runtime reload call must first
// replace direct access with an atomic snapshot API.
func TestGlobalConfigWritersRemainInSingleThreadedLifecycle_SW_CFG_001(t *testing.T) {
	moduleRoot := filepath.Clean("..")
	files := token.NewFileSet()
	callers := make(map[string]struct{})
	err := filepath.WalkDir(moduleRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		parsed, err := parser.ParseFile(files, path, nil, 0)
		if err != nil {
			return err
		}
		ast.Inspect(parsed, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			name := ""
			switch function := call.Fun.(type) {
			case *ast.SelectorExpr:
				name = function.Sel.Name
			case *ast.Ident:
				if parsed.Name.Name == "config" {
					name = function.Name
				}
			}
			if name == "ParseConfig" || name == "PrepareInstallationConfiguration" {
				relative, relErr := filepath.Rel(moduleRoot, path)
				if relErr == nil {
					callers[filepath.ToSlash(relative)+":"+name] = struct{}{}
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	callerFiles := make([]string, 0, len(callers))
	for caller := range callers {
		callerFiles = append(callerFiles, caller)
	}
	sort.Strings(callerFiles)
	want := []string{
		"cmd/install.go:PrepareInstallationConfiguration",
		"cmd/root.go:ParseConfig",
		"config/minimal_defaults.go:ParseConfig",
	}
	if !reflect.DeepEqual(callerFiles, want) {
		t.Fatalf("production configuration publication callers = %s, want startup-only callers %s", fmt.Sprint(callerFiles), fmt.Sprint(want))
	}
}
