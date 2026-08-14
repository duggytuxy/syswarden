package system

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
)

func TestFreeBSDRCScriptsGolden_SW_PKG_001(t *testing.T) {
	t.Parallel()
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test source path")
	}
	sourcePath := filepath.Join(filepath.Dir(currentFile), "service_freebsd.go")
	scripts := map[string]string{
		"rcScript":       filepath.Join("..", "..", "..", "..", "..", "testdata", "services", "freebsd-syswarden.rc"),
		"webtuiRcScript": filepath.Join("..", "..", "..", "..", "..", "testdata", "services", "freebsd-syswardenwebtui.rc"),
	}
	for variable, fixturePath := range scripts {
		variable, fixturePath := variable, fixturePath
		t.Run(variable, func(t *testing.T) {
			t.Parallel()
			got := extractAssignedString(t, sourcePath, variable)
			if os.Getenv("SYSWARDEN_UPDATE_CONTRACT_GOLDENS") == "1" {
				if err := os.WriteFile(fixturePath, []byte(got), 0600); err != nil {
					t.Fatalf("update rc.d golden: %v", err)
				}
				return
			}
			want, err := os.ReadFile(fixturePath) // #nosec G304 -- fixturePath is a fixed repository fixture
			if err != nil {
				t.Fatal(err)
			}
			if got != string(want) {
				t.Fatalf("FreeBSD rc.d script changed; review startup, stop, paths, permissions and ordering before updating %s", fixturePath)
			}
		})
	}
}

func extractAssignedString(t *testing.T, sourcePath, variable string) string {
	t.Helper()
	parsed, err := parser.ParseFile(token.NewFileSet(), sourcePath, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var value string
	ast.Inspect(parsed, func(node ast.Node) bool {
		assignment, ok := node.(*ast.AssignStmt)
		if !ok || len(assignment.Lhs) != 1 || len(assignment.Rhs) != 1 {
			return true
		}
		identifier, ok := assignment.Lhs[0].(*ast.Ident)
		if !ok || identifier.Name != variable {
			return true
		}
		literal, ok := assignment.Rhs[0].(*ast.BasicLit)
		if !ok || literal.Kind != token.STRING {
			t.Fatalf("%s is no longer assigned a string literal", variable)
		}
		value, err = strconv.Unquote(literal.Value)
		if err != nil {
			t.Fatal(err)
		}
		return false
	})
	if value == "" {
		t.Fatalf("string assignment %s not found in %s", variable, sourcePath)
	}
	return value
}
