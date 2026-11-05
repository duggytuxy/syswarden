//go:build linux

package system

import (
	"os"
	"path/filepath"
	"testing"
)

func dependencyPathFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for _, directory := range []string{"usr/bin", "etc/alternatives", "untrusted", "usr/hold"} {
		if err := os.MkdirAll(filepath.Join(root, directory), 0700); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(root, "usr/bin/real-tool")
	if err := os.WriteFile(path, []byte("inert executable fixture\n"), 0600); err != nil {
		t.Fatal(err)
	}
	// #nosec G302 -- Private inert fixture needs its execute bit to model a system binary; it is never executed.
	if err := os.Chmod(path, 0700); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestDependencyResolutionInspectsIntermediateSymlinkAncestry(t *testing.T) {
	for _, scenario := range []string{"direct", "absolute-link", "relative-link", "usr-merge", "protected-alternatives", "parent-traversal", "unsafe-intermediate", "unsafe-leaf-parent", "file-as-parent", "cycle", "missing", "directory", "nonexecutable", "wrong-owner", "unclean", "relative", "anchor-link"} {
		t.Run(scenario, func(t *testing.T) {
			root := dependencyPathFixture(t)
			anchor, path, uid := root, "/usr/bin/real-tool", os.Geteuid()
			link := func(name, target string) {
				t.Helper()
				if err := os.Symlink(target, filepath.Join(root, name)); err != nil {
					t.Fatal(err)
				}
			}
			accepted := false
			switch scenario {
			case "direct":
				accepted = true
			case "absolute-link", "relative-link":
				target := "/usr/bin/real-tool"
				if scenario == "relative-link" {
					target = "real-tool"
				}
				link("usr/bin/tool", target)
				path, accepted = "/usr/bin/tool", true
			case "usr-merge":
				link("bin", "usr/bin")
				path, accepted = "/bin/real-tool", true
			case "protected-alternatives", "unsafe-intermediate":
				link("usr/bin/tool", "/etc/alternatives/tool")
				link("etc/alternatives/tool", "/usr/bin/real-tool")
				path, accepted = "/usr/bin/tool", scenario == "protected-alternatives"
				if !accepted {
					// #nosec G302 -- Deliberately unsafe private fixture proves an intermediate directory cannot redirect trusted resolution.
					if err := os.Chmod(filepath.Join(root, "etc/alternatives"), 0777); err != nil {
						t.Fatal(err)
					}
				}
			case "parent-traversal":
				link("usr/bin/tool", "../hold/../bin/real-tool")
				path, accepted = "/usr/bin/tool", true
			case "unsafe-leaf-parent":
				// #nosec G302 -- Deliberately unsafe private fixture proves a writable final directory is refused.
				if err := os.Chmod(filepath.Join(root, "usr/bin"), 0777); err != nil {
					t.Fatal(err)
				}
			case "file-as-parent":
				link("usr/bin/tool", "real-tool/../real-tool")
				path = "/usr/bin/tool"
			case "cycle":
				link("usr/bin/tool", "loop")
				link("usr/bin/loop", "tool")
				path = "/usr/bin/tool"
			case "missing":
				path = "/usr/bin/missing"
			case "directory":
				path = "/usr/bin"
			case "nonexecutable":
				if err := os.Chmod(filepath.Join(root, "usr/bin/real-tool"), 0600); err != nil {
					t.Fatal(err)
				}
			case "wrong-owner":
				uid++
			case "unclean":
				path = "/usr/bin/../bin/real-tool"
			case "relative":
				path = "usr/bin/real-tool"
			case "anchor-link":
				anchor = filepath.Join(t.TempDir(), "anchor")
				if err := os.Symlink(root, anchor); err != nil {
					t.Fatal(err)
				}
			}
			got, err := resolveDependencyExecutableAt(anchor, path, uid)
			if (err == nil) != accepted || accepted && got != "/usr/bin/real-tool" {
				t.Fatalf("unexpected executable resolution: %q %v", got, err)
			}
		})
	}
}
