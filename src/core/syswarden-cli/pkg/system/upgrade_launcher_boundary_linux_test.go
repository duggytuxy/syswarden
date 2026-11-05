//go:build linux

package system

import (
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"
)

func nativeLauncherFixture(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	bin := filepath.Join(root, "usr/local/bin")
	if err := os.MkdirAll(bin, 0750); err != nil {
		t.Fatal(err)
	}
	for name, target := range map[string]string{"syswarden": "syswarden-cli", "syswarden-tui": "syswarden-tui"} {
		if err := os.Symlink("/opt/syswarden/bin/"+target, filepath.Join(bin, name)); err != nil {
			t.Fatal(err)
		}
	}
	return root, bin
}

func TestNativeLauncherInspectionPreservesExactLinks(t *testing.T) {
	root, bin := nativeLauncherFixture(t)
	first, err := inspectNativeLaunchersAt(t.Context(), root, os.Geteuid(), os.Getegid())
	if err != nil {
		t.Fatal(err)
	}
	second, err := inspectNativeLaunchersAt(t.Context(), root, os.Geteuid(), os.Getegid())
	if err != nil || first != second {
		t.Fatal("read-only observation changed launcher identity", err)
	}
	for name, target := range map[string]string{"syswarden": "syswarden-cli", "syswarden-tui": "syswarden-tui"} {
		value, err := os.Readlink(filepath.Join(bin, name))
		if err != nil || value != "/opt/syswarden/bin/"+target {
			t.Fatal("launcher changed")
		}
	}
}

func TestNativeLauncherInspectionRefusesAmbiguousEntries(t *testing.T) {
	for _, name := range []string{"syswarden", "syswarden-tui"} {
		for _, kind := range []string{"absent", "file", "directory", "fifo", "redirect", "relative", "newline", "hardlink"} {
			t.Run(name+"/"+kind, func(t *testing.T) {
				root, bin := nativeLauncherFixture(t)
				path := filepath.Join(bin, name)
				original, err := os.Readlink(path)
				if err != nil {
					t.Fatal(err)
				}
				if kind != "hardlink" {
					if err := os.Remove(path); err != nil {
						t.Fatal(err)
					}
				}
				switch kind {
				case "absent":
				case "file":
					err = os.WriteFile(path, []byte("PRIVATE-ADMIN-FIXTURE\n"), 0600)
				case "directory":
					err = os.Mkdir(path, 0750)
				case "fifo":
					err = syscall.Mkfifo(path, 0600)
				case "redirect":
					err = os.Symlink("/PRIVATE-ADMIN-FIXTURE", path)
				case "relative":
					err = os.Symlink("../../../opt/syswarden/bin/syswarden-cli", path)
				case "newline":
					err = os.Symlink(original+"\n", path)
				case "hardlink":
					err = os.Link(path, filepath.Join(bin, "other-link"))
				}
				if err != nil {
					t.Fatal(err)
				}
				before, beforeErr := os.Lstat(path)
				_, err = inspectNativeLaunchersAt(t.Context(), root, os.Geteuid(), os.Getegid())
				if err == nil || strings.Contains(err.Error(), "PRIVATE") {
					t.Fatal("ambiguous entry accepted or disclosed")
				}
				after, afterErr := os.Lstat(path)
				if beforeErr == nil {
					if afterErr != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
						t.Fatal("refusal changed entry")
					}
				} else if !errors.Is(afterErr, os.ErrNotExist) {
					t.Fatal("absent entry was created")
				}
				if kind == "file" {
					fixture, openErr := os.OpenRoot(bin)
					if openErr != nil {
						t.Fatal(openErr)
					}
					defer fixture.Close()
					data, err := fixture.ReadFile(name)
					if err != nil || string(data) != "PRIVATE-ADMIN-FIXTURE\n" {
						t.Fatal("operator bytes changed")
					}
				}
			})
		}
	}
}

func TestNativeLauncherInspectionRefusesUnsafeParentsAndContext(t *testing.T) {
	for _, kind := range []string{"writable-usr", "writable-local", "writable-bin", "parent-link", "parent-file", "missing-parent", "anchor-link", "wrong-uid", "wrong-gid", "nil-context", "cancelled", "relative-anchor"} {
		t.Run(kind, func(t *testing.T) {
			root, bin := nativeLauncherFixture(t)
			uid, gid := os.Geteuid(), os.Getegid()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			switch kind {
			case "writable-usr", "writable-local", "writable-bin":
				path := map[string]string{"writable-usr": filepath.Join(root, "usr"), "writable-local": filepath.Dir(bin), "writable-bin": bin}[kind]
				// #nosec G302 -- Deliberately unsafe parent inside a private temporary fixture proves that observation refuses writable ancestry.
				if err := os.Chmod(path, 0777); err != nil {
					t.Fatal(err)
				}
			case "parent-link", "parent-file", "missing-parent":
				if err := os.Rename(bin, filepath.Join(root, "preserved-bin")); err != nil {
					t.Fatal(err)
				}
				if kind == "parent-link" {
					if err := os.Symlink(filepath.Join(root, "preserved-bin"), bin); err != nil {
						t.Fatal(err)
					}
				}
				if kind == "parent-file" {
					if err := os.WriteFile(bin, []byte("PRIVATE-ADMIN-FIXTURE"), 0600); err != nil {
						t.Fatal(err)
					}
				}
			case "anchor-link":
				link := filepath.Join(t.TempDir(), "anchor")
				if err := os.Symlink(root, link); err != nil {
					t.Fatal(err)
				}
				root = link
			case "wrong-uid":
				uid++
			case "wrong-gid":
				gid++
			case "nil-context":
				ctx = nil
			case "cancelled":
				cancel()
			case "relative-anchor":
				root = "relative"
			}
			if _, err := inspectNativeLaunchersAt(ctx, root, uid, gid); err == nil {
				t.Fatal("unsafe observation accepted")
			}
		})
	}
}

func TestNativeLauncherGuardBindsBeforePreparationAndAfterPackageGuard(t *testing.T) {
	for _, outcome := range []string{"success", "initial-error", "initial-cancel", "changed", "final-error", "final-cancel", "package-error", "package-cancel", "nil-execution-context"} {
		t.Run(outcome, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			var events []string
			reads := 0
			reader := func(context.Context) (nativeLauncherSnapshot, error) {
				reads++
				events = append(events, "read")
				var snapshot nativeLauncherSnapshot
				snapshot.launchers[0].inode = 123
				if reads == 1 && outcome == "initial-error" || reads == 2 && outcome == "final-error" {
					return snapshot, errors.New("PRIVATE-ADMIN-FIXTURE")
				}
				if reads == 1 && outcome == "initial-cancel" || reads == 2 && outcome == "final-cancel" {
					cancel()
				}
				if reads == 2 && outcome == "changed" {
					snapshot.launchers[0].inode++
				}
				return snapshot, nil
			}
			packageGuard := func(context.Context) error {
				events = append(events, "package")
				if outcome == "package-error" {
					return errors.New("package refused")
				}
				if outcome == "package-cancel" {
					cancel()
				}
				return nil
			}
			guard, err := prepareNativeLauncherGuard(ctx, packageGuard, reader)
			if strings.HasPrefix(outcome, "initial-") {
				if err == nil || guard != nil || !reflect.DeepEqual(events, []string{"read"}) || strings.Contains(err.Error(), "PRIVATE") {
					t.Fatal("unsafe initial observation reached preparation")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			events = append(events, "prepare")
			executionCtx := ctx
			if outcome == "nil-execution-context" {
				executionCtx = nil
			}
			err = guard(executionCtx)
			if (err == nil) != (outcome == "success") {
				t.Fatal("unexpected final guard result", err)
			}
			if err != nil && strings.Contains(err.Error(), "PRIVATE") {
				t.Fatal("private observation error leaked")
			}
			want := []string{"read", "prepare", "package", "read"}
			if outcome == "nil-execution-context" {
				want = []string{"read", "prepare"}
			}
			if outcome == "package-error" || outcome == "package-cancel" {
				want = []string{"read", "prepare", "package"}
			}
			if !reflect.DeepEqual(events, want) {
				t.Fatalf("unexpected boundary order: %q", events)
			}
		})
	}
}

func TestNativeLauncherGuardRejectsIncompleteDependencies(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	reader := func(context.Context) (nativeLauncherSnapshot, error) {
		t.Fatal("unexpected read")
		return nativeLauncherSnapshot{}, nil
	}
	guard := func(context.Context) error { t.Fatal("unexpected package guard"); return nil }
	for _, test := range []struct {
		ctx    context.Context
		guard  func(context.Context) error
		reader nativeLauncherReader
	}{{nil, guard, reader}, {ctx, guard, reader}, {t.Context(), nil, reader}, {t.Context(), guard, nil}} {
		if got, err := prepareNativeLauncherGuard(test.ctx, test.guard, test.reader); err == nil || got != nil {
			t.Fatal("incomplete boundary accepted")
		}
	}
}

func TestNativeInstallerProductionWrappersBindLauncherGuard(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "upgrade_native_install.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, decl := range file.Decls {
		function, ok := decl.(*ast.FuncDecl)
		if !ok || (function.Name.Name != "runAuthenticatedNativeInstall" && function.Name.Name != "runAuthenticatedQualificationInstall") {
			continue
		}
		found++
		prepared, used := false, false
		ast.Inspect(function.Body, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			name, ok := call.Fun.(*ast.Ident)
			if !ok {
				return true
			}
			if name.Name == "prepareNativeLauncherGuard" && len(call.Args) == 3 {
				reader, ok := call.Args[2].(*ast.Ident)
				prepared = ok && reader.Name == "inspectInstalledNativeLaunchers"
			}
			if name.Name == "runAuthenticatedNativeInstallWith" && len(call.Args) > 0 {
				callback, ok := call.Args[len(call.Args)-1].(*ast.Ident)
				used = ok && callback.Name == "guard"
			}
			return true
		})
		if !prepared || !used {
			t.Fatal("production installer omitted the launcher guard")
		}
	}
	if found != 2 {
		t.Fatal("missing production installation channel")
	}
}

func TestNativeLauncherGuardStopsObservedReplacementBeforeNativeExecution(t *testing.T) {
	for _, selected := range []struct{ format, installer string }{
		{packageFormatDEB, "/usr/bin/apt-get"}, {packageFormatRPM, "/usr/bin/dnf"}, {packageFormatAPK, "/sbin/apk"},
	} {
		for _, offline := range []bool{false, true} {
			for _, changed := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%t/%t", selected.format, offline, changed), func(t *testing.T) {
					root, bin := nativeLauncherFixture(t)
					reader := func(ctx context.Context) (nativeLauncherSnapshot, error) {
						return inspectNativeLaunchersAt(ctx, root, os.Geteuid(), os.Getegid())
					}
					ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
					defer cancel()
					packageChecks, executions, preparations := 0, 0, 0
					guard, err := prepareNativeLauncherGuard(ctx, func(context.Context) error { packageChecks++; return nil }, reader)
					if err != nil {
						t.Fatal(err)
					}
					target := packageHeaderBoundaryTarget(t, "syswarden", selected.format, "v5.00.0")
					target.installer = selected.installer
					prepare := func() error {
						preparations++
						if changed {
							path := filepath.Join(bin, "syswarden")
							if err := os.Remove(path); err != nil {
								return err
							}
							return os.WriteFile(path, []byte("PRIVATE-ADMIN-FIXTURE\n"), 0600)
						}
						return nil
					}
					err = runAuthenticatedNativeInstallWith(ctx, target, "/var/tmp/syswarden-update-guard/"+target.filename, offline,
						func(context.Context, string) error { return prepare() },
						func(_ context.Context, _ string, args []string) ([]string, error) { return args, prepare() },
						func(context.Context, string, ...string) error { executions++; return nil }, guard)
					if (err != nil) != changed || preparations != 1 || packageChecks != 1 || executions != boolToNativeLauncherCount(!changed) {
						t.Fatal("native handoff did not preserve the observation boundary", err)
					}
					if changed {
						if !errors.Is(err, errNativeLauncherBoundary) {
							t.Fatal(err)
						}
						fixture, openErr := os.OpenRoot(bin)
						if openErr != nil {
							t.Fatal(openErr)
						}
						defer fixture.Close()
						data, readErr := fixture.ReadFile("syswarden")
						if readErr != nil || string(data) != "PRIVATE-ADMIN-FIXTURE\n" {
							t.Fatal("changed administrator wrapper was altered")
						}
					}
				})
			}
		}
	}
}

func boolToNativeLauncherCount(value bool) int {
	if value {
		return 1
	}
	return 0
}

func TestNativeLauncherInspectionClosesDirectoryHandles(t *testing.T) {
	root, _ := nativeLauncherFixture(t)
	before, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 32; i++ {
		if _, err := inspectNativeLaunchersAt(t.Context(), root, os.Geteuid(), os.Getegid()); err != nil {
			t.Fatal(err)
		}
	}
	after, err := os.ReadDir("/proc/self/fd")
	if err != nil || len(after) > len(before)+1 {
		t.Fatal("launcher inspection leaked directory descriptors", err)
	}
}
