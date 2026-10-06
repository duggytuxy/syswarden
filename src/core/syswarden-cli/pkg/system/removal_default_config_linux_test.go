//go:build linux

package system

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"syswarden-cli/config"
	"testing"
)

func TestDefaultRetirementPreservesMaximumSupportedOperatorModule(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "config")
	if err := config.EnsureDefaults(directory); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "modules", "99-user.toml")
	content := "#" + strings.Repeat("x", (256<<10)-2) + "\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := retirePristineDefaultConfiguration(directory, func() error { return nil }); err != nil {
		t.Fatal("valid operator module blocked retirement", err)
	}
	after, err := os.Stat(path)
	if err != nil || !os.SameFile(before, after) {
		t.Fatal("operator module inode changed", err)
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	got, err := root.ReadFile("modules/99-user.toml")
	if err != nil || string(got) != content {
		t.Fatal("operator module bytes changed", err)
	}
}

func TestDefaultConfigurationRetirementPreservesCustomizedModules(t *testing.T) {
	for _, customized := range []bool{false, true} {
		t.Run(map[bool]string{false: "pristine", true: "customized"}[customized], func(t *testing.T) {
			directory := filepath.Join(t.TempDir(), "config")
			if err := config.EnsureDefaults(directory); err != nil {
				t.Fatal(err)
			}
			root, err := os.OpenRoot(directory)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = root.Close() }()
			models, err := config.DefaultModularFileModels(directory)
			if err != nil {
				t.Fatal(err)
			}
			keep := map[string]string{}
			if customized {
				keep["modules/99-user.toml"] = "[core]\nlog_level = \"WARN\"\n"
				keep["modules/00-core.toml"] = models["modules/00-core.toml"] + "\n# Operator annotation.\n"
				keep["modules/75-operator.toml"] = "# Independent administrator module.\n"
				for relative, content := range keep {
					if err := root.WriteFile(relative, []byte(content), 0600); err != nil {
						t.Fatal(err)
					}
				}
			}
			if err := retirePristineDefaultConfiguration(directory, func() error { return nil }); err != nil {
				t.Fatal(err)
			}
			for relative := range models {
				if _, exists := keep[relative]; exists {
					continue
				}
				if _, err := os.Lstat(filepath.Join(directory, relative)); !errors.Is(err, fs.ErrNotExist) {
					t.Fatal("pristine template remains", relative, err)
				}
			}
			for relative, content := range keep {
				got, err := root.ReadFile(relative)
				if err != nil || string(got) != content {
					t.Fatal("administrator module changed", relative, err)
				}
			}
			if err := retirePristineDefaultConfiguration(directory, func() error { return nil }); err != nil {
				t.Fatal("repeat retirement failed", err)
			}
		})
	}
}

func TestDefaultConfigurationRetirementRefusesUnsafeCandidateBeforeAnyDeletion(t *testing.T) {
	for _, kind := range []string{"symlink", "hardlink", "fifo", "public", "migration", "changed-before-delete", "guard"} {
		t.Run(kind, func(t *testing.T) {
			base := t.TempDir()
			root, err := os.OpenRoot(base)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = root.Close() }()
			directory := filepath.Join(base, "config")
			if err := config.EnsureDefaults(directory); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(directory, "modules", "99-user.toml")
			original, err := root.ReadFile("config/modules/99-user.toml")
			if err != nil {
				t.Fatal(err)
			}
			outside := filepath.Join(base, "administrator")
			if err := root.WriteFile("administrator", original, 0600); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "symlink", "hardlink", "fifo":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if kind == "symlink" {
					err = os.Symlink(outside, path)
				} else if kind == "hardlink" {
					err = os.Link(outside, path)
				} else {
					err = syscall.Mkfifo(path, 0600)
				}
				if err != nil {
					t.Fatal(err)
				}
			case "public":
				if err := os.Chmod(path, 0666); err != nil { // #nosec G302 -- Deliberately unsafe metadata in a private fixture must be rejected.
					t.Fatal(err)
				}
			case "migration":
				if err := os.WriteFile(filepath.Join(directory, ".migration-in-progress"), []byte("private migration evidence"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			checks := 0
			guard := func() error {
				checks++
				if kind == "guard" {
					return errors.New("producer is still active")
				}
				if kind == "changed-before-delete" && checks == 2 {
					return os.WriteFile(filepath.Join(directory, "config.toml"), []byte("# Administrator replacement.\n"), 0600)
				}
				return nil
			}
			if err := retirePristineDefaultConfiguration(directory, guard); err == nil {
				t.Fatal("unsafe or changed candidate was accepted")
			}
			if _, err := os.Lstat(filepath.Join(directory, "config.toml")); err != nil {
				t.Fatal("master removed before failed preflight", err)
			}
			got, err := root.ReadFile("administrator")
			if err != nil || string(got) != string(original) {
				t.Fatal("administrator target changed", err)
			}
		})
	}
}

func TestDefaultRetirementRecognizesHistoricalTemplatesWithoutAdoptingEdits(t *testing.T) {
	for _, changed := range []bool{false, true} {
		t.Run(map[bool]string{false: "literal", true: "modified"}[changed], func(t *testing.T) {
			directory := filepath.Join(t.TempDir(), "config")
			if err := os.MkdirAll(filepath.Join(directory, "modules"), 0700); err != nil {
				t.Fatal(err)
			}
			models, err := config.DefaultModularFileVariants(directory)
			if err != nil {
				t.Fatal(err)
			}
			for name, variants := range models {
				content := variants[1]
				if changed && name == "modules/00-core.toml" {
					content += "\n# Administrator annotation.\n"
				}
				if err := os.WriteFile(filepath.Join(directory, name), []byte(content), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := retirePristineDefaultConfiguration(directory, func() error { return nil }); err != nil {
				t.Fatal(err)
			}
			for name := range models {
				_, err := os.Lstat(filepath.Join(directory, name))
				if changed && name == "modules/00-core.toml" {
					if err != nil {
						t.Fatal("customized historical file lost", err)
					}
				} else if !errors.Is(err, os.ErrNotExist) {
					t.Fatal("exact historical template remains", name, err)
				}
			}
		})
	}
}
