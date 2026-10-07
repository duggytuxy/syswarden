//go:build linux

package system

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestOperatorRetentionDecisionSurvivesEditsAndAllFinalizationBoundaries(t *testing.T) {
	directory, custom := operatorRetentionFixture(t)
	backups := t.TempDir()
	plan, err := inspectOperatorConfigurationRetention(directory)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := OperatorConfigurationRetentionPlanSHA256(plan)
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(custom)
	if err != nil {
		t.Fatal(err)
	}
	guard := func() error { return nil }
	_, decision, err := applyOperatorConfigurationRetention(directory, backups, digest, guard)
	if err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(custom)
	if err != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() || before.ModTime() != after.ModTime() {
		t.Fatal("retention approval modified the administrator file", err)
	}
	content := []byte("# Later administrator edit\n[core]\nlog_level = \"info\"\n")
	if err := os.WriteFile(custom, content, 0600); err != nil {
		t.Fatal(err)
	}
	if _, repeated, err := applyOperatorConfigurationRetention(directory, backups, digest, guard); err != nil || repeated != decision {
		t.Fatal("exact decision retry did not preserve later administrator edits", err)
	}
	approved, err := retainedOperatorConfigurationPaths(filepath.Dir(decision))
	if err != nil || len(approved) != 1 {
		t.Fatal("durable retention inventory did not bind its original paths", err)
	}
	if err := retirePristineDefaultConfigurationWithRetention(directory, guard, approved); err != nil {
		t.Fatal(err)
	}
	root := filepath.Dir(directory)
	for attempt := 0; attempt < 2; attempt++ {
		if err := attestRuntimeRetirementRootWithRetention(root, "/etc/syswarden", systemTestUID(t), systemTestGID(t), nil, approved); err != nil {
			t.Fatal("pre-erase inventory rejected reviewed configuration", err)
		}
		if err := finalizeRetainedOperatorConfigurationWithRetention(root, systemTestUID(t), systemTestGID(t), nil, approved); err != nil {
			t.Fatal("standalone finalization rejected reviewed configuration", err)
		}
	}
	got, err := os.ReadFile(custom) // #nosec G304 -- fixed private fixture below t.TempDir; content and inode are the preservation assertion.
	if err != nil || !bytes.Equal(got, content) {
		t.Fatal("reviewed administrator configuration changed during finalization", err)
	}
	unknown := filepath.Join(directory, "modules/76-new.toml")
	if err := os.WriteFile(unknown, []byte("[core]\nlog_level = \"warn\"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := attestRuntimeRetirementRootWithRetention(root, "/etc/syswarden", systemTestUID(t), systemTestGID(t), nil, approved); err == nil {
		t.Fatal("a previous decision adopted a new unreviewed path")
	}
}

func TestOperatorRetentionDecisionRefusesStalePlansAndGuardFailure(t *testing.T) {
	for _, kind := range []string{"changed", "guard", "hardlink", "record", "pending"} {
		t.Run(kind, func(t *testing.T) {
			directory, custom := operatorRetentionFixture(t)
			backups := t.TempDir()
			plan, err := inspectOperatorConfigurationRetention(directory)
			if err != nil {
				t.Fatal(err)
			}
			digest, err := OperatorConfigurationRetentionPlanSHA256(plan)
			if err != nil {
				t.Fatal(err)
			}
			guard := func() error { return nil }
			switch kind {
			case "changed":
				err = os.WriteFile(custom, []byte("[core]\nlog_level = \"warn\"\n"), 0600)
			case "guard":
				guard = func() error { return fmt.Errorf("fixture guard changed") }
			case "hardlink":
				err = os.Link(custom, filepath.Join(backups, "outside"))
			default:
				_, path, applyErr := applyOperatorConfigurationRetention(directory, backups, digest, guard)
				if applyErr != nil {
					t.Fatal(applyErr)
				}
				if kind == "pending" {
					path += ".new"
				}
				err = os.WriteFile(path, []byte("Changed decision\n"), 0600)
				if err == nil {
					if _, err := retainedOperatorConfigurationPaths(filepath.Dir(path)); err == nil {
						t.Fatal("modified or incomplete retention evidence was accepted")
					}
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			if kind != "pending" {
				if _, _, err := applyOperatorConfigurationRetention(directory, backups, digest, guard); err == nil {
					t.Fatal("unreviewed or unsafe retention was acknowledged")
				}
			}
			if _, err := os.Lstat(custom); err != nil {
				t.Fatal("retention refusal removed administrator configuration", err)
			}
		})
	}
}
