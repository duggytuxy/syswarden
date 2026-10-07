//go:build linux

package system

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syswarden-cli/config"
	"testing"
)

func operatorRetentionFixture(t *testing.T) (string, string) {
	t.Helper()
	directory := filepath.Join(t.TempDir(), "config")
	if err := os.MkdirAll(filepath.Join(directory, "modules"), 0700); err != nil {
		t.Fatal(err)
	}
	models, err := config.DefaultModularFileModels(directory)
	if err != nil {
		t.Fatal(err)
	}
	for relative, content := range models {
		if err := os.WriteFile(filepath.Join(directory, relative), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	custom := filepath.Join(directory, "modules/75-custom.toml")
	if err := os.WriteFile(custom, []byte("# Administrator settings\n[core]\nlog_level = \"debug\"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	return directory, custom
}

func TestOperatorRetentionInventoryPreservesOriginalAndExcludesPristineDefaults(t *testing.T) {
	directory, custom := operatorRetentionFixture(t)
	before, err := os.Stat(custom)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := inspectOperatorConfigurationRetention(directory)
	if err != nil || len(plan.Files) != 1 || plan.Files[0].Path != "/etc/syswarden/config/modules/75-custom.toml" {
		t.Fatal("custom inventory did not exclude exact pristine defaults", plan, err)
	}
	content, err := encodeOperatorConfigurationRetention(plan)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeOperatorConfigurationRetention(content)
	if err != nil || !reflect.DeepEqual(decoded, plan) {
		t.Fatal("canonical retention record lost its initial evidence", err)
	}
	digest, err := OperatorConfigurationRetentionPlanSHA256(plan)
	if err != nil || len(digest) != 64 {
		t.Fatal("review digest is unavailable", err)
	}
	after, err := os.Stat(custom)
	if err != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() || before.ModTime() != after.ModTime() {
		t.Fatal("read-only inventory changed the original configuration", err)
	}
	if err := os.WriteFile(custom, []byte("[core]\nlog_level = \"info\"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	changed, err := inspectOperatorConfigurationRetention(directory)
	if err != nil {
		t.Fatal(err)
	}
	changedDigest, err := OperatorConfigurationRetentionPlanSHA256(changed)
	if err != nil || changedDigest == digest {
		t.Fatal("changed administrator bytes reused a reviewed digest", err)
	}
}

func TestOperatorRetentionInventoryRefusesUnsafeAndUnsupportedArtifacts(t *testing.T) {
	for _, kind := range []string{"symlink", "hardlink", "mode", "directory", "unknown", "syntax", "nul", "utf8", "oversize", "master"} {
		t.Run(kind, func(t *testing.T) {
			directory, custom := operatorRetentionFixture(t)
			outside := filepath.Join(filepath.Dir(directory), "outside")
			var err error
			switch kind {
			case "symlink":
				err = os.Rename(custom, outside)
				if err == nil {
					err = os.Symlink(outside, custom)
				}
			case "hardlink":
				err = os.Link(custom, outside)
			case "mode":
				err = os.Chmod(custom, 0700) // #nosec G302 -- deliberate executable-file rejection input inside the private t.TempDir fixture.
			case "directory":
				err = os.Mkdir(filepath.Join(directory, "modules/nested.toml"), 0700)
			case "unknown":
				err = os.WriteFile(filepath.Join(directory, "modules/helper.sh"), []byte("exit 0\n"), 0600)
			case "master":
				err = os.WriteFile(filepath.Join(directory, "unrecognized"), []byte("private\n"), 0600)
			default:
				content := []byte("invalid TOML\n")
				if kind == "nul" {
					content = []byte("# comment\x00\n")
				} else if kind == "utf8" {
					content = []byte{'#', 0xff, '\n'}
				} else if kind == "oversize" {
					content = bytes.Repeat([]byte{' '}, 1+(256<<10))
				}
				err = os.WriteFile(custom, content, 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := inspectOperatorConfigurationRetention(directory); err == nil {
				t.Fatal("unsafe or unsupported configuration was included")
			}
			if _, err := os.Lstat(custom); err != nil {
				t.Fatal("inventory removed an original configuration", err)
			}
		})
	}
}

func TestOperatorRetentionRecordRejectsBroadenedOrNoncanonicalAuthority(t *testing.T) {
	directory, _ := operatorRetentionFixture(t)
	plan, err := inspectOperatorConfigurationRetention(directory)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := encodeOperatorConfigurationRetention(plan)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(wire), "\n")
	for _, content := range [][]byte{
		nil, wire[:len(wire)-1], append(bytes.Clone(wire), '\n'),
		bytes.Replace(wire, []byte("modules/75-custom.toml"), []byte("modules/../outside.toml"), 1),
		bytes.Replace(wire, []byte(operatorRetentionAuthority), []byte("delete-listed-files"), 1),
		[]byte(strings.Join(append(lines[:len(lines)-1], lines[2], ""), "\n")),
		bytes.Replace(wire, []byte(plan.Files[0].SHA256), []byte(strings.ToUpper(plan.Files[0].SHA256)), 1),
		bytes.Replace(wire, []byte("\t"+plan.Files[0].SHA256), []byte("\t"+plan.Files[0].SHA256+"\textra"), 1),
	} {
		if _, err := decodeOperatorConfigurationRetention(content); err == nil {
			t.Fatal("modified retention authority was accepted")
		}
	}
	for _, path := range []string{"/etc/syswarden/config/config.toml", "/etc/syswarden/config/modules/75-custom.toml", "/etc/syswarden/config/modules/99-user.toml"} {
		if !operatorRetentionPath(path) {
			t.Fatal("supported retention path rejected", path)
		}
	}
	for _, path := range []string{"/etc/shadow", "/etc/syswarden/config/modules/.hidden.toml", "/etc/syswarden/config/modules/a\nb.toml", "/etc/syswarden/config/modules/a/b.toml", "/etc/syswarden/config/modules/-a.toml"} {
		if operatorRetentionPath(path) {
			t.Fatal("retention escaped its supported configuration surfaces", path)
		}
	}
}

func TestOperatorRetentionRecordRejectsIntegerOverflowBeforeConversion(t *testing.T) {
	directory, _ := operatorRetentionFixture(t)
	plan, err := inspectOperatorConfigurationRetention(directory)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := encodeOperatorConfigurationRetention(plan)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(wire), "\n")
	fields := strings.Split(lines[2], "\t")
	for index, value := range map[int]string{
		2: "18446744073709551616", 3: "18446744073709551616",
		4: "4294967296", 5: "4294967296", 6: "4294967296",
		7: "9223372036854775808", 8: "9223372036854775808",
		9: "1000000000", 10: "9223372036854775808", 11: "1000000000",
	} {
		changed := append([]string(nil), fields...)
		changed[index] = value
		content := []byte(lines[0] + "\n" + lines[1] + "\n" + strings.Join(changed, "\t") + "\n")
		if _, err := decodeOperatorConfigurationRetention(content); err == nil {
			t.Fatal("out-of-range metadata was narrowed into valid retention authority", index, value)
		}
	}
}
