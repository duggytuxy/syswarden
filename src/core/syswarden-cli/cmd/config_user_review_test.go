package cmd

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"syswarden-cli/config"
)

type configReviewInput struct {
	output         *bytes.Buffer
	lines          []string
	beforeApproval func()
}

func (input *configReviewInput) Read(buffer []byte) (int, error) {
	if len(input.lines) == 0 {
		return 0, io.EOF
	}
	line := input.lines[0]
	input.lines = input.lines[1:]
	if line == "APPROVE" {
		if input.beforeApproval != nil {
			input.beforeApproval()
		}
		_, tail, found := strings.Cut(input.output.String(), "Type 'publish ")
		if !found {
			return 0, errors.New("approval requested before review")
		}
		id, _, found := strings.Cut(tail, "' to publish")
		if !found {
			return 0, errors.New("approval prompt is incomplete")
		}
		line = "publish " + id
	}
	line += "\n"
	if len(line) > len(buffer) {
		return 0, errors.New("input buffer too small")
	}
	return copy(buffer, line), nil
}

func configUserReviewFixture(t *testing.T) (string, *bytes.Buffer) {
	t.Helper()
	preserveConfigMenuPreflightHooks(t)
	originalContext := configCmd.Context()
	configCmd.SetContext(context.Background())
	t.Cleanup(func() { configCmd.SetContext(originalContext) })
	root := filepath.Join(t.TempDir(), "config")
	if err := config.InitializeDefaults(root); err != nil {
		t.Fatal(err)
	}
	configEditorRoot = root
	t.Setenv("EDITOR", "/operator/editor")
	preflightWireGuardPolicyTransition = func() error { return nil }
	inspectRemovalTombstone = func() (bool, error) { return false, nil }
	refusePendingFirewallTransactionHook = func() error { return nil }
	output := &bytes.Buffer{}
	configCmd.SetOut(output)
	configCmd.SetErr(output)
	return root, output
}

func TestConfigUserMenuRequiresReviewBeforePublication(t *testing.T) {
	for _, choice := range []string{"6", "7", "8"} {
		for _, approve := range []bool{false, true} {
			t.Run(choice+map[bool]string{true: "/approve", false: "/cancel"}[approve], func(t *testing.T) {
				root, output := configUserReviewFixture(t)
				before := snapshotRegularFiles(t, root)
				var stage string
				launchConfigEditor = func(_ string, path string, _ io.Reader, _ io.Writer, _ io.Writer) error {
					stage = path
					if filepath.Dir(path) == filepath.Join(root, "modules") {
						t.Fatal("editor used live configuration")
					}
					return os.WriteFile(path, []byte("[user]\nprofile_name='Reviewed'\n"), 0600)
				}
				lines := []string{choice}
				if choice == "7" {
					lines = append(lines, "Reviewed")
				}
				if choice == "8" {
					source := filepath.Join(t.TempDir(), "import.toml")
					if err := os.WriteFile(source, []byte("[user]\nprofile_name='Reviewed'\n"), 0600); err != nil {
						t.Fatal(err)
					}
					lines = append(lines, source)
				}
				reply := ""
				if approve {
					reply = "APPROVE"
				}
				lines = append(lines, reply, "0")
				configCmd.SetIn(&configReviewInput{output: output, lines: lines})
				if err := configCmd.RunE(configCmd, nil); err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(output.String(), "Host policy and services are not activated.") {
					t.Fatal("publication boundary missing")
				}
				if !approve {
					if after := snapshotRegularFiles(t, root); !reflect.DeepEqual(before, after) {
						t.Fatal("cancel changed live configuration")
					}
				} else {
					value, found, err := config.GetValidatedModularValue(root, "user.profile_name")
					if err != nil || !found || value != "Reviewed" {
						t.Fatalf("profile=%q found=%v err=%v", value, found, err)
					}
				}
				if stage != "" {
					if _, err := os.Lstat(filepath.Dir(stage)); !os.IsNotExist(err) {
						t.Fatal("private editor copy remains")
					}
				}
			})
		}
	}
}

func TestConfigUserMenuRechecksRecoveryAfterApproval(t *testing.T) {
	for _, barrier := range []string{"wireguard", "removal", "firewall", "configuration"} {
		t.Run(barrier, func(t *testing.T) {
			root, output := configUserReviewFixture(t)
			before := snapshotRegularFiles(t, root)
			input := &configReviewInput{output: output, lines: []string{"7", "Reviewed", "APPROVE"}}
			input.beforeApproval = func() {
				switch barrier {
				case "wireguard":
					preflightWireGuardPolicyTransition = func() error { return errors.New("pending WireGuard recovery") }
				case "removal":
					inspectRemovalTombstone = func() (bool, error) { return true, nil }
				case "firewall":
					refusePendingFirewallTransactionHook = func() error { return errors.New("pending firewall recovery") }
				case "configuration":
					if err := os.WriteFile(filepath.Join(root, "modules", "98-concurrent.toml"), []byte("# concurrent\n"), 0600); err != nil {
						t.Fatal(err)
					}
				}
			}
			configCmd.SetIn(input)
			if err := configCmd.RunE(configCmd, nil); err == nil {
				t.Fatal("publication bypassed new recovery state")
			}
			after := snapshotRegularFiles(t, root)
			if barrier == "configuration" {
				delete(after, "modules/98-concurrent.toml")
			}
			if !reflect.DeepEqual(before, after) {
				t.Fatal("refused publication changed live configuration")
			}
			if strings.Contains(output.String(), "Validated configuration file published.") {
				t.Fatal("refusal printed success")
			}
		})
	}
}

func TestConfigUserMenuEOFDoesNotApprove(t *testing.T) {
	root, output := configUserReviewFixture(t)
	before := snapshotRegularFiles(t, root)
	configCmd.SetIn(&configReviewInput{output: output, lines: []string{"7", "Reviewed"}})
	if err := configCmd.RunE(configCmd, nil); err == nil {
		t.Fatal("EOF accepted as approval")
	}
	if !reflect.DeepEqual(before, snapshotRegularFiles(t, root)) {
		t.Fatal("EOF changed live configuration")
	}
}

func TestConfigMenuUsesReviewedPrivateCopiesForEveryOrdinaryFile(t *testing.T) {
	for _, choice := range []string{"1", "2", "3", "4", "5", "9"} {
		for _, approve := range []bool{false, true} {
			t.Run(choice+map[bool]string{true: "/approve", false: "/cancel"}[approve], func(t *testing.T) {
				root, output := configUserReviewFixture(t)
				before := snapshotRegularFiles(t, root)
				var stage string
				launchConfigEditor = func(_ string, path string, _ io.Reader, _ io.Writer, _ io.Writer) error {
					stage = path
					if strings.HasPrefix(path, root+string(filepath.Separator)) {
						t.Fatal("ordinary editor received live path")
					}
					privateRoot, err := os.OpenRoot(filepath.Dir(path))
					if err != nil {
						return err
					}
					defer func() { _ = privateRoot.Close() }()
					content, err := privateRoot.ReadFile(filepath.Base(path))
					if err != nil {
						return err
					}
					if !reflect.DeepEqual(before, snapshotRegularFiles(t, root)) {
						t.Fatal("configuration changed before editor")
					}
					return privateRoot.WriteFile(filepath.Base(path), append(content, []byte("\n# operator edit\n")...), 0600)
				}
				reply := ""
				if approve {
					reply = "APPROVE"
				}
				configCmd.SetIn(&configReviewInput{output: output, lines: []string{choice, reply, "0"}})
				if err := configCmd.RunE(configCmd, nil); err != nil {
					t.Fatal(err)
				}
				after := snapshotRegularFiles(t, root)
				if !approve {
					if !reflect.DeepEqual(before, after) {
						t.Fatal("cancel changed live configuration")
					}
				} else {
					changed := 0
					for name, content := range before {
						if after[name] != content {
							changed++
							if after[name] != content+"\n# operator edit\n" {
								t.Fatal("unreviewed content published")
							}
						}
					}
					if changed != 1 || len(after) != len(before) {
						t.Fatalf("publication changed %d files or changed inventory", changed)
					}
				}
				if _, err := os.Lstat(filepath.Dir(stage)); !os.IsNotExist(err) {
					t.Fatal("private working copy remains")
				}
			})
		}
	}
}
