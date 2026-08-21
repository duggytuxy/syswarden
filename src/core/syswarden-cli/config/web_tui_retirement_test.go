package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRemoveRetiredWebTUIConfigurationIsExactAtomicAndIdempotent(t *testing.T) {
	root := filepath.Join(t.TempDir(), "config")
	modules := filepath.Join(root, "modules")
	if err := os.MkdirAll(modules, 0750); err != nil {
		t.Fatal(err)
	}
	masterPath := filepath.Join(root, "config.toml")
	modulePath := filepath.Join(modules, "99-user.toml")
	master := "# keep master bytes\nuser.webtui_password = \"master-secret\"\n[core]\nfirewall_backend = \"keep\"\n"
	module := "# keep operator comment\n[user]\nwebtui_password = \"module-secret\"\nprofile_name = \"production\" # keep inline comment\n\n[future]\nwebtui_password = \"unrelated-key\"\n"
	if err := os.WriteFile(masterPath, []byte(master), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(modulePath, []byte(module), 0640); err != nil { // #nosec G306 -- deliberate fixture mode verifies exact owner/group preservation
		t.Fatal(err)
	}

	if err := RemoveRetiredWebTUIConfiguration(root); err != nil {
		t.Fatal(err)
	}
	wantMaster := "# keep master bytes\n[core]\nfirewall_backend = \"keep\"\n"
	wantModule := "# keep operator comment\n[user]\nprofile_name = \"production\" # keep inline comment\n\n[future]\nwebtui_password = \"unrelated-key\"\n"
	assertFileContent(t, masterPath, wantMaster)
	assertFileContent(t, modulePath, wantModule)
	info, err := os.Lstat(modulePath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0640 {
		t.Fatalf("cleaned operator module mode = %#o, want 0640", info.Mode().Perm())
	}
	firstInfo := info
	if err := RemoveRetiredWebTUIConfiguration(root); err != nil {
		t.Fatal(err)
	}
	secondInfo, err := os.Lstat(modulePath)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(firstInfo, secondInfo) {
		t.Fatal("idempotent cleanup replaced an already clean inode")
	}
}

func TestRemoveRetiredWebTUIConfigurationPublishFailurePreservesSecretWithoutDisclosingIt(t *testing.T) {
	root := filepath.Join(t.TempDir(), "config")
	modules := filepath.Join(root, "modules")
	if err := os.MkdirAll(modules, 0750); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(modules, "99-user.toml")
	const secret = "sentinel-secret-must-not-be-logged"
	content := "[user]\nwebtui_password = \"" + secret + "\"\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	previous := publishRetiredWebTUI
	publishRetiredWebTUI = func(string, string, []byte, *secureFileIdentity) error {
		return errors.New("injected publish failure")
	}
	t.Cleanup(func() { publishRetiredWebTUI = previous })

	err := RemoveRetiredWebTUIConfiguration(root)
	if err == nil || !strings.Contains(err.Error(), "injected publish failure") {
		t.Fatalf("cleanup publish error = %v", err)
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("cleanup error disclosed retired secret: %v", err)
	}
	assertFileContent(t, path, content)
}

func TestRemoveRetiredWebTUIConfigurationRejectsSymlinkedModules(t *testing.T) {
	root := filepath.Join(t.TempDir(), "config")
	if err := os.MkdirAll(root, 0750); err != nil {
		t.Fatal(err)
	}
	victim := t.TempDir()
	if err := os.Symlink(victim, filepath.Join(root, "modules")); err != nil {
		t.Fatal(err)
	}
	if err := RemoveRetiredWebTUIConfiguration(root); err == nil {
		t.Fatal("cleanup accepted a symlinked modules directory")
	}
}

func TestRemoveRetiredWebTUIConfigurationRetiresStrictQuotedDottedAndInlineForms(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "quoted dotted assignment",
			in:   "# keep\n\"user\".\"webtui_password\" = \"secret\"\n[core]\nlog_level = \"INFO\"\n",
			want: "# keep\n[core]\nlog_level = \"INFO\"\n",
		},
		{
			name: "escaped quoted dotted assignment",
			in:   "user.\"webtui_\\u0070assword\" = \"secret\"\n[core]\nlog_level = \"INFO\"\n",
			want: "[core]\nlog_level = \"INFO\"\n",
		},
		{
			name: "quoted table assignment",
			in:   "[\"user\"]\n\"webtui_password\" = \"secret\"\nprofile_name = \"operator\"\n",
			want: "[\"user\"]\nprofile_name = \"operator\"\n",
		},
		{
			name: "inline first",
			in:   "# keep bytes\nuser = { webtui_password = \"secret\", profile_name = \"operator\" } # keep comment\n",
			want: "# keep bytes\nuser = {  profile_name = \"operator\" } # keep comment\n",
		},
		{
			name: "inline last",
			in:   "user = { profile_name = \"operator\", \"webtui_password\" = \"secret\" }\n",
			want: "user = { profile_name = \"operator\"}\n",
		},
		{
			name: "inline only",
			in:   "user = { webtui_password = \"secret\" }\n",
			want: "user = { }\n",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "config")
			if err := os.MkdirAll(filepath.Join(root, "modules"), 0750); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(root, "config.toml")
			if err := os.WriteFile(path, []byte(test.in), 0600); err != nil {
				t.Fatal(err)
			}
			if err := RemoveRetiredWebTUIConfiguration(root); err != nil {
				t.Fatal(err)
			}
			assertFileContent(t, path, test.want)
		})
	}
}

func TestRemoveRetiredWebTUIConfigurationPreflightsEveryFileBeforePublishing(t *testing.T) {
	root := filepath.Join(t.TempDir(), "config")
	modules := filepath.Join(root, "modules")
	if err := os.MkdirAll(modules, 0750); err != nil {
		t.Fatal(err)
	}
	masterPath := filepath.Join(root, "config.toml")
	modulePath := filepath.Join(modules, "99-user.toml")
	master := "user.webtui_password = \"master-secret\"\n"
	// This is valid TOML and semantically contains user.webtui_password, but
	// deleting the whole dotted subtree would not be an exact credential-only
	// rewrite. Cleanup must reject it before publishing the master rewrite.
	unsupported := "user = { webtui_password.nested = \"module-secret\" }\n"
	if err := os.WriteFile(masterPath, []byte(master), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(modulePath, []byte(unsupported), 0600); err != nil {
		t.Fatal(err)
	}
	err := RemoveRetiredWebTUIConfiguration(root)
	if err == nil || !strings.Contains(err.Error(), "unique byte-exact TOML representation") {
		t.Fatalf("unsupported exact rewrite error = %v", err)
	}
	assertFileContent(t, masterPath, master)
	assertFileContent(t, modulePath, unsupported)
}
