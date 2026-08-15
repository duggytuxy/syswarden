package firewall

import (
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestCanonicalHoneyPorts_SW_FW_004(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    string
		wantErr bool
	}{
		{name: "modular representation remains distinct", raw: "23 6379", want: "23, 6379"},
		{name: "legacy comma representation", raw: "23,6379", want: "23, 6379"},
		{name: "boundary ports", raw: "1 65535", want: "1, 65535"},
		{name: "concatenation regression", raw: "236379", wantErr: true},
		{name: "zero", raw: "0", wantErr: true},
		{name: "oversized", raw: "65536", wantErr: true},
		{name: "duplicate", raw: "23 23", wantErr: true},
		{name: "noncanonical duplicate", raw: "23 023", wantErr: true},
		{name: "leading zero", raw: "023", wantErr: true},
		{name: "empty item", raw: "23,,6379", wantErr: true},
		{name: "ambiguous empty list", raw: " , ", wantErr: true},
		{name: "shell syntax", raw: "23;6379", wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := canonicalHoneyPorts(test.raw)
			if (err != nil) != test.wantErr {
				t.Fatalf("canonicalHoneyPorts(%q) error = %v, wantErr %t", test.raw, err, test.wantErr)
			}
			if got != test.want {
				t.Fatalf("canonicalHoneyPorts(%q) = %q, want %q", test.raw, got, test.want)
			}
		})
	}
}

func TestPrivatePFConfig_SW_UPD_002(t *testing.T) {
	base := t.TempDir()
	path, cleanup, err := createPrivatePFConfig(base, []byte("block all\n"))
	if err != nil {
		t.Fatal(err)
	}
	parent := filepath.Dir(path)
	if parent == base || filepath.Dir(parent) != base {
		t.Fatalf("PF candidate directory %q is not a private child of %q", parent, base)
	}
	directoryInfo, err := os.Stat(parent)
	if err != nil {
		t.Fatal(err)
	}
	if directoryInfo.Mode().Perm() != 0700 {
		t.Fatalf("PF candidate directory mode = %04o, want 0700", directoryInfo.Mode().Perm())
	}
	root, err := os.OpenRoot(parent)
	if err != nil {
		t.Fatal(err)
	}
	file, err := root.Open(filepath.Base(path))
	if err != nil {
		_ = root.Close()
		t.Fatal(err)
	}
	content, err := io.ReadAll(file)
	_ = file.Close()
	_ = root.Close()
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "block all\n" {
		t.Fatalf("PF candidate content = %q", content)
	}
	if err := verifyPrivatePFConfig(path); err != nil {
		t.Fatalf("valid private PF candidate rejected: %v", err)
	}
	cleanup()
	if _, err := os.Lstat(parent); !os.IsNotExist(err) {
		t.Fatalf("private PF directory still exists after cleanup: %v", err)
	}
}

func TestPrivatePFConfigRejectsSymlinkAndNonRegular_SW_UPD_002(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.WriteFile(target, []byte("safe"), 0600); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(root, "candidate-link")
	if err := os.Symlink(target, symlink); err != nil {
		t.Fatal(err)
	}
	if err := verifyPrivatePFConfig(symlink); err == nil {
		t.Fatal("PF candidate verifier accepted a symlink")
	}
	directory := filepath.Join(root, "candidate-directory")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	if err := verifyPrivatePFConfig(directory); err == nil {
		t.Fatal("PF candidate verifier accepted a directory")
	}
}
