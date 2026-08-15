package cmd

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestWhitelistCommandPropagatesEveryEntryFailure(t *testing.T) {
	_, current, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve whitelist source")
	}
	root, err := os.OpenRoot(filepath.Dir(current))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	content, err := root.ReadFile("whitelist.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(content)
	for _, required := range []string{"RunE:", "errors.Join(failures...)", "at least one IP address or CIDR is required"} {
		if !strings.Contains(source, required) {
			t.Fatalf("whitelist command lacks %q", required)
		}
	}
}
