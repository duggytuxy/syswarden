//go:build linux

package logger

import (
	"bytes"
	"os"
	"path/filepath"
	"syswarden-core/fileorigin"
	"testing"
)

func TestProductLogCreationAndCompactionPreserveOriginBoundary(t *testing.T) {
	for _, owned := range []bool{false, true} {
		t.Run(map[bool]string{false: "legacy-unmarked", true: "new-owned"}[owned], func(t *testing.T) {
			directory := t.TempDir()
			path := filepath.Join(directory, "waf.json.1")
			root, err := os.OpenRoot(directory)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = root.Close() }()
			var file *os.File
			if owned {
				file, err = openAppendProductLog(path, fileorigin.TelemetryLog)
			} else {
				file, err = root.OpenFile("waf.json.1", os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			content := bytes.Repeat([]byte("{\"synthetic\":true}\n"), 30)
			if _, err := file.Write(content); err != nil {
				t.Fatal(err)
			}
			if err := file.Close(); err != nil {
				t.Fatal(err)
			}
			if err := compactTelemetryGenerationTail(path, 160); err != nil {
				t.Fatal(err)
			}
			saved, err := root.Open("waf.json.1")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = saved.Close() }()
			present, err := fileorigin.HasLogOrigin(saved, fileorigin.TelemetryLog)
			if err != nil || present != owned {
				t.Fatal("compaction changed the origin boundary", present, err)
			}
		})
	}
}

func TestCoreProcessLogReopenDoesNotAdoptExistingFile(t *testing.T) {
	directory := t.TempDir()
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	if err := root.WriteFile("existing", []byte("Administrator retained data.\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"existing", "new"} {
		file, err := OpenCoreProcessLog(filepath.Join(directory, name))
		if err != nil {
			t.Fatal(err)
		}
		present, err := fileorigin.HasLogOrigin(file, fileorigin.CoreLog)
		_ = file.Close()
		if err != nil || present != (name == "new") {
			t.Fatal("core log origin was assigned incorrectly", name, present, err)
		}
	}
}
