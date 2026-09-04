package config

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseConfigLoggingContract(t *testing.T) {
	previousConfig := GlobalConfig
	previousState := CurrentLoadState()
	previousLogOutput := log.Writer()
	t.Cleanup(func() {
		log.SetOutput(previousLogOutput)
		GlobalConfig = previousConfig
		loadStateMu.Lock()
		loadState = previousState
		loadStateMu.Unlock()
	})

	var logs bytes.Buffer
	log.SetOutput(&logs)

	modularRoot := filepath.Join(t.TempDir(), "config")
	if err := EnsureDefaults(modularRoot); err != nil {
		t.Fatal(err)
	}
	logs.Reset()
	if err := ParseConfig(modularRoot); err != nil {
		t.Fatalf("ParseConfig() modular error = %v", err)
	}
	if got := logs.String(); got != "" {
		t.Fatalf("normal modular load emitted a log message: %q", got)
	}
	if GlobalConfig == nil || GlobalConfig.FirewallBackend != "keep" {
		t.Fatalf("modular configuration was not loaded: %#v", GlobalConfig)
	}
	if state := CurrentLoadState(); state.Degraded || state.Source != modularRoot {
		t.Fatalf("modular load state = %#v", state)
	}

	legacyPath := filepath.Join(t.TempDir(), "syswarden-auto.conf")
	if err := os.WriteFile(legacyPath, []byte(DefaultConfig), 0600); err != nil {
		t.Fatal(err)
	}
	logs.Reset()
	if err := ParseConfig(legacyPath); err != nil {
		t.Fatalf("ParseConfig() legacy error = %v", err)
	}
	got := logs.String()
	for _, want := range []string{
		"[WARNING] Using old flat configuration format (deprecated)",
		"Please run 'syswarden migrate-config' to migrate to the new modular TOML format.",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("legacy log %q does not contain %q", got, want)
		}
	}
	if strings.Contains(got, "[INFO] Using new modular TOML configuration format") {
		t.Fatalf("legacy load emitted the retired modular INFO message: %q", got)
	}
}
