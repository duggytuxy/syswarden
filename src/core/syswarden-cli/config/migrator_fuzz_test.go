package config

import (
	"reflect"
	"strings"
	"testing"
)

const maxLegacyConfigFuzzBytes = 32 * 1024

func FuzzMigratorParseFromMemory(f *testing.F) {
	seeds := []string{
		"",
		"# comment\nSYSWARDEN_SSH_PORT=\"2222\"\n",
		"KEY_ONE='value'\nKEY_TWO=second # comment\n",
		"INVALID\n=ignored\nDUPLICATE=first\nDUPLICATE=second\n",
		"SPACED = value with spaces\nQUOTED=\"unterminated\n",
		"BINARY=\x00\xff\n",
	}
	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, content string) {
		if len(content) > maxLegacyConfigFuzzBytes {
			t.Skip()
		}

		migrator := &Migrator{}
		first, firstErr := migrator.ParseFromMemory(content)
		second, secondErr := migrator.ParseFromMemory(content)
		if errorText(firstErr) != errorText(secondErr) {
			t.Fatalf("ParseFromMemory() is not deterministic: first error %v, second error %v", firstErr, secondErr)
		}
		if !reflect.DeepEqual(first, second) {
			t.Fatalf("ParseFromMemory() is not deterministic: first %#v, second %#v", first, second)
		}

		for key, value := range first {
			if key == "" || key != strings.TrimSpace(key) {
				t.Fatalf("parser returned a non-canonical key %q", key)
			}
			if value != strings.TrimSpace(value) {
				t.Fatalf("parser returned a non-canonical value for %q: %q", key, value)
			}
			if strings.Contains(value, "#") {
				t.Fatalf("parser retained an inline comment for %q: %q", key, value)
			}
		}
	})
}

func errorText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
