package config

import (
	"encoding/base64"
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
		"HASH_LITERAL=#\nHASH_FRAGMENT=value#fragment\nQUOTED_HASH=\"#tag\"\n",
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

		for key := range first {
			if key == "" || key != strings.TrimSpace(key) {
				t.Fatalf("parser returned a non-canonical key %q", key)
			}
		}

		encoded := "v" + base64.RawStdEncoding.EncodeToString([]byte(content))
		withComment, err := migrator.ParseFromMemory(
			"FUZZ_UNQUOTED=   " + encoded + "   # inline comment\n" +
				"FUZZ_QUOTED=\"  " + encoded + "  \" # inline comment\n",
		)
		if err != nil {
			t.Fatalf("parse inline-comment probes: %v", err)
		}
		if got := withComment["FUZZ_UNQUOTED"]; got != encoded {
			t.Fatalf("unquoted inline-comment probe = %q, want %q", got, encoded)
		}
		if got, want := withComment["FUZZ_QUOTED"], "  "+encoded+"  "; got != want {
			t.Fatalf("quoted inline-comment probe = %q, want %q", got, want)
		}
	})
}

func errorText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
