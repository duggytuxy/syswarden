package security

import (
	"strings"
	"testing"
)

func TestLocalHardeningResultIsBounded_SW_DOC_001(t *testing.T) {
	for _, forbidden := range []string{"NIS2", "ISO27001", "ISO 27001", "compliant", "all kernel"} {
		if strings.Contains(strings.ToLower(localHardeningCheckOK), strings.ToLower(forbidden)) {
			t.Fatalf("local result retains unsupported claim %q: %s", forbidden, localHardeningCheckOK)
		}
	}
	for _, required := range []string{"selected local checks", "when readable", "when present", "Other settings were not evaluated"} {
		if !strings.Contains(localHardeningCheckOK, required) {
			t.Fatalf("local result omits scope boundary %q: %s", required, localHardeningCheckOK)
		}
	}
}

func TestRPFilterEnabledModes(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want bool
	}{
		{name: "disabled", raw: "0\n", want: false},
		{name: "strict", raw: "1\n", want: true},
		{name: "loose", raw: "2\n", want: true},
		{name: "loose with whitespace", raw: " 2 \n", want: true},
		{name: "empty", raw: "", want: false},
		{name: "invalid numeric", raw: "10\n", want: false},
		{name: "invalid text", raw: "enabled\n", want: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := rpFilterEnabled([]byte(test.raw)); got != test.want {
				t.Fatalf("rpFilterEnabled(%q) = %t, want %t", test.raw, got, test.want)
			}
		})
	}
}
