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
