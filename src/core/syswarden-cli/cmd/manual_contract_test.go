package cmd

import (
	"strings"
	"testing"
)

func TestManualDescribesHAValidationRollbackContract_SW_DOC_001(t *testing.T) {
	for _, required := range []string{"non-empty bearer token", "configuration validation", "previous valid configuration active"} {
		if !strings.Contains(haAuthenticationManualContract, required) {
			t.Fatalf("HA token manual contract omits %q: %s", required, haAuthenticationManualContract)
		}
	}
	if strings.Contains(haAuthenticationManualContract, "listener from starting") {
		t.Fatalf("HA token manual contract retains the obsolete listener claim: %s", haAuthenticationManualContract)
	}
}
