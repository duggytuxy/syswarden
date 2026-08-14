package system

import (
	"os"
	"strings"
	"testing"
)

func TestAuditLabelsDescribeBoundedObservations_SW_DOC_001(t *testing.T) {
	for _, path := range []string{"audit_linux.go", "audit_freebsd.go"} {
		content, err := os.ReadFile(path) // #nosec G304 -- paths are fixed repository test fixtures
		if err != nil {
			t.Fatal(err)
		}
		text := string(content)
		for _, forbidden := range []string{"Enterprise Full Audit", "[PASS]", "compliance certification or a complete kernel-state assessment" + " guaranteed"} {
			if strings.Contains(text, forbidden) {
				t.Fatalf("%s retains unsupported audit claim %q", path, forbidden)
			}
		}
		for _, required := range []string{"Local Operational Diagnostic", "[OBSERVED]", "not a compliance certification or a complete kernel-state assessment"} {
			if !strings.Contains(text, required) {
				t.Fatalf("%s omits bounded diagnostic wording %q", path, required)
			}
		}
	}
}
