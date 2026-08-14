package webhook

import (
	"strings"
	"testing"
)

func TestLocalCheckWebhookPresentation_SW_DOC_001(t *testing.T) {
	for _, status := range []string{"OK", "DRIFT"} {
		title, _ := localCheckAlertPresentation(status)
		if !strings.Contains(title, "Local Check") || strings.Contains(title, "Compliance") {
			t.Fatalf("status %s produced unsupported title %q", status, title)
		}
	}
}
