package telemetry

import (
	"strings"
	"testing"
)

func TestReportedURIPathDropsQueryAndBoundsLength_SW_KPI_001(t *testing.T) {
	if got := reportedURIPath("/reset-password?token=RESET-TOKEN&email=jane%40example.com"); got != "/reset-password" {
		t.Fatalf("reported URI path = %q", got)
	}
	if got := reportedURIPath("/" + strings.Repeat("a", 200)); len([]rune(got)) != maxReportedURIPathLength {
		t.Fatalf("reported URI path length = %d", len([]rune(got)))
	}
	if got := reportedURIPath("?q=SELECT+*+FROM+orders"); got != "/" {
		t.Fatalf("reported URI path = %q", got)
	}
	if got := reportedURIPath("/a%3Fb"); got != "/a%3Fb" {
		t.Fatalf("reported URI path = %q", got)
	}
}
