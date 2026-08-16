package platformpaths

import (
	"errors"
	"strings"
	"testing"
)

func TestReconcileCronRecordsPreservesOperatorBytesAndTerminators(t *testing.T) {
	managed := "*/30 * * * * " + CLI + " ha-sync >/dev/null 2>&1"
	operator := "MAILTO=operator@example.invalid\n\n \t \n15 2 * * * /usr/local/bin/operator"
	withoutManaged := operator + "\n" + managed

	filtered, err := ReconcileCronRecords(withoutManaged, IsManagedHACronLine, "")
	if err != nil {
		t.Fatal(err)
	}
	if filtered != operator+"\n" {
		t.Fatalf("filtered records = %q, want %q", filtered, operator+"\n")
	}
	unchanged, err := ReconcileCronRecords(operator, IsManagedHACronLine, "")
	if err != nil || unchanged != operator {
		t.Fatalf("unterminated operator content = %q, %v", unchanged, err)
	}
	if _, err := ReconcileCronRecords(operator, IsManagedHACronLine, managed); !errors.Is(err, ErrUnterminatedOperatorCronRecord) {
		t.Fatalf("unsafe append error = %v", err)
	}
	terminated := operator + "\n"
	appended, err := ReconcileCronRecords(terminated, IsManagedHACronLine, managed)
	if err != nil || appended != terminated+managed+"\n" {
		t.Fatalf("safe append = %q, %v", appended, err)
	}
}

func TestIsManagedCronLineRequiresExactGeneratedCommand(t *testing.T) {
	haLine := "*/30 * * * * " + CLI + " ha-sync >/dev/null 2>&1"
	feedLine := "17 * * * * " + CLI + " update-feeds >/dev/null 2>&1"
	managed := []struct {
		line string
		ha   bool
		feed bool
	}{
		{line: haLine, ha: true},
		{line: feedLine, feed: true},
	}
	for _, testCase := range managed {
		if !IsManagedCronLine(testCase.line) {
			t.Fatalf("managed cron line rejected: %q", testCase.line)
		}
		if got := IsManagedHACronLine(testCase.line); got != testCase.ha {
			t.Fatalf("HA classification for %q = %t, want %t", testCase.line, got, testCase.ha)
		}
		if got := IsManagedFeedCronLine(testCase.line); got != testCase.feed {
			t.Fatalf("feed classification for %q = %t, want %t", testCase.line, got, testCase.feed)
		}
	}

	unrelated := []string{
		"# operator note mentioning syswarden-cli",
		"17 3 * * * /usr/local/sbin/my-syswarden-cli-helper",
		"17 * * * * " + CLI + " update-feeds --operator-option >/dev/null 2>&1",
		"17 * * * * /usr/local/bin/syswarden update-feeds >/dev/null 2>&1",
		"00 * * * * " + CLI + " update-feeds >/dev/null 2>&1",
		" " + haLine,
		haLine + " ",
		strings.Replace(haLine, "*/30 *", "*/30\t*", 1),
		strings.Replace(feedLine, "17 *", "17  *", 1),
	}
	for _, line := range unrelated {
		if IsManagedCronLine(line) || IsManagedHACronLine(line) || IsManagedFeedCronLine(line) {
			t.Fatalf("unrelated cron line accepted: %q", line)
		}
	}
}
