package platformpaths

import "testing"

func TestIsManagedCronLineRequiresExactGeneratedCommand(t *testing.T) {
	managed := []string{
		"*/30 * * * * " + CLI + " ha-sync >/dev/null 2>&1",
		"17 * * * * " + CLI + " update-feeds >/dev/null 2>&1",
	}
	for _, line := range managed {
		if !IsManagedCronLine(line) {
			t.Fatalf("managed cron line rejected: %q", line)
		}
	}

	unrelated := []string{
		"# operator note mentioning syswarden-cli",
		"17 3 * * * /usr/local/sbin/my-syswarden-cli-helper",
		"17 * * * * " + CLI + " update-feeds --operator-option >/dev/null 2>&1",
		"17 * * * * /usr/local/bin/syswarden update-feeds >/dev/null 2>&1",
		"00 * * * * " + CLI + " update-feeds >/dev/null 2>&1",
	}
	for _, line := range unrelated {
		if IsManagedCronLine(line) {
			t.Fatalf("unrelated cron line accepted: %q", line)
		}
	}
}
