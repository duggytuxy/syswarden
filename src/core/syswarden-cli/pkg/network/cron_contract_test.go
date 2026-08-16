package network

import (
	"errors"
	"os/exec"
	"strings"
	"testing"

	"syswarden-cli/pkg/platformpaths"
)

func mustCron(t *testing.T, content string, err error) string {
	t.Helper()
	if err != nil {
		t.Fatalf("build crontab: %v", err)
	}
	return content
}

func mustHACron(t *testing.T, existing string, enabled bool) string {
	t.Helper()
	content, err := buildHACrontab(existing, enabled)
	return mustCron(t, content, err)
}

func mustFeedsCron(t *testing.T, existing string, minute int) string {
	t.Helper()
	content, err := buildFeedsCrontab(existing, minute)
	return mustCron(t, content, err)
}

func TestCronBuildersReconcileOnlyTheirOwnedJob(t *testing.T) {
	operatorBackup := "15 2 * * * /usr/local/bin/operator-backup --keep-syswarden-cli"
	operatorFeedLookalike := "17 * * * * " + platformpaths.CLI + " update-feeds --operator-option >/dev/null 2>&1"
	operatorHALookalike := "*/30 * * * * " + platformpaths.CLI + " ha-sync --operator-option >/dev/null 2>&1"
	operatorWhitespaceFeed := "17  * * * * " + platformpaths.CLI + " update-feeds >/dev/null 2>&1"
	operatorWhitespaceHA := "*/30\t* * * * " + platformpaths.CLI + " ha-sync >/dev/null 2>&1"
	feed17 := "17 * * * * " + platformpaths.CLI + " update-feeds >/dev/null 2>&1"
	feed41 := "41 * * * * " + platformpaths.CLI + " update-feeds >/dev/null 2>&1"
	ha := "*/30 * * * * " + platformpaths.CLI + " ha-sync >/dev/null 2>&1"

	existing := strings.Join([]string{
		operatorBackup,
		"",
		" \t ",
		operatorFeedLookalike,
		operatorHALookalike,
		operatorWhitespaceFeed,
		operatorWhitespaceHA,
		feed17,
		ha,
		feed41,
		ha,
	}, "\n") + "\n"

	wantHAOff := strings.Join([]string{
		operatorBackup,
		"",
		" \t ",
		operatorFeedLookalike,
		operatorHALookalike,
		operatorWhitespaceFeed,
		operatorWhitespaceHA,
		feed17,
		feed41,
	}, "\n") + "\n"
	if got := mustHACron(t, existing, false); got != wantHAOff {
		t.Fatalf("HA-disabled crontab:\n%s\nwant:\n%s", got, wantHAOff)
	}

	wantHAOn := wantHAOff + ha + "\n"
	if got := mustHACron(t, existing, true); got != wantHAOn {
		t.Fatalf("HA-enabled crontab:\n%s\nwant:\n%s", got, wantHAOn)
	}

	wantFeeds := strings.Join([]string{
		operatorBackup,
		"",
		" \t ",
		operatorFeedLookalike,
		operatorHALookalike,
		operatorWhitespaceFeed,
		operatorWhitespaceHA,
		ha,
		ha,
		"23 * * * * " + platformpaths.CLI + " update-feeds >/dev/null 2>&1",
	}, "\n") + "\n"
	if got := mustFeedsCron(t, existing, 23); got != wantFeeds {
		t.Fatalf("feeds crontab:\n%s\nwant:\n%s", got, wantFeeds)
	}

	wantInstallHAOff := strings.Join([]string{
		operatorBackup,
		"",
		" \t ",
		operatorFeedLookalike,
		operatorHALookalike,
		operatorWhitespaceFeed,
		operatorWhitespaceHA,
		"23 * * * * " + platformpaths.CLI + " update-feeds >/dev/null 2>&1",
	}, "\n") + "\n"
	feeds := mustFeedsCron(t, existing, 23)
	if got := mustHACron(t, feeds, false); got != wantInstallHAOff {
		t.Fatalf("feeds then HA-disabled crontab:\n%s\nwant:\n%s", got, wantInstallHAOff)
	}

	wantInstallHAOn := wantInstallHAOff + ha + "\n"
	if got := mustHACron(t, feeds, true); got != wantInstallHAOn {
		t.Fatalf("feeds then HA-enabled crontab:\n%s\nwant:\n%s", got, wantInstallHAOn)
	}
}

func TestCronBuildersPreserveRecordTerminatorsAndRejectUnsafeAppend(t *testing.T) {
	operator := "MAILTO=operator@example.invalid\n \t \n15 2 * * * /usr/local/bin/operator-backup"
	if got := mustHACron(t, operator, false); got != operator {
		t.Fatalf("HA-disabled unterminated operator bytes = %q, want %q", got, operator)
	}
	if _, err := buildHACrontab(operator, true); !errors.Is(err, platformpaths.ErrUnterminatedOperatorCronRecord) {
		t.Fatalf("HA append after unterminated operator = %v", err)
	}
	if _, err := buildFeedsCrontab(operator, 23); !errors.Is(err, platformpaths.ErrUnterminatedOperatorCronRecord) {
		t.Fatalf("feed append after unterminated operator = %v", err)
	}

	ha := "*/30 * * * * " + platformpaths.CLI + " ha-sync >/dev/null 2>&1"
	operatorBeforeHA := operator + "\n" + ha
	if got := mustHACron(t, operatorBeforeHA, false); got != operator+"\n" {
		t.Fatalf("terminated operator record lost its LF: %q", got)
	}

	terminated := operator + "\n"
	wantHA := terminated + ha + "\n"
	if got := mustHACron(t, terminated, true); got != wantHA {
		t.Fatalf("HA append to terminated crontab = %q, want %q", got, wantHA)
	}
}

func TestRootCrontabUpdateDistinguishesAbsenceAndFailsClosed(t *testing.T) {
	t.Run("read failure prevents write", func(t *testing.T) {
		readCommand := exec.Command("/bin/sh", "-c", "exit 1")
		writeCommand := exec.Command("/bin/sh", "-c", "exit 0")
		err := updateRootCrontab(readCommand, writeCommand, func(existing string) (string, error) {
			return existing + "replacement\n", nil
		})
		if err == nil || !strings.Contains(err.Error(), "failed to read root crontab") {
			t.Fatalf("read failure = %v", err)
		}
		if writeCommand.ProcessState != nil {
			t.Fatal("crontab write executed after a read failure")
		}
	})

	absenceCommands := []struct {
		name    string
		command *exec.Cmd
	}{
		{name: "Vixie message", command: exec.Command("/bin/sh", "-c", "printf '%s\\n' 'no crontab for root' >&2; exit 1")},
		{name: "prefixed message", command: exec.Command("/bin/sh", "-c", "printf '%s\\n' 'crontab: no crontab for root' >&2; exit 1")},
		{name: "BusyBox message", command: exec.Command("/bin/sh", "-c", "printf '%s\\n' \"crontab: can't open 'root': No such file or directory\" >&2; exit 1")},
	}
	for _, testCase := range absenceCommands {
		t.Run("confirmed absence "+testCase.name, func(t *testing.T) {
			writeCommand := exec.Command("/bin/sh", "-c", "exit 0")
			if err := updateRootCrontab(testCase.command, writeCommand, func(existing string) (string, error) {
				if existing != "" {
					t.Fatalf("absent crontab read as %q", existing)
				}
				return "replacement\n", nil
			}); err != nil {
				t.Fatalf("confirmed absence rejected: %v", err)
			}
			if writeCommand.ProcessState == nil || !writeCommand.ProcessState.Success() {
				t.Fatal("confirmed absence did not reach the crontab write")
			}
		})
	}

	t.Run("successful read excludes stderr", func(t *testing.T) {
		readCommand := exec.Command(
			"/bin/sh",
			"-c",
			"printf '%s\\n' '15 2 * * * /usr/local/bin/operator-backup'; printf '%s\\n' 'warning from crontab' >&2",
		)
		got, present, err := readRootCrontab(readCommand)
		if err != nil {
			t.Fatalf("successful crontab read: %v", err)
		}
		if !present {
			t.Fatal("successful crontab read was classified as absent")
		}
		want := "15 2 * * * /usr/local/bin/operator-backup\n"
		if got != want {
			t.Fatalf("crontab stdout = %q, want %q", got, want)
		}
	})

	t.Run("write failure propagates", func(t *testing.T) {
		readCommand := exec.Command("/bin/sh", "-c", "printf '%s\\n' '15 2 * * * /usr/local/bin/operator-backup'")
		writeCommand := exec.Command("/bin/sh", "-c", "exit 1")
		err := updateRootCrontab(readCommand, writeCommand, func(existing string) (string, error) {
			return existing + "replacement\n", nil
		})
		if err == nil || !strings.Contains(err.Error(), "failed to write root crontab") {
			t.Fatalf("write failure = %v", err)
		}
	})

	for _, testCase := range []struct {
		name    string
		command *exec.Cmd
	}{
		{name: "leading whitespace", command: exec.Command("/bin/sh", "-c", "printf '%s\\n' ' no crontab for root' >&2; exit 1")},
		{name: "trailing whitespace", command: exec.Command("/bin/sh", "-c", "printf '%s\\n' 'no crontab for root ' >&2; exit 1")},
		{name: "extra diagnostic", command: exec.Command("/bin/sh", "-c", "printf '%s\\n' 'no crontab for root' 'extra' >&2; exit 1")},
		{name: "wrong exit code", command: exec.Command("/bin/sh", "-c", "printf '%s\\n' 'no crontab for root' >&2; exit 2")},
		{name: "partial stdout", command: exec.Command("/bin/sh", "-c", "printf partial; printf '%s\\n' 'no crontab for root' >&2; exit 1")},
	} {
		t.Run("reject "+testCase.name, func(t *testing.T) {
			writeCommand := exec.Command("/bin/sh", "-c", "exit 0")
			err := updateRootCrontab(testCase.command, writeCommand, func(existing string) (string, error) {
				return "replacement\n", nil
			})
			if err == nil {
				t.Fatal("invalid absence evidence was accepted")
			}
			if writeCommand.ProcessState != nil {
				t.Fatal("write executed after invalid absence evidence")
			}
		})
	}

	t.Run("unchanged transformation skips write", func(t *testing.T) {
		readCommand := exec.Command("/bin/sh", "-c", "printf operator")
		writeCommand := exec.Command("/bin/sh", "-c", "exit 0")
		if err := updateRootCrontab(readCommand, writeCommand, func(existing string) (string, error) {
			return existing, nil
		}); err != nil {
			t.Fatalf("unchanged transformation: %v", err)
		}
		if writeCommand.ProcessState != nil {
			t.Fatal("unchanged crontab was rewritten")
		}
	})
}
