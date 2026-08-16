package system

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"syswarden-cli/pkg/platformpaths"
)

func TestAbsentRootCronSpoolRejectsExistingFilesAndLinks(t *testing.T) {
	root := t.TempDir()
	missing := filepath.Join(root, "missing")
	if err := verifyAbsentRootCronSpool(missing); err != nil {
		t.Fatalf("missing spool rejected: %v", err)
	}
	regular := filepath.Join(root, "root")
	if err := os.WriteFile(regular, []byte("operator cron\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := verifyAbsentRootCronSpool(regular); err == nil {
		t.Fatal("existing root spool file was accepted as absent")
	}
	link := filepath.Join(root, "root-link")
	if err := os.Symlink(regular, link); err != nil {
		t.Fatal(err)
	}
	if err := verifyAbsentRootCronSpool(link); err == nil {
		t.Fatal("root spool symlink was accepted as absent")
	}
}

func TestManagedRootCronFilterPreservesOperatorBytesAndLF(t *testing.T) {
	ha := "*/30 * * * * " + platformpaths.CLI + " ha-sync >/dev/null 2>&1"
	feed := "17 * * * * " + platformpaths.CLI + " update-feeds >/dev/null 2>&1"
	comment := "# operator note mentioning syswarden-cli"
	leading := " " + feed
	trailing := ha + " "
	doubleSpace := strings.Replace(feed, "17 *", "17  *", 1)
	tab := strings.Replace(ha, "*/30 *", "*/30\t*", 1)
	operator := "19 4 * * * " + platformpaths.CLI + " update-feeds --operator-option"
	whitespaceOnly := " \t "
	alternatePlatform := "23 * * * * /usr/local/syswarden/bin/syswarden-cli update-feeds >/dev/null 2>&1"
	if runtime.GOOS == "freebsd" {
		alternatePlatform = "23 * * * * /opt/syswarden/bin/syswarden-cli update-feeds >/dev/null 2>&1"
	}

	survivors := []string{
		comment,
		leading,
		trailing,
		doubleSpace,
		tab,
		operator,
		whitespaceOnly,
	}
	inputLines := []string{
		comment,
		ha,
		leading,
		feed,
		trailing,
		doubleSpace,
		tab,
		operator,
		whitespaceOnly,
	}
	if !platformpaths.IsManagedCronLine(alternatePlatform) {
		survivors = append(survivors, alternatePlatform)
	}
	inputLines = append(inputLines, alternatePlatform)
	want := strings.Join(survivors, "\n")

	for _, finalLF := range []bool{false, true} {
		name := "without final LF"
		input := strings.Join(inputLines, "\n")
		expected := want
		if finalLF {
			name = "with final LF"
			input += "\n"
			expected += "\n"
		}
		t.Run(name, func(t *testing.T) {
			if got := filterManagedRootCrontab(input); got != expected {
				t.Fatalf("filtered crontab = %q, want %q", got, expected)
			}
		})
	}

	for _, onlyManaged := range []string{ha, ha + "\n", feed, feed + "\n"} {
		if got := filterManagedRootCrontab(onlyManaged); got != "" {
			t.Fatalf("managed-only crontab filtered to %q", got)
		}
	}
	operatorBeforeUnterminatedManaged := operator + "\n" + feed
	if got := filterManagedRootCrontab(operatorBeforeUnterminatedManaged); got != operator+"\n" {
		t.Fatalf("terminated operator record lost its LF: %q", got)
	}
}

func TestRootCrontabReadDistinguishesAbsenceFromErrors(t *testing.T) {
	absenceCommands := []struct {
		name    string
		command *exec.Cmd
	}{
		{name: "Debian or Cronie", command: exec.Command("/bin/sh", "-c", "printf '%s\\n' 'no crontab for root' >&2; exit 1")},
		{name: "FreeBSD", command: exec.Command("/bin/sh", "-c", "printf '%s\\n' 'crontab: no crontab for root' >&2; exit 1")},
		{name: "BusyBox", command: exec.Command("/bin/sh", "-c", "printf '%s\\n' \"crontab: can't open 'root': No such file or directory\" >&2; exit 1")},
	}
	for _, testCase := range absenceCommands {
		t.Run(testCase.name, func(t *testing.T) {
			content, present, err := readRootCrontab(testCase.command)
			if err != nil || present || content != "" {
				t.Fatalf("confirmed absence = %q, present=%t, %v", content, present, err)
			}
		})
	}

	errorCommands := []struct {
		name    string
		command *exec.Cmd
	}{
		{name: "unexpected exit one", command: exec.Command("/bin/sh", "-c", "printf '%s\\n' 'permission denied' >&2; exit 1")},
		{name: "absence plus diagnostic", command: exec.Command("/bin/sh", "-c", "printf '%s\\n' 'no crontab for root' 'extra diagnostic' >&2; exit 1")},
		{name: "leading space", command: exec.Command("/bin/sh", "-c", "printf '%s\\n' ' no crontab for root' >&2; exit 1")},
		{name: "trailing space", command: exec.Command("/bin/sh", "-c", "printf '%s\\n' 'no crontab for root ' >&2; exit 1")},
		{name: "wrong exit with exact absence", command: exec.Command("/bin/sh", "-c", "printf '%s\\n' 'no crontab for root' >&2; exit 2")},
		{name: "partial stdout with exact absence", command: exec.Command("/bin/sh", "-c", "printf partial; printf '%s\\n' 'no crontab for root' >&2; exit 1")},
		{name: "exit two", command: exec.Command("/bin/sh", "-c", "exit 2")},
		{name: "missing binary", command: exec.Command("/syswarden-test/missing-crontab")},
		{name: "partial stdout", command: exec.Command("/bin/sh", "-c", "printf '%s\\n' '15 2 * * * /usr/local/bin/operator'; exit 1")},
	}
	for _, testCase := range errorCommands {
		t.Run(testCase.name, func(t *testing.T) {
			if _, _, err := readRootCrontab(testCase.command); err == nil {
				t.Fatal("material crontab read error was accepted")
			}
		})
	}

	command := exec.Command(
		"/bin/sh",
		"-c",
		"printf '%s\\n' '15 2 * * * /usr/local/bin/operator'; printf '%s\\n' warning >&2",
	)
	content, present, err := readRootCrontab(command)
	if err != nil || !present || content != "15 2 * * * /usr/local/bin/operator\n" {
		t.Fatalf("successful stdout-only crontab read = %q, present=%t, %v", content, present, err)
	}
	empty, present, err := readRootCrontab(exec.Command("/bin/sh", "-c", "exit 0"))
	if err != nil || !present || empty != "" {
		t.Fatalf("successful empty crontab = %q, present=%t, %v", empty, present, err)
	}
}

func TestManagedRootCronRemovalFailsClosed(t *testing.T) {
	t.Run("read failure prevents write", func(t *testing.T) {
		readCommand := exec.Command("/bin/sh", "-c", "exit 2")
		writeCommand := exec.Command("/bin/sh", "-c", "exit 0")
		if err := removeManagedRootCron(readCommand, writeCommand); err == nil {
			t.Fatal("read failure was accepted")
		}
		if writeCommand.ProcessState != nil {
			t.Fatal("write executed after read failure")
		}
	})

	t.Run("absence does not create crontab", func(t *testing.T) {
		readCommand := exec.Command("/bin/sh", "-c", "printf '%s\\n' 'no crontab for root' >&2; exit 1")
		writeCommand := exec.Command("/bin/sh", "-c", "exit 0")
		if err := removeManagedRootCron(readCommand, writeCommand); err != nil {
			t.Fatalf("confirmed absence: %v", err)
		}
		if writeCommand.ProcessState != nil {
			t.Fatal("absence created an empty crontab")
		}
	})

	t.Run("write failure propagates", func(t *testing.T) {
		readCommand := exec.Command(
			"/bin/sh",
			"-c",
			"printf '%s\\n' '17 * * * * /opt/syswarden/bin/syswarden-cli update-feeds >/dev/null 2>&1' '19 4 * * * /usr/local/bin/operator'",
		)
		writeCommand := exec.Command("/bin/sh", "-c", "exit 1")
		if err := removeManagedRootCron(readCommand, writeCommand); err == nil {
			t.Fatal("crontab write failure was accepted")
		}
	})
}

func TestManagedOnlyRootCrontabIsRemovedAndAbsenceVerified(t *testing.T) {
	managed := "17 * * * * " + platformpaths.CLI + " update-feeds >/dev/null 2>&1\n"

	t.Run("remove and verify absence", func(t *testing.T) {
		marker := filepath.Join(t.TempDir(), "removed")
		writeCommand := exec.Command("/bin/sh", "-c", "exit 91")
		removeCommand := exec.Command("/bin/sh", "-c", "printf removed > \"$SYSWARDEN_TEST_MARKER\"")
		removeCommand.Env = append(os.Environ(), "SYSWARDEN_TEST_MARKER="+marker)
		verifyCommand := exec.Command("/bin/sh", "-c", "test -f \"$SYSWARDEN_TEST_MARKER\"; printf '%s\\n' 'no crontab for root' >&2; exit 1")
		verifyCommand.Env = append(os.Environ(), "SYSWARDEN_TEST_MARKER="+marker)

		removed, err := removeManagedRootCronContent(
			managed,
			true,
			writeCommand,
			removeCommand,
			verifyCommand,
		)
		if err != nil || !removed {
			t.Fatalf("managed-only removal = removed %t, error %v", removed, err)
		}
		if writeCommand.ProcessState != nil {
			t.Fatal("managed-only removal wrote an empty crontab")
		}
		if _, err := os.Stat(marker); err != nil {
			t.Fatalf("remove command did not run: %v", err)
		}
	})

	t.Run("explicit empty crontab stays present", func(t *testing.T) {
		writeCommand := exec.Command("/syswarden-test/unexpected-write")
		removeCommand := exec.Command("/syswarden-test/unexpected-remove")
		verifyCommand := exec.Command("/syswarden-test/unexpected-verify")
		removed, err := removeManagedRootCronContent(
			"",
			true,
			writeCommand,
			removeCommand,
			verifyCommand,
		)
		if err != nil || removed {
			t.Fatalf("explicit empty crontab = removed %t, error %v", removed, err)
		}
		for name, command := range map[string]*exec.Cmd{
			"write": writeCommand, "remove": removeCommand, "verify": verifyCommand,
		} {
			if command.ProcessState != nil {
				t.Fatalf("%s command ran for explicit empty crontab", name)
			}
		}
	})

	t.Run("remove failure is material", func(t *testing.T) {
		verifyCommand := exec.Command("/syswarden-test/unexpected-verify")
		removed, err := removeManagedRootCronContent(
			managed,
			true,
			exec.Command("/syswarden-test/unexpected-write"),
			exec.Command("/bin/sh", "-c", "exit 23"),
			verifyCommand,
		)
		if err == nil || removed {
			t.Fatalf("remove failure = removed %t, error %v", removed, err)
		}
		if verifyCommand.ProcessState != nil {
			t.Fatal("absence verification ran after remove failure")
		}
	})

	t.Run("successful remove must report absence", func(t *testing.T) {
		removed, err := removeManagedRootCronContent(
			managed,
			true,
			exec.Command("/syswarden-test/unexpected-write"),
			exec.Command("/bin/sh", "-c", "exit 0"),
			exec.Command("/bin/sh", "-c", "exit 0"),
		)
		if err == nil || removed {
			t.Fatalf("present spool after remove = removed %t, error %v", removed, err)
		}
	})
}

func TestManagedFeedCronCountRejectsCommentsAndLookalikes(t *testing.T) {
	feed := "17 * * * * " + platformpaths.CLI + " update-feeds >/dev/null 2>&1"
	content := strings.Join([]string{
		"# " + feed,
		" " + feed,
		feed + " ",
		strings.Replace(feed, "17 *", "17\t*", 1),
		strings.Replace(feed, "17 *", "17  *", 1),
		feed,
	}, "\n")
	if got := managedFeedCronCount(content); got != 1 {
		t.Fatalf("managed feed count = %d, want 1", got)
	}
}
