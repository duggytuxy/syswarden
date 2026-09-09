package cmd

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

func TestAlertSourcesStartLiveOnlyAtCurrentBoundary(t *testing.T) {
	if got, want := wafTailArgs(), []string{"-F", "-n", "0", wafAlertLogPath}; !reflect.DeepEqual(got, want) {
		t.Fatalf("WAF tail args = %v, want %v", got, want)
	}
	if got, want := kernelLogCommandArgs(true), []string{"-F", "-n", "0", kernelAlertLogPath}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Alpine kernel tail args = %v, want %v", got, want)
	}
	if got, want := kernelLogCommandArgs(false), []string{"-k", "-f", "-n", "0", "--no-pager"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("journald args = %v, want %v", got, want)
	}
}

func TestTailBoundaryDoesNotReplayExistingRecord(t *testing.T) {
	logDirectory := t.TempDir()
	logPath := filepath.Join(logDirectory, "alerts.log")
	if err := os.WriteFile(logPath, []byte("before-boundary\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	command := exec.Command("tail", "-F", "-n", "0", logPath) // #nosec G204 -- the path is a test-owned temporary file
	started := make(chan struct{})
	records := make(chan string, 2)
	done := make(chan error, 1)
	go func() {
		done <- consumeAlertCommand(
			context.Background(),
			command,
			func() { close(started) },
			func(line string) {
				records <- line
				if command.Process != nil {
					_ = command.Process.Kill()
				}
			},
			func(string) {},
		)
	}()

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("tail did not start")
	}
	waitForProcessOpenFile(t, command.Process.Pid, logPath)

	logRoot, err := os.OpenRoot(logDirectory)
	if err != nil {
		t.Fatal(err)
	}
	defer logRoot.Close()
	file, err := logRoot.OpenFile("alerts.log", os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString("after-boundary\n"); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	select {
	case record := <-records:
		if record != "after-boundary" {
			t.Fatalf("first live record = %q, want after-boundary", record)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("new boundary record was not followed")
	}
	select {
	case record := <-records:
		t.Fatalf("unexpected replayed record %q", record)
	case <-time.After(50 * time.Millisecond):
	}
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "source command exited") {
			t.Fatalf("killed tail error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("killed tail did not exit")
	}
}

func waitForProcessOpenFile(t *testing.T, pid int, path string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	fdDirectory := fmt.Sprintf("/proc/%d/fd", pid)
	for time.Now().Before(deadline) {
		entries, err := os.ReadDir(fdDirectory)
		if err == nil {
			for _, entry := range entries {
				target, err := os.Readlink(filepath.Join(fdDirectory, entry.Name()))
				if err == nil && target == path {
					return
				}
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("tail process %d did not open %s", pid, path)
}

func TestAlertRowsAreExplicitlyLive(t *testing.T) {
	now := time.Date(2026, time.September, 9, 12, 30, 0, 0, time.UTC)
	wafLine := `{"action":"SHADOW-ALERT","timestamp":"2026-09-09T12:29:58Z","ip":"192.0.2.8","jail":"L3-PORTSCAN"}`
	wafRow, err := parseWAFAlertRow(wafLine, alertPhaseLive, now)
	if err != nil {
		t.Fatal(err)
	}
	if wafRow.Phase != alertPhaseLive || wafRow.Action != "SHADOW-ALERT" || wafRow.Module != "INSIDER THREAT" {
		t.Fatalf("WAF row = %#v", wafRow)
	}
	if got := formatAlertTextRow(wafRow); !strings.Contains(got, "[LIVE] [INSIDER THREAT] [SHADOW-ALERT]") {
		t.Fatalf("WAF text row does not expose live origin: %s", got)
	}

	kernelRow, ok := parseKernelAlertRow(
		`kernel: [SYSWARDEN-DROP] SRC=198.51.100.9 DPT=22 PROTO=TCP`,
		alertPhaseLive,
		now,
	)
	if !ok {
		t.Fatal("kernel alert was not recognized")
	}
	if kernelRow.Phase != alertPhaseLive || kernelRow.Source != "198.51.100.9" || kernelRow.Target != "PORT: 22" {
		t.Fatalf("kernel row = %#v", kernelRow)
	}
	if _, ok := parseKernelAlertRow("unrelated kernel message", alertPhaseLive, now); ok {
		t.Fatal("unrelated kernel message was presented as an alert")
	}
}

func TestWAFAlertRowsPreserveSupportedActions(t *testing.T) {
	now := time.Date(2026, time.September, 9, 12, 30, 0, 0, time.UTC)
	tests := []struct {
		name       string
		line       string
		wantAction string
		wantModule string
		wantTarget string
	}{
		{
			name:       "allowed SSH user",
			line:       `{"action":"ALLOWED","ip":"192.0.2.10","jail":"sshd","payload":"Accepted publickey for alice from 192.0.2.10"}`,
			wantAction: "ALLOWED",
			wantModule: "SYSWARDEN WAF",
			wantTarget: "SERVICE: sshd | alice",
		},
		{
			name:       "compliance ok",
			line:       `{"action":"COMPLIANCE-OK","ip":"127.0.0.1","jail":"NIS2-AUDIT","payload":"verified"}`,
			wantAction: "COMPLIANCE-OK",
			wantModule: "SYSWARDEN WAF",
			wantTarget: "verified",
		},
		{
			name:       "compliance drift",
			line:       `{"action":"COMPLIANCE-DRIFT","ip":"127.0.0.1","jail":"NIS2-AUDIT","payload":"rp_filter changed"}`,
			wantAction: "COMPLIANCE-DRIFT",
			wantModule: "SYSWARDEN WAF",
			wantTarget: "rp_filter changed",
		},
		{
			name:       "simulated ban",
			line:       `{"action":"SIMULATED-BAN","ip":"198.51.100.11","jail":"ssh-auth"}`,
			wantAction: "SIMULATED-BAN",
			wantModule: "SYSWARDEN WAF",
			wantTarget: "JAIL: ssh-auth",
		},
		{
			name:       "detected",
			line:       `{"action":"DETECTED","ip":"198.51.100.12","jail":"L2-ARP-FLOOD"}`,
			wantAction: "DETECTED",
			wantModule: "SYSWARDEN WAF",
			wantTarget: "JAIL: L2-ARP-FLOOD",
		},
		{
			name:       "default ban with port",
			line:       `{"action":"BANNED","ip":"198.51.100.13","jail":"L3-PORTSCAN","payload":"PROTO=TCP DPT=8443"}`,
			wantAction: "BANNED",
			wantModule: "SYSWARDEN WAF",
			wantTarget: "JAIL: L3-PORTSCAN | PORT: 8443",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			row, err := parseWAFAlertRow(test.line, alertPhaseLive, now)
			if err != nil {
				t.Fatal(err)
			}
			if row.Action != test.wantAction || row.Module != test.wantModule || row.Target != test.wantTarget {
				t.Fatalf("row = %#v, want action %q, module %q, target %q", row, test.wantAction, test.wantModule, test.wantTarget)
			}
		})
	}
}

func TestAlertSourceStatusTreatsQuietAsHealthy(t *testing.T) {
	status := alertSourceStatus{
		Following:     true,
		LastLiveEvent: time.Date(2026, time.September, 8, 8, 0, 0, 0, time.UTC),
	}
	got := formatAlertSourceStatus("WAF", status)
	for _, want := range []string{"LIVE FOLLOWING", "last live event: 2026-09-08 08:00:00", "quiet periods are healthy"} {
		if !strings.Contains(got, want) {
			t.Fatalf("healthy status %q omits %q", got, want)
		}
	}
	if strings.Contains(strings.ToLower(got), "stale") || strings.Contains(got, "ERROR") {
		t.Fatalf("quiet source was treated as failed: %q", got)
	}

	failed := formatAlertSourceStatus("KERNEL", alertSourceStatus{TerminalError: "journal unavailable"})
	if failed != "KERNEL SOURCE: ERROR | journal unavailable" {
		t.Fatalf("failed source status = %q", failed)
	}
}

func TestTextSourceStatusDoesNotRepeatForEachLiveRecord(t *testing.T) {
	var output bytes.Buffer
	report := newAlertTextStatusReporter(&output, "WAF")
	report(alertSourceStatus{Following: true})
	report(alertSourceStatus{Following: true, LastLiveEvent: time.Now()})
	report(alertSourceStatus{Following: true, LastLiveEvent: time.Now().Add(time.Second)})
	if got := strings.Count(output.String(), "WAF SOURCE: LIVE FOLLOWING"); got != 1 {
		t.Fatalf("live source status was printed %d times, output: %s", got, output.String())
	}
}

func TestConsumeAlertCommandExposesLifecycleErrors(t *testing.T) {
	noOp := func() {}
	noLine := func(string) {}

	stdoutAlreadySet := alertHelperCommand("line")
	stdoutAlreadySet.Stdout = io.Discard
	if err := consumeAlertCommand(context.Background(), stdoutAlreadySet, noOp, noLine, noLine); err == nil || !strings.Contains(err.Error(), "open stdout") {
		t.Fatalf("StdoutPipe error = %v", err)
	}

	missing := exec.Command("/proc/self/syswarden-test-missing-alert-source")
	if err := consumeAlertCommand(context.Background(), missing, noOp, noLine, noLine); err == nil || !strings.Contains(err.Error(), "start source command") {
		t.Fatalf("Start error = %v", err)
	}

	if err := consumeAlertCommand(context.Background(), alertHelperCommand("oversized"), noOp, noLine, noLine); err == nil || !strings.Contains(err.Error(), "read alert source stdout") {
		t.Fatalf("Scan error = %v", err)
	}

	if err := consumeAlertCommand(context.Background(), alertHelperCommand("wait-error"), noOp, noLine, noLine); err == nil || !strings.Contains(err.Error(), "source command exited") {
		t.Fatalf("Wait error = %v", err)
	}

	var notices []string
	if err := consumeAlertCommand(context.Background(), alertHelperCommand("stderr"), noOp, noLine, func(line string) { notices = append(notices, line) }); err != nil {
		t.Fatalf("stderr helper failed: %v", err)
	}
	if !reflect.DeepEqual(notices, []string{"source warning"}) {
		t.Fatalf("source notices = %v", notices)
	}
}

func TestLiveSourcePublishesLifecycleAndNeverHistory(t *testing.T) {
	var phases []alertStreamPhase
	var statuses []alertSourceStatus
	calls := 0
	runLiveAlertSource(
		context.Background(),
		func(context.Context) *exec.Cmd {
			calls++
			return alertHelperCommand("line")
		},
		func(phase alertStreamPhase, line string) bool {
			phases = append(phases, phase)
			if line != "live-record" {
				t.Errorf("record = %q", line)
			}
			return true
		},
		func(status alertSourceStatus) { statuses = append(statuses, status) },
	)
	if calls != 1 {
		t.Fatalf("source command factory called %d times, want one live follower", calls)
	}
	if !reflect.DeepEqual(phases, []alertStreamPhase{alertPhaseLive}) {
		t.Fatalf("record phases = %v", phases)
	}
	if len(statuses) < 4 || statuses[0].Following || !statuses[1].Following || statuses[len(statuses)-1].TerminalError == "" {
		t.Fatalf("source lifecycle statuses = %#v", statuses)
	}
}

func TestConsumeAlertCommandCancellationReapsFollower(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	command := alertHelperCommand("block")
	started := make(chan int, 1)
	done := make(chan error, 1)
	go func() {
		done <- consumeAlertCommand(
			ctx,
			command,
			func() { started <- command.Process.Pid },
			func(string) {},
			func(string) {},
		)
	}()

	var pid int
	select {
	case pid = <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("blocking alert follower did not start")
	}
	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled follower error = %v, want context cancellation", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cancelled alert follower was not reaped")
	}
	if command.ProcessState == nil {
		t.Fatalf("alert follower %d was not waited", pid)
	}
	if _, err := os.Stat(fmt.Sprintf("/proc/%d", pid)); !os.IsNotExist(err) {
		t.Fatalf("alert follower %d still exists in /proc (stat error %v)", pid, err)
	}
}

func TestAlertUIQueueCancellationUnblocksProducerWithoutPump(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	queue := newAlertUIQueue(ctx, tview.NewApplication())
	for index := 0; index < alertUIQueueCapacity; index++ {
		if !queue.enqueue(false, func() {}) {
			t.Fatalf("bounded UI queue rejected update %d before capacity", index)
		}
	}

	done := make(chan bool, 1)
	go func() {
		done <- queue.enqueue(false, func() {})
	}()
	select {
	case <-done:
		t.Fatal("producer did not backpressure when the bounded UI queue was full")
	case <-time.After(25 * time.Millisecond):
	}
	cancel()
	select {
	case accepted := <-done:
		if accepted {
			t.Fatal("cancelled UI queue accepted a blocked update")
		}
	case <-time.After(time.Second):
		t.Fatal("context cancellation did not release the blocked UI producer")
	}
}

func TestTUIViewEventErrorReapsFollowers(t *testing.T) {
	screen := tcell.NewSimulationScreen("UTF-8")
	app := tview.NewApplication().SetScreen(screen)

	type follower struct {
		command *exec.Cmd
		pid     int
	}
	started := make(chan follower, 2)
	source := func(ctx context.Context, _ *alertUIQueue, _ *tview.Table, _ *tview.TextView) {
		command := alertHelperCommand("block")
		_ = consumeAlertCommand(
			ctx,
			command,
			func() { started <- follower{command: command, pid: command.Process.Pid} },
			func(string) {},
			func(string) {},
		)
	}

	done := make(chan error, 1)
	go func() {
		done <- runAlertsTUIWithSources(context.Background(), app, source, source)
	}()
	followers := make([]follower, 0, 2)
	for len(followers) < 2 {
		select {
		case process := <-started:
			followers = append(followers, process)
		case <-time.After(2 * time.Second):
			t.Fatal("TUI followers did not start")
		}
	}

	wantErr := errors.New("synthetic screen failure")
	if err := screen.PostEvent(tcell.NewEventError(wantErr)); err != nil {
		t.Fatalf("post EventError: %v", err)
	}
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), wantErr.Error()) {
			t.Fatalf("TUI EventError = %v, want %q", err, wantErr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("TUI EventError waited on its UI queue or followers")
	}

	for _, process := range followers {
		if process.command.ProcessState == nil {
			t.Errorf("TUI follower %d was not waited", process.pid)
		}
		if _, err := os.Stat(fmt.Sprintf("/proc/%d", process.pid)); !os.IsNotExist(err) {
			t.Errorf("TUI follower %d still exists in /proc (stat error %v)", process.pid, err)
		}
	}
}

func TestAlertSignalContextHandlesTargetedSIGTERM(t *testing.T) {
	command := alertHelperCommand("signal-context")
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	scanner := bufio.NewScanner(stdout)
	if !scanner.Scan() || scanner.Text() != "signal-ready" {
		_ = command.Process.Kill()
		_ = command.Wait()
		t.Fatalf("signal helper readiness = %q, error %v", scanner.Text(), scanner.Err())
	}
	if err := command.Process.Signal(syscall.SIGTERM); err != nil {
		_ = command.Process.Kill()
		_ = command.Wait()
		t.Fatal(err)
	}
	if !scanner.Scan() || scanner.Text() != "signal-cancelled" {
		_ = command.Process.Kill()
		_ = command.Wait()
		t.Fatalf("signal helper cancellation = %q, error %v", scanner.Text(), scanner.Err())
	}
	if err := command.Wait(); err != nil {
		t.Fatalf("signal-aware helper exit: %v", err)
	}
}

func TestConsumeAlertCommandOversizedStderrIsBoundedAndDoesNotDeadlock(t *testing.T) {
	done := make(chan error, 1)
	go func() {
		done <- consumeAlertCommand(
			context.Background(),
			alertHelperCommand("oversized-stderr"),
			func() {},
			func(string) {},
			func(string) {},
		)
	}()

	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "read alert source stderr") {
			t.Fatalf("oversized stderr error = %v", err)
		}
		if len(err.Error()) > 300 {
			t.Fatalf("oversized stderr error is not bounded: %d bytes", len(err.Error()))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("oversized stderr deadlocked alert source shutdown")
	}
}

func TestKernelNonAlertDoesNotAdvanceLiveFreshness(t *testing.T) {
	var statuses []alertSourceStatus
	runLiveAlertSource(
		context.Background(),
		func(context.Context) *exec.Cmd { return alertHelperCommand("kernel-mixed") },
		func(phase alertStreamPhase, line string) bool {
			_, accepted := parseKernelAlertRow(line, phase, time.Now())
			return accepted
		},
		func(status alertSourceStatus) { statuses = append(statuses, status) },
	)

	freshnessUpdates := 0
	var lastFreshness time.Time
	for _, status := range statuses {
		if !status.LastLiveEvent.IsZero() && !status.LastLiveEvent.Equal(lastFreshness) {
			freshnessUpdates++
			lastFreshness = status.LastLiveEvent
		}
	}
	if freshnessUpdates != 1 {
		t.Fatalf("live freshness was updated %d times, want only the one accepted SysWarden alert; statuses: %#v", freshnessUpdates, statuses)
	}
}

func alertHelperCommand(mode string) *exec.Cmd {
	command := exec.Command(os.Args[0], "-test.run=^TestAlertSourceHelperProcess$", "--", mode) // #nosec G204 G702 -- executable is the current test binary and mode is test-owned data passed as one argv element
	command.Env = append(os.Environ(), "GO_WANT_ALERT_SOURCE_HELPER=1", "GO_ALERT_SOURCE_HELPER_MODE="+mode)
	return command
}

func TestAlertSourceHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_ALERT_SOURCE_HELPER") != "1" {
		return
	}
	switch os.Getenv("GO_ALERT_SOURCE_HELPER_MODE") {
	case "line":
		fmt.Println("live-record")
	case "oversized":
		fmt.Print(strings.Repeat("x", wafScannerMaxLineSize+1))
	case "oversized-stderr":
		fmt.Fprint(os.Stderr, strings.Repeat("x", wafScannerMaxLineSize+1))
	case "wait-error":
		os.Exit(7)
	case "stderr":
		fmt.Fprintln(os.Stderr, "source warning")
	case "block":
		for {
			time.Sleep(time.Hour)
		}
	case "kernel-mixed":
		fmt.Println("IPv4: Redirect from 188.165.113.62 ignored")
		fmt.Println("kernel: [SYSWARDEN-DROP] SRC=198.51.100.9 DPT=22 PROTO=TCP")
	case "signal-context":
		ctx, stop := alertSignalContext(context.Background())
		fmt.Println("signal-ready")
		<-ctx.Done()
		stop()
		fmt.Println("signal-cancelled")
	default:
		os.Exit(8)
	}
	os.Exit(0)
}
