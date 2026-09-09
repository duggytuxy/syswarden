package cmd

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/gdamore/tcell/v2"
)

const (
	wafAlertLogPath       = "/var/log/syswarden/waf.json"
	wafScannerMaxLineSize = 1024 * 1024
)

type alertStreamPhase string

const (
	alertPhaseLive alertStreamPhase = "LIVE"
)

type wafAlertEvent struct {
	Action    string `json:"action"`
	Timestamp string `json:"timestamp"`
	IP        string `json:"ip"`
	Jail      string `json:"jail"`
	Payload   string `json:"payload"`
}

type alertRow struct {
	Phase       alertStreamPhase
	Date        string
	Module      string
	TextModule  string
	Action      string
	Source      string
	Target      string
	ModuleColor tcell.Color
	ActionColor tcell.Color
}

type alertSourceStatus struct {
	Following     bool
	LastLiveEvent time.Time
	Notice        string
	TerminalError string
}

type alertSourceMonitor struct {
	mu     sync.Mutex
	status alertSourceStatus
	report func(alertSourceStatus)
}

var (
	wafAcceptedSSHUserPattern = regexp.MustCompile(`Accepted (?:password|publickey) for (\S+) from`)
	wafDestinationPortPattern = regexp.MustCompile(`DPT=([0-9]+)`)
	wafProtocolPattern        = regexp.MustCompile(`PROTO=([A-Za-z0-9]+)`)
)

func newAlertSourceMonitor(report func(alertSourceStatus)) *alertSourceMonitor {
	return &alertSourceMonitor{report: report}
}

func (monitor *alertSourceMonitor) update(change func(*alertSourceStatus)) {
	monitor.mu.Lock()
	change(&monitor.status)
	status := monitor.status
	monitor.mu.Unlock()
	monitor.report(status)
}

func (monitor *alertSourceMonitor) connectingLive() {
	monitor.update(func(status *alertSourceStatus) {
		status.Following = false
		status.TerminalError = ""
	})
}

func (monitor *alertSourceMonitor) followingLive() {
	monitor.update(func(status *alertSourceStatus) {
		status.Following = true
		status.TerminalError = ""
	})
}

func (monitor *alertSourceMonitor) recordLiveEvent(at time.Time) {
	monitor.update(func(status *alertSourceStatus) {
		status.Following = true
		status.LastLiveEvent = at
	})
}

func (monitor *alertSourceMonitor) sourceNotice(message string) {
	monitor.update(func(status *alertSourceStatus) {
		status.Notice = boundedSingleLine(message)
	})
}

func (monitor *alertSourceMonitor) sourceFailed(err error) {
	monitor.update(func(status *alertSourceStatus) {
		status.Following = false
		status.TerminalError = boundedSingleLine(err.Error())
	})
}

func runWAFSource(ctx context.Context, emit func(alertStreamPhase, string) bool, report func(alertSourceStatus)) {
	runLiveAlertSource(ctx, newWAFTailCommand, emit, report)
}

func runLiveAlertSource(
	ctx context.Context,
	newCommand func(context.Context) *exec.Cmd,
	emit func(alertStreamPhase, string) bool,
	report func(alertSourceStatus),
) {
	monitor := newAlertSourceMonitor(report)
	monitor.connectingLive()
	err := consumeAlertCommand(
		ctx,
		newCommand(ctx),
		monitor.followingLive,
		func(line string) {
			if emit(alertPhaseLive, line) {
				monitor.recordLiveEvent(time.Now())
			}
		},
		monitor.sourceNotice,
	)
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return
	}
	if err == nil {
		err = fmt.Errorf("source command ended unexpectedly")
	}
	monitor.sourceFailed(fmt.Errorf("live follow: %w", err))
}

func wafTailArgs() []string {
	return []string{"-F", "-n", "0", wafAlertLogPath}
}

func newWAFTailCommand(ctx context.Context) *exec.Cmd {
	args := wafTailArgs()
	if _, err := exec.LookPath("stdbuf"); err == nil {
		return exec.CommandContext(ctx, "stdbuf", append([]string{"-oL", "tail"}, args...)...) // #nosec G204 -- executable and arguments are fixed internally for the live WAF log follower
	}
	return exec.CommandContext(ctx, "tail", args...) // #nosec G204 -- executable and arguments are fixed internally for the live WAF log follower
}

type alertPipeResult struct {
	name string
	err  error
}

func consumeAlertCommand(ctx context.Context, command *exec.Cmd, started func(), emit func(string), notice func(string)) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		return fmt.Errorf("open stdout: %w", err)
	}
	stderr, err := command.StderrPipe()
	if err != nil {
		return fmt.Errorf("open stderr: %w", err)
	}
	if err := command.Start(); err != nil {
		return fmt.Errorf("start source command: %w", err)
	}
	started()

	issues := make(chan alertPipeResult, 2)
	done := make(chan alertPipeResult, 2)
	drain := func(name string, reader io.Reader, consume func(string)) {
		scanner := newWAFScanner(reader)
		for scanner.Scan() {
			consume(scanner.Text())
		}
		result := alertPipeResult{name: name, err: scanner.Err()}
		if result.err != nil {
			// Report the bounded scanner failure immediately so the parent can
			// terminate the follower, then keep draining until its pipe closes.
			// This prevents an oversized diagnostic from filling stderr while
			// command shutdown waits for both readers to finish.
			issues <- result
			_, _ = io.Copy(io.Discard, reader)
		}
		done <- result
	}
	go drain("stdout", stdout, emit)
	go drain("stderr", stderr, notice)

	ctxDone := ctx.Done()
	var terminalErr error
	completed := 0
	kill := func() {
		if command.Process != nil {
			_ = command.Process.Kill()
		}
	}
	for completed < 2 {
		select {
		case <-ctxDone:
			ctxDone = nil
			if terminalErr == nil {
				terminalErr = ctx.Err()
			}
			kill()
		case issue := <-issues:
			if terminalErr == nil {
				terminalErr = boundedAlertReadError(issue)
			}
			kill()
		case result := <-done:
			completed++
			if result.err != nil && terminalErr == nil {
				terminalErr = boundedAlertReadError(result)
				kill()
			}
		}
	}
	waitErr := command.Wait()

	if err := ctx.Err(); err != nil {
		return err
	}
	if terminalErr != nil {
		return terminalErr
	}
	if waitErr != nil {
		return fmt.Errorf("source command exited: %w", waitErr)
	}
	return nil
}

func boundedAlertReadError(result alertPipeResult) error {
	return fmt.Errorf("read alert source %s: %s", result.name, boundedSingleLine(result.err.Error()))
}

func newWAFScanner(reader io.Reader) *bufio.Scanner {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 64*1024), wafScannerMaxLineSize)
	return scanner
}

func parseWAFAlertRow(line string, phase alertStreamPhase, now time.Time) (alertRow, error) {
	var event wafAlertEvent
	if err := json.Unmarshal([]byte(line), &event); err != nil {
		return alertRow{}, err
	}

	row := alertRow{
		Phase:       phase,
		Date:        now.Format("2006-01-02 15:04:05"),
		Module:      "SYSWARDEN WAF",
		TextModule:  "SYSWARDEN L7",
		Action:      "BANNED",
		Source:      event.IP,
		Target:      "JAIL: " + event.Jail,
		ModuleColor: tcell.ColorPurple,
		ActionColor: tcell.ColorRed,
	}
	if timestamp, err := time.Parse(time.RFC3339, event.Timestamp); err == nil {
		row.Date = timestamp.Format("2006-01-02 15:04:05")
	}

	switch event.Action {
	case "ALLOWED":
		row.Action = "ALLOWED"
		row.Target = "SERVICE: " + event.Jail
		row.ModuleColor = tcell.ColorGreen
		row.ActionColor = tcell.ColorGreen
		if event.Payload != "" && event.Jail == "sshd" {
			if match := wafAcceptedSSHUserPattern.FindStringSubmatch(event.Payload); len(match) > 1 {
				row.Target += " | " + match[1]
			}
		}
	case "COMPLIANCE-OK":
		row.Action = "COMPLIANCE-OK"
		row.Target = event.Payload
		row.ModuleColor = tcell.ColorGreen
		row.ActionColor = tcell.ColorGreen
	case "COMPLIANCE-DRIFT":
		row.Action = "COMPLIANCE-DRIFT"
		row.Target = event.Payload
		row.ModuleColor = tcell.ColorRed
		row.ActionColor = tcell.ColorRed
	case "SIMULATED-BAN":
		row.Action = "SIMULATED-BAN"
		row.ModuleColor = tcell.ColorOrange
		row.ActionColor = tcell.ColorOrange
	case "SHADOW-ALERT":
		row.Module = "INSIDER THREAT"
		row.TextModule = "INSIDER THREAT"
		row.Action = "SHADOW-ALERT"
		row.ModuleColor = tcell.ColorOrange
		row.ActionColor = tcell.ColorOrange
	case "DETECTED":
		row.Action = "DETECTED"
		row.ModuleColor = tcell.ColorYellow
		row.ActionColor = tcell.ColorYellow
	default:
		if event.Payload != "" && (event.Jail == "L3-PORTSCAN" || event.Jail == "L2-ARP-FLOOD") {
			if match := wafDestinationPortPattern.FindStringSubmatch(event.Payload); len(match) > 1 {
				row.Target += " | PORT: " + match[1]
			} else if match := wafProtocolPattern.FindStringSubmatch(event.Payload); len(match) > 1 {
				row.Target += " | PROTO: " + match[1]
			}
		}
	}

	return row, nil
}

func formatAlertTextRow(row alertRow) string {
	return fmt.Sprintf("[%s] [%s] [%s] [%s] %s -> %s", row.Date, row.Phase, row.TextModule, row.Action, row.Source, row.Target)
}

func formatAlertSourceStatus(source string, status alertSourceStatus) string {
	if status.TerminalError != "" {
		return source + " SOURCE: ERROR | " + status.TerminalError
	}

	var message string
	if status.Following {
		lastEvent := "none in this session"
		if !status.LastLiveEvent.IsZero() {
			lastEvent = status.LastLiveEvent.Format("2006-01-02 15:04:05")
		}
		message = source + " SOURCE: LIVE FOLLOWING | last live event: " + lastEvent + " | quiet periods are healthy"
	} else {
		message = source + " SOURCE: LIVE CONNECTING"
	}
	if status.Notice != "" {
		message += " | source notice: " + status.Notice
	}
	return message
}

func newAlertTextStatusReporter(writer io.Writer, source string) func(alertSourceStatus) {
	var mu sync.Mutex
	lastKey := ""
	return func(status alertSourceStatus) {
		key := fmt.Sprintf("%t|%s|%s", status.Following, status.Notice, status.TerminalError)
		mu.Lock()
		defer mu.Unlock()
		if key == lastKey {
			return
		}
		lastKey = key
		fmt.Fprintln(writer, "[SYSWARDEN ALERTS] "+formatAlertSourceStatus(source, status))
	}
}

func boundedSingleLine(message string) string {
	const maximumRunes = 240
	message = strings.Join(strings.Fields(message), " ")
	runes := []rune(message)
	if len(runes) <= maximumRunes {
		return message
	}
	return string(runes[:maximumRunes-3]) + "..."
}
