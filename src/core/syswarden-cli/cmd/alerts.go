package cmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var alertsCmd = &cobra.Command{
	Use:   "alerts",
	Short: "Launch the real-time TUI dashboard for alerts",
	Run: func(cmd *cobra.Command, args []string) {
		if !term.IsTerminal(int(os.Stdout.Fd())) {
			runTextModeFallback()
			return
		}

		app := tview.NewApplication()
		table := tview.NewTable().
			SetBorders(false).
			SetSelectable(true, false).
			SetFixed(1, 0) // Keep header fixed

		// Add header row
		headers := []string{"TIMESTAMP", "MODULE", "ACTION", "SOURCE IP", "TARGET (PORT/JAIL/SERVICES)"}
		for col, header := range headers {
			table.SetCell(0, col, tview.NewTableCell(header).
				SetTextColor(tcell.ColorGray).
				SetSelectable(false).
				SetAlign(tview.AlignCenter).
				SetExpansion(1)) // Ensure even expansion
		}

		// Frame wrapping the table
		frame := tview.NewFrame(table).
			SetBorders(0, 0, 0, 0, 0, 0).
			AddText(" [ SYSWARDEN CLI DASHBOARD (Live Alerts) ] ", true, tview.AlignCenter, tcell.ColorGreen).
			AddText(" Tailing live Threat Intelligence Logs... (Press Ctrl+C to stop) ", false, tview.AlignCenter, tcell.ColorYellow)

		frame.SetBorder(true).
			SetBorderColor(tcell.ColorBlue).
			SetTitleColor(tcell.ColorWhite).
			SetTitleAlign(tview.AlignCenter)

		// Start streams
		go StreamKernelLogs(app, table)
		go streamWAF(app, table)

		// Run TUI app
		if err := app.SetRoot(frame, true).EnableMouse(true).Run(); err != nil {
			panic(err)
		}
	},
}

func addRow(app *tview.Application, table *tview.Table, date, module, action, src, targetInfo string, modColor, actColor tcell.Color) {
	app.QueueUpdateDraw(func() {
		row := table.GetRowCount()
		table.SetCell(row, 0, tview.NewTableCell(date).SetTextColor(tcell.ColorGray).SetAlign(tview.AlignCenter))
		table.SetCell(row, 1, tview.NewTableCell(module).SetTextColor(modColor).SetAlign(tview.AlignCenter))
		table.SetCell(row, 2, tview.NewTableCell(action).SetTextColor(actColor).SetAlign(tview.AlignCenter))
		table.SetCell(row, 3, tview.NewTableCell(src).SetTextColor(tcell.ColorYellow).SetAlign(tview.AlignCenter))
		table.SetCell(row, 4, tview.NewTableCell(targetInfo).SetTextColor(tcell.ColorGray).SetAlign(tview.AlignCenter))

		// Auto scroll to the end
		table.ScrollToEnd()
	})
}

func StreamKernelLogs(app *tview.Application, table *tview.Table) {
	cmd := getKernelLogCommand()
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return
	}
	if err := cmd.Start(); err != nil {
		return
	}

	scanner := bufio.NewScanner(stdout)
	ipRegex := regexp.MustCompile(`SRC=([0-9a-fA-F:.]+)`)
	portRegex := regexp.MustCompile(`DPT=([0-9]+)`)
	protoRegex := regexp.MustCompile(`PROTO=([A-Za-z0-9]+)`)
	modRegex := regexp.MustCompile(`\[(SysWarden-[A-Za-z]+|Catch-All)\]`)

	for scanner.Scan() {
		line := scanner.Text()
		if !strings.Contains(line, "SysWarden-") && !strings.Contains(line, "Catch-All") {
			continue
		}

		date := time.Now().Format("2006-01-02 15:04:05")
		module := "SysWarden-DROP"
		modColor := tcell.ColorBlue
		if strings.Contains(line, "[Catch-All]") {
			module = "SysWarden-CATCH"
			modColor = tcell.ColorDarkCyan
		} else if m := modRegex.FindStringSubmatch(line); len(m) > 1 {
			module = m[1]
		}

		src := "N/A"
		if m := ipRegex.FindStringSubmatch(line); len(m) > 1 {
			src = m[1]
		}

		targetInfo := "PORT: N/A"
		if m := portRegex.FindStringSubmatch(line); len(m) > 1 {
			targetInfo = "PORT: " + m[1]
		} else if m := protoRegex.FindStringSubmatch(line); len(m) > 1 {
			targetInfo = "PROTO: " + m[1]
		}

		addRow(app, table, date, module, "BLOCKED", src, targetInfo, modColor, tcell.ColorRed)
	}
}

func streamWAF(app *tview.Application, table *tview.Table) {
	cmd := exec.Command("stdbuf", "-oL", "/usr/bin/tail", "-F", "-n", "10", "/var/log/syswarden/waf.json")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return
	}
	if err := cmd.Start(); err != nil {
		return
	}

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := scanner.Text()
		var wafEvent struct {
			Action    string `json:"action"`
			Timestamp string `json:"timestamp"`
			IP        string `json:"ip"`
			Jail      string `json:"jail"`
			Payload   string `json:"payload"`
		}
		if err := json.Unmarshal([]byte(line), &wafEvent); err != nil {
			addRow(app, table, time.Now().Format("2006-01-02 15:04:05"), "SYSWARDEN ERR", "JSON", err.Error(), line, tcell.ColorRed, tcell.ColorRed)
			continue
		}

		date := time.Now().Format("2006-01-02 15:04:05")
		if t, err := time.Parse(time.RFC3339, wafEvent.Timestamp); err == nil {
			date = t.Format("2006-01-02 15:04:05")
		}

		switch wafEvent.Action {
		case "ALLOWED":
			info := "SERVICE: " + wafEvent.Jail
			if wafEvent.Payload != "" {
				if wafEvent.Jail == "sshd" {
					match := regexp.MustCompile(`Accepted (?:password|publickey) for (\S+) from`).FindStringSubmatch(wafEvent.Payload)
					if len(match) > 1 {
						info += " | " + match[1]
					}
				} else {
					info += " | " + wafEvent.Payload
				}
			}
			addRow(app, table, date, "SYSWARDEN WAF", "ALLOWED", wafEvent.IP, info, tcell.ColorGreen, tcell.ColorGreen)
		case "SHADOW-ALERT":
			info := "JAIL: " + wafEvent.Jail
			if wafEvent.Payload != "" {
				info += " | " + wafEvent.Payload
			}
			addRow(app, table, date, "INSIDER THREAT", "SHADOW-ALERT", wafEvent.IP, info, tcell.ColorOrange, tcell.ColorOrange)
		default:
			info := "JAIL: " + wafEvent.Jail
			if wafEvent.Payload != "" {
				if wafEvent.Jail == "L3-PORTSCAN" || wafEvent.Jail == "L2-ARP-FLOOD" {
					portRegex := regexp.MustCompile(`DPT=([0-9]+)`)
					protoRegex := regexp.MustCompile(`PROTO=([A-Za-z0-9]+)`)

					if m := portRegex.FindStringSubmatch(wafEvent.Payload); len(m) > 1 {
						info += " | PORT: " + m[1]
					} else if m := protoRegex.FindStringSubmatch(wafEvent.Payload); len(m) > 1 {
						info += " | PROTO: " + m[1]
					}
				} else {
					info += " | " + wafEvent.Payload
				}
			}
			addRow(app, table, date, "SYSWARDEN WAF", "BANNED", wafEvent.IP, info, tcell.ColorPurple, tcell.ColorRed)
		}
	}
}

func init() {
	rootCmd.AddCommand(alertsCmd)
}

func runTextModeFallback() {
	fmt.Println("=== SYSWARDEN TEXT MODE FALLBACK (Non-Interactive) ===")
	fmt.Println("Streaming live telemetry to standard output...")

	go StreamKernelLogsText()
	go streamWAFText()

	// Block forever
	select {}
}

func StreamKernelLogsText() {
	cmd := getKernelLogCommand()
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return
	}
	if err := cmd.Start(); err != nil {
		return
	}

	scanner := bufio.NewScanner(stdout)
	ipRegex := regexp.MustCompile(`SRC=([0-9a-fA-F:.]+)`)
	portRegex := regexp.MustCompile(`DPT=([0-9]+)`)
	protoRegex := regexp.MustCompile(`PROTO=([A-Za-z0-9]+)`)
	modRegex := regexp.MustCompile(`\[(SysWarden-[A-Za-z]+|Catch-All)\]`)

	for scanner.Scan() {
		line := scanner.Text()
		if !strings.Contains(line, "SysWarden-") && !strings.Contains(line, "Catch-All") {
			continue
		}

		date := time.Now().Format("2006-01-02 15:04:05")
		module := "SysWarden-DROP"
		if strings.Contains(line, "[Catch-All]") {
			module = "SysWarden-CATCH"
		} else if m := modRegex.FindStringSubmatch(line); len(m) > 1 {
			module = m[1]
		}

		src := "N/A"
		if m := ipRegex.FindStringSubmatch(line); len(m) > 1 {
			src = m[1]
		}

		targetInfo := "PORT: N/A"
		if m := portRegex.FindStringSubmatch(line); len(m) > 1 {
			targetInfo = "PORT: " + m[1]
		} else if m := protoRegex.FindStringSubmatch(line); len(m) > 1 {
			targetInfo = "PROTO: " + m[1]
		}

		fmt.Printf("[%s] [%s] [BLOCKED] %s -> TARGET: %s\n", date, module, src, targetInfo)
	}
}

func streamWAFText() {
	cmd := exec.Command("stdbuf", "-oL", "/usr/bin/tail", "-F", "-n", "10", "/var/log/syswarden/waf.json")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return
	}
	if err := cmd.Start(); err != nil {
		return
	}

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := scanner.Text()
		var wafEvent struct {
			Action    string `json:"action"`
			Timestamp string `json:"timestamp"`
			IP        string `json:"ip"`
			Jail      string `json:"jail"`
			Payload   string `json:"payload"`
		}
		if err := json.Unmarshal([]byte(line), &wafEvent); err != nil {
			fmt.Printf("[%s] [SYSWARDEN ERR] [JSON] %s -> %s\n", time.Now().Format("2006-01-02 15:04:05"), err.Error(), line)
			continue
		}

		date := time.Now().Format("2006-01-02 15:04:05")
		if t, err := time.Parse(time.RFC3339, wafEvent.Timestamp); err == nil {
			date = t.Format("2006-01-02 15:04:05")
		}

		switch wafEvent.Action {
		case "ALLOWED":
			info := "SERVICE: " + wafEvent.Jail
			if wafEvent.Payload != "" {
				if wafEvent.Jail == "sshd" {
					match := regexp.MustCompile(`Accepted (?:password|publickey) for (\S+) from`).FindStringSubmatch(wafEvent.Payload)
					if len(match) > 1 {
						info += " | " + match[1]
					}
				} else {
					info += " | " + wafEvent.Payload
				}
			}
			fmt.Printf("[%s] [SYSWARDEN L7] [ALLOWED] %s -> %s\n", date, wafEvent.IP, info)
		case "SHADOW-ALERT":
			info := "JAIL: " + wafEvent.Jail
			if wafEvent.Payload != "" {
				info += " | " + wafEvent.Payload
			}
			fmt.Printf("[%s] [INSIDER THREAT] [SHADOW-ALERT] %s -> %s\n", date, wafEvent.IP, info)
		default:
			info := "JAIL: " + wafEvent.Jail
			if wafEvent.Payload != "" {
				if wafEvent.Jail == "L3-PORTSCAN" || wafEvent.Jail == "L2-ARP-FLOOD" {
					portRegex := regexp.MustCompile(`DPT=([0-9]+)`)
					protoRegex := regexp.MustCompile(`PROTO=([A-Za-z0-9]+)`)

					if m := portRegex.FindStringSubmatch(wafEvent.Payload); len(m) > 1 {
						info += " | PORT: " + m[1]
					} else if m := protoRegex.FindStringSubmatch(wafEvent.Payload); len(m) > 1 {
						info += " | PROTO: " + m[1]
					}
				} else {
					info += " | " + wafEvent.Payload
				}
			}
			fmt.Printf("[%s] [SYSWARDEN L7] [BANNED] %s -> %s\n", date, wafEvent.IP, info)
		}
	}
}
