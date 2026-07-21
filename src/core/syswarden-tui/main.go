package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
	"golang.org/x/term"
)

const DataFile = "/var/lib/syswarden/ui/data.json"
const SysWardenVersion = "v3.74.5"

var (
	activeNodeIP = "local"
	haPeerPort   = "62026"
	httpClient   = &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
)

// --- DATA MODELS ---
type Service struct {
	Name   string `json:"name"`
	Path   string `json:"path"`
	Status string `json:"status"`
}

type Port struct {
	IP       string `json:"ip"`
	State    string `json:"state"`
	Port     string `json:"port"`
	Protocol string `json:"protocol"`
}

type SystemData struct {
	Hostname    string    `json:"hostname"`
	Uptime      string    `json:"uptime"`
	LoadAverage string    `json:"load_average"`
	RamUsedMb   int       `json:"ram_used_mb"`
	RamTotalMb  int       `json:"ram_total_mb"`
	DiskUsedMb  int       `json:"disk_used_mb"`
	DiskTotalMb int       `json:"disk_total_mb"`
	Cores       string    `json:"cores"`
	Arch        string    `json:"arch"`
	Os          string    `json:"os"`
	CpuModel    string    `json:"cpu_model"`
	ServerIP    string    `json:"server_ip"`
	Services    []Service `json:"services"`
	Ports       []Port    `json:"ports"`
}

type Layer3 struct {
	GlobalBlocked int  `json:"global_blocked"`
	GeoIPBlocked  int  `json:"geoip_blocked"`
	ASNBlocked    int  `json:"asn_blocked"`
	L7Banned      int  `json:"l7_banned"`
	ZeroTrustMode bool `json:"zero_trust_mode"`
}

type JailData struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
	Mitre string `json:"mitre"`
}

type AllowedEvent struct {
	Timestamp string `json:"timestamp"`
	IP        string `json:"ip"`
	Service   string `json:"service"`
	Payload   string `json:"payload"`
}

type BannedIP struct {
	IP      string `json:"ip"`
	Jail    string `json:"jail"`
	Payload string `json:"payload"`
	Mitre   string `json:"mitre"`
	Action  string `json:"action"`
}

type Attacker struct {
	IP       string `json:"ip"`
	Severity string `json:"severity"`
	Port     string `json:"port"`
	Country  string `json:"country"`
	ASN      string `json:"asn"`
	ISP      string `json:"isp"`
}

type WAF struct {
	TotalBanned      int            `json:"total_banned"`
	TotalDetected    int            `json:"total_detected"`
	ActiveSignatures int            `json:"active_signatures"`
	SignaturesData   []JailData     `json:"signatures_data"`
	BannedIPs        []BannedIP     `json:"banned_ips"`
	TopAttackers     []Attacker     `json:"top_attackers"`
	RiskRadar        []int          `json:"risk_radar"`
	AllowedEvents    []AllowedEvent `json:"allowed_events"`
}

type Whitelist struct {
	ActiveIPs int      `json:"active_ips"`
	IPs       []string `json:"ips"`
}

type DashboardData struct {
	Timestamp     string     `json:"timestamp"`
	GithubStars   string     `json:"github_stars"`
	GithubRelease string     `json:"github_release"`
	System        SystemData `json:"system"`
	Layer3        Layer3     `json:"layer3"`
	WAF           WAF        `json:"waf"`
	Whitelist     Whitelist  `json:"whitelist"`
}

var (
	app            *tview.Application
	data           DashboardData
	mu             sync.Mutex
	headerText     *tview.TextView
	l3Text         *tview.TextView
	vectorsText    *tview.TextView
	trustedText    *tview.TextView
	jailsTable     *tview.Table
	attackersTable *tview.Table
	bannedTable    *tview.Table

	recentlyUnbanned   = make(map[string]time.Time)
	recentlyUnbannedMu sync.Mutex

	fetchError error
)

func main() {
	if !term.IsTerminal(int(os.Stdout.Fd())) {
		printDashboardText()
		return
	}

	app = tview.NewApplication()

	// 1. Header (System Info)
	headerText = tview.NewTextView().
		SetDynamicColors(true).
		SetRegions(true).
		SetWrap(true)
	headerText.SetBorder(true).
		SetTitle(fmt.Sprintf(" [white::b]SYSWARDEN %s[-:-:-] ", SysWardenVersion)).
		SetTitleColor(tcell.ColorAqua).
		SetBorderColor(tcell.ColorBlue)

	// 2. L3 Blocks
	l3Text = tview.NewTextView().SetDynamicColors(true).SetWrap(false)
	l3Text.SetBorder(true).SetTitle(" [cyan]❖ L3 KERNEL BLOCKS (GLOBAL)[-] ").SetBorderColor(tcell.ColorDarkGray)

	// 3. Risk Vectors
	vectorsText = tview.NewTextView().SetDynamicColors(true).SetWrap(false)
	vectorsText.SetBorder(true).SetTitle(" [white]❖ GLOBAL RISK VECTORS[-] ").SetBorderColor(tcell.ColorDarkGray)

	// 4. Trusted Hosts
	trustedText = tview.NewTextView().SetDynamicColors(true).SetWrap(false)
	trustedText.SetBorder(true).SetTitle(" [green]❖ TRUSTED HOSTS (WHITELIST)[-] ").SetBorderColor(tcell.ColorDarkGray)

	metricsFlex := tview.NewFlex().
		AddItem(l3Text, 0, 1, false).
		AddItem(vectorsText, 0, 2, false).
		AddItem(trustedText, 0, 1, false)

	// 5. Signatures Table
	jailsTable = tview.NewTable().SetBorders(false).SetSelectable(false, false)
	jailsTable.SetBorder(true).SetTitle(" [white]❖ SIGNATURES LOAD DISTRIBUTION[-] ").SetBorderColor(tcell.ColorDarkGray)

	// 6. Top Attackers Table
	attackersTable = tview.NewTable().SetBorders(false).SetSelectable(false, false)
	attackersTable.SetBorder(true).SetTitle(" [white]❖ TOP ATTACKERS (OSINT HISTORY)[-] ").SetBorderColor(tcell.ColorDarkGray)

	midFlex := tview.NewFlex().
		AddItem(jailsTable, 0, 1, false).
		AddItem(attackersTable, 0, 2, false)

	// 7. Banned IPs Table
	bannedTable = tview.NewTable().
		SetBorders(false).
		SetSelectable(true, false).
		SetFixed(1, 0)
	bannedTable.SetBorder(true).
		SetTitle(" [white]❖ WAF ALLOWED/BANNED IP REGISTRY (L4/L7)[-] ").
		SetBorderColor(tcell.ColorBlue)

	// Layout Setup
	mainFlex := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(headerText, 8, 1, false).
		AddItem(metricsFlex, 6, 1, false).
		AddItem(midFlex, 8, 1, false).
		AddItem(bannedTable, 0, 3, true)

	bannedTable.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Rune() == 'u' || event.Rune() == 'U' {
			row, _ := bannedTable.GetSelection()
			if row > 0 {
				cell := bannedTable.GetCell(row, 0)
				if cell != nil {
					ip := cell.Text
					if ip != "" && ip != "Registry is empty. Architecture is secure." {
						modal := tview.NewModal().
							SetText(fmt.Sprintf("[white]Do you want to delete / unban IP %s from the list?[-]", ip)).
							AddButtons([]string{"y", "n"}).
							SetDoneFunc(func(buttonIndex int, buttonLabel string) {
								if buttonLabel == "y" {
									recentlyUnbannedMu.Lock()
									recentlyUnbanned[ip] = time.Now()
									recentlyUnbannedMu.Unlock()

									go func(targetIP string) {
										_ = exec.Command("syswarden", "unblock", targetIP).Run() // #nosec
										readDataAndUpdate()
									}(ip)
								}
								app.SetRoot(mainFlex, true)
								if buttonLabel == "y" {
									go readDataAndUpdate()
								}
							})
						app.SetRoot(modal, false)
					}
				}
			}
		}
		return event
	})

	// Ensure safe exiting via Q/Ctrl+C
	ctx, cancel := context.WithCancel(context.Background())

	app.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Rune() == 'q' || event.Rune() == 'Q' || event.Key() == tcell.KeyCtrlC {
			cancel()
			app.EnableMouse(false)
			time.Sleep(50 * time.Millisecond)
			app.Stop()
			return nil
		}
		if event.Key() == tcell.KeyEscape {
			showP2PMenu(mainFlex)
			return nil
		}
		return event
	})

	// Background Poller
	go func() {
		// First read immediately
		readDataAndUpdate()
		for {
			select {
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Second):
				readDataAndUpdate()
			}
		}
	}()

	if err := app.SetRoot(mainFlex, true).EnableMouse(true).Run(); err != nil {
		cancel()
		panic(err)
	}
	cancel()
}

// --- P2P MESH TUI LOGIC ---

func getHAPeers() []string {
	var peers []string
	file, err := os.Open("/opt/syswarden/syswarden-auto.conf") // #nosec
	if err != nil {
		return peers
	}
	defer func() { _ = file.Close() }()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "SYSWARDEN_HA_PEER_IP=") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				ips := strings.TrimSpace(strings.Trim(strings.TrimSpace(parts[1]), "\"'"))
				ips = strings.ReplaceAll(ips, ",", " ")
				peers = append(peers, strings.Fields(ips)...)
			}
		}
	}
	return peers
}

func showP2PMenu(mainFlex *tview.Flex) {
	list := tview.NewList().
		AddItem("ACTUAL NODE", "Supervise local telemetry", '1', func() {
			activeNodeIP = "local"
			app.SetRoot(mainFlex, true)
			go readDataAndUpdate()
		}).
		AddItem("NODES HA-CLUSTERS", "Explore and supervise HA peer nodes", '2', func() {
			showNodesList(mainFlex)
		}).
		AddItem("HOTKEYS", "Show functional hotkeys", '3', func() {
			showHotkeysMenu(mainFlex)
		}).
		AddItem("EXIT", "Quit SysWarden TUI", '4', func() {
			app.EnableMouse(false)
			time.Sleep(50 * time.Millisecond)
			app.Stop()
		})

	list.SetBorder(true).
		SetTitle(" [white]❖ P2P HA-CLUSTER MESH MENU[-] ").
		SetBorderColor(tcell.ColorBlue)

	app.SetRoot(list, true)
}

func showHotkeysMenu(mainFlex *tview.Flex) {
	modal := tview.NewModal().
		SetText("[white]P2P TUI HOTKEYS[-]\n\n[yellow]Esc[-]    : Open P2P HA-Cluster Menu\n[yellow]Ctrl+C[-] : Force exit TUI\n[yellow]q / Q[-]  : Quit TUI\n[yellow]u / U[-]  : Unban IP (when in ALLOWED/BANNED table)\n[yellow]Tab[-]    : Switch focus between panels\n[yellow]Enter[-]  : Select Node in HA-Cluster Explorer").
		AddButtons([]string{"Back"}).
		SetDoneFunc(func(buttonIndex int, buttonLabel string) {
			showP2PMenu(mainFlex)
		})
	app.SetRoot(modal, false)
}

func showNodesList(mainFlex *tview.Flex) {
	peers := getHAPeers()

	table := tview.NewTable().
		SetBorders(true).
		SetSelectable(true, false).
		SetFixed(1, 0)

	table.SetBorder(true).
		SetTitle(" [white]❖ HA-CLUSTER NODES EXPLORER[-] ").
		SetBorderColor(tcell.ColorBlue)

	table.SetCell(0, 0, tview.NewTableCell("Hostname").SetTextColor(tcell.ColorYellow).SetSelectable(false))
	table.SetCell(0, 1, tview.NewTableCell("IP").SetTextColor(tcell.ColorYellow).SetSelectable(false))
	table.SetCell(0, 2, tview.NewTableCell("OS").SetTextColor(tcell.ColorYellow).SetSelectable(false))
	table.SetCell(0, 3, tview.NewTableCell("Status").SetTextColor(tcell.ColorYellow).SetSelectable(false))
	table.SetCell(0, 4, tview.NewTableCell("Version").SetTextColor(tcell.ColorYellow).SetSelectable(false))

	if len(peers) == 0 {
		table.SetCell(1, 0, tview.NewTableCell("No peers configured in syswarden-auto.conf").SetTextColor(tcell.ColorGray))
	} else {
		for i, ip := range peers {
			row := i + 1
			table.SetCell(row, 0, tview.NewTableCell("Probing...").SetTextColor(tcell.ColorGray))
			table.SetCell(row, 1, tview.NewTableCell(ip).SetTextColor(tcell.ColorWhite))
			table.SetCell(row, 2, tview.NewTableCell("...").SetTextColor(tcell.ColorGray))
			table.SetCell(row, 3, tview.NewTableCell("[gray]WAITING[-]").SetTextColor(tcell.ColorGray))
			table.SetCell(row, 4, tview.NewTableCell("...").SetTextColor(tcell.ColorGray))

			go func(ip string, r int) {
				resp, err := httpClient.Get(fmt.Sprintf("https://%s:%s/ha/status", ip, haPeerPort))

				app.QueueUpdateDraw(func() {
					if err != nil {
						table.SetCell(r, 0, tview.NewTableCell("Unknown").SetTextColor(tcell.ColorDarkGray))
						table.SetCell(r, 2, tview.NewTableCell("Unknown").SetTextColor(tcell.ColorDarkGray))
						table.SetCell(r, 3, tview.NewTableCell("OFFLINE").SetTextColor(tcell.ColorRed))
						table.SetCell(r, 4, tview.NewTableCell("-").SetTextColor(tcell.ColorDarkGray))
						return
					}
					defer func() { _ = resp.Body.Close() }()

					if resp.StatusCode == 200 {
						var status struct {
							Hostname string `json:"hostname"`
							OS       string `json:"os"`
							Version  string `json:"version"`
							Status   string `json:"status"`
						}
						_ = json.NewDecoder(resp.Body).Decode(&status)
						table.SetCell(r, 0, tview.NewTableCell(status.Hostname).SetTextColor(tcell.ColorWhite))
						table.SetCell(r, 2, tview.NewTableCell(status.OS).SetTextColor(tcell.ColorWhite))
						table.SetCell(r, 3, tview.NewTableCell("ONLINE").SetTextColor(tcell.ColorGreen))
						table.SetCell(r, 4, tview.NewTableCell(status.Version).SetTextColor(tcell.ColorWhite))
					} else {
						table.SetCell(r, 3, tview.NewTableCell("OFFLINE").SetTextColor(tcell.ColorRed))
					}
				})
			}(ip, row)
		}
	}

	table.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Key() == tcell.KeyEscape {
			showP2PMenu(mainFlex)
			return nil
		}
		if event.Key() == tcell.KeyEnter {
			row, _ := table.GetSelection()
			if row > 0 {
				cell := table.GetCell(row, 1)
				if cell != nil && cell.Text != "" {
					activeNodeIP = cell.Text
					app.SetRoot(mainFlex, true)
					go readDataAndUpdate()
				}
			}
			return nil
		}
		return event
	})

	app.SetRoot(table, true)
}

func readDataAndUpdate() {
	var bytes []byte
	var err error

	if activeNodeIP == "local" {
		bytes, err = os.ReadFile(DataFile) // #nosec
	} else {
		resp, reqErr := httpClient.Get(fmt.Sprintf("https://%s:%s/ha/telemetry", activeNodeIP, haPeerPort))
		if reqErr != nil {
			err = reqErr
		} else {
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode == 200 {
				bytes, err = io.ReadAll(resp.Body)
			} else {
				err = fmt.Errorf("HTTP %d", resp.StatusCode)
			}
		}
	}

	mu.Lock()
	if err != nil {
		if activeNodeIP == "local" {
			fetchError = fmt.Errorf("data unreadable: %w", err)
		} else {
			fetchError = fmt.Errorf("node %s unreachable: %w", activeNodeIP, err)
		}
		mu.Unlock()
		app.QueueUpdateDraw(func() { refreshUI() })
		return
	}

	var newData DashboardData
	if err := json.Unmarshal(bytes, &newData); err != nil {
		fetchError = fmt.Errorf("invalid telemetry JSON: %w", err)
		mu.Unlock()
		app.QueueUpdateDraw(func() { refreshUI() })
		return
	}

	fetchError = nil
	data = newData

	// Reverse BannedIPs
	for i, j := 0, len(data.WAF.BannedIPs)-1; i < j; i, j = i+1, j-1 {
		data.WAF.BannedIPs[i], data.WAF.BannedIPs[j] = data.WAF.BannedIPs[j], data.WAF.BannedIPs[i]
	}

	// Sort Signatures
	sort.Slice(data.WAF.SignaturesData, func(i, j int) bool {
		return data.WAF.SignaturesData[i].Count > data.WAF.SignaturesData[j].Count
	})
	mu.Unlock()

	app.QueueUpdateDraw(func() {
		refreshUI()
	})
}

func buildProgressBar(used, total int, label string, color string) string {
	if total == 0 {
		return fmt.Sprintf("[gray][%s 0%%][-]", label)
	}
	pct := float64(used) / float64(total)
	if pct > 1.0 {
		pct = 1.0
	}

	barsCount := 20
	filled := int(pct * float64(barsCount))
	if filled > barsCount {
		filled = barsCount
	}

	barStr := strings.Repeat("█", filled) + strings.Repeat("░", barsCount-filled)
	c := color
	if pct > 0.85 {
		c = "red"
	} else if pct > 0.60 {
		c = "yellow"
	}

	return fmt.Sprintf("[%s]%s %.1f%% %s[-]", c, label, pct*100, barStr)
}

func TranslateAllowedPayload(service, payload, ip string) string {
	ts := time.Now().Format("2006-01-02 15:04:05")
	if service == "sshd" {
		user := "unknown"
		var authMethod string
		keyInfo := ""

		if strings.Contains(payload, "Accepted publickey for ") {
			authMethod = "public key"
			parts := strings.Split(payload, "Accepted publickey for ")
			if len(parts) > 1 {
				subParts := strings.Split(parts[1], " from ")
				if len(subParts) > 0 {
					user = subParts[0]
				}
			}
			if idx := strings.Index(payload, "ssh2: "); idx != -1 {
				keyInfo = strings.TrimSpace(payload[idx+6:])
			}
		} else if strings.Contains(payload, "Accepted password for ") {
			authMethod = "password"
			parts := strings.Split(payload, "Accepted password for ")
			if len(parts) > 1 {
				subParts := strings.Split(parts[1], " from ")
				if len(subParts) > 0 {
					user = subParts[0]
				}
			}
		} else {
			return fmt.Sprintf("[%s] Access granted for IP %s", ts, ip)
		}

		if keyInfo != "" {
			return fmt.Sprintf("[%s] Access granted for user '%s' via %s (%s) from IP %s", ts, user, authMethod, keyInfo, ip)
		}
		return fmt.Sprintf("[%s] Access granted for user '%s' via %s from IP %s", ts, user, authMethod, ip)
	}

	return fmt.Sprintf("[%s] Access granted for IP %s", ts, ip)
}

func TranslatePayload(jail, payload, ip string) string {
	ts := time.Now().Format("2006-01-02 15:04:05")
	j := strings.ToLower(jail)
	url := fmt.Sprintf("(https://www.abuseipdb.com/check/%s)", ip)

	if strings.Contains(j, "ssh") || strings.Contains(j, "bruteforce") || strings.Contains(j, "auth") {
		port := "22"
		if idx := strings.Index(payload, "port "); idx != -1 {
			parts := strings.Split(payload[idx+5:], " ")
			if len(parts) > 0 {
				port = strings.Trim(parts[0], ":")
			}
		} else if idx := strings.Index(payload, "DPT="); idx != -1 {
			pStr := payload[idx+4:]
			if spaceIdx := strings.Index(pStr, " "); spaceIdx != -1 {
				port = pStr[:spaceIdx]
			}
		}
		return fmt.Sprintf("[%s] Attempted SSH brute-force on port %s by IP %s %s", ts, port, ip, url)
	}

	if strings.Contains(j, "scan") || strings.Contains(j, "zero-trust") || strings.Contains(j, "catch-all") {
		port := "unknown"
		if dptIdx := strings.Index(payload, "DPT="); dptIdx != -1 {
			pStr := payload[dptIdx+4:]
			if spaceIdx := strings.Index(pStr, " "); spaceIdx != -1 {
				port = pStr[:spaceIdx]
			}
		}
		return fmt.Sprintf("[%s] Attempted port scan on port %s by IP %s %s", ts, port, ip, url)
	}

	if strings.Contains(j, "sqli") || strings.Contains(j, "xss") || strings.Contains(j, "lfi") || strings.Contains(j, "rce") {
		uri := "/"
		if idx := strings.Index(payload, "GET "); idx != -1 {
			parts := strings.Split(payload[idx+4:], " ")
			if len(parts) > 0 {
				uri = parts[0]
			}
		} else if idx := strings.Index(payload, "POST "); idx != -1 {
			parts := strings.Split(payload[idx+5:], " ")
			if len(parts) > 0 {
				uri = parts[0]
			}
		}
		return fmt.Sprintf("[%s] Attempted Web exploit (%s) on URI '%s' by IP %s %s", ts, strings.ToUpper(jail), uri, ip, url)
	}

	return fmt.Sprintf("[%s] Attempted attack (%s) by IP %s %s", ts, strings.ToUpper(jail), ip, url)
}

func refreshUI() {
	mu.Lock()
	d := data
	currentErr := fetchError
	mu.Unlock()

	// --- Header Calculation ---
	ghStars, ghRelease := d.GithubStars, d.GithubRelease
	if ghStars == "" {
		ghStars = "--"
	}
	if ghRelease == "" {
		ghRelease = "--"
	}

	load1Str := "0.00"
	if parts := strings.Split(d.System.LoadAverage, ","); len(parts) > 0 {
		load1Str = strings.TrimSpace(parts[0])
	}
	loadVal, _ := strconv.ParseFloat(load1Str, 64)
	cLoad := "green"
	if loadVal >= 0.75 {
		cLoad = "red"
	} else if loadVal >= 0.50 {
		cLoad = "yellow"
	}

	var servicesStr []string
	for _, s := range d.System.Services {
		n := strings.ToUpper(s.Name)
		st := strings.ToUpper(s.Status)
		cSt := "red"
		switch st {
		case "ACTIVE", "ONLINE":
			cSt = "green"
		case "SKIPPED":
			cSt = "yellow"
		case "INACTIVE":
			cSt = "red"
		}
		if strings.Contains(st, ":") {
			cSt = "cyan"
		}
		servicesStr = append(servicesStr, fmt.Sprintf("[white]%s[-]:[%s]%s[-]", n, cSt, st))
	}

	var portsStr []string
	for _, p := range d.System.Ports {
		portsStr = append(portsStr, fmt.Sprintf("%s:%s", p.Protocol, p.Port))
	}
	pStr := strings.Join(portsStr, " │ ")
	if len(portsStr) == 0 {
		pStr = "No external ports exposed. Locked down."
	}

	ramBar := buildProgressBar(d.System.RamUsedMb, d.System.RamTotalMb, "MEM", "green")
	diskBar := buildProgressBar(d.System.DiskUsedMb, d.System.DiskTotalMb, "DSK", "cyan")

	errState := " [green]ONLINE[-]"
	if currentErr != nil {
		errState = " [red]OFFLINE (Telemetry Error)[-]"
	}

	headerLines := fmt.Sprintf(
		" [gray]IP:[-] [green]%s[-] │ [gray]Stars:[-] [yellow]%s[-] │ [gray]Release:[-] [cyan]%s[-] │ [gray]NODE:[-] [white]%s[-]%s\n\n"+
			" [gray]Cores:[-] [white]%s[-] │ [gray]Arch:[-] [white]%s[-] │ [gray]OS:[-] [white]%s[-] │ [gray]CPU:[-] [white]%s[-]\n"+
			" [gray]Uptime:[-] [cyan]%s[-] │ [gray]Load:[-] [%s]%s[-] │ %s │ %s\n"+
			" [gray]Services:[-] %s\n"+
			" [gray]Ports:[-] [blue]%s[-]",
		d.System.ServerIP, ghStars, ghRelease, d.System.Hostname, errState,
		d.System.Cores, d.System.Arch, d.System.Os, d.System.CpuModel,
		d.System.Uptime, cLoad, d.System.LoadAverage, ramBar, diskBar,
		strings.Join(servicesStr, " │ "),
		pStr,
	)
	headerText.SetText(headerLines)

	// --- L3 Metrics ---
	globalBlockedStr := fmt.Sprintf("%d", d.Layer3.GlobalBlocked)
	if d.Layer3.ZeroTrustMode {
		globalBlockedStr = fmt.Sprintf("%d (Zero-Trust)", d.Layer3.GlobalBlocked)
	}
	l3Lines := fmt.Sprintf("\n [gray]Value:[-] [white]%s[-] [gray](L7/HA: %d)[-]\n [gray]GeoIP:[-] [white]%d[-] │ [gray]ASN:[-] [white]%d[-]",
		globalBlockedStr, d.Layer3.L7Banned, d.Layer3.GeoIPBlocked, d.Layer3.ASNBlocked)
	l3Text.SetText(l3Lines)

	// --- Risk Vectors ---
	re, rb, rr, rd, ra := 0, 0, 0, 0, 0
	if len(d.WAF.RiskRadar) >= 5 {
		re, rb, rr, rd, ra = d.WAF.RiskRadar[0], d.WAF.RiskRadar[1], d.WAF.RiskRadar[2], d.WAF.RiskRadar[3], d.WAF.RiskRadar[4]
	}
	vecLines := fmt.Sprintf("\n [gray]Value:[-] [white]%d[-] │ [gray]Detected:[-] [yellow]%d[-]\n [gray]Active Signatures:[-] [white]%d[-]\n\n [red]Exploits:[-] %d │ [yellow]Brute-Force:[-] %d │ [blue]Recon:[-] %d │ [gray]DDoS:[-] %d │ [yellow]Abuse/Spam:[-] %d",
		d.WAF.TotalBanned, d.WAF.TotalDetected, d.WAF.ActiveSignatures, re, rb, rr, rd, ra)
	vectorsText.SetText(vecLines)

	// --- Trusted ---
	wlIps := "None"
	if len(d.Whitelist.IPs) > 0 {
		if len(d.Whitelist.IPs) > 3 {
			wlIps = strings.Join(d.Whitelist.IPs[:3], ", ") + ", ..."
		} else {
			wlIps = strings.Join(d.Whitelist.IPs, ", ")
		}
	}
	truLines := fmt.Sprintf("\n [gray]Active IPs:[-] [white]%d[-]\n [gray]IPs:[-] [green]%s[-]", d.Whitelist.ActiveIPs, wlIps)
	trustedText.SetText(truLines)

	// --- Jails Table ---
	jailsTable.Clear()
	jailsTable.SetCell(0, 0, tview.NewTableCell("SIGNATURE / VECTOR").SetTextColor(tcell.ColorGray))
	jailsTable.SetCell(0, 1, tview.NewTableCell("MITRE ATT&CK").SetTextColor(tcell.ColorGray))
	jailsTable.SetCell(0, 2, tview.NewTableCell("LOAD").SetTextColor(tcell.ColorGray))
	for i := 0; i < 5 && i < len(d.WAF.SignaturesData); i++ {
		j := d.WAF.SignaturesData[i]
		mitre := strings.Split(j.Mitre, ":")[0]
		jailsTable.SetCell(i+1, 0, tview.NewTableCell(j.Name).SetTextColor(tcell.ColorAqua))
		jailsTable.SetCell(i+1, 1, tview.NewTableCell(mitre).SetTextColor(tcell.ColorWhite))
		jailsTable.SetCell(i+1, 2, tview.NewTableCell(fmt.Sprintf("%d", j.Count)).SetTextColor(tcell.ColorYellow))
	}

	// --- Top Attackers ---
	attackersTable.Clear()
	attackersTable.SetCell(0, 0, tview.NewTableCell("IP ADDRESS").SetTextColor(tcell.ColorGray))
	attackersTable.SetCell(0, 1, tview.NewTableCell("SEVERITY").SetTextColor(tcell.ColorGray))
	attackersTable.SetCell(0, 2, tview.NewTableCell("PORT").SetTextColor(tcell.ColorGray))
	attackersTable.SetCell(0, 3, tview.NewTableCell("COUNTRY").SetTextColor(tcell.ColorGray))
	attackersTable.SetCell(0, 4, tview.NewTableCell("ASN").SetTextColor(tcell.ColorGray))
	attackersTable.SetCell(0, 5, tview.NewTableCell("ISP").SetTextColor(tcell.ColorGray))
	for i := 0; i < 5 && i < len(d.WAF.TopAttackers); i++ {
		t := d.WAF.TopAttackers[i]
		attackersTable.SetCell(i+1, 0, tview.NewTableCell(t.IP).SetTextColor(tcell.ColorRed))
		attackersTable.SetCell(i+1, 1, tview.NewTableCell(t.Severity).SetTextColor(tcell.ColorFuchsia))
		attackersTable.SetCell(i+1, 2, tview.NewTableCell(t.Port).SetTextColor(tcell.ColorYellow))
		attackersTable.SetCell(i+1, 3, tview.NewTableCell(t.Country).SetTextColor(tcell.ColorWhite))
		attackersTable.SetCell(i+1, 4, tview.NewTableCell(t.ASN).SetTextColor(tcell.ColorAqua))
		attackersTable.SetCell(i+1, 5, tview.NewTableCell(t.ISP).SetTextColor(tcell.ColorWhite))
	}

	// --- Banned Table ---
	// Preserve selection
	r, c := bannedTable.GetSelection()
	bannedTable.Clear()
	bannedTable.SetCell(0, 0, tview.NewTableCell("IP ADDRESS").SetTextColor(tcell.ColorGray).SetSelectable(false))
	bannedTable.SetCell(0, 1, tview.NewTableCell("TRIGGERING").SetTextColor(tcell.ColorGray).SetSelectable(false))
	bannedTable.SetCell(0, 2, tview.NewTableCell("MITRE ATT&CK / TYPE").SetTextColor(tcell.ColorGray).SetSelectable(false))
	bannedTable.SetCell(0, 3, tview.NewTableCell("REASON (ATTEMPTED ATTACK)").SetTextColor(tcell.ColorGray).SetSelectable(false))

	recentlyUnbannedMu.Lock()
	now := time.Now()
	var filteredBanned []BannedIP
	for _, b := range d.WAF.BannedIPs {
		if unbanTime, exists := recentlyUnbanned[b.IP]; exists {
			if now.Sub(unbanTime) < 15*time.Second {
				continue
			} else {
				delete(recentlyUnbanned, b.IP)
			}
		}
		filteredBanned = append(filteredBanned, b)
	}
	recentlyUnbannedMu.Unlock()
	d.WAF.BannedIPs = filteredBanned

	if len(d.WAF.BannedIPs) == 0 && len(d.WAF.AllowedEvents) == 0 {
		bannedTable.SetCell(1, 0, tview.NewTableCell("Registry is empty. Architecture is secure.").SetTextColor(tcell.ColorGreen).SetSelectable(false))
	} else {
		row := 1
		for _, a := range d.WAF.AllowedEvents {
			bannedTable.SetCell(row, 0, tview.NewTableCell(a.IP).SetTextColor(tcell.ColorWhite))
			bannedTable.SetCell(row, 1, tview.NewTableCell(a.Service).SetTextColor(tcell.ColorYellow))
			bannedTable.SetCell(row, 2, tview.NewTableCell("ALLOWED").SetTextColor(tcell.ColorGreen))
			bannedTable.SetCell(row, 3, tview.NewTableCell(TranslateAllowedPayload(a.Service, a.Payload, a.IP)).SetTextColor(tcell.ColorGray))
			row++
		}
		for _, b := range d.WAF.BannedIPs {
			mitre := strings.Split(b.Mitre, ":")[0]
			payload := strings.ReplaceAll(strings.ReplaceAll(b.Payload, "\n", ""), "\r", "")

			var cVec tcell.Color
			j := strings.ToLower(b.Jail)
			if strings.Contains(j, "sqli") || strings.Contains(j, "xss") || strings.Contains(j, "lfi") || strings.Contains(j, "rce") || strings.Contains(j, "revshell") || strings.Contains(j, "webshell") || strings.Contains(j, "ssti") || strings.Contains(j, "ssrf") || strings.Contains(j, "jndi") || strings.Contains(j, "modsec") {
				cVec = tcell.ColorRed
			} else if strings.Contains(j, "ssh") || strings.Contains(j, "auth") || strings.Contains(j, "privesc") || strings.Contains(j, "prestashop") {
				cVec = tcell.ColorYellow
			} else if strings.Contains(j, "scan") || strings.Contains(j, "bot") || strings.Contains(j, "mapper") || strings.Contains(j, "enum") || strings.Contains(j, "hunter") || strings.Contains(j, "tls") || strings.Contains(j, "honeypot") || strings.Contains(j, "honeyport") {
				cVec = tcell.ColorBlue
			} else if strings.Contains(j, "flood") || strings.Contains(j, "slowloris") || strings.Contains(j, "dos") {
				cVec = tcell.ColorDarkGray
			} else {
				cVec = tcell.ColorYellow
			}

			switch b.Action {
			case "SHADOW-ALERT":
				bannedTable.SetCell(row, 0, tview.NewTableCell(b.IP).SetTextColor(tcell.ColorOrange))
				bannedTable.SetCell(row, 1, tview.NewTableCell("SHADOW-ALERT: "+b.Jail).SetTextColor(tcell.ColorOrange))
				bannedTable.SetCell(row, 2, tview.NewTableCell(mitre).SetTextColor(tcell.ColorOrange))
				bannedTable.SetCell(row, 3, tview.NewTableCell(TranslatePayload(b.Jail, payload, b.IP)).SetTextColor(tcell.ColorYellow))
			case "DETECTED":
				bannedTable.SetCell(row, 0, tview.NewTableCell(b.IP).SetTextColor(tcell.ColorYellow))
				bannedTable.SetCell(row, 1, tview.NewTableCell("DETECTED: "+b.Jail).SetTextColor(tcell.ColorYellow))
				bannedTable.SetCell(row, 2, tview.NewTableCell(mitre).SetTextColor(tcell.ColorYellow))
				bannedTable.SetCell(row, 3, tview.NewTableCell(TranslatePayload(b.Jail, payload, b.IP)).SetTextColor(tcell.ColorYellow))
			default:
				bannedTable.SetCell(row, 0, tview.NewTableCell(b.IP).SetTextColor(tcell.ColorWhite))
				bannedTable.SetCell(row, 1, tview.NewTableCell(b.Jail).SetTextColor(cVec))
				bannedTable.SetCell(row, 2, tview.NewTableCell(mitre).SetTextColor(tcell.ColorWhite))
				bannedTable.SetCell(row, 3, tview.NewTableCell(TranslatePayload(b.Jail, payload, b.IP)).SetTextColor(tcell.ColorWhite))
			}
			row++
		}
	}
	bannedTable.Select(r, c)
}

func printDashboardText() {
	bytes, err := os.ReadFile(DataFile) // #nosec
	if err != nil {
		fmt.Printf("=== SYSWARDEN ENTERPRISE DASHBOARD (SNAPSHOT) ===\n[ERROR] Telemetry data unreadable: %v\n", err)
		return
	}

	var d DashboardData
	if err := json.Unmarshal(bytes, &d); err != nil {
		fmt.Printf("=== SYSWARDEN ENTERPRISE DASHBOARD (SNAPSHOT) ===\n[ERROR] Invalid telemetry JSON: %v\n", err)
		return
	}

	load1Str := "0.00"
	if parts := strings.Split(d.System.LoadAverage, ","); len(parts) > 0 {
		load1Str = strings.TrimSpace(parts[0])
	}

	fmt.Println("=== SYSWARDEN ENTERPRISE DASHBOARD (SNAPSHOT) ===")
	fmt.Printf("[SYSTEM] NODE: %s | Uptime: %s | Load: %s\n", d.System.Hostname, d.System.Uptime, load1Str)
	fmt.Printf("[L3 FIREWALL] Global Blocks: %d (GeoIP: %d | ASN: %d)\n", d.Layer3.GlobalBlocked, d.Layer3.GeoIPBlocked, d.Layer3.ASNBlocked)
	fmt.Printf("[WAAP L7] Active Bans: %d\n", d.WAF.TotalBanned)

	// Format Jails
	var jails []string
	for i := 0; i < len(d.WAF.SignaturesData); i++ {
		jails = append(jails, fmt.Sprintf("%s (%d)", d.WAF.SignaturesData[i].Name, d.WAF.SignaturesData[i].Count))
	}
	if len(jails) > 0 {
		fmt.Printf("[WAAP JAILS] %s\n", strings.Join(jails, ", "))
	} else {
		fmt.Println("[WAAP JAILS] None")
	}

	fmt.Println("[TOP ATTACKERS]")
	if len(d.WAF.TopAttackers) == 0 {
		fmt.Println(" - None")
	} else {
		for i := 0; i < len(d.WAF.TopAttackers); i++ {
			a := d.WAF.TopAttackers[i]
			fmt.Printf(" - %s (%s / %s / %s)\n", a.IP, a.Country, a.ASN, a.ISP)
		}
	}
}
