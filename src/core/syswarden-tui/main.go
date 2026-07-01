package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
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
const SysWardenVersion = "v3.40.5"

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
	Services    []Service `json:"services"`
	Ports       []Port    `json:"ports"`
}

type Layer3 struct {
	GlobalBlocked int `json:"global_blocked"`
	GeoIPBlocked  int `json:"geoip_blocked"`
	ASNBlocked    int `json:"asn_blocked"`
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
	IP      string `json:"ip"`
	Port    string `json:"port"`
	Country string `json:"country"`
	ASN     string `json:"asn"`
	ISP     string `json:"isp"`
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
		AddItem(attackersTable, 0, 1, false)

	// 7. Banned IPs Table
	bannedTable = tview.NewTable().
		SetBorders(false).
		SetSelectable(true, false).
		SetFixed(1, 0)
	bannedTable.SetBorder(true).
		SetTitle(" [white]❖ WAF ALLOWED/BANNED IP REGISTRY (L4/L7)[-] ").
		SetBorderColor(tcell.ColorBlue)

	// Ensure safe exiting via Q/Ctrl+C
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup

	app.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Rune() == 'q' || event.Rune() == 'Q' || event.Key() == tcell.KeyCtrlC {
			cancel()
			app.Stop()
			return nil
		}
		return event
	})

	// Layout Setup
	mainFlex := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(headerText, 8, 1, false).
		AddItem(metricsFlex, 6, 1, false).
		AddItem(midFlex, 8, 1, false).
		AddItem(bannedTable, 0, 3, true)

	// Background Poller
	wg.Add(1)
	go func() {
		defer wg.Done()
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
		wg.Wait()
		panic(err)
	}
	wg.Wait()
}

func readDataAndUpdate() {
	bytes, err := os.ReadFile(DataFile)
	mu.Lock()
	if err != nil {
		fetchError = fmt.Errorf("data unreadable: %w", err)
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

func refreshUI() {
	mu.Lock()
	d := data
	currentErr := fetchError
	mu.Unlock()

	// --- Header Calculation ---
	totalThreats := d.Layer3.GlobalBlocked + d.WAF.TotalBanned
	noisePct, signalPct := "0.00%", "0.00%"
	if totalThreats > 0 {
		noisePct = fmt.Sprintf("%.2f%%", float64(d.Layer3.GlobalBlocked)/float64(totalThreats)*100)
		signalPct = fmt.Sprintf("%.2f%%", float64(d.WAF.TotalBanned)/float64(totalThreats)*100)
	}

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
		n := strings.ToUpper(strings.Split(s.Name, " ")[0])
		st := strings.ToUpper(s.Status)
		cSt := "red"
		switch st {
		case "ACTIVE", "ONLINE":
			cSt = "green"
		case "SKIPPED":
			cSt = "yellow"
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
		" [gray]Noise:[-] [green]%s[-] │ [gray]Signal:[-] [red]%s[-] │ [gray]Stars:[-] [yellow]%s[-] │ [gray]Release:[-] [cyan]%s[-] │ [gray]Node:[-] [white]%s[-]%s\n\n"+
			" [gray]Cores:[-] [white]%s[-] │ [gray]Arch:[-] [white]%s[-] │ [gray]OS:[-] [white]%s[-] │ [gray]CPU:[-] [white]%s[-]\n"+
			" [gray]Uptime:[-] [cyan]%s[-] │ [gray]Load:[-] [%s]%s[-] │ %s │ %s\n"+
			" [gray]Services:[-] %s\n"+
			" [gray]Ports:[-] [blue]%s[-]",
		noisePct, signalPct, ghStars, ghRelease, d.System.Hostname, errState,
		d.System.Cores, d.System.Arch, d.System.Os, d.System.CpuModel,
		d.System.Uptime, cLoad, d.System.LoadAverage, ramBar, diskBar,
		strings.Join(servicesStr, " │ "),
		pStr,
	)
	headerText.SetText(headerLines)

	// --- L3 Metrics ---
	l3Lines := fmt.Sprintf("\n [gray]Value:[-] [white]%d[-]\n [gray]GeoIP:[-] [white]%d[-] │ [gray]ASN:[-] [white]%d[-]",
		d.Layer3.GlobalBlocked, d.Layer3.GeoIPBlocked, d.Layer3.ASNBlocked)
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
	attackersTable.SetCell(0, 1, tview.NewTableCell("PORT").SetTextColor(tcell.ColorGray))
	attackersTable.SetCell(0, 2, tview.NewTableCell("COUNTRY").SetTextColor(tcell.ColorGray))
	attackersTable.SetCell(0, 3, tview.NewTableCell("ASN").SetTextColor(tcell.ColorGray))
	attackersTable.SetCell(0, 4, tview.NewTableCell("ISP").SetTextColor(tcell.ColorGray))
	for i := 0; i < 5 && i < len(d.WAF.TopAttackers); i++ {
		t := d.WAF.TopAttackers[i]
		attackersTable.SetCell(i+1, 0, tview.NewTableCell(t.IP).SetTextColor(tcell.ColorRed))
		attackersTable.SetCell(i+1, 1, tview.NewTableCell(t.Port).SetTextColor(tcell.ColorYellow))
		attackersTable.SetCell(i+1, 2, tview.NewTableCell(t.Country).SetTextColor(tcell.ColorWhite))
		attackersTable.SetCell(i+1, 3, tview.NewTableCell(t.ASN).SetTextColor(tcell.ColorAqua))
		attackersTable.SetCell(i+1, 4, tview.NewTableCell(t.ISP).SetTextColor(tcell.ColorWhite))
	}

	// --- Banned Table ---
	// Preserve selection
	r, c := bannedTable.GetSelection()
	bannedTable.Clear()
	bannedTable.SetCell(0, 0, tview.NewTableCell("IP ADDRESS").SetTextColor(tcell.ColorGray).SetSelectable(false))
	bannedTable.SetCell(0, 1, tview.NewTableCell("TARGET (PORT/JAIL/SERVICES)").SetTextColor(tcell.ColorGray).SetSelectable(false))
	bannedTable.SetCell(0, 2, tview.NewTableCell("MITRE ATT&CK / TYPE").SetTextColor(tcell.ColorGray).SetSelectable(false))
	bannedTable.SetCell(0, 3, tview.NewTableCell("TRIGGER PAYLOAD").SetTextColor(tcell.ColorGray).SetSelectable(false))

	if len(d.WAF.BannedIPs) == 0 && len(d.WAF.AllowedEvents) == 0 {
		bannedTable.SetCell(1, 0, tview.NewTableCell("Registry is empty. Architecture is secure.").SetTextColor(tcell.ColorGreen).SetSelectable(false))
	} else {
		row := 1
		for _, a := range d.WAF.AllowedEvents {
			bannedTable.SetCell(row, 0, tview.NewTableCell(a.IP).SetTextColor(tcell.ColorWhite))
			bannedTable.SetCell(row, 1, tview.NewTableCell(a.Service).SetTextColor(tcell.ColorYellow))
			bannedTable.SetCell(row, 2, tview.NewTableCell("ALLOWED").SetTextColor(tcell.ColorGreen))
			bannedTable.SetCell(row, 3, tview.NewTableCell(a.Payload).SetTextColor(tcell.ColorGray))
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
				bannedTable.SetCell(row, 3, tview.NewTableCell(payload).SetTextColor(tcell.ColorYellow))
			case "DETECTED":
				bannedTable.SetCell(row, 0, tview.NewTableCell(b.IP).SetTextColor(tcell.ColorYellow))
				bannedTable.SetCell(row, 1, tview.NewTableCell("DETECTED: "+b.Jail).SetTextColor(tcell.ColorYellow))
				bannedTable.SetCell(row, 2, tview.NewTableCell(mitre).SetTextColor(tcell.ColorYellow))
				bannedTable.SetCell(row, 3, tview.NewTableCell(payload).SetTextColor(tcell.ColorYellow))
			default:
				bannedTable.SetCell(row, 0, tview.NewTableCell(b.IP).SetTextColor(tcell.ColorWhite))
				bannedTable.SetCell(row, 1, tview.NewTableCell(b.Jail).SetTextColor(cVec))
				bannedTable.SetCell(row, 2, tview.NewTableCell(mitre).SetTextColor(tcell.ColorWhite))
				bannedTable.SetCell(row, 3, tview.NewTableCell(payload).SetTextColor(tcell.ColorWhite))
			}
			row++
		}
	}
	bannedTable.Select(r, c)
}

func printDashboardText() {
	bytes, err := os.ReadFile(DataFile)
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
	fmt.Printf("[SYSTEM] Node: %s | Uptime: %s | Load: %s\n", d.System.Hostname, d.System.Uptime, load1Str)
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
