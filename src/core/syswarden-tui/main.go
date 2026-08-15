package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
	"golang.org/x/term"
)

const DataFile = "/var/lib/syswarden/ui/data.json"
const SysWardenVersion = "v4.02.11"
const haPeerCABundleFile = "/etc/syswarden/ha-ca.pem"
const haModularConfigDirectory = "/etc/syswarden/config"
const maxTUIHAResponseBytes = 1024 * 1024

var (
	activeNodeIP        = "local"
	haPeerPort          = "62026"
	haBearerToken       string
	haRuntimeConfigErr  error
	haRuntimeConfigMu   sync.RWMutex
	httpClient, haCAErr = newHAHTTPClient(haPeerCABundleFile)
)

func newHAHTTPClient(caBundleFile string) (*http.Client, error) {
	rootCAs, err := loadHATrustRoots(caBundleFile)
	if err != nil {
		return nil, err
	}
	client := &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS13,
				RootCAs:    rootCAs,
			},
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return fmt.Errorf("HA redirects are disabled")
		},
	}
	return client, nil
}

func loadHATrustRoots(caBundleFile string) (*x509.CertPool, error) {
	caBundleFile = filepath.Clean(caBundleFile)
	info, err := os.Lstat(caBundleFile)
	if errors.Is(err, fs.ErrNotExist) {
		roots, systemErr := x509.SystemCertPool()
		if systemErr != nil || roots == nil {
			roots = x509.NewCertPool()
		}
		return roots, nil
	}
	if err != nil {
		return nil, fmt.Errorf("inspect HA CA bundle: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("HA CA bundle must be a regular file")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || (int(stat.Uid) != 0 && int(stat.Uid) != os.Geteuid()) {
		return nil, fmt.Errorf("HA CA bundle has an unexpected owner")
	}
	if info.Mode().Perm()&0022 != 0 {
		return nil, fmt.Errorf("HA CA bundle must not be group/world writable")
	}
	parent := filepath.Dir(caBundleFile)
	parentInfo, err := os.Lstat(parent)
	if err != nil || !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("HA CA bundle parent must be a real directory")
	}
	root, err := os.OpenRoot(parent)
	if err != nil {
		return nil, fmt.Errorf("open HA CA bundle parent: %w", err)
	}
	defer root.Close()
	openedParent, err := root.Stat(".")
	if err != nil || !os.SameFile(parentInfo, openedParent) {
		return nil, fmt.Errorf("HA CA bundle parent changed while opening")
	}
	file, err := root.Open(filepath.Base(caBundleFile))
	if err != nil {
		return nil, fmt.Errorf("open HA CA bundle: %w", err)
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect opened HA CA bundle: %w", err)
	}
	currentInfo, err := root.Lstat(filepath.Base(caBundleFile))
	if err != nil || !openedInfo.Mode().IsRegular() || !currentInfo.Mode().IsRegular() ||
		!os.SameFile(info, openedInfo) || !os.SameFile(openedInfo, currentInfo) {
		return nil, fmt.Errorf("HA CA bundle changed while opening")
	}
	const maxHACABytes = 1024 * 1024
	bundle, err := io.ReadAll(io.LimitReader(file, maxHACABytes+1))
	if err != nil {
		return nil, fmt.Errorf("read HA CA bundle: %w", err)
	}
	roots := x509.NewCertPool()
	if len(bundle) > maxHACABytes {
		return nil, fmt.Errorf("HA CA bundle contains no valid certificate")
	}
	if err := addStrictHATrustCertificates(roots, bundle); err != nil {
		return nil, fmt.Errorf("HA CA bundle is invalid: %w", err)
	}
	return roots, nil
}

func addStrictHATrustCertificates(roots *x509.CertPool, bundle []byte) error {
	if roots == nil {
		return fmt.Errorf("certificate pool is unavailable")
	}
	remaining := bundle
	certificates := 0
	for {
		remaining = bytes.TrimLeft(remaining, " \t\r\n")
		if len(remaining) == 0 {
			break
		}
		if !bytes.HasPrefix(remaining, []byte("-----BEGIN CERTIFICATE-----")) {
			return fmt.Errorf("unexpected data outside a CERTIFICATE block")
		}
		block, rest := pem.Decode(remaining)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return fmt.Errorf("invalid CERTIFICATE block")
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("parse CERTIFICATE block: %w", err)
		}
		roots.AddCert(certificate)
		certificates++
		remaining = rest
	}
	if certificates == 0 {
		return fmt.Errorf("bundle contains no certificate")
	}
	return nil
}

func haPeerURL(peer, path string) (string, error) {
	peer = strings.TrimSpace(peer)
	if strings.HasPrefix(peer, "[") && strings.HasSuffix(peer, "]") {
		peer = strings.TrimSuffix(strings.TrimPrefix(peer, "["), "]")
	}
	address, err := netip.ParseAddr(peer)
	if err != nil || address.Is4In6() || address.Zone() != "" {
		return "", fmt.Errorf("HA destination must be an exact IP address")
	}
	haRuntimeConfigMu.RLock()
	port := haPeerPort
	haRuntimeConfigMu.RUnlock()
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return "", fmt.Errorf("invalid HA peer port")
	}
	return "https://" + net.JoinHostPort(address.String(), strconv.Itoa(portNumber)) + path, nil
}

func haGet(url string) (*http.Response, error) {
	if haCAErr != nil {
		return nil, fmt.Errorf("HA TLS trust configuration: %w", haCAErr)
	}
	haRuntimeConfigMu.RLock()
	token := haBearerToken
	configErr := haRuntimeConfigErr
	haRuntimeConfigMu.RUnlock()
	if configErr != nil {
		return nil, fmt.Errorf("HA configuration unavailable: %w", configErr)
	}
	if token == "" || strings.TrimSpace(token) != token {
		return nil, fmt.Errorf("HA bearer token is required; configure integrations.ha.token and upgrade legacy HA clients")
	}
	request, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := httpClient.Do(request)
	if err != nil {
		return nil, err
	}
	wire, readErr := io.ReadAll(io.LimitReader(response.Body, maxTUIHAResponseBytes+1))
	closeErr := response.Body.Close()
	if readErr != nil {
		return nil, fmt.Errorf("read HA response: %w", readErr)
	}
	if len(wire) > maxTUIHAResponseBytes {
		return nil, fmt.Errorf("HA response exceeds %d bytes", maxTUIHAResponseBytes)
	}
	if closeErr != nil {
		return nil, fmt.Errorf("close HA response: %w", closeErr)
	}
	response.Body = io.NopCloser(bytes.NewReader(wire))
	return response, nil
}

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
	Timestamp string `json:"timestamp"`
	IP        string `json:"ip"`
	Jail      string `json:"jail"`
	Payload   string `json:"payload"`
	Mitre     string `json:"mitre"`
	Action    string `json:"action"`
}

type Attacker struct {
	IP       string `json:"ip"`
	Severity string `json:"severity"`
	Port     string `json:"port"`
	Country  string `json:"country"`
	ASN      string `json:"asn"`
	Threat   string `json:"threat"`
	Org      string `json:"org"`
	Hits     int    `json:"hits"`
	LastSeen string `json:"last_seen"`
}

type TargetedPort struct {
	Port      string `json:"port"`
	Service   string `json:"service"`
	Hits      int    `json:"hits"`
	UniqueIPs int    `json:"unique_ips"`
}

type WAF struct {
	TotalBanned      int            `json:"total_banned"`
	TotalDetected    int            `json:"total_detected"`
	ActiveSignatures int            `json:"active_signatures"`
	SignaturesData   []JailData     `json:"signatures_data"`
	TargetedPorts    []TargetedPort `json:"targeted_ports"`
	BannedIPs        []BannedIP     `json:"banned_ips"`
	TopAttackers     []Attacker     `json:"top_attackers"`
	RiskRadar        []int          `json:"risk_radar"`
	Sparkline24h     [24]int        `json:"sparkline_24h"`
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
	ProfileName   string     `json:"profile_name"`
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
	portsTable     *tview.Table
	sparklineText  *tview.TextView
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

	// 5. Ports Table
	portsTable = tview.NewTable().SetBorders(false).SetSelectable(false, false)
	portsTable.SetBorder(true).SetTitle(" [white]❖ TOP TARGETED PORTS[-] ").SetBorderColor(tcell.ColorDarkGray)

	// 5b. Sparkline
	sparklineText = tview.NewTextView().SetDynamicColors(true).SetWrap(false).SetTextAlign(tview.AlignLeft)
	sparklineText.SetBorder(true).SetTitle(" [white]❖ WAF L7 BANS (24H)[-] ").SetBorderColor(tcell.ColorDarkGray)

	// 6. Top Attackers Table
	attackersTable = tview.NewTable().SetBorders(false).SetSelectable(false, false)
	attackersTable.SetBorder(true).SetTitle(" [white]❖ TOP ATTACKERS (OSINT HISTORY)[-] ").SetBorderColor(tcell.ColorDarkGray)

	midFlex := tview.NewFlex().
		AddItem(portsTable, 0, 3, false).
		AddItem(attackersTable, 0, 5, false)

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
		AddItem(sparklineText, 10, 1, false).
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
									go func(targetIP string) {
										if err := runSyswardenIPAction("unblock", targetIP); err != nil {
											showTUIActionError(app, mainFlex, "unblock", targetIP, err)
											return
										}
										recentlyUnbannedMu.Lock()
										recentlyUnbanned[targetIP] = time.Now()
										recentlyUnbannedMu.Unlock()
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
		} else if event.Rune() == 'w' || event.Rune() == 'W' {
			row, _ := bannedTable.GetSelection()
			if row > 0 {
				cell := bannedTable.GetCell(row, 0)
				if cell != nil {
					ip := cell.Text
					if ip != "" {
						modal := tview.NewModal().
							SetText(fmt.Sprintf("[white]Do you want to permanently WHITELIST IP %s?[-]", ip)).
							AddButtons([]string{"y", "n"}).
							SetDoneFunc(func(buttonIndex int, buttonLabel string) {
								if buttonLabel == "y" {
									go func(targetIP string) {
										if err := runSyswardenIPAction("whitelist", targetIP); err != nil {
											showTUIActionError(app, mainFlex, "whitelist", targetIP, err)
											return
										}
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
		} else if event.Rune() == 'b' || event.Rune() == 'B' {
			row, _ := bannedTable.GetSelection()
			if row > 0 {
				cell := bannedTable.GetCell(row, 0)
				stateCell := bannedTable.GetCell(row, 3)
				if cell != nil && stateCell != nil {
					ip := cell.Text
					state := stateCell.Text
					if ip != "" && state == "DETECT" {
						modal := tview.NewModal().
							SetText(fmt.Sprintf("[white]Do you want to permanently BAN IP %s?[-]", ip)).
							AddButtons([]string{"y", "n"}).
							SetDoneFunc(func(buttonIndex int, buttonLabel string) {
								if buttonLabel == "y" {
									go func(targetIP string) {
										if err := runSyswardenIPAction("block", targetIP); err != nil {
											showTUIActionError(app, mainFlex, "block", targetIP, err)
											return
										}
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

func showTUIActionError(app *tview.Application, mainFlex *tview.Flex, action, target string, err error) {
	app.QueueUpdateDraw(func() {
		modal := tview.NewModal().
			SetText(fmt.Sprintf("[red]SysWarden %s failed for %s: %v[-]", action, target, err)).
			AddButtons([]string{"ok"}).
			SetDoneFunc(func(int, string) { app.SetRoot(mainFlex, true) })
		app.SetRoot(modal, false)
	})
}

// --- P2P MESH TUI LOGIC ---

type tuiHAConfig struct {
	Enabled  bool
	PeerIPs  []string
	PeerPort string
	Token    string
}

func getHAPeers() []string {
	cfg, err := loadTUIHAConfig(haModularConfigDirectory, haLegacyConfigFile)
	haRuntimeConfigMu.Lock()
	defer haRuntimeConfigMu.Unlock()
	haRuntimeConfigErr = err
	if err != nil || !cfg.Enabled {
		haBearerToken = ""
		return nil
	}
	haPeerPort = cfg.PeerPort
	haBearerToken = cfg.Token
	return dialableTUIHAPeers(cfg.PeerIPs)
}

func loadTUIHAConfig(modularDirectory, legacyFile string) (tuiHAConfig, error) {
	info, err := os.Lstat(modularDirectory)
	if err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return tuiHAConfig{}, fmt.Errorf("modular HA config must be a real directory")
		}
		cfg := tuiHAConfig{PeerPort: "62026"}
		files := make([]string, 0)
		master := filepath.Join(modularDirectory, "config.toml")
		if _, statErr := os.Lstat(master); statErr == nil {
			files = append(files, master)
		} else if !errors.Is(statErr, fs.ErrNotExist) {
			return tuiHAConfig{}, fmt.Errorf("inspect modular HA master config: %w", statErr)
		}
		modules := filepath.Join(modularDirectory, "modules")
		if moduleInfo, statErr := os.Lstat(modules); statErr == nil {
			if moduleInfo.Mode()&os.ModeSymlink != 0 || !moduleInfo.IsDir() {
				return tuiHAConfig{}, fmt.Errorf("modular HA modules path must be a real directory")
			}
			entries, readErr := os.ReadDir(modules)
			if readErr != nil {
				return tuiHAConfig{}, fmt.Errorf("read modular HA modules: %w", readErr)
			}
			moduleFiles := make([]string, 0)
			for _, entry := range entries {
				if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".toml") {
					moduleFiles = append(moduleFiles, filepath.Join(modules, entry.Name()))
				}
			}
			sort.Strings(moduleFiles)
			files = append(files, moduleFiles...)
		} else if !errors.Is(statErr, fs.ErrNotExist) {
			return tuiHAConfig{}, fmt.Errorf("inspect modular HA modules: %w", statErr)
		}
		for _, file := range files {
			wire, readErr := readTUIConfigFile(file)
			if readErr != nil {
				return tuiHAConfig{}, readErr
			}
			if err := mergeTUIHATOML(&cfg, wire); err != nil {
				return tuiHAConfig{}, fmt.Errorf("parse modular HA configuration: %w", err)
			}
		}
		return validateTUIHAConfig(cfg)
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return tuiHAConfig{}, fmt.Errorf("inspect modular HA configuration: %w", err)
	}
	wire, err := readTUIConfigFile(legacyFile)
	if err != nil {
		return tuiHAConfig{}, fmt.Errorf("read legacy HA configuration: %w", err)
	}
	cfg, err := parseTUILegacyHAConfig(wire)
	if err != nil {
		return tuiHAConfig{}, err
	}
	return validateTUIHAConfig(cfg)
}

func readTUIConfigFile(path string) ([]byte, error) {
	path = filepath.Clean(path)
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("HA configuration file must be regular")
	}
	if info.Mode().Perm()&0022 != 0 {
		return nil, fmt.Errorf("HA configuration file must not be group/world writable")
	}
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	defer root.Close()
	file, err := root.Open(filepath.Base(path))
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return nil, err
	}
	current, err := root.Lstat(filepath.Base(path))
	if err != nil || !opened.Mode().IsRegular() || !current.Mode().IsRegular() ||
		!os.SameFile(info, opened) || !os.SameFile(opened, current) {
		return nil, fmt.Errorf("HA configuration file changed while opening")
	}
	const maxConfigBytes = 1024 * 1024
	wire, err := io.ReadAll(io.LimitReader(file, maxConfigBytes+1))
	if err != nil {
		return nil, err
	}
	if len(wire) > maxConfigBytes {
		return nil, fmt.Errorf("HA configuration file is too large")
	}
	return wire, nil
}

func mergeTUIHATOML(cfg *tuiHAConfig, wire []byte) error {
	scanner := bufio.NewScanner(strings.NewReader(string(wire)))
	section := ""
	seen := make(map[string]struct{})
	for scanner.Scan() {
		line := strings.TrimSpace(stripTUIConfigComment(scanner.Text()))
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") {
			if !strings.HasSuffix(line, "]") {
				return fmt.Errorf("invalid TOML section")
			}
			section = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(line, "["), "]"))
			continue
		}
		if section != "integrations.ha" {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			return fmt.Errorf("invalid HA TOML assignment")
		}
		key, value := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
		if _, duplicate := seen[key]; duplicate {
			return fmt.Errorf("duplicate HA TOML key")
		}
		seen[key] = struct{}{}
		switch key {
		case "enabled":
			parsed, err := strconv.ParseBool(value)
			if err != nil {
				return err
			}
			cfg.Enabled = parsed
		case "peer_ips":
			values, err := parseTUIStringArray(value)
			if err != nil {
				return err
			}
			cfg.PeerIPs = values
		case "peer_port":
			cfg.PeerPort = strings.Trim(value, "\"'")
		case "token":
			parsed, err := parseTUIQuotedString(value)
			if err != nil {
				return err
			}
			cfg.Token = parsed
		}
	}
	return scanner.Err()
}

func stripTUIConfigComment(line string) string {
	var quote rune
	escaped := false
	for index, character := range line {
		if escaped {
			escaped = false
			continue
		}
		if character == '\\' && quote == '"' {
			escaped = true
			continue
		}
		if character == '\'' || character == '"' {
			if quote == 0 {
				quote = character
			} else if quote == character {
				quote = 0
			}
			continue
		}
		if character == '#' && quote == 0 {
			return line[:index]
		}
	}
	return line
}

func parseTUIQuotedString(value string) (string, error) {
	value = strings.TrimSpace(value)
	if len(value) < 2 {
		return "", fmt.Errorf("HA TOML value must be quoted")
	}
	if value[0] == '\'' && value[len(value)-1] == '\'' {
		return value[1 : len(value)-1], nil
	}
	if value[0] != '"' || value[len(value)-1] != '"' {
		return "", fmt.Errorf("HA TOML value must be quoted")
	}
	return strconv.Unquote(value)
}

func parseTUIStringArray(value string) ([]string, error) {
	value = strings.TrimSpace(value)
	if len(value) < 2 || value[0] != '[' || value[len(value)-1] != ']' {
		return nil, fmt.Errorf("HA peer_ips must be a string array")
	}
	inner := strings.TrimSpace(value[1 : len(value)-1])
	if inner == "" {
		return []string{}, nil
	}
	parts := strings.Split(inner, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		parsed, err := parseTUIQuotedString(strings.TrimSpace(part))
		if err != nil {
			return nil, err
		}
		result = append(result, parsed)
	}
	return result, nil
}

func parseTUILegacyHAConfig(wire []byte) (tuiHAConfig, error) {
	cfg := tuiHAConfig{PeerPort: "62026"}
	scanner := bufio.NewScanner(strings.NewReader(string(wire)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		value := strings.Trim(strings.TrimSpace(parts[1]), "\"'")
		switch strings.TrimSpace(parts[0]) {
		case "SYSWARDEN_HA_ENABLED":
			cfg.Enabled = value == "y" || value == "1" || strings.EqualFold(value, "true")
		case "SYSWARDEN_HA_PEER_IP":
			cfg.PeerIPs = strings.Fields(strings.ReplaceAll(value, ",", " "))
		case "SYSWARDEN_HA_PEER_PORT":
			cfg.PeerPort = value
		case "SYSWARDEN_HA_TOKEN":
			cfg.Token = value
		}
	}
	return cfg, scanner.Err()
}

func validateTUIHAConfig(cfg tuiHAConfig) (tuiHAConfig, error) {
	if cfg.PeerPort == "" {
		cfg.PeerPort = "62026"
	}
	port, err := strconv.Atoi(cfg.PeerPort)
	if err != nil || port < 1 || port > 65535 {
		return tuiHAConfig{}, fmt.Errorf("invalid HA peer port")
	}
	if !cfg.Enabled {
		return cfg, nil
	}
	if cfg.Token == "" || strings.TrimSpace(cfg.Token) != cfg.Token {
		return tuiHAConfig{}, fmt.Errorf("HA bearer token is required; configure integrations.ha.token and upgrade legacy HA clients")
	}
	if len(cfg.PeerIPs) == 0 {
		return tuiHAConfig{}, fmt.Errorf("HA peer_ips is required")
	}
	for _, peer := range cfg.PeerIPs {
		if strings.Contains(peer, "/") {
			prefix, err := netip.ParsePrefix(peer)
			if err != nil || prefix.Addr().Is4In6() || prefix.Addr().Zone() != "" || prefix.Addr() != prefix.Masked().Addr() {
				return tuiHAConfig{}, fmt.Errorf("invalid HA peer CIDR")
			}
			continue
		}
		address, err := netip.ParseAddr(strings.Trim(peer, "[]"))
		if err != nil || address.Is4In6() || address.Zone() != "" {
			return tuiHAConfig{}, fmt.Errorf("invalid exact HA peer")
		}
	}
	return cfg, nil
}

func dialableTUIHAPeers(configured []string) []string {
	peers := make([]string, 0, len(configured))
	seen := make(map[string]struct{}, len(configured))
	for _, peer := range configured {
		if strings.Contains(peer, "/") {
			continue
		}
		address, err := netip.ParseAddr(strings.Trim(peer, "[]"))
		if err != nil || address.Is4In6() || address.Zone() != "" {
			continue
		}
		canonical := address.String()
		if _, duplicate := seen[canonical]; duplicate {
			continue
		}
		seen[canonical] = struct{}{}
		peers = append(peers, canonical)
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
		table.SetCell(1, 0, tview.NewTableCell("No dialable exact HA peers configured").SetTextColor(tcell.ColorGray))
	} else {
		for i, ip := range peers {
			row := i + 1
			table.SetCell(row, 0, tview.NewTableCell("Probing...").SetTextColor(tcell.ColorGray))
			table.SetCell(row, 1, tview.NewTableCell(ip).SetTextColor(tcell.ColorWhite))
			table.SetCell(row, 2, tview.NewTableCell("...").SetTextColor(tcell.ColorGray))
			table.SetCell(row, 3, tview.NewTableCell("[gray]WAITING[-]").SetTextColor(tcell.ColorGray))
			table.SetCell(row, 4, tview.NewTableCell("...").SetTextColor(tcell.ColorGray))

			go func(ip string, r int) {
				endpoint, endpointErr := haPeerURL(ip, "/ha/status")
				var resp *http.Response
				err := endpointErr
				if err == nil {
					resp, err = haGet(endpoint)
				}

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
		endpoint, reqErr := haPeerURL(activeNodeIP, "/ha/telemetry")
		var resp *http.Response
		if reqErr == nil {
			resp, reqErr = haGet(endpoint)
		}
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

func TranslateAllowedPayload(service, payload, ip, timestamp string) string {
	ts := timestamp
	if ts == "" {
		ts = time.Now().Format("2006-01-02 15:04:05")
	}
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

func TranslatePayload(jail, payload, ip, timestamp string) string {
	ts := timestamp
	if ts == "" {
		ts = time.Now().Format("2006-01-02 15:04:05")
	}
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
		port := ""
		if dptIdx := strings.Index(payload, "DPT="); dptIdx != -1 {
			pStr := payload[dptIdx+4:]
			if spaceIdx := strings.Index(pStr, " "); spaceIdx != -1 {
				port = pStr[:spaceIdx]
			}
		} else if protoIdx := strings.Index(payload, "PROTO="); protoIdx != -1 {
			pStr := payload[protoIdx+6:]
			if spaceIdx := strings.Index(pStr, " "); spaceIdx != -1 {
				port = pStr[:spaceIdx]
			}
		}

		if port == "" {
			return fmt.Sprintf("[%s] Attempted network scan by IP %s %s", ts, ip, url)
		}

		if port == "ICMP" || port == "ICMPv6" || port == "IGMP" || port == "GRE" || port == "IPSEC" || port == "IPIP" {
			return fmt.Sprintf("[%s] Attempted network sweep (Protocol: %s) by IP %s %s", ts, port, ip, url)
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

	profileStr := ""
	if d.ProfileName != "" {
		profileStr = fmt.Sprintf(" │ [gray]Profile:[-] [yellow]%s[-]", d.ProfileName)
	}

	headerLines := fmt.Sprintf(
		" [gray]IP:[-] [green]%s[-] │ [gray]Stars:[-] [yellow]%s[-] │ [gray]Release:[-] [cyan]%s[-]%s │ [gray]NODE:[-] [white]%s[-]%s\n\n"+
			" [gray]Cores:[-] [white]%s[-] │ [gray]Arch:[-] [white]%s[-] │ [gray]OS:[-] [white]%s[-] │ [gray]CPU:[-] [white]%s[-]\n"+
			" [gray]Uptime:[-] [cyan]%s[-] │ [gray]Load:[-] [%s]%s[-] │ %s │ %s\n"+
			" [gray]Services:[-] %s\n"+
			" [gray]Ports:[-] [blue]%s[-]",
		d.System.ServerIP, ghStars, ghRelease, profileStr, d.System.Hostname, errState,
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
	l3Lines := fmt.Sprintf(" [gray]Value:[-] [white]%s[-] [gray](L7/HA: %d)[-]\n [gray]GeoIP:[-] [white]%d[-] │ [gray]ASN:[-] [white]%d[-]",
		globalBlockedStr, d.Layer3.L7Banned, d.Layer3.GeoIPBlocked, d.Layer3.ASNBlocked)
	l3Text.SetText(l3Lines)

	// --- Risk Vectors ---
	re, rb, rr, rd, ra := 0, 0, 0, 0, 0
	if len(d.WAF.RiskRadar) >= 5 {
		re, rb, rr, rd, ra = d.WAF.RiskRadar[0], d.WAF.RiskRadar[1], d.WAF.RiskRadar[2], d.WAF.RiskRadar[3], d.WAF.RiskRadar[4]
	}
	vecLines := fmt.Sprintf(" [gray]WAF L7 Bans:[-] [white]%d[-] │ [gray]Detected:[-] [yellow]%d[-]\n [gray]Active Signatures:[-] [white]%d[-]\n\n [red]Exploits:[-] %d │ [yellow]Brute-Force:[-] %d │ [blue]Recon:[-] %d │ [gray]DDoS:[-] %d │ [yellow]Abuse/Spam:[-] %d",
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
	truLines := fmt.Sprintf(" [gray]Active IPs:[-] [white]%d[-]\n [gray]IPs:[-] [green]%s[-]", d.Whitelist.ActiveIPs, wlIps)
	trustedText.SetText(truLines)

	// --- Ports Table ---
	portsTable.Clear()
	portsTable.SetCell(0, 0, tview.NewTableCell("PORT").SetTextColor(tcell.ColorGray))
	portsTable.SetCell(0, 1, tview.NewTableCell("SERVICE").SetTextColor(tcell.ColorGray))
	portsTable.SetCell(0, 2, tview.NewTableCell("HITS").SetTextColor(tcell.ColorGray))
	portsTable.SetCell(0, 3, tview.NewTableCell("UNIQUE IPS").SetTextColor(tcell.ColorGray))
	for i := 0; i < 5 && i < len(d.WAF.TargetedPorts); i++ {
		p := d.WAF.TargetedPorts[i]
		portsTable.SetCell(i+1, 0, tview.NewTableCell(p.Port).SetTextColor(tcell.ColorAqua))
		portsTable.SetCell(i+1, 1, tview.NewTableCell(p.Service).SetTextColor(tcell.ColorWhite))
		portsTable.SetCell(i+1, 2, tview.NewTableCell(fmt.Sprintf("%d", p.Hits)).SetTextColor(tcell.ColorYellow))
		portsTable.SetCell(i+1, 3, tview.NewTableCell(fmt.Sprintf("%d", p.UniqueIPs)).SetTextColor(tcell.ColorBlue))
	}

	// --- Sparkline (ASCII Multi-line Graph) ---
	_, _, graphWidth, _ := sparklineText.GetInnerRect()
	if graphWidth < 50 {
		graphWidth = 72 // fallback minimum
	}

	maxBans := 1
	for _, v := range d.WAF.Sparkline24h {
		if v > maxBans {
			maxBans = v
		}
	}
	halfMax := maxBans / 2
	if halfMax == 0 {
		halfMax = 1
	}

	wPerPoint := (graphWidth - 12) / 24
	if wPerPoint < 1 {
		wPerPoint = 1
	}

	var line3, line2, line1, line0 strings.Builder
	for _, v := range d.WAF.Sparkline24h {
		blockStr := strings.Repeat("█", wPerPoint-1) + " "
		emptyStr := strings.Repeat(" ", wPerPoint)

		if v == 0 {
			line0.WriteString(emptyStr)
			line1.WriteString(emptyStr)
			line2.WriteString(emptyStr)
			line3.WriteString(emptyStr)
		} else {
			pct := float64(v) / float64(maxBans)
			if pct >= 0.75 {
				line0.WriteString(blockStr)
				line1.WriteString(blockStr)
				line2.WriteString(blockStr)
				line3.WriteString(blockStr)
			} else if pct >= 0.50 {
				line0.WriteString(emptyStr)
				line1.WriteString(blockStr)
				line2.WriteString(blockStr)
				line3.WriteString(blockStr)
			} else if pct >= 0.25 {
				line0.WriteString(emptyStr)
				line1.WriteString(emptyStr)
				line2.WriteString(blockStr)
				line3.WriteString(blockStr)
			} else {
				line0.WriteString(emptyStr)
				line1.WriteString(emptyStr)
				line2.WriteString(emptyStr)
				line3.WriteString(blockStr)
			}
		}
	}

	xAxis := "     └─"
	for i := 0; i < 24; i++ {
		seg := strings.Repeat("─", wPerPoint/2) + "┴" + strings.Repeat("─", wPerPoint-(wPerPoint/2)-1)
		xAxis += seg
	}
	xAxis += strings.Repeat("─", wPerPoint/2) + "┴─┐"

	nowTime := time.Now()
	xLabels := strings.Repeat(" ", 6+(wPerPoint/2))
	for i := 0; i <= 24; i += 3 {
		tickTime := nowTime.Add(time.Duration(i-23) * time.Hour)
		xLabels += fmt.Sprintf("%sh", tickTime.Format("15"))
		if i < 24 {
			spaceCount := (3 * wPerPoint) - 3
			if spaceCount > 0 {
				xLabels += strings.Repeat(" ", spaceCount)
			}
		}
	}

	graph := fmt.Sprintf(" [gray]%4d ┤[-] [white]%s[-]\n", maxBans, line0.String())
	graph += fmt.Sprintf(" [gray]     │[-] [white]%s[-]\n", line1.String())
	graph += fmt.Sprintf(" [gray]%4d ┤[-] [white]%s[-]\n", halfMax, line2.String())
	graph += fmt.Sprintf(" [gray]   0 ┤[-] [white]%s[-]\n", line3.String())
	graph += fmt.Sprintf(" [gray]%s[-]\n", xAxis)
	graph += fmt.Sprintf(" [gray]%s[-]\n", xLabels)

	sparklineText.SetText("\n" + graph)

	// --- Top Attackers ---
	attackersTable.Clear()
	attackersTable.SetCell(0, 0, tview.NewTableCell("IP ADDRESS").SetTextColor(tcell.ColorGray))
	attackersTable.SetCell(0, 1, tview.NewTableCell("HITS").SetTextColor(tcell.ColorGray))
	attackersTable.SetCell(0, 2, tview.NewTableCell("LAST SEEN").SetTextColor(tcell.ColorGray))
	attackersTable.SetCell(0, 3, tview.NewTableCell("SEVERITY").SetTextColor(tcell.ColorGray))
	attackersTable.SetCell(0, 4, tview.NewTableCell("PORT").SetTextColor(tcell.ColorGray))
	attackersTable.SetCell(0, 5, tview.NewTableCell("COUNTRY").SetTextColor(tcell.ColorGray))
	attackersTable.SetCell(0, 6, tview.NewTableCell("ASN").SetTextColor(tcell.ColorGray))
	attackersTable.SetCell(0, 7, tview.NewTableCell("THREAT").SetTextColor(tcell.ColorGray))
	attackersTable.SetCell(0, 8, tview.NewTableCell("ORG").SetTextColor(tcell.ColorGray))
	for i := 0; i < 5 && i < len(d.WAF.TopAttackers); i++ {
		t := d.WAF.TopAttackers[i]
		attackersTable.SetCell(i+1, 0, tview.NewTableCell(t.IP).SetTextColor(tcell.ColorRed))
		attackersTable.SetCell(i+1, 1, tview.NewTableCell(fmt.Sprintf("%d", t.Hits)).SetTextColor(tcell.ColorYellow))
		ls := t.LastSeen
		if len(ls) >= 19 {
			ls = ls[11:19]
		}
		attackersTable.SetCell(i+1, 2, tview.NewTableCell(ls).SetTextColor(tcell.ColorGray))
		attackersTable.SetCell(i+1, 3, tview.NewTableCell(t.Severity).SetTextColor(tcell.ColorFuchsia))
		attackersTable.SetCell(i+1, 4, tview.NewTableCell(t.Port).SetTextColor(tcell.ColorYellow))
		attackersTable.SetCell(i+1, 5, tview.NewTableCell(t.Country).SetTextColor(tcell.ColorWhite))
		attackersTable.SetCell(i+1, 6, tview.NewTableCell(t.ASN).SetTextColor(tcell.ColorAqua))
		attackersTable.SetCell(i+1, 7, tview.NewTableCell(t.Threat).SetTextColor(tcell.ColorOrange))
		attackersTable.SetCell(i+1, 8, tview.NewTableCell(t.Org).SetTextColor(tcell.ColorWhite))
	}

	// --- Banned Table ---
	// Preserve selection
	r, c := bannedTable.GetSelection()
	bannedTable.Clear()
	bannedTable.SetCell(0, 0, tview.NewTableCell("IP ADDRESS").SetTextColor(tcell.ColorGray).SetSelectable(false))
	bannedTable.SetCell(0, 1, tview.NewTableCell("TRIGGERING").SetTextColor(tcell.ColorGray).SetSelectable(false))
	bannedTable.SetCell(0, 2, tview.NewTableCell("MITRE ATT&CK / TYPE").SetTextColor(tcell.ColorGray).SetSelectable(false))
	bannedTable.SetCell(0, 3, tview.NewTableCell("STATE").SetTextColor(tcell.ColorGray).SetSelectable(false))
	bannedTable.SetCell(0, 4, tview.NewTableCell("REASON (ATTEMPTED ATTACK)").SetTextColor(tcell.ColorGray).SetSelectable(false))

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
			bannedTable.SetCell(row, 2, tview.NewTableCell("-").SetTextColor(tcell.ColorGray))
			bannedTable.SetCell(row, 3, tview.NewTableCell("ALLOW").SetTextColor(tcell.ColorGreen))
			bannedTable.SetCell(row, 4, tview.NewTableCell(TranslateAllowedPayload(a.Service, a.Payload, a.IP, a.Timestamp)).SetTextColor(tcell.ColorGray))
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
			case "SIMULATED-BAN":
				bannedTable.SetCell(row, 0, tview.NewTableCell(b.IP).SetTextColor(tcell.ColorOrange))
				bannedTable.SetCell(row, 1, tview.NewTableCell("DRY-RUN: "+b.Jail).SetTextColor(tcell.ColorOrange))
				bannedTable.SetCell(row, 2, tview.NewTableCell(mitre).SetTextColor(tcell.ColorOrange))
				bannedTable.SetCell(row, 3, tview.NewTableCell("AUDIT").SetTextColor(tcell.ColorOrange))
				bannedTable.SetCell(row, 4, tview.NewTableCell(TranslatePayload(b.Jail, payload, b.IP, b.Timestamp)).SetTextColor(tcell.ColorYellow))
			case "COMPLIANCE-DRIFT":
				ts := b.Timestamp
				if ts == "" {
					ts = time.Now().Format("2006-01-02 15:04:05")
				}
				bannedTable.SetCell(row, 0, tview.NewTableCell(b.IP).SetTextColor(tcell.ColorRed))
				bannedTable.SetCell(row, 1, tview.NewTableCell(b.Jail).SetTextColor(tcell.ColorRed))
				bannedTable.SetCell(row, 2, tview.NewTableCell("TA0005").SetTextColor(tcell.ColorRed)) // Defense Evasion
				bannedTable.SetCell(row, 3, tview.NewTableCell("DRIFT").SetTextColor(tcell.ColorRed))
				bannedTable.SetCell(row, 4, tview.NewTableCell(fmt.Sprintf("[%s] %s", ts, b.Payload)).SetTextColor(tcell.ColorWhite))
			case "COMPLIANCE-OK":
				ts := b.Timestamp
				if ts == "" {
					ts = time.Now().Format("2006-01-02 15:04:05")
				}
				bannedTable.SetCell(row, 0, tview.NewTableCell(b.IP).SetTextColor(tcell.ColorGreen))
				bannedTable.SetCell(row, 1, tview.NewTableCell(b.Jail).SetTextColor(tcell.ColorGreen))
				bannedTable.SetCell(row, 2, tview.NewTableCell("-").SetTextColor(tcell.ColorGreen))
				bannedTable.SetCell(row, 3, tview.NewTableCell("OK").SetTextColor(tcell.ColorGreen))
				bannedTable.SetCell(row, 4, tview.NewTableCell(fmt.Sprintf("[%s] %s", ts, b.Payload)).SetTextColor(tcell.ColorGray))
			case "SHADOW-ALERT":
				bannedTable.SetCell(row, 0, tview.NewTableCell(b.IP).SetTextColor(tcell.ColorOrange))
				bannedTable.SetCell(row, 1, tview.NewTableCell("SHADOW-ALERT: "+b.Jail).SetTextColor(tcell.ColorOrange))
				bannedTable.SetCell(row, 2, tview.NewTableCell(mitre).SetTextColor(tcell.ColorOrange))
				bannedTable.SetCell(row, 3, tview.NewTableCell("DETECT").SetTextColor(tcell.ColorOrange))
				bannedTable.SetCell(row, 4, tview.NewTableCell(TranslatePayload(b.Jail, payload, b.IP, b.Timestamp)).SetTextColor(tcell.ColorYellow))
			case "DETECTED":
				bannedTable.SetCell(row, 0, tview.NewTableCell(b.IP).SetTextColor(tcell.ColorYellow))
				bannedTable.SetCell(row, 1, tview.NewTableCell("DETECTED: "+b.Jail).SetTextColor(tcell.ColorYellow))
				bannedTable.SetCell(row, 2, tview.NewTableCell(mitre).SetTextColor(tcell.ColorYellow))
				bannedTable.SetCell(row, 3, tview.NewTableCell("DETECT").SetTextColor(tcell.ColorYellow))
				bannedTable.SetCell(row, 4, tview.NewTableCell(TranslatePayload(b.Jail, payload, b.IP, b.Timestamp)).SetTextColor(tcell.ColorYellow))
			default:
				bannedTable.SetCell(row, 0, tview.NewTableCell(b.IP).SetTextColor(tcell.ColorWhite))
				bannedTable.SetCell(row, 1, tview.NewTableCell(b.Jail).SetTextColor(cVec))
				bannedTable.SetCell(row, 2, tview.NewTableCell(mitre).SetTextColor(tcell.ColorWhite))
				bannedTable.SetCell(row, 3, tview.NewTableCell("BAN").SetTextColor(tcell.ColorRed))
				bannedTable.SetCell(row, 4, tview.NewTableCell(TranslatePayload(b.Jail, payload, b.IP, b.Timestamp)).SetTextColor(tcell.ColorWhite))
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
			fmt.Printf(" - %s (%s / %s / %s)\n", a.IP, a.Country, a.ASN, a.Org)
		}
	}
}
