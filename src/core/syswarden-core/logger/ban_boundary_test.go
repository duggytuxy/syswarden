package logger

import (
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/viper"
)

// Guard the boundary before invoking ban logging so this regression test cannot
// accidentally touch the production blocklist paths if the old call returns.
func requireEventLoggingWithoutStaticPolicyWrites(t *testing.T) {
	t.Helper()
	files, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	functions := make(map[string]*ast.FuncDecl)
	for _, entry := range files {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), entry.Name(), nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, declaration := range file.Decls {
			if function, ok := declaration.(*ast.FuncDecl); ok {
				functions[function.Name.Name] = function
			}
		}
	}
	pending := []string{"LogBan", "LogBanWithRule"}
	seen := make(map[string]bool)
	for len(pending) > 0 {
		name := pending[0]
		pending = pending[1:]
		if seen[name] {
			continue
		}
		seen[name] = true
		switch name {
		case "persistBanToDisk", "UpdatePersistentBlocklist", "publishPersistentBlocklist", "openPersistentBlocklistDirectory":
			t.Fatalf("event logging reaches static policy writer %s", name)
		}
		function := functions[name]
		if function == nil {
			continue
		}
		ast.Inspect(function.Body, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			switch callee := call.Fun.(type) {
			case *ast.Ident:
				pending = append(pending, callee.Name)
			case *ast.SelectorExpr:
				pending = append(pending, callee.Sel.Name)
			}
			return true
		})
	}
}

type banBoundaryTransport func(*http.Request) (*http.Response, error)

func (transport banBoundaryTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	return transport(request)
}

func TestBanLoggingRetainsTelemetryWithoutPermanentPolicy(t *testing.T) {
	requireEventLoggingWithoutStaticPolicyWrites(t)
	previousTransport := http.DefaultTransport
	http.DefaultTransport = banBoundaryTransport(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("external requests are disabled in this synthetic regression")
	})
	t.Cleanup(func() { http.DefaultTransport = previousTransport })
	previousAbuse := viper.Get("integrations.abuseipdb.enabled")
	viper.Set("integrations.abuseipdb.enabled", false)
	t.Cleanup(func() { viper.Set("integrations.abuseipdb.enabled", previousAbuse) })

	directory := t.TempDir()
	staticPath := filepath.Join(directory, "syswarden_blacklist.ipv4")
	// Existing explicit administrator/HA policy remains independently writable.
	if err := UpdatePersistentBlocklist(staticPath, "192.0.2.70", true); err != nil {
		t.Fatal(err)
	}
	before := string(readLoggerTestFile(t, staticPath))
	path := filepath.Join(directory, "waf.json")
	eventLogger := NewLogger(path)
	eventLogger.LogBanWithRule("192.0.2.71", "synthetic-runtime-rule", "synthetic successful runtime ban", RuleContext{
		RuleID:                  "synthetic-runtime-rule",
		RiskCategory:            "reconnaissance",
		RuleAction:              "ban",
		EffectiveThreshold:      1,
		SignatureCatalogVersion: "synthetic-catalog-v1",
		SignatureCatalogSHA256:  strings.Repeat("a", 64),
		RiskModelVersion:        "sw-risk-v1",
		MetricEligible:          true,
		ObservationModel:        "collector-content-window-v1",
	})
	eventLogger.Close()

	if after := string(readLoggerTestFile(t, staticPath)); after != before {
		t.Fatalf("event logging changed explicit policy: before=%q after=%q", before, after)
	}
	var event TelemetryEvent
	if err := json.Unmarshal(readLoggerTestFile(t, path), &event); err != nil {
		t.Fatal(err)
	}
	if event.Action != "BANNED" || event.IP != "192.0.2.71" || event.RuleAttestationStatus != "attested" {
		t.Fatalf("successful runtime ban lost its telemetry: %#v", event)
	}
	if err := UpdatePersistentBlocklist(staticPath, "192.0.2.72", true); err != nil {
		t.Fatal(err)
	}
	if after := string(readLoggerTestFile(t, staticPath)); after != "192.0.2.70\n192.0.2.72\n" {
		t.Fatalf("explicit policy writer no longer works independently: %q", after)
	}
}

func TestUnverifiedPacketDispositionNeverAttestsABan(t *testing.T) {
	for _, jail := range []string{"L3-PORTSCAN", "L3-HONEYPORT-SCAN"} {
		for _, action := range []string{"DETECTED", "BANNED", "SIMULATED-BAN", "SHADOW-ALERT"} {
			t.Run(jail+"/"+action, func(t *testing.T) {
				rule := RuleContext{
					RuleID: jail, RiskCategory: "reconnaissance", RuleAction: "ban", EffectiveThreshold: 1,
					SignatureCatalogVersion: "sw-kernel-signals-v1", SignatureCatalogSHA256: strings.Repeat("c", 64),
					RiskModelVersion: "sw-risk-v1", MetricEligible: true,
					ObservationModel: "kernel-log-observation-v1", ObservationDisposition: "packet-source-unverified",
				}
				event := newTelemetryEvent(action, "192.0.2.73", jail, "synthetic packet observation", 7, &rule)
				if action == "DETECTED" {
					if event.RuleAttestationStatus != "attested" || event.ObservationDisposition != "packet-source-unverified" {
						t.Fatalf("packet observation lost its explicit disposition: %#v", event)
					}
				} else if event.RuleAttestationStatus != "invalid" || event.ObservationDisposition != "" {
					t.Fatalf("unverified source disposition attested an enforcement decision: %#v", event)
				}
			})
		}
	}
	for _, change := range []func(*RuleContext){
		func(rule *RuleContext) { rule.RuleID = "L2-ARP-FLOOD" },
		func(rule *RuleContext) { rule.ObservationModel = "collector-content-window-v1" },
		func(rule *RuleContext) { rule.ObservationDisposition = "unknown" },
	} {
		rule := RuleContext{
			RuleID: "L3-HONEYPORT-SCAN", RiskCategory: "reconnaissance", RuleAction: "ban", EffectiveThreshold: 1,
			SignatureCatalogVersion: "sw-kernel-signals-v1", SignatureCatalogSHA256: strings.Repeat("c", 64),
			RiskModelVersion: "sw-risk-v1", MetricEligible: true,
			ObservationModel: "kernel-log-observation-v1", ObservationDisposition: "packet-source-unverified",
		}
		change(&rule)
		if event := newTelemetryEvent("DETECTED", "192.0.2.73", rule.RuleID, "synthetic packet observation", 7, &rule); event.RuleAttestationStatus != "invalid" {
			t.Fatalf("unrelated evidence acquired packet observation disposition: %#v", event)
		}
	}
}
