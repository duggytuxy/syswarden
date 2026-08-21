//go:build linux

package firewall

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"syswarden-cli/config"
)

const (
	actContainerIsolationEnvironment = "SYSWARDEN_ACT_CONTAINER_ISOLATION"
	actContainerIsolationMarker      = "security-audit-v1"
	linuxFirewallHelperEnvironment   = "SYSWARDEN_LINUX_FIREWALL_GOLDEN_HELPER"
	linuxFirewallTargetDirectory     = "/etc/syswarden"
	linuxFirewallTargetFile          = "/etc/syswarden/syswarden.nft"
)

func TestNftablesRulesGolden_SW_QA_001(t *testing.T) {
	if os.Getenv(linuxFirewallHelperEnvironment) == "1" {
		runLinuxFirewallGoldenHelper(t)
		return
	}

	var got []byte
	if actContainerIsolationRequested() {
		got = runActContainerFirewallGolden(t)
	} else {
		got = runBubblewrapFirewallGolden(t)
	}
	if bytes.Contains(got, []byte("236379")) {
		t.Fatal("SW-FW-004 regression: generated nftables rules contain concatenated honeyports")
	}
	if bytes.Count(got, []byte("tcp dport { 23, 6379 }")) != 2 {
		t.Fatal("generated nftables rules do not preserve honeyports 23 and 6379 as two distinct values")
	}
	if bytes.Contains(got, []byte("ct state new tcp dport { 443, 2222")) {
		t.Fatal("the detected SSH listener bypassed SSH-only source policy")
	}
	structuralRules := got
	if populationStart := bytes.Index(structuralRules, []byte("add element ")); populationStart >= 0 {
		structuralRules = structuralRules[:populationStart]
	}

	wantPath := filepath.Join("..", "..", "..", "..", "..", "testdata", "firewall", "nftables-v4.02.8.nft")
	if !bytes.HasSuffix(structuralRules, []byte("\n\n")) || bytes.HasSuffix(structuralRules, []byte("\n\n\n")) {
		t.Fatal("nftables output must end with exactly one blank separator line")
	}
	if os.Getenv("SYSWARDEN_UPDATE_CONTRACT_GOLDENS") == "1" {
		fixture := structuralRules[:len(structuralRules)-1]
		fixture = bytes.ReplaceAll(
			fixture,
			[]byte("tcp dport { 23, 6379 }"),
			[]byte("tcp dport { 236379 }"),
		)
		if bytes.Count(fixture, []byte("tcp dport { 236379 }")) != 2 {
			t.Fatal("updated nftables golden does not preserve the two historical SW-FW-004 characterization rules")
		}
		if err := os.WriteFile(wantPath, fixture, 0600); err != nil { // #nosec G703 -- wantPath is a fixed repository fixture behind the explicit golden-update gate
			t.Fatalf("update nftables golden: %v", err)
		}
		return
	}
	want, err := os.ReadFile(wantPath) // #nosec G304 -- wantPath is a fixed repository fixture
	if err != nil {
		t.Fatalf("read nftables golden: %v", err)
	}
	if !bytes.HasSuffix(want, []byte("\n")) || bytes.HasSuffix(want, []byte("\n\n")) {
		t.Fatal("nftables golden must end with one newline and no blank line at EOF")
	}
	wantRuntime := append(append([]byte(nil), want...), '\n')
	wantRuntime = bytes.ReplaceAll(wantRuntime, []byte("flags timeout;"), []byte("flags interval,timeout;"))
	wantRuntime = bytes.ReplaceAll(wantRuntime, []byte("tcp dport { 236379 }"), []byte("tcp dport { 23, 6379 }"))
	if !bytes.Equal(structuralRules, wantRuntime) {
		t.Fatalf("nftables rules changed; review and approve the complete golden diff before updating %s", wantPath)
	}
}

func runBubblewrapFirewallGolden(t *testing.T) []byte {
	t.Helper()
	bwrap, err := exec.LookPath("bwrap")
	if err != nil {
		requireOrSkipFirewallSandbox(t, "bubblewrap is not installed")
		return nil
	}
	root := t.TempDir()
	etcDir := filepath.Join(root, "etc")
	toolDir := filepath.Join(root, "tools")
	if err := os.MkdirAll(etcDir, 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(toolDir, 0750); err != nil {
		t.Fatal(err)
	}
	writeLinuxFirewallTestTools(t, toolDir)

	command := exec.Command( // #nosec G204 G702 -- bwrap is resolved by LookPath and every command argument is a controlled test fixture
		bwrap,
		"--ro-bind", "/", "/",
		"--dev", "/dev",
		"--bind", etcDir, "/etc",
		"--tmpfs", "/tmp",
		"--ro-bind", os.Args[0], "/tmp/syswarden-firewall.test",
		"--ro-bind", toolDir, "/tmp/test-tools",
		"--setenv", "PATH", "/tmp/test-tools",
		"--setenv", linuxFirewallHelperEnvironment, "1",
		"--", "/tmp/syswarden-firewall.test", "-test.run=^TestNftablesRulesGolden_SW_QA_001$",
	)
	if output, err := command.CombinedOutput(); err != nil {
		requireOrSkipFirewallSandbox(t, string(output))
		return nil
	}

	gotPath := filepath.Join(etcDir, "syswarden", "syswarden.nft")
	got, err := os.ReadFile(gotPath) // #nosec G304 -- gotPath is inside the isolated test root
	if err != nil {
		t.Fatalf("read isolated nftables output: %v", err)
	}
	return got
}

func runActContainerFirewallGolden(t *testing.T) []byte {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Fatal("Act container firewall characterization requires the container root user")
	}
	if !runningInContainer() {
		t.Fatal("Act container firewall characterization requires a verified container marker")
	}
	if info, err := os.Lstat("/etc"); err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("Act container /etc is not a real directory: %v", err)
	}
	if _, err := os.Lstat(linuxFirewallTargetDirectory); !errors.Is(err, os.ErrNotExist) {
		if err == nil {
			t.Fatalf("refusing to use pre-existing Act container path %s", linuxFirewallTargetDirectory)
		}
		t.Fatalf("inspect Act container firewall target: %v", err)
	}

	cleaned := false
	cleanup := func() error {
		if err := os.Remove(filepath.Join(linuxFirewallTargetDirectory, ".firewall-reload.lock")); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove isolated nftables lock: %w", err)
		}
		if err := os.Remove(linuxFirewallTargetFile); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove isolated nftables file: %w", err)
		}
		if err := os.Remove(linuxFirewallTargetDirectory); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove isolated firewall directory: %w", err)
		}
		if _, err := os.Lstat(linuxFirewallTargetDirectory); !errors.Is(err, os.ErrNotExist) {
			if err == nil {
				return fmt.Errorf("isolated firewall directory still exists after cleanup")
			}
			return fmt.Errorf("verify isolated firewall cleanup: %w", err)
		}
		cleaned = true
		return nil
	}
	t.Cleanup(func() {
		if !cleaned {
			if err := cleanup(); err != nil {
				t.Errorf("Act container firewall cleanup: %v", err)
			}
		}
	})

	toolDir := filepath.Join(t.TempDir(), "tools")
	if err := os.Mkdir(toolDir, 0750); err != nil {
		t.Fatal(err)
	}
	writeLinuxFirewallTestTools(t, toolDir)
	testExecutable, err := os.Executable()
	if err != nil {
		t.Fatalf("resolve firewall test executable: %v", err)
	}
	command := exec.Command( // #nosec G204 G702 -- the executable is the current test binary and all arguments and environment values are controlled fixtures
		testExecutable,
		"-test.run=^TestNftablesRulesGolden_SW_QA_001$",
	)
	command.Env = []string{
		"PATH=" + toolDir,
		linuxFirewallHelperEnvironment + "=1",
	}
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("Act container firewall helper failed: %v\n%s", err, string(output))
	}
	info, err := os.Lstat(linuxFirewallTargetFile)
	if err != nil {
		t.Fatalf("inspect Act container nftables output: %v", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		t.Fatalf("Act container nftables output has unexpected type or mode: %s", info.Mode())
	}
	got, err := os.ReadFile(linuxFirewallTargetFile) // #nosec G304 -- the fixed file exists only inside the verified disposable Act container
	if err != nil {
		t.Fatalf("read Act container nftables output: %v", err)
	}
	if err := cleanup(); err != nil {
		t.Fatal(err)
	}
	return got
}

func actContainerIsolationRequested() bool {
	return os.Getenv("ACT") == "true" &&
		os.Getenv(actContainerIsolationEnvironment) == actContainerIsolationMarker
}

func runningInContainer() bool {
	for _, marker := range []string{"/run/.containerenv", "/.dockerenv"} {
		if info, err := os.Lstat(marker); err == nil && info.Mode().IsRegular() {
			return true
		}
	}
	return false
}

func runLinuxFirewallGoldenHelper(t *testing.T) {
	cleanupLists := writeLinuxFirewallListFixtures(t)
	defer cleanupLists()
	previous := config.GlobalConfig
	t.Cleanup(func() { config.GlobalConfig = previous })
	config.GlobalConfig = &config.Config{
		Interfaces: "eth-test0,eth-test1",
		SSHPort:    "2222",
		LANSubnets: "203.0.113.0/24",
		EnableGeo:  true,
		GeoCodes:   "be",
		GeoAllowed: "fr",
		EnableASN:  true,
		ASNList:    "AS64500",
		ASNAllowed: "AS64501",
		HAEnabled:  true,
		HAPeerPort: "62026",
		EnableWG:   true,
		WGSubnet:   "10.66.66.0/24",
		LANMode:    true,
		HoneyPorts: "23 6379",
		ArpProtect: false,
	}
	if err := ApplyPolicies(); err != nil {
		t.Fatalf("ApplyPolicies() in isolated sandbox: %v", err)
	}
}

func writeLinuxFirewallListFixtures(t *testing.T) func() {
	t.Helper()
	if _, err := os.Lstat(linuxFirewallTargetDirectory); !errors.Is(err, os.ErrNotExist) {
		if err == nil {
			t.Fatalf("firewall helper refuses pre-existing path %s", linuxFirewallTargetDirectory)
		}
		t.Fatalf("inspect firewall helper target: %v", err)
	}
	listDirectory := filepath.Join(linuxFirewallTargetDirectory, "lists")
	if err := os.MkdirAll(listDirectory, 0750); err != nil {
		t.Fatal(err)
	}
	fixtures := map[string]string{
		"allowed_fr.ipv4":      "192.0.2.0/24\n",
		"allowed_fr.ipv6":      "2001:db8:1::/48\n",
		"allowed_AS64501.ipv4": "198.51.100.0/24\n",
		"allowed_AS64501.ipv6": "2001:db8:2::/48\n",
		"be.ipv4":              "203.0.113.0/24\n",
		"be.ipv6":              "2001:db8:3::/48\n",
		"AS64500.ipv4":         "198.18.0.0/15\n",
		"AS64500.ipv6":         "2001:db8:4::/48\n",
	}
	paths := make([]string, 0, len(fixtures))
	for name, content := range fixtures {
		path := filepath.Join(listDirectory, name)
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, path)
	}
	return func() {
		for _, path := range paths {
			_ = os.Remove(path)
		}
		_ = os.Remove(listDirectory)
	}
}

func requireOrSkipFirewallSandbox(t *testing.T, reason string) {
	t.Helper()
	if firewallSandboxRequired() {
		t.Fatalf("isolated firewall characterization is required but unavailable: %s", reason)
	}
	t.Skipf("isolated firewall characterization unavailable: %s", reason)
}

func firewallSandboxRequired() bool {
	return os.Getenv("CI") != "" ||
		os.Getenv("ACT") == "true" ||
		os.Getenv("SYSWARDEN_REQUIRE_FIREWALL_TESTS") == "1" ||
		os.Getenv("SYSWARDEN_REQUIRE_FIREWALL_SANDBOX") == "1"
}

func TestFirewallSandboxRequirementContract_SW_QA_001(t *testing.T) {
	keys := []string{
		"CI",
		"ACT",
		"SYSWARDEN_REQUIRE_FIREWALL_TESTS",
		"SYSWARDEN_REQUIRE_FIREWALL_SANDBOX",
	}
	tests := []struct {
		name  string
		key   string
		value string
		want  bool
	}{
		{name: "local development may skip"},
		{name: "CI is mandatory", key: "CI", value: "1", want: true},
		{name: "Act is mandatory", key: "ACT", value: "true", want: true},
		{name: "firewall gate is mandatory", key: "SYSWARDEN_REQUIRE_FIREWALL_TESTS", value: "1", want: true},
		{name: "legacy sandbox gate remains mandatory", key: "SYSWARDEN_REQUIRE_FIREWALL_SANDBOX", value: "1", want: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for _, key := range keys {
				t.Setenv(key, "")
			}
			if test.key != "" {
				t.Setenv(test.key, test.value)
			}
			if got := firewallSandboxRequired(); got != test.want {
				t.Fatalf("firewallSandboxRequired() = %t, want %t", got, test.want)
			}
		})
	}
}

func TestActContainerIsolationRequirementContract_SW_QA_001(t *testing.T) {
	tests := []struct {
		name   string
		act    string
		marker string
		want   bool
	}{
		{name: "disabled by default"},
		{name: "Act alone is insufficient", act: "true"},
		{name: "marker alone is insufficient", marker: actContainerIsolationMarker},
		{name: "wrong marker is rejected", act: "true", marker: "unexpected"},
		{name: "exact Act contract is accepted", act: "true", marker: actContainerIsolationMarker, want: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("ACT", test.act)
			t.Setenv(actContainerIsolationEnvironment, test.marker)
			if got := actContainerIsolationRequested(); got != test.want {
				t.Fatalf("actContainerIsolationRequested() = %t, want %t", got, test.want)
			}
		})
	}
}

func writeLinuxFirewallTestTools(t *testing.T, toolDir string) {
	t.Helper()
	populations := []nftSetPopulation{
		{name: "syswarden_whitelist"},
		{name: "syswarden_whitelist6"},
		{name: "syswarden_whitelist_ports", kind: nftAddressPortPopulation},
		{name: "syswarden_whitelist_ports6", kind: nftAddressPortPopulation},
		{name: "syswarden_ssh_bypass", inetOnly: true},
		{name: "syswarden_ssh_bypass6", inetOnly: true},
		{name: "syswarden_zt_allowed", entries: []string{"192.0.2.0/24", "198.51.100.0/24"}},
		{name: "syswarden_zt_allowed6", entries: []string{"2001:db8:1::/48", "2001:db8:2::/48"}},
		{name: "syswarden_blacklist"},
		{name: "syswarden_blacklist6"},
		{name: "syswarden_geoip", entries: []string{"203.0.113.0/24"}},
		{name: "syswarden_geoip6", entries: []string{"2001:db8:3::/48"}},
		{name: "syswarden_asn", entries: []string{"198.18.0.0/15"}},
		{name: "syswarden_asn6", entries: []string{"2001:db8:4::/48"}},
	}
	for index := range populations {
		normalized, err := normalizeNFTIntervals(populations[index].name, populations[index].entries)
		if err != nil {
			t.Fatalf("normalize fake kernel population %s: %v", populations[index].name, err)
		}
		populations[index].entries = normalized
	}
	verificationPlan := buildNftVerificationPlan(populations, false)
	// Runtime-owned ban sets are intentionally empty in this isolated generator
	// fixture. A negative cardinality in the verification plan means
	// existence-only, but the generic JSON helper uses placeholder strings for
	// that case; those are not valid firewall elements and must never masquerade
	// as a kernel snapshot.
	for key, count := range verificationPlan.sets {
		if count < 0 {
			verificationPlan.sets[key] = 0
		}
	}
	verificationJSON := string(nftVerificationJSON(verificationPlan, 0))
	nftScript := `#!/bin/sh
if [ "$*" = "-j list tables" ]; then
    printf '%s\n' '{"nftables":[]}'
    exit 0
fi
if [ "$*" = "-j list ruleset" ]; then
    /bin/cat <<'EOF'
` + verificationJSON + `
EOF
    exit 0
fi
exit 0
`
	writeExecutable(t, filepath.Join(toolDir, "nft"), nftScript)
	writeExecutable(t, filepath.Join(toolDir, "sysctl"), "#!/bin/sh\nexit 0\n")
	writeExecutable(t, filepath.Join(toolDir, "ss"), `#!/bin/sh
/bin/cat <<'EOF'
Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port
tcp LISTEN 0 128 0.0.0.0:443 0.0.0.0:*
tcp LISTEN 0 128 0.0.0.0:2222 0.0.0.0:*
tcp LISTEN 0 128 127.0.0.1:5432 0.0.0.0:*
udp UNCONN 0 0 *:53 *:*
EOF
`)
}

func writeExecutable(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0700); err != nil { // #nosec G302 -- the owner-only test fixture must be executable inside the sandbox
		t.Fatal(err)
	}
}
