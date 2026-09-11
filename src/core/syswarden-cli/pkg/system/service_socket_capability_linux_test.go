package system

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestCoreSystemdUnitsPermitPrivateSyslogSocketOwnership(t *testing.T) {
	packaged := mustReadTestFile(t, filepath.Join("..", "..", "..", "..", "init", "systemd", "syswarden-core.service"))
	// The socket is created by root and then assigned to the verified syslog
	// group. CAP_FOWNER and CAP_DAC_OVERRIDE do not authorize that chown.
	want := map[string]bool{
		"CAP_CHOWN": true, "CAP_NET_ADMIN": true, "CAP_NET_RAW": true,
		"CAP_DAC_OVERRIDE": true, "CAP_FOWNER": true,
	}
	for name, unit := range map[string]string{"generated": systemdCoreService, "packaged": string(packaged)} {
		t.Run(name, func(t *testing.T) {
			capabilities := make(map[string]bool)
			count := 0
			for _, line := range strings.Split(unit, "\n") {
				if value, ok := strings.CutPrefix(line, "CapabilityBoundingSet="); ok {
					count++
					for _, capability := range strings.Fields(value) {
						capabilities[capability] = true
					}
				}
			}
			if count != 1 || !reflect.DeepEqual(capabilities, want) {
				t.Fatalf("core capability boundary cannot support private socket ownership: %v (%d directives)", capabilities, count)
			}
			for _, boundary := range []string{"User=root\n", "ProtectSystem=strict\n", "NoNewPrivileges=true\n"} {
				if !strings.Contains(unit, boundary) {
					t.Fatalf("core unit lost security boundary %q", boundary)
				}
			}
		})
	}
}

func TestCoreSocketCapabilityUpgradePreservesServiceAttestation(t *testing.T) {
	for _, mode := range []os.FileMode{0600, 0644} {
		for _, modified := range []bool{false, true} {
			t.Run(fmt.Sprintf("mode-%04o-modified-%t", mode, modified), func(t *testing.T) {
				directory, wants := withSystemdPublicationTestPaths(t)
				core := filepath.Join(directory, "syswarden-core.service")
				old := historicalV4043SystemdCoreService
				if modified {
					old += "# Operator customization\n"
				}
				mustWriteFile(t, core, old)
				mustChmodTestPath(t, core, mode)
				firewall := filepath.Join(directory, "syswarden-firewall.service")
				mustWriteFile(t, firewall, systemdFirewallService)
				mustMkdirAll(t, wants)
				err := publishSystemdServices()
				if modified {
					if err == nil || string(mustReadTestFile(t, core)) != old {
						t.Fatalf("modified historical unit was not preserved and refused: %v", err)
					}
				} else {
					if err != nil {
						t.Fatal(err)
					}
					if got := string(mustReadTestFile(t, core)); got != systemdCoreService {
						t.Fatal("exact v4.04.3 unit did not migrate to the socket-capable unit")
					}
					assertServiceEnablementTarget(t, filepath.Join(wants, "syswarden-core.service"), "../syswarden-core.service")
				}
				if string(mustReadTestFile(t, firewall)) != systemdFirewallService {
					t.Fatal("socket capability migration changed the firewall unit")
				}
				assertNoServiceMigrationArtifacts(t, directory)
			})
		}
	}
}
