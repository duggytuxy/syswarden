package network

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestProductionSchedulingNeverWritesRootCrontab(t *testing.T) {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve cron contract test path")
	}
	directory := filepath.Dir(currentFile)
	requiredReconciler := map[string]string{
		"cluster.go":    "cronstate.ReconcileHA",
		"downloader.go": "cronstate.ReconcileFeed",
	}
	for _, name := range []string{"cluster.go", "downloader.go"} {
		content, err := os.ReadFile(filepath.Join(directory, name)) // #nosec G304 -- name is selected from the fixed source contract inventory
		if err != nil {
			t.Fatal(err)
		}
		source := string(content)
		for _, forbidden := range []string{
			`exec.Command("crontab", "` + `-")`,
			`exec.Command("crontab", "` + `-r")`,
			"writeRoot" + "Crontab",
			"updateRoot" + "Crontab",
		} {
			if strings.Contains(source, forbidden) {
				t.Fatalf("%s contains forbidden root crontab writer %q", name, forbidden)
			}
		}
		if !strings.Contains(source, requiredReconciler[name]) {
			t.Fatalf("%s does not use %s", name, requiredReconciler[name])
		}
		if !strings.Contains(source, "system.ReadOnlyRootCrontabEvidence") {
			t.Fatalf("%s does not use the attested read-only root crontab reader", name)
		}
		if !strings.Contains(source, "options.AttestCronDProvider = system.AttestRuntimeCronDProvider") {
			t.Fatalf("%s does not require the read-only cron.d provider attestation", name)
		}
	}
}
