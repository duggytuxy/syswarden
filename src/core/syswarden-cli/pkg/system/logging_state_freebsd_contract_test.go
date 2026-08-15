package system

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestFreeBSDLoggingTransitionSnapshotsAndRestoresBaseDaemon(t *testing.T) {
	_, current, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve logging state source")
	}
	root, err := os.OpenRoot(filepath.Dir(current))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	content, err := root.ReadFile("logging_state_freebsd.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(content)
	for _, required := range []string{
		`freeBSDLoggingStateName = "logging-service-state.json"`,
		`stopFreeBSDLoggingService("syslogd")`,
		`target.SyslogdEnable = freeBSDRCValue{Present: true, Value: "NO"}`,
		`target.RsyslogdEnable = freeBSDRCValue{Present: true, Value: "YES"}`,
		`target.RsyslogdPIDFile = freeBSDRCValue{Present: true, Value: "/var/run/syslog.pid"}`,
		`setFreeBSDRCValue(variable.name, variable.value)`,
		`startFreeBSDLoggingService("syslogd")`,
		`applyFreeBSDLoggingStateWithRollback(target, current)`,
		`removeFreeBSDOwnedState(freeBSDLoggingStateName)`,
	} {
		if !strings.Contains(source, required) {
			t.Fatalf("FreeBSD logging transition lacks %q", required)
		}
	}
}
