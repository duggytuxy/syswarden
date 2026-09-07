package go127probe

import (
	"runtime/pprof"
	"testing"
)

func TestGo127GoroutineLeakProfileIsAvailable(t *testing.T) {
	if profile := pprof.Lookup("goroutineleak"); profile == nil {
		t.Fatal("Go 1.27 goroutineleak profile is unavailable")
	}
}
