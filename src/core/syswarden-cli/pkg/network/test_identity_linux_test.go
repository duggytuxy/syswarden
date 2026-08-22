//go:build linux

package network

import (
	"os"
	"strconv"
	"testing"
)

func narrowNetworkTestIdentity(value int) (uint32, bool) {
	wide := int64(value)
	if wide < 0 || wide > int64(^uint32(0)) {
		return 0, false
	}
	return uint32(wide), true // #nosec G115 -- the preceding bounds check proves this test-only conversion exact

}

func checkedNetworkTestIdentity(t *testing.T, name string, value int) uint32 {
	t.Helper()
	identity, ok := narrowNetworkTestIdentity(value)
	if !ok {
		t.Fatalf("effective %s is outside uint32: %d", name, value)
	}
	return identity
}

func networkTestUID(t *testing.T) uint32 {
	t.Helper()
	return checkedNetworkTestIdentity(t, "UID", os.Geteuid())
}

func networkTestGID(t *testing.T) uint32 {
	t.Helper()
	return checkedNetworkTestIdentity(t, "GID", os.Getegid())
}

func networkTestIdentity(t *testing.T) (uint32, uint32) {
	t.Helper()
	return networkTestUID(t), networkTestGID(t)
}

func TestNarrowNetworkTestIdentityRejectsOutOfRange_SW2_WGSTATE_001(t *testing.T) {
	for _, test := range []struct {
		name  string
		value int
		want  bool
	}{
		{name: "negative", value: -1},
		{name: "zero", value: 0, want: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, ok := narrowNetworkTestIdentity(test.value)
			if ok != test.want {
				t.Fatalf("narrowNetworkTestIdentity(%d) valid = %t, want %t", test.value, ok, test.want)
			}
		})
	}
	if strconv.IntSize == 64 {
		aboveUint32 := int(int64(^uint32(0)) + 1)
		if _, ok := narrowNetworkTestIdentity(aboveUint32); ok {
			t.Fatalf("narrowNetworkTestIdentity(%d) accepted a value above uint32", aboveUint32)
		}
	}
}
