//go:build linux

package system

import (
	"os"
	"strconv"
	"testing"
)

func checkedSystemTestIdentity(value int) (uint32, bool) {
	wide := int64(value)
	if wide < 0 || wide > int64(^uint32(0)) {
		return 0, false
	}
	return uint32(wide), true // #nosec G115 -- the preceding bounds check proves this test-only conversion exact
}

func systemTestIdentityValue(t *testing.T, name string, value int) uint32 {
	t.Helper()
	identity, ok := checkedSystemTestIdentity(value)
	if !ok {
		t.Fatalf("effective %s is outside uint32: %d", name, value)
	}
	return identity
}

func systemTestUID(t *testing.T) uint32 {
	t.Helper()
	return systemTestIdentityValue(t, "UID", os.Geteuid())
}

func systemTestGID(t *testing.T) uint32 {
	t.Helper()
	return systemTestIdentityValue(t, "GID", os.Getegid())
}

func systemTestIdentity(t *testing.T) (uint32, uint32) {
	t.Helper()
	return systemTestUID(t), systemTestGID(t)
}

func TestCheckedSystemTestIdentityRejectsOutOfRange_SW2_FWBACKEND_001(t *testing.T) {
	for _, test := range []struct {
		name  string
		value int
		want  bool
	}{
		{name: "negative", value: -1},
		{name: "zero", value: 0, want: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, ok := checkedSystemTestIdentity(test.value)
			if ok != test.want {
				t.Fatalf("checkedSystemTestIdentity(%d) valid = %t, want %t", test.value, ok, test.want)
			}
		})
	}
	if strconv.IntSize == 64 {
		aboveUint32 := int(int64(^uint32(0)) + 1)
		if _, ok := checkedSystemTestIdentity(aboveUint32); ok {
			t.Fatalf("checkedSystemTestIdentity(%d) accepted a value above uint32", aboveUint32)
		}
	}
}
