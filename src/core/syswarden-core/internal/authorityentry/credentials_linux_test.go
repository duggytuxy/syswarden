package authorityentry

import (
	"errors"
	"reflect"
	"testing"

	"golang.org/x/sys/unix"
)

func TestRootLaunchIdentity(t *testing.T) {
	if !exactRootIdentity([3]int{}, [3]int{}) {
		t.Fatal("root identity rejected")
	}
	for i := 0; i < 3; i++ {
		for _, v := range []int{-1, 1, 65533} {
			ids := [3]int{}
			ids[i] = v
			if exactRootIdentity(ids, [3]int{}) || exactRootIdentity([3]int{}, ids) {
				t.Fatal("partial root identity admitted")
			}
		}
	}
}

func TestCredentialDropStopsAtEveryFailure(t *testing.T) {
	for _, failure := range []int{-1, 0, 1, 2, 3, 4} {
		var calls []int
		step := func(n int) error {
			calls = append(calls, n)
			if n == failure {
				return unix.EPERM
			}
			return nil
		}
		ops := credentialOperations{
			prepare: func() error { return step(0) },
			groups: func(groups []int) error {
				if !reflect.DeepEqual(groups, []int{103}) {
					t.Fatal("unexpected groups")
				}
				return step(1)
			},
			gids: func(r, e, s int) error {
				if r != 102 || e != 102 || s != 102 {
					t.Fatal("incomplete GID drop")
				}
				return step(2)
			},
			uids: func(r, e, s int) error {
				if r != 101 || e != 101 || s != 101 {
					t.Fatal("incomplete UID drop")
				}
				return step(3)
			},
			clear: func() error { return step(4) },
		}
		err := changeAuthorityCredentials(101, 102, 103, ops)
		want := []int{0, 1, 2, 3, 4}
		if failure >= 0 {
			want = want[:failure+1]
			if !errors.Is(err, unix.EPERM) {
				t.Fatal("lost transition failure")
			}
		} else if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(calls, want) {
			t.Fatal("transition reordered or continued after failure", calls)
		}
	}
	for _, bad := range []uint32{0, 1 << 31, ^uint32(0)} {
		for _, ids := range [][3]uint32{{bad, 102, 103}, {101, bad, 103}, {101, 102, bad}} {
			if changeAuthorityCredentials(ids[0], ids[1], ids[2], credentialOperations{}) == nil {
				t.Fatal("invalid numeric identity admitted")
			}
		}
	}
}

func TestCapabilityBoundingDrop(t *testing.T) {
	for _, kind := range []string{"valid", "already-empty", "initial-error", "missing-api", "drop-error", "readback-error", "unchanged", "invalid-value", "unknown-range"} {
		t.Run(kind, func(t *testing.T) {
			cleared := map[uintptr]bool{}
			drops := 0
			err := clearAuthorityBoundingSet(func(cap uintptr) (int, error) {
				if kind == "missing-api" {
					return 0, unix.EINVAL
				}
				if cap == 3 && kind == "initial-error" {
					return 0, unix.EPERM
				}
				if cap == 4 && kind != "unknown-range" {
					return 0, unix.EINVAL
				}
				if cleared[cap] {
					if kind == "readback-error" {
						return 0, unix.EIO
					}
					if kind == "unchanged" {
						return 1, nil
					}
					return 0, nil
				}
				if kind == "invalid-value" {
					return 2, nil
				}
				if kind == "already-empty" || kind == "unknown-range" {
					return 0, nil
				}
				return 1, nil
			}, func(cap uintptr) error {
				drops++
				if kind == "drop-error" {
					return unix.EPERM
				}
				cleared[cap] = true
				return nil
			})
			good := kind == "valid" || kind == "already-empty"
			if (err == nil) != good {
				t.Fatal("unsafe capability decision", err)
			}
			if kind == "valid" && drops != 4 {
				t.Fatal("incomplete bounding set removal")
			}
			if (kind == "already-empty" || kind == "unknown-range" || kind == "missing-api" || kind == "invalid-value") && drops != 0 {
				t.Fatal("unexpected capability mutation")
			}
		})
	}
}
