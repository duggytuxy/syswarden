package authorityentry

import (
	"errors"
	"fmt"
	"syscall"
	"testing"
)

func TestAuthorityResourceBudgets(t *testing.T) {
	for _, limit := range []syscall.Rlimit{{Cur: 256, Max: 256}, {Cur: 256, Max: 1024}, {Cur: 1024, Max: 4096}, {Cur: ^uint64(0), Max: ^uint64(0)}} {
		state := map[int]syscall.Rlimit{syscall.RLIMIT_CORE: {Cur: 0, Max: 0}, syscall.RLIMIT_NOFILE: limit}
		if err := setAuthorityResourceLimits(func(r int, l *syscall.Rlimit) error { *l = state[r]; return nil }, func(r int, l *syscall.Rlimit) error { state[r] = *l; return nil }); err != nil {
			t.Fatal(err)
		}
		if state[syscall.RLIMIT_CORE] != (syscall.Rlimit{}) || state[syscall.RLIMIT_NOFILE] != (syscall.Rlimit{Cur: 256, Max: 256}) {
			t.Fatal("missing hard ceiling", state)
		}
	}
	for _, resource := range []int{syscall.RLIMIT_CORE, syscall.RLIMIT_NOFILE} {
		limits := []syscall.Rlimit{{Cur: 512, Max: 256}}
		if resource == syscall.RLIMIT_NOFILE {
			limits = append(limits, syscall.Rlimit{Cur: 128, Max: 512}, syscall.Rlimit{Cur: 128, Max: 128}, syscall.Rlimit{})
		}
		for _, limit := range limits {
			err := setAuthorityResourceLimits(func(r int, l *syscall.Rlimit) error {
				*l = syscall.Rlimit{Cur: 1024, Max: 4096}
				if r == resource {
					*l = limit
				}
				return nil
			}, func(int, *syscall.Rlimit) error { t.Fatal("changed limits before budget validation"); return nil })
			if !errors.Is(err, errAuthorityResources) {
				t.Fatal("invalid or insufficient budget admitted", resource, limit, err)
			}
		}
	}
	if setAuthorityResourceLimits(nil, syscall.Setrlimit) == nil || setAuthorityResourceLimits(syscall.Getrlimit, nil) == nil {
		t.Fatal("missing kernel operation accepted")
	}
}

func TestAuthorityResourceKernelFailures(t *testing.T) {
	// Two initial reads, then set/readback for each of the two limits.
	for failure := -1; failure < 6; failure++ {
		for _, silent := range []bool{false, true} {
			t.Run(fmt.Sprintf("operation-%d-silent-%t", failure, silent), func(t *testing.T) {
				calls := 0
				expectedResources := []int{syscall.RLIMIT_CORE, syscall.RLIMIT_NOFILE, syscall.RLIMIT_CORE, syscall.RLIMIT_CORE, syscall.RLIMIT_NOFILE, syscall.RLIMIT_NOFILE}
				state := map[int]syscall.Rlimit{syscall.RLIMIT_CORE: {Cur: 4096, Max: 8192}, syscall.RLIMIT_NOFILE: {Cur: 1024, Max: 4096}}
				operation := func(r int, write bool, l *syscall.Rlimit) error {
					index := calls
					calls++
					if index >= len(expectedResources) || expectedResources[index] != r || write != (index == 2 || index == 4) {
						t.Fatal("unexpected kernel operation", index, r, write)
					}
					if failure == index && !silent {
						return syscall.EPERM
					}
					if write {
						target := uint64(0)
						if r == syscall.RLIMIT_NOFILE {
							target = 256
						}
						if *l != (syscall.Rlimit{Cur: target, Max: target}) {
							t.Fatal("unexpected resource ceiling", *l)
						}
						if failure != index {
							state[r] = *l
						}
					} else {
						*l = state[r]
						if failure == index && silent {
							l.Cur = l.Max + 1
						}
					}
					return nil
				}
				err := setAuthorityResourceLimits(func(r int, l *syscall.Rlimit) error { return operation(r, false, l) }, func(r int, l *syscall.Rlimit) error { return operation(r, true, l) })
				if failure < 0 {
					if err != nil || calls != 6 {
						t.Fatal("valid confinement refused", calls, err)
					}
					return
				}
				want := failure + 1
				if silent && (failure == 2 || failure == 4) {
					want++
				}
				if err == nil || calls != want {
					t.Fatal("uncertain confinement continued", calls, want, err)
				}
				if !silent && !errors.Is(err, syscall.EPERM) {
					t.Fatal("kernel denial lost", err)
				}
			})
		}
	}
}
