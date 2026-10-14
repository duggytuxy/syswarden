package authorityentry

import (
	"errors"
	"testing"

	"golang.org/x/sys/unix"
)

// Fault injection must never clear descriptor flags after a failed unshare,
// continue after uncertain fcntl results or substitute an incomplete inventory.
func TestExecDescriptorIsolationFailsClosed(t *testing.T) {
	for _, failure := range []int{-1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9} {
		for _, silent := range []bool{false, true} {
			calls := 0
			err := sealExecDescriptors(func(first, last, flags uint) error {
				if first != 3 || last != uint(^uint32(0)) || flags != unix.CLOSE_RANGE_UNSHARE|unix.CLOSE_RANGE_CLOEXEC {
					t.Fatal("incomplete descriptor isolation")
				}
				if failure == 0 {
					return unix.EPERM
				}
				return nil
			}, func(fd uintptr, command, value int) (int, error) {
				calls++
				wantFD := uintptr(3 + (calls-1)/2)
				wantCommand := unix.F_SETFD
				if calls%2 == 0 || calls == 9 {
					wantCommand = unix.F_GETFD
				}
				if fd != wantFD || command != wantCommand || value != 0 {
					t.Fatal("unexpected descriptor allowlist")
				}
				if failure == calls {
					if silent && command == unix.F_GETFD {
						if fd == 7 {
							return 0, nil
						}
						return unix.FD_CLOEXEC, nil
					}
					return 0, unix.EBADF
				}
				if fd == 7 {
					return unix.FD_CLOEXEC, nil
				}
				return 0, nil
			})
			if failure == -1 {
				if err != nil || calls != 9 {
					t.Fatal("valid isolation rejected", err)
				}
			} else {
				if err == nil || calls != failure {
					t.Fatal("uncertain isolation continued", failure, calls, err)
				}
				if failure == 0 && !errors.Is(err, unix.EPERM) {
					t.Fatal("lost kernel policy denial")
				}
			}
		}
	}
}
