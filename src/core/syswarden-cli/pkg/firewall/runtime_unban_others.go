//go:build !linux

package firewall

import "fmt"

func preflightRuntimeUnban(string) error {
	return fmt.Errorf("authoritative runtime unblock requires Linux")
}
