//go:build !linux

package config

import "fmt"

func replaceSecureConfigFile(string, string, []byte, *secureFileIdentity, func() error, func() error, func() error) error {
	return fmt.Errorf("atomic configuration replacement requires Linux renameat2 support")
}
