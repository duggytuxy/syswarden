//go:build !linux

package config

import "fmt"

func replaceSecureConfigFile(string, string, []byte, *secureFileIdentity, func() error, func() error, func() error) error {
	return fmt.Errorf("atomic configuration replacement requires Linux renameat2 support")
}

func publishReviewedModule(*moduleProposalState, func() error, func() error, func() error) error {
	return fmt.Errorf("reviewed configuration publication requires Linux renameat2 support")
}

func applyModuleEditRecovery(*moduleEditRecoveryState, func() error) error {
	return fmt.Errorf("configuration edit recovery requires Linux renameat2 support")
}
