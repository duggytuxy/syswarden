//go:build linux

package sshpolicy

import (
	"errors"
	"fmt"
	"os"
	"path"
	"reflect"
	"strings"
)

// Private recovery data must never become input to sshd, including through a
// currently unmatched Include or a conditional/nested configuration file.
// The inventory reader rejects globbed directory components and noncanonical
// aliases. Reserve the entire product state parent rather than trying one
// example random filename against a pattern that could match another one.
func checkSSHStateIsolation(snapshot inventorySnapshot) error {
	if _, exists := snapshot.files[MainPath]; !exists {
		return ErrInventoryUnsafe
	}
	for name, content := range snapshot.files {
		if name == IntentPath {
			continue
		}
		for _, line := range strings.Split(string(content), "\n") {
			key, rest := splitDirective(line)
			if key != "include" {
				continue
			}
			inputs, err := arguments(rest)
			if err != nil || len(inputs) == 0 {
				return errors.Join(ErrInventoryUnsafe, err)
			}
			for _, input := range inputs {
				pattern, err := includePattern(input)
				if err != nil {
					return errors.Join(ErrInventoryUnsafe, err)
				}
				matchesParent, err := path.Match(pattern, sshStateParent)
				if err != nil {
					return errors.Join(ErrInventoryUnsafe, err)
				}
				if matchesParent || strings.HasPrefix(pattern, sshStateParent+"/") {
					return fmt.Errorf("SSH Include can reach private transaction storage; preserve configuration for review: %w", ErrInventoryUnsafe)
				}
			}
		}
	}
	return nil
}

func collectSSHStateInventory(root *os.File, uid int) (inventorySnapshot, error) {
	if root == nil {
		return inventorySnapshot{}, ErrInventoryUnsafe
	}
	snapshot, err := collectInventory(root, uid)
	if err != nil {
		return inventorySnapshot{}, err
	}
	if err := checkSSHStateIsolation(snapshot); err != nil {
		return inventorySnapshot{}, err
	}
	if err := recheckSSHStateInventory(root, uid, snapshot); err != nil {
		return inventorySnapshot{}, err
	}
	return snapshot, nil
}

func recheckSSHStateInventory(root *os.File, uid int, snapshot inventorySnapshot) error {
	current, err := collectInventory(root, uid)
	if err != nil || !reflect.DeepEqual(snapshot, current) {
		return errors.Join(ErrInventoryChanged, err)
	}
	return checkSSHStateIsolation(current)
}
