//go:build linux

package sshpolicy

import (
	"errors"
	"fmt"
	"path"
	"reflect"
	"strings"
)

// A same-directory main-file stage will be needed for RENAME_EXCHANGE.
// Its name is derived only from the validated private transaction identity.
// This function does not create it or authorize any filesystem mutation.
func sshMainStagePath(transaction string) (string, error) {
	if !lowerDigest.MatchString(transaction) {
		return "", ErrInventoryUnsafe
	}
	return "/etc/ssh/.syswarden-ssh-main-" + transaction, nil
}

// Both the candidate main file and the displaced original will occupy the
// stage name during a future exchange. Neither may enter an Include expansion.
// Examine all attested files, including nested/conditional and empty Includes,
// not only the graph currently selected for one administrator context.
func checkSSHPublicationIsolation(plan migrationPlan, transaction string) error {
	stage, err := sshMainStagePath(transaction)
	if err != nil || plan.intent.Owner != "syswarden" {
		return errors.Join(ErrInventoryUnsafe, err)
	}
	if _, exists := plan.inventory.files[MainPath]; !exists {
		return ErrInventoryUnsafe
	}
	contents := make([][]byte, 0, len(plan.inventory.files)+2)
	for name, content := range plan.inventory.files {
		if name != IntentPath {
			contents = append(contents, content)
		}
	}
	contents = append(contents, plan.main, plan.candidate.Bytes())
	for _, content := range contents {
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
					return err
				}
				matches, err := path.Match(pattern, stage)
				if err != nil || matches {
					return fmt.Errorf("SSH Include can reach the transaction stage; preserve configuration for review: %w", errors.Join(ErrInventoryUnsafe, err))
				}
			}
		}
	}
	return nil
}

// An intermediate publication may retain an old policy value or already apply
// its reviewed replacement. It may not introduce a third value, omit a setting
// or change any unrelated setting. Match-specific effective output is checked
// independently by the caller. Values remain private in errors.
func compareSSHIntermediate(before, intermediate, after sshEffective, allowed map[string]bool) error {
	if err := compareEffective(before, intermediate, allowed); err != nil {
		return err
	}
	for key := range allowed {
		value, present := intermediate[key]
		old, oldPresent := before[key]
		next, nextPresent := after[key]
		if !present || !oldPresent || !nextPresent || len(value) == 0 ||
			(!reflect.DeepEqual(value, old) && !reflect.DeepEqual(value, next)) {
			return fmt.Errorf("SSH intermediate policy differs from both reviewed states: %s", key)
		}
	}
	return nil
}
