package config

import (
	"fmt"
	"os"
)

// A privileged proposal must not treat another user's writable configuration
// tree as publication authority. Refusal preserves all original ownership.
func (snapshot *mergedConfigSnapshot) requireEditOwnership(operatorUID int) error {
	if snapshot == nil || operatorUID < 0 {
		return fmt.Errorf("configuration edit ownership is unavailable")
	}
	require := func(name string, info os.FileInfo) error {
		uid, ok := fileOwnerUID(info)
		if !ok || int64(uid) != int64(operatorUID) {
			return fmt.Errorf("configuration edit requires effective-user ownership of %s; preserve and review its administrator ownership", name)
		}
		return nil
	}
	if err := require("configuration root", snapshot.configRootInfo); err != nil {
		return err
	}
	if err := require("modules root", snapshot.modulesRootInfo); err != nil {
		return err
	}
	if snapshot.master != nil {
		if err := require("config.toml", snapshot.master.info); err != nil {
			return err
		}
	}
	if snapshot.user != nil {
		if err := require("modules/"+userModuleName, snapshot.user.info); err != nil {
			return err
		}
	}
	for name, identity := range snapshot.modules {
		if identity == nil {
			return fmt.Errorf("configuration module identity is missing")
		}
		if err := require("modules/"+name, identity.info); err != nil {
			return err
		}
	}
	return nil
}

// Reject unsupported recovery metadata before presenting publication approval
// or creating a staging file. Never change ownership, links or modes to fit.
func (snapshot *mergedConfigSnapshot) requireEditRecoveryMetadata() error {
	if snapshot == nil {
		return fmt.Errorf("configuration recovery input snapshot is missing")
	}
	if _, err := moduleEditDirectoryFrom(snapshot.configRootInfo); err != nil {
		return err
	}
	if _, err := moduleEditDirectoryFrom(snapshot.modulesRootInfo); err != nil {
		return err
	}
	inputs := make([]*secureFileIdentity, 0, len(snapshot.modules)+2)
	if snapshot.master != nil {
		inputs = append(inputs, snapshot.master)
	}
	if snapshot.user != nil {
		inputs = append(inputs, snapshot.user)
	}
	for _, identity := range snapshot.modules {
		inputs = append(inputs, identity)
	}
	if len(inputs) > maximumModuleEditInputs {
		return fmt.Errorf("configuration edit exceeds its input inventory limit")
	}
	for _, identity := range inputs {
		if _, err := moduleEditFileFrom(identity); err != nil {
			return err
		}
	}
	return nil
}
