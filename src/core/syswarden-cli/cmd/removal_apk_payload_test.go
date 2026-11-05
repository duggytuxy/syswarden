package cmd

import (
	"bytes"
	"errors"
	"testing"
)

func TestAPKRetentionCommandDoesNotLoadConfigurationOrRecoverFirewall(t *testing.T) {
	oldRetain, oldPreserve, oldLoad, oldRecover := retainAPKPayload, preserveAPKRemovalPayload, initConfigHook, recoverPendingFirewallTransactionHook
	defer func() {
		retainAPKPayload, preserveAPKRemovalPayload, initConfigHook, recoverPendingFirewallTransactionHook = oldRetain, oldPreserve, oldLoad, oldRecover
		preparePackageRemovalCmd.SetOut(nil)
	}()
	retainAPKPayload = true
	initConfigHook = func() { t.Fatal("APK recovery loaded configuration") }
	recoverPendingFirewallTransactionHook = func() error { t.Fatal("APK recovery changed firewall"); return nil }
	preparePackageRemovalCmd.SetOut(&bytes.Buffer{})
	for _, fail := range []bool{false, true} {
		called := false
		preserveAPKRemovalPayload = func() (string, error) {
			called = true
			if fail {
				return "", errors.New("backup refused")
			}
			return "/private/verified", nil
		}
		if err := rootCmd.PersistentPreRunE(preparePackageRemovalCmd, nil); err != nil {
			t.Fatal(err)
		}
		err := preparePackageRemovalCmd.RunE(preparePackageRemovalCmd, nil)
		if !called || (err != nil) != fail {
			t.Fatal("retention outcome was not propagated", err)
		}
	}
}
