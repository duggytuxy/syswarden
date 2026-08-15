//go:build freebsd

package cmd

import (
	"testing"

	"syswarden-cli/pkg/firewall"
)

func TestPackagePFSnapshotIsRootOnlyAndUsesExplicitProvenance(t *testing.T) {
	if _, ok := degradedConfigAllowlist["package-capture-pf"]; !ok {
		t.Fatal("hidden package PF snapshot is unavailable with degraded config")
	}
	originalEUID := packagePFSnapshotEUID
	originalCapture := capturePackagePFPolicy
	originalLegacy := packagePFLegacyV4028
	t.Cleanup(func() {
		packagePFSnapshotEUID = originalEUID
		capturePackagePFPolicy = originalCapture
		packagePFLegacyV4028 = originalLegacy
	})

	var observed firewall.PFSnapshotProvenance
	capturePackagePFPolicy = func(provenance firewall.PFSnapshotProvenance) error {
		observed = provenance
		return nil
	}
	packagePFSnapshotEUID = func() int { return 0 }
	packagePFLegacyV4028 = false
	if err := packagePFSnapshotCmd.RunE(packagePFSnapshotCmd, nil); err != nil {
		t.Fatal(err)
	}
	if observed != firewall.PFSnapshotExactLive {
		t.Fatalf("fresh package capture used %q", observed)
	}
	packagePFLegacyV4028 = true
	if err := packagePFSnapshotCmd.RunE(packagePFSnapshotCmd, nil); err != nil {
		t.Fatal(err)
	}
	if observed != firewall.PFSnapshotLegacyDerived {
		t.Fatalf("legacy package capture used %q", observed)
	}
	packagePFSnapshotEUID = func() int { return 1000 }
	if err := packagePFSnapshotCmd.RunE(packagePFSnapshotCmd, nil); err == nil {
		t.Fatal("non-root package PF snapshot was accepted")
	}
}
