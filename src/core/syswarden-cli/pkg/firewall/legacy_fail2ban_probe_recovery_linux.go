//go:build linux

package firewall

import (
	"crypto/sha256"
	"fmt"
)

// Reconstruct only the exact journal-bound originals, then evaluate the
// original and final configurations again. A previous successful dump is not
// evidence that a different interpreter or parser can safely resume the plan.
func revalidateLegacyFail2banPlanViews(host nftPersistenceFilesystem, record legacyFail2banPlanRecord, probe legacyFail2banConfigurationProbe) error {
	if probe == nil {
		return fmt.Errorf("Fail2ban recovery requires an attested parser")
	}
	state, err := inspectLegacyFail2banPlanState(host, record)
	if err != nil {
		return err
	}
	paths := make(map[string]bool, len(record.Targets))
	for _, path := range record.Targets {
		paths[path] = true
	}
	var retiring []nftPersistenceRetiredSource
	jails := make(map[string]bool)
	for _, source := range state.baseline.sources {
		if !paths[source.path] {
			continue
		}
		match, exact := matchLegacyFail2banTemplate(source.path, source.snapshot.content)
		if !exact {
			return fmt.Errorf("Fail2ban recovery source no longer matches its complete template")
		}
		retiring = append(retiring, nftPersistenceRetiredSource{source.path, source.sha256})
		if match.kind == "jail" {
			jails[match.jail] = true
		}
	}
	before, err := probe(cloneLegacyFail2banInventory(state.baseline), nil)
	if err != nil {
		return fmt.Errorf("reattest original Fail2ban recovery configuration: %w", err)
	}
	after, err := probe(cloneLegacyFail2banInventory(state.baseline), retiring)
	if err != nil {
		return fmt.Errorf("reattest final Fail2ban recovery configuration: %w", err)
	}
	if before.parserSHA256 != record.ParserSHA256 || after.parserSHA256 != record.ParserSHA256 {
		return fmt.Errorf("Fail2ban recovery parser differs from the published plan; preserve the journal and source evidence")
	}
	views := [4][sha256.Size]byte{sha256.Sum256(before.enabled), sha256.Sum256(before.allJails), sha256.Sum256(after.enabled), sha256.Sum256(after.allJails)}
	if views != record.Views {
		return fmt.Errorf("Fail2ban recovery effective configuration differs from the published plan")
	}
	if err := verifyLegacyFail2banConfigurationViews(before, after, jails); err != nil {
		return err
	}
	_, err = inspectLegacyFail2banPlanState(host, record)
	return err
}

// These production file-phase adapters require the caller to hold removal
// locks, retain the barrier and independently attest quiescent target jails,
// exact live actions, service entry points and unrelated active protections.
// The guard is read-only and mandatory. Neither helper stops a jail or claims
// complete host removal after moving files.
func publishVerifiedLegacyFail2banFilePlan(host nftPersistenceFilesystem, plan legacyFail2banRetirementPlan, liveGuard func() error, ops legacyRetirementFileOps) error {
	if !validLegacyRetirementOperations(liveGuard, ops) {
		return fmt.Errorf("Fail2ban retirement requires complete live guards")
	}
	if err := liveGuard(); err != nil {
		return err
	}
	parser, err := captureLegacyFail2banParser(host)
	if err != nil {
		return err
	}
	if parser.digest != plan.binding.ParserSHA256 {
		return fmt.Errorf("Fail2ban retirement parser differs from the inspected plan")
	}
	probe := legacyFail2banConfigurationProbeUsingParser(host, parser)
	if err := revalidateLegacyFail2banPlanViews(host, plan.binding, probe); err != nil {
		return err
	}
	guard := func() error {
		if err := liveGuard(); err != nil {
			return err
		}
		return parser.reattest(host)
	}
	if err := persistLegacyFail2banPlanUsing(host, plan, guard, ops); err != nil {
		return err
	}
	if err := revalidateLegacyFail2banPlanViews(host, plan.binding, probe); err != nil {
		return err
	}
	if err := guard(); err != nil {
		return err
	}
	_, err = inspectLegacyFail2banPlanState(host, plan.binding)
	return err
}

func resumeVerifiedLegacyFail2banFilePlan(host nftPersistenceFilesystem, digest string, liveGuard func() error, ops legacyRetirementFileOps) error {
	if !validLegacyRetirementOperations(liveGuard, ops) {
		return fmt.Errorf("Fail2ban recovery requires complete live guards")
	}
	if err := liveGuard(); err != nil {
		return err
	}
	record, err := readLegacyFail2banPlan(host, digest)
	if err != nil {
		return err
	}
	parser, err := captureLegacyFail2banParser(host)
	if err != nil {
		return err
	}
	if parser.digest != record.ParserSHA256 {
		return fmt.Errorf("Fail2ban recovery parser differs from the published plan")
	}
	probe := legacyFail2banConfigurationProbeUsingParser(host, parser)
	if err := revalidateLegacyFail2banPlanViews(host, record, probe); err != nil {
		return err
	}
	guard := func() error {
		if err := liveGuard(); err != nil {
			return err
		}
		return parser.reattest(host)
	}
	if err := resumeLegacyFail2banPlanUsing(host, digest, guard, ops); err != nil {
		return err
	}
	if err := revalidateLegacyFail2banPlanViews(host, record, probe); err != nil {
		return err
	}
	if err := guard(); err != nil {
		return err
	}
	_, err = inspectLegacyFail2banPlanState(host, record)
	return err
}
