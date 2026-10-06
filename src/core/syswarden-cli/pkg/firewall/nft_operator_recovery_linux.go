//go:build linux

package firewall

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"slices"
	"syswarden-cli/config"
	"time"
)

// Metadata only. Rule predicates, original configuration and counter evidence
// remain in the explicitly requested export or the private local decision.
type OperatorPolicyPreservationSummary struct {
	Schema                     string `json:"schema"`
	PlanSHA256                 string `json:"plan_sha256"`
	PreservationSHA256         string `json:"preservation_sha256"`
	ConfigurationPath          string `json:"configuration_path"`
	ReceiverPath               string `json:"receiver_path"`
	ReceiverTable              string `json:"receiver_table"`
	ReceiverSHA256             string `json:"receiver_sha256"`
	RuleCount                  int    `json:"rule_count"`
	DecisionPath               string `json:"decision_path"`
	ChangesActiveConfiguration bool   `json:"changes_active_configuration"`
	ChangesKernelRules         bool   `json:"changes_kernel_rules"`
	AlreadyRecorded            bool   `json:"already_recorded"`
}

func openNFTOperatorPreservation(ctx context.Context) (*nftOperatorPreservationInspection, func(), error) {
	if firewallCleanupEffectiveUserID() != 0 {
		return nil, nil, fmt.Errorf("operator preservation inspection must run as root")
	}
	candidate, err := config.InspectOperatorPolicyForRecovery("/etc/syswarden/config")
	if err != nil {
		return nil, nil, err
	}
	if path, err := config.OperatorPolicySourcePath(candidate); err != nil || path != nftOperatorConfigurationPath {
		return nil, nil, fmt.Errorf("operator preservation requires the exact documented administrator source")
	}
	root, err := os.OpenRoot("/")
	if err != nil {
		return nil, nil, err
	}
	closeRoot := func() { _ = root.Close() }
	fail := func(err error) (*nftOperatorPreservationInspection, func(), error) { closeRoot(); return nil, nil, err }
	host := nftPersistenceFilesystem{root: root}
	loader, err := inspectNFTOperatorBootLoader(ctx, host)
	if err != nil {
		return fail(err)
	}
	runner, err := uninstallNFTRunnerFactory()
	if err != nil {
		return fail(err)
	}
	dependencies := nftOperatorPreservationDependencies{
		rules:  slices.Clone(candidate.OperatorPolicy.Rules),
		source: func() error { return config.ReattestOperatorPolicySource(candidate) },
		loader: loader.digest, entries: slices.Clone(loader.loader.status.entries), verifyLoader: loader.verify, runner: runner,
	}
	inspection, err := inspectNFTOperatorPreservationUsing(ctx, host, dependencies)
	if err != nil {
		return fail(err)
	}
	return inspection, closeRoot, nil
}

// Kept as an internal dependency for isolated filesystem and kernel fixtures.
// Production has no environment variable or command-line option replacing it.
var openNFTOperatorRemovalProof = openNFTOperatorPreservation

func authorizeNFTOperatorPolicyRemoval(ctx context.Context, expected *nftPreservedOperatorInputs) (*nftPreservedOperatorInputs, error) {
	if err := expected.validate(); err != nil {
		return nil, err
	}
	inspection, closeInspection, err := openNFTOperatorRemovalProof(ctx)
	if err != nil {
		return nil, err
	}
	if inspection == nil || closeInspection == nil {
		return nil, fmt.Errorf("administrator preservation proof is unavailable")
	}
	defer closeInspection()
	if err := inspection.authorize(ctx); err != nil {
		return nil, err
	}
	actual := &nftPreservedOperatorInputs{Rules: slices.Clone(inspection.binding.Rules), Proof: inspection.key}
	if expected != nil {
		left, err := compileOperatorPolicy(expected.Rules)
		if err != nil {
			return nil, err
		}
		right, err := compileOperatorPolicy(actual.Rules)
		if err != nil || expected.Proof != actual.Proof || left.chain != right.chain {
			return nil, fmt.Errorf("administrator preservation differs from the bound retirement inputs")
		}
	}
	return actual, nil
}

func verifyNFTOperatorRemovalBinding(ctx context.Context, input *nftCurrentPersistenceInputs) error {
	if input == nil {
		return fmt.Errorf("current removal input is missing")
	}
	if input.Operator == nil {
		return nil
	}
	_, err := authorizeNFTOperatorPolicyRemoval(ctx, input.Operator)
	return err
}

func (inspection *nftOperatorPreservationInspection) summary(ctx context.Context) (OperatorPolicyPreservationSummary, error) {
	var empty OperatorPolicyPreservationSummary
	if err := inspection.verify(ctx); err != nil {
		return empty, err
	}
	record, err := readNFTOperatorPreservationRecord(inspection.host, inspection.key)
	var digest string
	recorded := err == nil
	if recorded {
		if err := inspection.authorize(ctx); err != nil {
			return empty, err
		}
		digest = record.Reviewed
	} else {
		if !errors.Is(err, fs.ErrNotExist) {
			return empty, err
		}
		plan, err := inspection.plan(ctx)
		if err != nil {
			return empty, err
		}
		_, digest, err = encodeNFTOperatorPreservationPlan(inspection.host, plan)
		if err != nil {
			return empty, err
		}
	}
	return OperatorPolicyPreservationSummary{
		Schema: nftOperatorPreservationSchema, PlanSHA256: digest, PreservationSHA256: inspection.key,
		ConfigurationPath: nftOperatorConfigurationPath, ReceiverPath: nftOperatorReceiverPath(inspection.model),
		ReceiverTable: inspection.model.table, ReceiverSHA256: nftSHA256Hex(inspection.model.source), RuleCount: len(inspection.model.rules),
		DecisionPath: nftOperatorPreservationDirectory(inspection.key) + "/plan.json", AlreadyRecorded: recorded,
	}, nil
}

// Export is read-only preparation. The operator must review and independently
// install this exact policy under the actual shared loader before preservation
// can be acknowledged. Exporting does not grant any removal authority.
type OperatorPolicyReceiverExport struct {
	Path   string
	Source []byte
}

func ExportOperatorPolicyReceiver() (OperatorPolicyReceiverExport, error) {
	var empty OperatorPolicyReceiverExport
	if firewallCleanupEffectiveUserID() != 0 {
		return empty, fmt.Errorf("operator policy export must run as root")
	}
	candidate, err := config.InspectOperatorPolicyForRecovery("/etc/syswarden/config")
	if err != nil {
		return empty, err
	}
	model, err := prepareNFTOperatorReceiver(candidate.OperatorPolicy.Rules)
	if err != nil {
		return empty, err
	}
	if err := config.ReattestOperatorPolicySource(candidate); err != nil {
		return empty, err
	}
	return OperatorPolicyReceiverExport{nftOperatorReceiverPath(model), slices.Clone(model.source)}, nil
}

func InspectOperatorPolicyPreservation(ctx context.Context) (OperatorPolicyPreservationSummary, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	inspection, closeInspection, err := openNFTOperatorPreservation(ctx)
	if err != nil {
		return OperatorPolicyPreservationSummary{}, err
	}
	defer closeInspection()
	return inspection.summary(ctx)
}

func ApplyOperatorPolicyPreservation(ctx context.Context, reviewed string) (OperatorPolicyPreservationSummary, error) {
	var empty OperatorPolicyPreservationSummary
	if !validLegacyRetirementDigest(reviewed) {
		return empty, fmt.Errorf("operator preservation requires the exact reviewed lowercase SHA-256")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	inspection, closeInspection, err := openNFTOperatorPreservation(ctx)
	if err != nil {
		return empty, err
	}
	defer closeInspection()
	lock, err := acquireNFTReloadGuard()
	if err != nil {
		return empty, err
	}
	defer releaseNFTReloadGuard(lock)
	if err := inspection.apply(ctx, reviewed, defaultLegacyRetirementFileOps()); err != nil {
		return empty, err
	}
	return inspection.summary(ctx)
}
