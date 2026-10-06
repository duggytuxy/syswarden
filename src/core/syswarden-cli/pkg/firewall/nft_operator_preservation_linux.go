//go:build linux

package firewall

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"syswarden-cli/config"
)

const nftOperatorConfigurationPath = "/etc/syswarden/config/modules/99-user.toml"
const nftOperatorPreservationSchema = "syswarden-operator-preservation-v1"

type nftOperatorPreservationBinding struct {
	Schema        string                          `json:"schema"`
	Configuration nftPersistenceGraphSourceRecord `json:"configuration"`
	Receiver      nftPersistenceGraphSourceRecord `json:"receiver"`
	Rules         []config.OperatorPolicyRule     `json:"rules"`
	Loader        string                          `json:"loader_sha256"`
}

// A preservation proof does not transfer ownership of administrator rules to
// the product. It records a reviewed, separately loaded copy of the exact typed
// policy. Product ownership and every surrounding runtime object remain subject
// to their independent existing retirement recognizers.
type nftOperatorPreservationPlan struct {
	Binding    nftOperatorPreservationBinding       `json:"binding"`
	Writer     nftPersistenceGraphSourceRecord      `json:"writer"`
	Source     nftPersistenceGraphSourceRecord      `json:"source"`
	Entries    []string                             `json:"loader_entries"`
	Files      []nftPersistenceGraphSourceRecord    `json:"graph_sources"`
	Expansions []nftPersistenceGraphExpansionRecord `json:"graph_expansions"`
}

type nftOperatorPreservationDependencies struct {
	rules        []config.OperatorPolicyRule
	source       func() error
	loader       string
	entries      []string
	verifyLoader func(context.Context) error
	runner       nftCommandRunner
}

type nftOperatorPreservationInspection struct {
	host         nftPersistenceFilesystem
	dependencies nftOperatorPreservationDependencies
	model        nftOperatorReceiverModel
	binding      nftOperatorPreservationBinding
	key          string
	graph        nftPersistenceGraph
}

func nftOperatorReceiverPath(model nftOperatorReceiverModel) string {
	return "/etc/nftables.d/" + model.table + ".nft"
}

func encodeNFTOperatorPreservationBinding(host nftPersistenceFilesystem, binding nftOperatorPreservationBinding) ([]byte, string, error) {
	invalid := func() ([]byte, string, error) {
		return nil, "", fmt.Errorf("operator preservation binding is incomplete or unbounded")
	}
	if binding.Schema != nftOperatorPreservationSchema || !validLegacyRetirementDigest(binding.Loader) {
		return invalid()
	}
	model, err := prepareNFTOperatorReceiver(binding.Rules)
	if err != nil {
		return invalid()
	}
	if binding.Configuration.Artifact.Path != nftOperatorConfigurationPath || binding.Receiver.Artifact.Path != nftOperatorReceiverPath(model) || binding.Receiver.Artifact.SHA256 != nftSHA256Hex(model.source) {
		return invalid()
	}
	for _, record := range []nftPersistenceGraphSourceRecord{binding.Configuration, binding.Receiver} {
		if !validNFTOperatorPreservationSourceMode(record.Artifact.Path, record.Artifact.Mode) || record.Size == 0 || record.EditedSHA256 != record.Artifact.SHA256 || !validLegacyRetirementDigest(record.Xattrs) || validateLegacyRetirementFileRecord(nftPersistenceGraphFileRecord(record, nftSHA256Hex([]byte(nftOperatorPreservationSchema))), host.expectedUID, host.expectedGID) != nil {
			return invalid()
		}
	}
	wire, err := json.Marshal(binding)
	if err != nil || len(wire) > 128<<10 {
		return invalid()
	}
	return wire, nftSHA256Hex(wire), nil
}

func inspectNFTOperatorPreservationUsing(ctx context.Context, host nftPersistenceFilesystem, dependencies nftOperatorPreservationDependencies) (*nftOperatorPreservationInspection, error) {
	if dependencies.source == nil || dependencies.verifyLoader == nil || dependencies.runner == nil || !validLegacyRetirementDigest(dependencies.loader) || len(dependencies.entries) != 1 {
		return nil, fmt.Errorf("operator preservation requires independent typed source, enabled loader and runtime inspection")
	}
	if err := dependencies.source(); err != nil {
		return nil, err
	}
	if err := dependencies.verifyLoader(ctx); err != nil {
		return nil, err
	}
	model, err := prepareNFTOperatorReceiver(dependencies.rules)
	if err != nil {
		return nil, err
	}
	configuration, err := bindNFTOperatorPrivateSource(host, nftOperatorConfigurationPath)
	if err != nil {
		return nil, err
	}
	receiver, err := bindNFTOperatorPrivateSource(host, nftOperatorReceiverPath(model))
	if err != nil {
		return nil, err
	}
	binding := nftOperatorPreservationBinding{nftOperatorPreservationSchema, configuration, receiver, slices.Clone(dependencies.rules), dependencies.loader}
	_, key, err := encodeNFTOperatorPreservationBinding(host, binding)
	if err != nil {
		return nil, err
	}
	graph, err := inspectNFTPersistenceGraph(dependencies.entries, host.reader())
	if err != nil {
		return nil, err
	}
	inspection := &nftOperatorPreservationInspection{host, dependencies, model, binding, key, graph}
	return inspection, inspection.verify(ctx)
}

// Keep the two documented administrator configuration modes unchanged. The
// artifact validator independently requires the expected owner and root group.
// Receiver and product writer sources retain their exact private mode.
func validNFTOperatorPreservationSourceMode(path string, mode uint32) bool {
	return mode == 0600 || path == nftOperatorConfigurationPath && mode == 0640
}

func bindNFTOperatorPrivateSource(host nftPersistenceFilesystem, path string) (nftPersistenceGraphSourceRecord, error) {
	var empty nftPersistenceGraphSourceRecord
	source, attrs, err := snapshotNFTPersistenceMetadata(host, path)
	if err != nil || source.identity == nil || !validNFTOperatorPreservationSourceMode(path, uint32(source.identity.Mode().Perm())) || len(source.content) == 0 {
		return empty, fmt.Errorf("operator preservation source is absent or lacks exact private metadata")
	}
	return bindNFTPersistenceGraphSource(path, source, attrs, source.content)
}

func (inspection *nftOperatorPreservationInspection) verify(ctx context.Context) error {
	if inspection == nil || inspection.dependencies.source == nil || inspection.dependencies.verifyLoader == nil || inspection.dependencies.runner == nil {
		return fmt.Errorf("operator preservation inspection is missing")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := inspection.dependencies.source(); err != nil {
		return err
	}
	if err := inspection.dependencies.verifyLoader(ctx); err != nil {
		return err
	}
	_, key, err := encodeNFTOperatorPreservationBinding(inspection.host, inspection.binding)
	if err != nil || key != inspection.key {
		return fmt.Errorf("operator preservation binding changed")
	}
	for _, record := range []nftPersistenceGraphSourceRecord{inspection.binding.Configuration, inspection.binding.Receiver} {
		source, attrs, err := snapshotNFTPersistenceMetadata(inspection.host, record.Artifact.Path)
		if err != nil || !matchesNFTHistoricalInput(record, source, attrs) {
			return fmt.Errorf("operator configuration or receiver source changed after inspection")
		}
	}
	if err := verifyNFTPersistenceGraph(inspection.graph, inspection.host.reader()); err != nil {
		return err
	}
	if err := verifyNFTOperatorReceiverGraph(inspection.model, nftOperatorReceiverPath(inspection.model), inspection.graph, inspection.host.read); err != nil {
		return err
	}
	observed, err := inspection.dependencies.runner.Run(ctx, nil, "-j", "list", "table", "inet", inspection.model.table)
	if err != nil {
		return fmt.Errorf("independent administrator receiver is not observable")
	}
	_, err = inspection.model.inspect(observed)
	return err
}

func (inspection *nftOperatorPreservationInspection) plan(ctx context.Context) (nftOperatorPreservationPlan, error) {
	var empty nftOperatorPreservationPlan
	if err := inspection.verify(ctx); err != nil {
		return empty, err
	}
	origin, receipt, err := inspectNFTPolicyReceipt(inspection.host)
	if err != nil {
		return empty, err
	}
	source, err := bindNFTOperatorPrivateSource(inspection.host, legacyNFTIncludePath)
	if err != nil {
		return empty, err
	}
	original, err := inspection.host.read(legacyNFTIncludePath)
	if err != nil {
		return empty, err
	}
	preservation := &nftPreservedOperatorInputs{Rules: inspection.binding.Rules, Proof: inspection.key}
	if _, err := currentNFTInputsFromPreservedOwnership(original, receipt, preservation); err != nil {
		return empty, err
	}
	live, err := inspection.dependencies.runner.Run(ctx, nil, "-j", "list", "table", "inet", "syswarden")
	if err != nil {
		return empty, err
	}
	if _, _, err := normalizeNFTOperatorRuntime(live, inspection.binding.Rules); err != nil {
		return empty, err
	}
	plan := nftOperatorPreservationPlan{Binding: inspection.binding, Writer: origin.record, Source: source, Entries: slices.Clone(inspection.graph.entries)}
	for _, item := range inspection.graph.sources {
		snapshot, attrs, err := snapshotNFTPersistenceMetadata(inspection.host, item.path)
		if err != nil || nftSHA256Hex(snapshot.content) != fmt.Sprintf("%x", item.sha256) {
			return empty, fmt.Errorf("operator preservation graph source changed")
		}
		record, err := bindNFTPersistenceGraphSource(item.path, snapshot, attrs, snapshot.content)
		if err != nil {
			return empty, err
		}
		plan.Files = append(plan.Files, record)
	}
	for _, item := range inspection.graph.expansions {
		plan.Expansions = append(plan.Expansions, nftPersistenceGraphExpansionRecord{Pattern: item.pattern, Paths: slices.Clone(item.paths)})
	}
	if _, _, err := encodeNFTOperatorPreservationPlan(inspection.host, plan); err != nil {
		return empty, err
	}
	return plan, inspection.verify(ctx)
}

func encodeNFTOperatorPreservationPlan(host nftPersistenceFilesystem, plan nftOperatorPreservationPlan) ([]byte, string, error) {
	_, key, err := encodeNFTOperatorPreservationBinding(host, plan.Binding)
	if err != nil {
		return nil, "", err
	}
	invalid := func() ([]byte, string, error) {
		return nil, "", fmt.Errorf("operator preservation plan lacks bounded review evidence")
	}
	if plan.Writer.Artifact.Path != nftStateDirectory+"/"+nftPolicyOwnershipName || plan.Source.Artifact.Path != legacyNFTIncludePath || len(plan.Entries) != 1 || len(plan.Files) == 0 || len(plan.Files) > maximumNFTPersistenceFiles || len(plan.Expansions) > maximumNFTPersistenceIncludes {
		return invalid()
	}
	seen := map[string]bool{}
	for _, record := range append([]nftPersistenceGraphSourceRecord{plan.Writer, plan.Source}, plan.Files...) {
		if record.EditedSHA256 != record.Artifact.SHA256 || !validLegacyRetirementDigest(record.Xattrs) || validateLegacyRetirementFileRecord(nftPersistenceGraphFileRecord(record, key), host.expectedUID, host.expectedGID) != nil {
			return invalid()
		}
	}
	for _, record := range plan.Files {
		if seen[record.Artifact.Path] {
			return invalid()
		}
		seen[record.Artifact.Path] = true
	}
	if !seen[plan.Entries[0]] || !seen[plan.Binding.Receiver.Artifact.Path] {
		return invalid()
	}
	for _, item := range plan.Expansions {
		if !canonicalNFTPersistencePath(item.Pattern, true) || len(item.Paths) > maximumNFTPersistenceFiles {
			return invalid()
		}
		for _, path := range item.Paths {
			if !seen[path] {
				return invalid()
			}
		}
	}
	wire, err := json.Marshal(plan)
	if err != nil || len(wire) > 2<<20 {
		return invalid()
	}
	return wire, nftSHA256Hex(wire), nil
}

func equalNFTOperatorBindings(host nftPersistenceFilesystem, left, right nftOperatorPreservationBinding) bool {
	a, _, err := encodeNFTOperatorPreservationBinding(host, left)
	if err != nil {
		return false
	}
	b, _, err := encodeNFTOperatorPreservationBinding(host, right)
	return err == nil && bytes.Equal(a, b)
}
