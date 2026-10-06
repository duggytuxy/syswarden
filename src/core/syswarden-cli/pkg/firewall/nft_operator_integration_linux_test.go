//go:build linux

package firewall

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
	"syswarden-cli/config"
	"testing"
)

func fixtureNFTOperatorRemovalProof(t *testing.T) (*nftOperatorPreservationInspection, *nftRemovalFixtureRunner, *config.Config) {
	t.Helper()
	return fixtureNFTOperatorRemovalProofWithMode(t, 0600)
}

func fixtureNFTOperatorRemovalProofWithMode(t *testing.T, mode fs.FileMode) (*nftOperatorPreservationInspection, *nftRemovalFixtureRunner, *config.Config) {
	t.Helper()
	inspection, _ := fixtureNFTOperatorPreservation(t)
	var module strings.Builder
	module.WriteString("# Administrator source retained at the original path.\n")
	for _, rule := range inspection.binding.Rules {
		fmt.Fprintf(&module, "[[operator_policy.rules]]\nid = %q\nfamily = %q\ndirection = %q\nprotocol = %q\nsource = %q\naction = %q\n", rule.ID, rule.Family, rule.Direction, rule.Protocol, rule.Source, rule.Action)
		if rule.ICMPType != "" {
			fmt.Fprintf(&module, "type = %q\n", rule.ICMPType)
		}
		if rule.DestinationPort != 0 {
			fmt.Fprintf(&module, "destination_port = %d\n", rule.DestinationPort)
		}
	}
	if err := inspection.host.root.WriteFile(nftOperatorConfigurationPath[1:], []byte(module.String()), 0600); err != nil {
		t.Fatal(err)
	}
	if err := inspection.host.root.Chmod(nftOperatorConfigurationPath[1:], mode); err != nil {
		t.Fatal(err)
	}
	candidate, err := config.InspectOperatorPolicyForRecovery(filepath.Join(inspection.host.root.Name(), "etc/syswarden/config"))
	if err != nil {
		t.Fatal(err)
	}
	fixture, _, _ := fixtureNFTOperatorCurrent(t, 7)
	runner := fixtureNFTCurrentRuntimeRunner(fixture)
	runner.tables[nftTableTarget{family: "inet", name: inspection.model.table}] = marshalMutableNFTVerificationFixture(t, fixtureNFTOperatorReceiverDocument(t, inspection.model))
	deps := inspection.dependencies
	deps.rules = candidate.OperatorPolicy.Rules
	deps.source = func() error { return config.ReattestOperatorPolicySource(candidate) }
	deps.runner = runner
	inspection, err = inspectNFTOperatorPreservationUsing(context.Background(), inspection.host, deps)
	if err != nil {
		t.Fatal(err)
	}
	oldOpen := openNFTOperatorRemovalProof
	openNFTOperatorRemovalProof = func(ctx context.Context) (*nftOperatorPreservationInspection, func(), error) {
		fresh, err := inspectNFTOperatorPreservationUsing(ctx, inspection.host, inspection.dependencies)
		if err != nil {
			return nil, nil, err
		}
		return fresh, func() {}, nil
	}
	t.Cleanup(func() { openNFTOperatorRemovalProof = oldOpen })
	return inspection, runner, candidate
}

func approveNFTOperatorFixture(t *testing.T, inspection *nftOperatorPreservationInspection) {
	t.Helper()
	plan, err := inspection.plan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	_, digest, err := encodeNFTOperatorPreservationPlan(inspection.host, plan)
	if err != nil {
		t.Fatal(err)
	}
	if err := inspection.apply(context.Background(), digest, defaultLegacyRetirementFileOps()); err != nil {
		t.Fatal(err)
	}
}

func TestNFTOperatorRemovalRequiresActualReviewedReceiver(t *testing.T) {
	inspection, runner, candidate := fixtureNFTOperatorRemovalProof(t)
	oldConfig := config.GlobalConfig
	config.GlobalConfig = candidate
	t.Cleanup(func() { config.GlobalConfig = oldConfig })
	document, err := decodeNFTJSON(runner.tables[nftTableTarget{family: "inet", name: "syswarden"}])
	if err != nil {
		t.Fatal(err)
	}
	if err := preflightConfiguredOperatorPolicyRemoval(); err == nil {
		t.Fatal("unacknowledged configured policy accepted")
	}
	if err := preflightLiveOperatorPolicyRemoval(document); err == nil {
		t.Fatal("unacknowledged live policy accepted")
	}
	if _, err := inspectNFTPolicyOwnership(inspection.host); err == nil {
		t.Fatal("unacknowledged writer policy accepted")
	}
	approveNFTOperatorFixture(t, inspection)
	if err := preflightConfiguredOperatorPolicyRemoval(); err != nil {
		t.Fatal(err)
	}
	if err := preflightLiveOperatorPolicyRemoval(document); err != nil {
		t.Fatal(err)
	}
	owned, err := inspectNFTPolicyOwnership(inspection.host)
	if err != nil || owned.inputs.Operator == nil || owned.inputs.Operator.Proof != inspection.key {
		t.Fatal("writer did not bind exact independent preservation", err)
	}
	target := nftTableTarget{family: "inet", name: inspection.model.table}
	runner.tables[target] = bytes.Replace(runner.tables[target], []byte("accept"), []byte("drop"), 1)
	if err := preflightConfiguredOperatorPolicyRemoval(); err == nil {
		t.Fatal("changed receiver accepted for configured policy")
	}
	if err := preflightLiveOperatorPolicyRemoval(document); err == nil {
		t.Fatal("changed receiver accepted for live policy")
	}
	if _, err := inspectNFTPolicyOwnership(inspection.host); err == nil {
		t.Fatal("changed receiver accepted by writer recognition")
	}
}

func TestNFTOperatorRemovalPreservationDoesNotAuthorizeForeignRuntime(t *testing.T) {
	for _, kind := range []string{"changed-operator", "extra-reference", "foreign-chain", "foreign-rule", "wrong-population", "extra-operator-prefix"} {
		t.Run(kind, func(t *testing.T) {
			inspection, runner, _ := fixtureNFTOperatorRemovalProof(t)
			approveNFTOperatorFixture(t, inspection)
			producers := nftRemovalProducerInspection{entries: []string{"/etc/nftables.conf"}, digest: strings.Repeat("b", 64), verify: func(context.Context) error { return nil }}
			session, err := prepareNFTRemovalSession(context.Background(), inspection.host, producers)
			if err != nil {
				t.Fatal(err)
			}
			target := nftTableTarget{family: "inet", name: "syswarden"}
			wire := runner.tables[target]
			switch kind {
			case "changed-operator":
				wire = bytes.Replace(wire, []byte("198.51.100.42"), []byte("198.51.100.43"), 1)
			case "extra-reference":
				wire = appendNFTObjectsFixture(t, wire, map[string]any{"rule": map[string]any{"family": "inet", "table": "syswarden", "chain": "stateful_protect", "handle": 900001, "expr": []any{map[string]any{"jump": map[string]any{"target": operatorPolicyChainName}}}}})
			case "foreign-chain":
				wire = appendNFTObjectsFixture(t, wire, map[string]any{"chain": map[string]any{"family": "inet", "table": "syswarden", "name": "administrator", "handle": 900001}})
			case "foreign-rule":
				wire = appendNFTObjectsFixture(t, wire, map[string]any{"rule": map[string]any{"family": "inet", "table": "syswarden", "chain": "stateful_protect", "handle": 900001, "expr": []any{map[string]any{"drop": nil}}}})
			case "wrong-population":
				wire = bytes.Replace(wire, []byte("192.0.2.0"), []byte("192.0.3.0"), 1)
			case "extra-operator-prefix":
				wire = appendNFTObjectsFixture(t, wire, map[string]any{"rule": map[string]any{"family": "inet", "table": "syswarden", "chain": "stateful_protect", "handle": 900001, "comment": operatorPolicyCommentPrefix + "unbound", "expr": []any{map[string]any{"accept": nil}}}})
			}
			runner.tables[target] = wire
			if err := session.inspectRuntime(context.Background(), runner); err == nil {
				t.Fatal("foreign or modified runtime accepted", kind)
			}
			if _, err := inspection.host.root.Stat(legacyNFTIncludePath[1:]); err != nil {
				t.Fatal("refusal changed product source", err)
			}
		})
	}
}

func TestNFTOperatorRemovalWholeSessionAndFinalFenceRefusal(t *testing.T) {
	for _, kind := range []string{"complete", "complete-group-readable", "receiver-rule-race", "loader-disabled-race", "source-replaced-race", "decision-missing-race"} {
		t.Run(kind, func(t *testing.T) {
			ctx := context.Background()
			mode := fs.FileMode(0600)
			if kind == "complete-group-readable" {
				mode = 0640
			}
			inspection, runner, _ := fixtureNFTOperatorRemovalProofWithMode(t, mode)
			approveNFTOperatorFixture(t, inspection)
			receiver := nftTableTarget{family: "inet", name: inspection.model.table}
			originalReceiver := bytes.Clone(runner.tables[receiver])
			originalConfiguration, err := inspection.host.read(nftOperatorConfigurationPath)
			if err != nil {
				t.Fatal(err)
			}
			producers := nftRemovalProducerInspection{entries: []string{"/etc/nftables.conf"}, digest: strings.Repeat("b", 64), verify: func(context.Context) error { return nil }}
			session, err := prepareNFTRemovalSession(ctx, inspection.host, producers)
			if err != nil {
				t.Fatal(err)
			}
			if err := session.inspectRuntime(ctx, runner); err != nil {
				t.Fatal(err)
			}
			if err := applyNFTOwnedRemovalSources(inspection.host, session.plan, session.guard(ctx), defaultLegacyRetirementFileOps()); err != nil {
				t.Fatal(err)
			}
			applied := 0
			factory := func(ctx context.Context, observe func(context.Context) ([]nftTableTarget, error)) (nftRemovalFence, error) {
				targets, err := observe(ctx)
				if err != nil {
					return nil, err
				}
				return &nftRemovalFixtureFence{run: func(_ context.Context, guard func() error) error {
					switch kind {
					case "receiver-rule-race":
						runner.tables[receiver] = bytes.Replace(originalReceiver, []byte("accept"), []byte("drop"), 1)
					case "loader-disabled-race":
						inspection.dependencies.verifyLoader = func(context.Context) error { return errors.New("loader disabled after intent") }
					case "source-replaced-race":
						if err := inspection.host.root.WriteFile(nftOperatorConfigurationPath[1:], []byte("# changed after intent\n"), 0600); err != nil {
							return err
						}
					case "decision-missing-race":
						if err := inspection.host.root.Remove((nftOperatorPreservationDirectory(inspection.key) + "/plan.json")[1:]); err != nil {
							return err
						}
					}
					if err := guard(); err != nil {
						return err
					}
					applied++
					for _, target := range targets {
						delete(runner.tables, target)
					}
					return nil
				}}, nil
			}
			err = retireNFTCurrentRuntimeUsing(ctx, inspection.host, session.plan, session.plan.sha256, session.guard(ctx), runner, defaultLegacyRetirementFileOps(), factory)
			if kind != "complete" && kind != "complete-group-readable" {
				if err == nil || applied != 0 || runner.tables[nftTableTarget{family: "inet", name: "syswarden"}] == nil {
					t.Fatal("final proof change did not stop kernel deletion", err)
				}
				return
			}
			if err != nil || applied != 1 {
				t.Fatal("verified product deletion failed", err)
			}
			if err := session.retireMetadata(ctx, runner, defaultLegacyRetirementFileOps()); err != nil {
				t.Fatal(err)
			}
			if len(runner.tables) != 2 || runner.tables[nftTableTarget{family: "inet", name: "administrator"}] == nil || !bytes.Equal(runner.tables[receiver], originalReceiver) {
				t.Fatal("removal changed receiver or unrelated table")
			}
			final, err := inspection.host.read(nftOperatorConfigurationPath)
			if err != nil || !bytes.Equal(final, originalConfiguration) {
				t.Fatal("removal changed administrator configuration", err)
			}
			info, err := inspection.host.root.Stat(nftOperatorConfigurationPath[1:])
			if err != nil || info.Mode().Perm() != mode {
				t.Fatal("removal changed administrator configuration permissions", err)
			}
			for _, path := range []string{legacyNFTIncludePath, nftStateDirectory + "/" + nftPolicyOwnershipName, nftRemovalProgressPath} {
				if _, err := inspection.host.root.Stat(path[1:]); !errors.Is(err, fs.ErrNotExist) {
					t.Fatal("product state remains", path, err)
				}
			}
			if _, err := authorizeNFTOperatorPolicyRemoval(ctx, session.plan.binding.Current.Operator); err != nil {
				t.Fatal("receiver proof did not survive product removal", err)
			}
		})
	}
}

func appendNFTObjectsFixture(t *testing.T, wire []byte, entries ...map[string]any) []byte {
	t.Helper()
	var document mutableNFTVerificationDocument
	if err := json.Unmarshal(wire, &document); err != nil {
		t.Fatal(err)
	}
	document.NFTables = append(document.NFTables, entries...)
	return marshalMutableNFTVerificationFixture(t, document)
}
