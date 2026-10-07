//go:build linux

package firewall

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"slices"
	"strings"
	"testing"
)

type nftOperatorPreservationRunner struct {
	model              nftOperatorReceiverModel
	original, receiver []byte
	calls              int
}

func (runner *nftOperatorPreservationRunner) Run(ctx context.Context, input []byte, args ...string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	runner.calls++
	if len(input) != 0 || len(args) != 5 || !slices.Equal(args[:4], []string{"-j", "list", "table", "inet"}) {
		return nil, fmt.Errorf("unexpected mutation or inspection")
	}
	switch args[4] {
	case "syswarden":
		if runner.original != nil {
			return bytes.Clone(runner.original), nil
		}
	case runner.model.table:
		return bytes.Clone(runner.receiver), nil
	}
	return nil, fmt.Errorf("unavailable fixture table")
}

func fixtureNFTOperatorPreservation(t *testing.T) (*nftOperatorPreservationInspection, *nftOperatorPreservationRunner) {
	t.Helper()
	_, host := fixtureNFTPersistenceFilesystem(t)
	fixture, rules, receipt := fixtureNFTOperatorCurrent(t, 7)
	model, err := prepareNFTOperatorReceiver(rules)
	if err != nil {
		t.Fatal(err)
	}
	for _, directory := range []string{"var/backups", "etc/syswarden/config/modules"} {
		if err := host.root.MkdirAll(directory, 0700); err != nil {
			t.Fatal(err)
		}
	}
	files := map[string][]byte{
		nftOperatorConfigurationPath:                     []byte("# Exact private original source fixture.\n"),
		nftOperatorReceiverPath(model):                   model.source,
		legacyNFTIncludePath:                             []byte(fixture.Source),
		nftStateDirectory + "/" + nftPolicyOwnershipName: receipt,
		"/etc/nftables.conf":                             []byte("flush ruleset\n" + legacyNFTIncludeMarker + "\n" + legacyNFTIncludeLine + "\ninclude \"" + nftOperatorReceiverPath(model) + "\"\n"),
	}
	for path, content := range files {
		if err := host.root.WriteFile(path[1:], content, 0600); err != nil {
			t.Fatal(err)
		}
	}
	runner := &nftOperatorPreservationRunner{model: model, original: fixture.InetJSON, receiver: marshalMutableNFTVerificationFixture(t, fixtureNFTOperatorReceiverDocument(t, model))}
	deps := nftOperatorPreservationDependencies{rules: rules, source: func() error { return nil }, loader: strings.Repeat("b", 64), entries: []string{"/etc/nftables.conf"}, verifyLoader: func(context.Context) error { return nil }, runner: runner}
	inspection, err := inspectNFTOperatorPreservationUsing(context.Background(), host, deps)
	if err != nil {
		t.Fatal(err)
	}
	return inspection, runner
}

func TestNFTOperatorPreservationReviewAndRetryKeepOriginalEvidence(t *testing.T) {
	ctx := context.Background()
	inspection, runner := fixtureNFTOperatorPreservation(t)
	plan, err := inspection.plan(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, digest, err := encodeNFTOperatorPreservationPlan(inspection.host, plan)
	if err != nil {
		t.Fatal(err)
	}
	if err := inspection.authorize(ctx); err == nil {
		t.Fatal("unreviewed copy granted removal authority")
	}
	if err := inspection.apply(ctx, strings.Repeat("0", 64), defaultLegacyRetirementFileOps()); err == nil {
		t.Fatal("different review accepted")
	}
	if _, err := inspection.host.root.Stat("var/backups/syswarden-retired-v1"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("rejected plan created private state", err)
	}
	if err := inspection.apply(ctx, digest, defaultLegacyRetirementFileOps()); err != nil {
		t.Fatal(err)
	}
	before, err := inspection.host.read(nftOperatorPreservationDirectory(inspection.key) + "/plan.json")
	if err != nil {
		t.Fatal(err)
	}
	runner.receiver = bytes.ReplaceAll(runner.receiver, []byte("1800"), []byte("9999"))
	if err := inspection.apply(ctx, digest, defaultLegacyRetirementFileOps()); err != nil {
		t.Fatal(err)
	}
	after, err := inspection.host.read(nftOperatorPreservationDirectory(inspection.key) + "/plan.json")
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("retry overwrote original observation", err)
	}
	if err := inspection.authorize(ctx); err != nil {
		t.Fatal(err)
	}
	record, err := readNFTOperatorPreservationRecord(inspection.host, inspection.key)
	if err != nil || record.OriginalCounters[0].Packets != 21 || record.ReceiverCounters[0].Bytes != 1800 {
		t.Fatal("original counter observations changed", err)
	}
	for _, original := range plan.Files {
		snapshot, attrs, err := snapshotNFTPersistenceMetadata(inspection.host, original.Artifact.Path)
		if err != nil || !matchesNFTHistoricalInput(original, snapshot, attrs) {
			t.Fatal("review changed active files or their identities", err)
		}
	}
}

func TestNFTOperatorPreservationSupportsReceiverAfterProductRetirement(t *testing.T) {
	ctx := context.Background()
	inspection, runner := fixtureNFTOperatorPreservation(t)
	plan, err := inspection.plan(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, digest, err := encodeNFTOperatorPreservationPlan(inspection.host, plan)
	if err != nil {
		t.Fatal(err)
	}
	if err := inspection.apply(ctx, digest, defaultLegacyRetirementFileOps()); err != nil {
		t.Fatal(err)
	}
	// Model only the completed change performed by the separately verified
	// product source retirement. This fixture does not grant deletion authority.
	if err := inspection.host.root.WriteFile("etc/nftables.conf", []byte("flush ruleset\ninclude \""+nftOperatorReceiverPath(inspection.model)+"\"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := inspection.host.root.Remove(legacyNFTIncludePath[1:]); err != nil {
		t.Fatal(err)
	}
	if err := inspection.host.root.Remove((nftStateDirectory + "/" + nftPolicyOwnershipName)[1:]); err != nil {
		t.Fatal(err)
	}
	runner.original = nil
	if err := inspection.authorize(ctx); err == nil {
		t.Fatal("per-operation graph change was ignored")
	}
	resumed, err := inspectNFTOperatorPreservationUsing(ctx, inspection.host, inspection.dependencies)
	if err != nil {
		t.Fatal(err)
	}
	if resumed.key != inspection.key {
		t.Fatal("product retirement changed independent receiver identity")
	}
	if err := resumed.authorize(ctx); err != nil {
		t.Fatal("independent protection could not be reverified after product retirement", err)
	}
}

func TestNFTOperatorPreservationRefusesEveryChangedBoundary(t *testing.T) {
	for _, kind := range []string{"configuration", "receiver-bytes", "receiver-mode", "receiver-replaced", "receiver-symlink", "receiver-hardlink", "receiver-missing", "receiver-runtime", "source-guard", "loader-guard", "detached-include", "extra-include", "cancelled"} {
		t.Run(kind, func(t *testing.T) {
			ctx := context.Background()
			inspection, runner := fixtureNFTOperatorPreservation(t)
			plan, err := inspection.plan(ctx)
			if err != nil {
				t.Fatal(err)
			}
			_, digest, err := encodeNFTOperatorPreservationPlan(inspection.host, plan)
			if err != nil {
				t.Fatal(err)
			}
			if err := inspection.apply(ctx, digest, defaultLegacyRetirementFileOps()); err != nil {
				t.Fatal(err)
			}
			path := nftOperatorReceiverPath(inspection.model)[1:]
			switch kind {
			case "configuration":
				err = inspection.host.root.WriteFile(nftOperatorConfigurationPath[1:], []byte("# changed\n"), 0600)
			case "receiver-bytes":
				err = inspection.host.root.WriteFile(path, append(bytes.Clone(inspection.model.source), '\n'), 0600)
			case "receiver-mode":
				err = inspection.host.root.Chmod(path, 0644)
			case "receiver-replaced":
				if err = inspection.host.root.Rename(path, path+".original"); err == nil {
					err = inspection.host.root.WriteFile(path, inspection.model.source, 0600)
				}
			case "receiver-symlink":
				if err = inspection.host.root.Rename(path, path+".original"); err == nil {
					err = inspection.host.root.Symlink("/"+path+".original", path)
				}
			case "receiver-hardlink":
				err = inspection.host.root.Link(path, path+".linked")
			case "receiver-missing":
				err = inspection.host.root.Remove(path)
			case "receiver-runtime":
				runner.receiver = bytes.Replace(runner.receiver, []byte("accept"), []byte("drop"), 1)
			case "source-guard":
				inspection.dependencies.source = func() error { return errors.New("typed configuration changed") }
			case "loader-guard":
				inspection.dependencies.verifyLoader = func(context.Context) error { return errors.New("loader disabled") }
			case "detached-include":
				err = inspection.host.root.WriteFile("etc/nftables.conf", []byte(legacyNFTIncludeMarker+"\n"+legacyNFTIncludeLine+"\n"), 0600)
			case "extra-include":
				err = inspection.host.root.WriteFile("etc/nftables.conf", []byte("include \""+nftOperatorReceiverPath(inspection.model)+"\"\ninclude \""+nftOperatorReceiverPath(inspection.model)+"\"\n"), 0600)
			case "cancelled":
				cancelled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = cancelled
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := inspection.authorize(ctx); err == nil {
				t.Fatal("changed preservation boundary accepted", kind)
			}
		})
	}
}

func TestNFTOperatorPreservationPublicationInterruptions(t *testing.T) {
	for _, phase := range []string{"backup-directory-durable", "plan-staged", "operator-preservation-published", "operator-preservation-durable"} {
		t.Run(phase, func(t *testing.T) {
			ctx := context.Background()
			inspection, _ := fixtureNFTOperatorPreservation(t)
			plan, err := inspection.plan(ctx)
			if err != nil {
				t.Fatal(err)
			}
			_, digest, err := encodeNFTOperatorPreservationPlan(inspection.host, plan)
			if err != nil {
				t.Fatal(err)
			}
			sentinel := errors.New("simulated interruption")
			ops := defaultLegacyRetirementFileOps()
			ops.checkpoint = func(at string) error {
				if at == phase {
					return sentinel
				}
				return nil
			}
			if err := inspection.apply(ctx, digest, ops); !errors.Is(err, sentinel) {
				t.Fatal("wrong interruption result", err)
			}
			if err := inspection.apply(ctx, digest, defaultLegacyRetirementFileOps()); err != nil {
				t.Fatal("exact retry failed", err)
			}
			if err := inspection.authorize(ctx); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestNFTOperatorPreservationRejectsChangeAtPublication(t *testing.T) {
	ctx := context.Background()
	inspection, _ := fixtureNFTOperatorPreservation(t)
	plan, err := inspection.plan(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, digest, err := encodeNFTOperatorPreservationPlan(inspection.host, plan)
	if err != nil {
		t.Fatal(err)
	}
	ops := defaultLegacyRetirementFileOps()
	ops.checkpoint = func(phase string) error {
		if phase == "plan-staged" {
			return inspection.host.root.WriteFile(nftOperatorConfigurationPath[1:], []byte("# changed after staging\n"), 0600)
		}
		return nil
	}
	if err := inspection.apply(ctx, digest, ops); err == nil {
		t.Fatal("configuration race accepted at publication")
	}
	if _, err := inspection.host.root.Stat((nftOperatorPreservationDirectory(inspection.key) + "/plan.json")[1:]); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("unreviewed decision was published", err)
	}
}
