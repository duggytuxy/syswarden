//go:build linux

package firewall

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"reflect"
	"slices"
	"syswarden-cli/pkg/system"
	"time"
)

const nftHistoricalReviewedPersistenceSchema = "syswarden-historical-persistence-binding-v2"

// The summary exposes identities and declared effects, never the private
// configuration, network addresses or historical listening-port observations.
type HistoricalFirewallPersistenceSummary struct {
	Schema                      string   `json:"schema"`
	Generation                  string   `json:"generation"`
	PlanSHA256                  string   `json:"plan_sha256"`
	InputCaptureSHA256          string   `json:"input_capture_sha256"`
	SourceSHA256                string   `json:"source_sha256"`
	SharedFiles                 []string `json:"shared_files"`
	PrivateInputFiles           []string `json:"private_input_files"`
	BackupDirectory             string   `json:"backup_directory"`
	RequiresOriginalInputReview bool     `json:"requires_original_input_review"`
	RequiresAbsentProductTables bool     `json:"requires_absent_product_tables"`
	ChangesKernelRules          bool     `json:"changes_kernel_rules"`
	StopsProductServices        bool     `json:"stops_product_services"`
	PreservesSharedService      bool     `json:"preserves_shared_service"`
	AlreadyComplete             bool     `json:"already_complete"`
}

type nftHistoricalRecovery struct {
	host      nftPersistenceFilesystem
	origin    nftHistoricalInputInspection
	plan      nftHistoricalPersistencePlan
	producers nftRemovalProducerInspection
	absent    func(context.Context) error
}

func prepareNFTHistoricalRecovery(ctx context.Context, host nftPersistenceFilesystem, origin nftHistoricalInputInspection, producers nftRemovalProducerInspection, reviewed string, absent func(context.Context) error) (*nftHistoricalRecovery, error) {
	if absent == nil || producers.verify == nil || !validLegacyRetirementDigest(producers.digest) || reviewed != "" && !validLegacyRetirementDigest(reviewed) {
		return nil, fmt.Errorf("historical persistence recovery requires independently inspected inputs, producers and runtime absence")
	}
	if err := origin.verify(host); err != nil {
		return nil, err
	}
	if err := producers.verify(ctx); err != nil {
		return nil, err
	}
	if err := absent(ctx); err != nil {
		return nil, err
	}
	var plan nftHistoricalPersistencePlan
	var err error
	if reviewed != "" {
		plan, err = readNFTHistoricalPersistencePlan(host, reviewed)
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			// A graph can be durable before its separate source binding. Resume
			// that boundary only while every active source is still original.
			if _, missing := host.snapshot(legacyFail2banPlanPath(reviewed) + "/historical-source.json"); !errors.Is(missing, fs.ErrNotExist) {
				return nil, err
			}
			graph, readErr := readNFTPersistenceGraphRecord(host, reviewed)
			if readErr != nil {
				return nil, readErr
			}
			state, stateErr := inspectNFTPersistenceGraphState(host, graph)
			if stateErr != nil || len(state.edited) != 0 || len(state.retired) != 0 {
				return nil, fmt.Errorf("historical input binding is missing after active source changes; preserve the original evidence")
			}
			err = fs.ErrNotExist
		}
	}
	if reviewed == "" || errors.Is(err, fs.ErrNotExist) {
		entries := append(slices.Clone(producers.entries), legacyNFTIncludePath)
		plan, err = prepareNFTRecognizedPersistencePlan(host, entries, nftHistoricalPersistenceBinding{
			Schema: nftHistoricalReviewedPersistenceSchema, Origins: origin.digest, Producers: producers.digest,
			V4028: &origin.document.Inputs, ProductEntry: true,
		})
		if err != nil {
			return nil, err
		}
	}
	if reviewed != "" && plan.sha256 != reviewed {
		return nil, fmt.Errorf("historical persistence changed after review; no source mutation is authorized")
	}
	session := &nftHistoricalRecovery{host, origin, plan, producers, absent}
	return session, session.check(ctx)
}

func (session *nftHistoricalRecovery) check(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if session.plan.binding.Schema != nftHistoricalReviewedPersistenceSchema || !session.plan.binding.ProductEntry {
		return fmt.Errorf("historical recovery cannot reinterpret a different source review")
	}
	if err := session.origin.verify(session.host); err != nil {
		return err
	}
	if err := session.origin.independentOf(session.plan); err != nil {
		return err
	}
	wanted := append(slices.Clone(session.producers.entries), legacyNFTIncludePath)
	slices.Sort(wanted)
	if session.plan.binding.Producers != session.producers.digest || !slices.Equal(wanted, session.plan.graph.Entries) {
		return fmt.Errorf("historical persistence loader evidence changed after review")
	}
	if err := session.producers.verify(ctx); err != nil {
		return err
	}
	if err := requireNFTHistoricalOnlyAuthority(session.host); err != nil {
		return err
	}
	if err := session.absent(ctx); err != nil {
		return err
	}
	return verifyNFTHistoricalPersistencePlan(session.host, session.plan)
}

// Missing current writer authority is not replaced or manufactured. A modern
// receipt or an existing modern removal session requires its original route.
func requireNFTHistoricalOnlyAuthority(host nftPersistenceFilesystem) error {
	for _, path := range []string{nftStateDirectory + "/" + nftPolicyOwnershipName, nftTransactionJournalPath(nftStateDirectory), nftRemovalProgressPath} {
		if _, err := host.snapshot(path); !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("current firewall ownership or removal evidence exists or is unsafe; preserve it for its original recovery route")
		}
	}
	return nil
}

func (session *nftHistoricalRecovery) summary() (HistoricalFirewallPersistenceSummary, error) {
	state, err := inspectNFTPersistenceGraphState(session.host, session.plan.graph)
	if err != nil {
		return HistoricalFirewallPersistenceSummary{}, err
	}
	result := HistoricalFirewallPersistenceSummary{
		Schema: "syswarden-historical-firewall-persistence-review-v1", Generation: "v4.02.8",
		PlanSHA256: session.plan.sha256, InputCaptureSHA256: session.origin.digest,
		SourceSHA256:      session.plan.binding.Source.Artifact.SHA256,
		PrivateInputFiles: nftHistoricalInputFilePaths(session.origin), BackupDirectory: legacyFail2banPlanPath(session.plan.sha256),
		RequiresOriginalInputReview: true, RequiresAbsentProductTables: true,
		StopsProductServices: true, PreservesSharedService: true,
		AlreadyComplete: state.retired[legacyNFTIncludePath],
	}
	for _, source := range session.plan.graph.Sources {
		if source.EditedSHA256 != source.Artifact.SHA256 {
			result.SharedFiles = append(result.SharedFiles, source.Artifact.Path)
			result.AlreadyComplete = result.AlreadyComplete && state.edited[source.Artifact.Path]
		}
	}
	if result.AlreadyComplete {
		result.StopsProductServices = false
	}
	return result, nil
}

func (session *nftHistoricalRecovery) apply(ctx context.Context, reviewed string, ops legacyRetirementFileOps) error {
	if reviewed != session.plan.sha256 {
		return fmt.Errorf("historical source recovery requires the exact reviewed digest")
	}
	guard := func(origin, producers string) error {
		if origin != session.origin.digest || producers != session.producers.digest {
			return fmt.Errorf("historical source recovery authority changed")
		}
		return session.check(ctx)
	}
	if err := applyNFTHistoricalPersistencePlan(session.host, session.plan, reviewed, guard, ops); err != nil {
		return err
	}
	if err := session.check(ctx); err != nil {
		return err
	}
	result, err := session.summary()
	if err != nil || !result.AlreadyComplete {
		return fmt.Errorf("historical source retirement is incomplete; preserve the exact review and private evidence")
	}
	return nil
}

func attestHistoricalRecoveryInspection() error {
	if err := system.PreflightHistoricalHostRemoval(); err != nil {
		return err
	}
	if err := PreflightHistoricalFail2banRemoval(); err != nil {
		return err
	}
	return preflightConfiguredOperatorPolicyRemoval()
}

func openHistoricalFirewallPersistence(ctx context.Context, inputPath, reviewed string) (*nftHistoricalRecovery, error) {
	if os.Geteuid() != 0 {
		return nil, fmt.Errorf("historical firewall recovery requires root")
	}
	root, err := os.OpenRoot("/")
	if err != nil {
		return nil, err
	}
	host := nftPersistenceFilesystem{root: root}
	fail := func(err error) (*nftHistoricalRecovery, error) { _ = root.Close(); return nil, err }
	origin, err := inspectNFTHistoricalInputs(host, inputPath)
	if err != nil {
		return fail(err)
	}
	producers, err := inspectNFTRemovalProducersUsing(ctx, host, inspectNFTPersistenceLoader, attestHistoricalRecoveryInspection)
	if err != nil {
		return fail(err)
	}
	runner, err := uninstallNFTRunnerFactory()
	if err != nil {
		return fail(err)
	}
	absent := func(ctx context.Context) error {
		tables, err := observeNFTRemovalTargets(ctx, runner)
		if err != nil {
			return err
		}
		if len(tables) != 0 {
			return fmt.Errorf("historical persistence recovery requires absent product tables; it does not infer live rule ownership from an old source")
		}
		return nil
	}
	session, err := prepareNFTHistoricalRecovery(ctx, host, origin, producers, reviewed, absent)
	if err != nil {
		return fail(err)
	}
	return session, nil
}

func InspectHistoricalFirewallPersistence(ctx context.Context, inputPath string) (HistoricalFirewallPersistenceSummary, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	session, err := openHistoricalFirewallPersistence(ctx, inputPath, "")
	if err != nil {
		return HistoricalFirewallPersistenceSummary{}, err
	}
	defer func() { _ = session.host.root.Close() }()
	return session.summary()
}

func ApplyHistoricalFirewallPersistence(ctx context.Context, inputPath, reviewed string, originalInputsConfirmed bool, prepare func() error) (HistoricalFirewallPersistenceSummary, error) {
	var empty HistoricalFirewallPersistenceSummary
	if !validLegacyRetirementDigest(reviewed) || !originalInputsConfirmed || prepare == nil {
		return empty, fmt.Errorf("historical persistence requires the exact reviewed digest and explicit confirmation of original independent generation inputs")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	session, err := openHistoricalFirewallPersistence(ctx, inputPath, reviewed)
	if err != nil {
		return empty, err
	}
	defer func() { _ = session.host.root.Close() }()
	prior, err := session.summary()
	if err != nil {
		return empty, err
	}
	if prior.AlreadyComplete {
		return prior, nil
	}
	if err := prepare(); err != nil {
		return empty, err
	}
	lock, err := acquireNFTReloadGuard()
	if err != nil {
		return empty, err
	}
	defer releaseNFTReloadGuard(lock)
	stopped, err := inspectNFTRemovalProducers(ctx, session.host)
	if err != nil || stopped.digest != session.producers.digest || !reflect.DeepEqual(stopped.entries, session.producers.entries) {
		return empty, fmt.Errorf("historical loader or producer evidence changed during removal preparation")
	}
	session.producers = stopped
	if err := session.apply(ctx, reviewed, defaultLegacyRetirementFileOps()); err != nil {
		return empty, err
	}
	return session.summary()
}
