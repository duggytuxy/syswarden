//go:build linux

package firewall

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"reflect"
	"time"
)

const legacyIPTablesBackupRoot = legacyRetirementBackupRoot + "/iptables-v1"

// Public summaries omit addresses, configuration bytes and complete rules.
// The private original files remain available for the required operator review.
type LegacyIPTablesRecoverySummary struct {
	Schema                 string                    `json:"schema"`
	Generation             string                    `json:"generation"`
	PlanSHA256             string                    `json:"plan_sha256"`
	InputCaptureSHA256     string                    `json:"input_capture_sha256"`
	Targets                []nftGenerationRuleTarget `json:"targets"`
	RetainedRuleCount      int                       `json:"retained_rule_count"`
	PrivateBackupDirectory string                    `json:"private_backup_directory"`
	RequiresOriginReview   bool                      `json:"requires_origin_review"`
	RequiresRetainedReview bool                      `json:"requires_retained_rule_review"`
	StopsProductServices   bool                      `json:"stops_product_services"`
	ChangesSharedRules     bool                      `json:"changes_shared_rules"`
	DeletesSharedTable     bool                      `json:"deletes_shared_table"`
	AlreadyComplete        bool                      `json:"already_complete"`
}

type legacyIPTablesRecoveryRecord struct {
	Schema    string          `json:"schema"`
	InputPath string          `json:"input_path"`
	Origins   string          `json:"origins_sha256"`
	Producers string          `json:"producers_sha256"`
	Epoch     nftRemovalEpoch `json:"epoch"`
	NFT       string          `json:"nft_observation"`
	Save      string          `json:"iptables_observation"`
	Plan      string          `json:"plan_sha256"`
}

type legacyIPTablesRecovery struct {
	host      nftPersistenceFilesystem
	origin    legacyIPTablesInputInspection
	producers nftRemovalProducerInspection
	observer  func(context.Context) (legacyIPTablesObservation, []byte, []byte, error)
	epoch     func() (nftRemovalEpoch, error)
	plan      legacyIPTablesPlan
	review    string
	record    legacyIPTablesRecoveryRecord
}

func bindLegacyIPTablesRecovery(origin legacyIPTablesInputInspection, producers string, record legacyIPTablesRecoveryRecord) (legacyIPTablesPlan, string, error) {
	var empty legacyIPTablesPlan
	if record.Schema != "syswarden-historical-iptables-retirement-v1" || record.InputPath != origin.path || record.Origins != origin.digest || record.Epoch != origin.document.Epoch || record.Producers != producers || !validLegacyRetirementDigest(producers) {
		return empty, "", fmt.Errorf("historical iptables intent differs from its independent input and producer bindings")
	}
	current, err := observeLegacyIPTables([]byte(record.NFT), []byte(record.Save))
	if err != nil {
		return empty, "", err
	}
	plan, err := prepareLegacyIPTablesPlan(origin.before, origin.generated, current, origin.document.Inputs, origin.digest)
	if err != nil || plan.digest != record.Plan {
		return empty, "", fmt.Errorf("historical iptables intent does not reconstruct its exact reviewed transaction")
	}
	content, err := json.Marshal([]string{plan.digest, producers})
	if err != nil {
		return empty, "", err
	}
	return plan, nftSHA256Hex(content), nil
}

func (session *legacyIPTablesRecovery) check(ctx context.Context) error {
	if session.epoch == nil || session.producers.verify == nil || session.observer == nil {
		return fmt.Errorf("historical iptables recovery lacks complete guards")
	}
	epoch, err := session.epoch()
	if err != nil {
		return err
	}
	if err := session.origin.verify(session.host, epoch); err != nil {
		return err
	}
	if err := session.producers.verify(ctx); err != nil {
		return err
	}
	plan, review, err := bindLegacyIPTablesRecovery(session.origin, session.producers.digest, session.record)
	if err != nil || review != session.review || !reflect.DeepEqual(plan, session.plan) {
		return fmt.Errorf("historical iptables recovery changed after review")
	}
	return nil
}

func (session *legacyIPTablesRecovery) state(ctx context.Context) (bool, error) {
	if err := session.check(ctx); err != nil {
		return false, err
	}
	current, _, _, err := session.observer(ctx)
	if err != nil {
		return false, err
	}
	canonical, err := legacyIPTablesObservationBytes(current)
	if err != nil {
		return false, err
	}
	if bytes.Equal(canonical, session.plan.after) {
		return true, nil
	}
	if !bytes.Equal(canonical, session.plan.before) {
		return false, fmt.Errorf("shared iptables state changed outside the reviewed retirement; preserve its private intent and all rules")
	}
	return false, nil
}

func (session *legacyIPTablesRecovery) summary(ctx context.Context) (LegacyIPTablesRecoverySummary, error) {
	complete, err := session.state(ctx)
	if err != nil {
		return LegacyIPTablesRecoverySummary{}, err
	}
	var after struct {
		Lines []string `json:"lines"`
	}
	if err := json.Unmarshal(session.plan.after, &after); err != nil {
		return LegacyIPTablesRecoverySummary{}, err
	}
	return LegacyIPTablesRecoverySummary{
		Schema: "syswarden-historical-iptables-review-v1", Generation: "v4.02.8", PlanSHA256: session.review,
		InputCaptureSHA256: session.origin.digest, Targets: append([]nftGenerationRuleTarget(nil), session.plan.targets...),
		RetainedRuleCount: len(after.Lines), PrivateBackupDirectory: legacyIPTablesBackupRoot + "/" + session.review,
		RequiresOriginReview: true, RequiresRetainedReview: true, StopsProductServices: !complete, ChangesSharedRules: !complete, AlreadyComplete: complete,
	}, nil
}

func readLegacyIPTablesRecord(host nftPersistenceFilesystem, review string) (legacyIPTablesRecoveryRecord, nftPersistenceRead, error) {
	var empty legacyIPTablesRecoveryRecord
	if !validLegacyRetirementDigest(review) {
		return empty, nftPersistenceRead{}, fmt.Errorf("historical iptables recovery requires the exact reviewed digest")
	}
	path := legacyIPTablesBackupRoot + "/" + review
	root, err := host.openDirectory(path)
	if err != nil {
		return empty, nftPersistenceRead{}, err
	}
	info, statErr := root.Stat(".")
	closeErr := root.Close()
	if statErr != nil || closeErr != nil || info.Mode().Perm() != 0700 {
		return empty, nftPersistenceRead{}, fmt.Errorf("historical iptables intent directory is not private")
	}
	snapshot, err := host.snapshot(path + "/kernel.json")
	if err != nil || snapshot.identity == nil || snapshot.identity.Mode().Perm() != 0600 {
		return empty, snapshot, errors.Join(fmt.Errorf("historical iptables intent is missing or unsafe"), err)
	}
	var record legacyIPTablesRecoveryRecord
	decoder := json.NewDecoder(bytes.NewReader(snapshot.content))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&record) != nil {
		return empty, snapshot, fmt.Errorf("invalid historical iptables intent encoding")
	}
	canonical, err := json.Marshal(record)
	if err != nil || !bytes.Equal(snapshot.content, canonical) {
		return empty, snapshot, fmt.Errorf("historical iptables intent is not canonical")
	}
	return record, snapshot, nil
}

func (session *legacyIPTablesRecovery) persist(ctx context.Context, ops legacyRetirementFileOps) error {
	if !validLegacyRetirementOperations(func() error { return session.check(ctx) }, ops) {
		return fmt.Errorf("historical iptables intent requires complete guards and durable filesystem operations")
	}
	if err := session.check(ctx); err != nil {
		return err
	}
	path := legacyIPTablesBackupRoot + "/" + session.review
	if err := ensureLegacyRetirementPrivateDirectory(session.host, path, ops); err != nil {
		return err
	}
	root, err := session.host.openDirectory(path)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	descriptor, err := root.Open(".")
	if err != nil {
		return err
	}
	defer func() { _ = descriptor.Close() }()
	_, snapshot, err := readLegacyIPTablesRecord(session.host, session.review)
	if errors.Is(err, fs.ErrNotExist) {
		complete, stateErr := session.state(ctx)
		if stateErr != nil || complete {
			return fmt.Errorf("cannot publish missing historical iptables intent after a runtime change")
		}
		content, err := json.Marshal(session.record)
		if err != nil {
			return err
		}
		if err := publishLegacyRetirementJSON(root, descriptor, "kernel", content, ops); err != nil {
			return err
		}
	} else if err != nil {
		return err
	} else {
		// A visible prior intent can still need directory synchronization.
		if err := syncLegacyFail2banNFTIntent(session.host, path, snapshot); err != nil {
			return err
		}
	}
	if err := session.verifyIntent(ctx); err != nil {
		return err
	}
	return ops.checkpoint("iptables-intent-durable")
}

func (session *legacyIPTablesRecovery) verifyIntent(ctx context.Context) error {
	if err := session.check(ctx); err != nil {
		return err
	}
	record, _, err := readLegacyIPTablesRecord(session.host, session.review)
	if err != nil || !reflect.DeepEqual(record, session.record) {
		return fmt.Errorf("historical iptables durable intent changed")
	}
	return nil
}

type legacyIPTablesFenceFactory func(context.Context, func(context.Context) ([]nftGenerationRuleTarget, error)) (nftRemovalFence, error)

func (session *legacyIPTablesRecovery) apply(ctx context.Context, reviewed string, ops legacyRetirementFileOps, fenceFactory legacyIPTablesFenceFactory) error {
	if reviewed != session.review || !validLegacyRetirementDigest(reviewed) || fenceFactory == nil {
		return fmt.Errorf("historical iptables apply requires the exact reviewed plan and kernel fence")
	}
	if err := session.persist(ctx, ops); err != nil {
		return err
	}
	complete, err := session.state(ctx)
	if err != nil || complete {
		return err
	}
	fence, err := fenceFactory(ctx, func(ctx context.Context) ([]nftGenerationRuleTarget, error) {
		if err := session.verifyIntent(ctx); err != nil {
			return nil, err
		}
		complete, err := session.state(ctx)
		if err != nil || complete {
			return nil, fmt.Errorf("historical iptables state changed before generation-bound retirement")
		}
		return append([]nftGenerationRuleTarget(nil), session.plan.targets...), nil
	})
	if err != nil {
		return err
	}
	defer fence.close()
	if err := fence.apply(ctx, func() error { return session.verifyIntent(ctx) }); err != nil {
		return err
	}
	complete, err = session.state(ctx)
	if err != nil || !complete {
		return fmt.Errorf("historical iptables retirement is unconfirmed; preserve the private intent before retrying: %w", errors.Join(err, errors.New("exact retained state required")))
	}
	return session.verifyIntent(ctx)
}

func openLegacyIPTablesRecovery(ctx context.Context, inputPath, review string) (*legacyIPTablesRecovery, error) {
	if os.Geteuid() != 0 {
		return nil, fmt.Errorf("historical iptables recovery requires root")
	}
	root, err := os.OpenRoot("/")
	if err != nil {
		return nil, err
	}
	host := nftPersistenceFilesystem{root: root}
	fail := func(err error) (*legacyIPTablesRecovery, error) { _ = root.Close(); return nil, err }
	epoch, err := currentNFTRemovalEpoch()
	if err != nil {
		return fail(err)
	}
	origin, err := inspectLegacyIPTablesInputs(host, inputPath, epoch)
	if err != nil {
		return fail(err)
	}
	producers, err := inspectNFTRemovalProducersUsing(ctx, host, inspectNFTPersistenceLoader, attestHistoricalRecoveryInspection)
	if err != nil {
		return fail(err)
	}
	observer, err := newLegacyIPTablesObserver()
	if err != nil {
		return fail(err)
	}
	var record legacyIPTablesRecoveryRecord
	if review != "" {
		record, _, err = readLegacyIPTablesRecord(host, review)
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fail(err)
		}
	}
	if record.Schema == "" {
		current, nft, save, err := observer.observe(ctx)
		if err != nil {
			return fail(err)
		}
		plan, err := prepareLegacyIPTablesPlan(origin.before, origin.generated, current, origin.document.Inputs, origin.digest)
		if err != nil {
			return fail(err)
		}
		record = legacyIPTablesRecoveryRecord{"syswarden-historical-iptables-retirement-v1", origin.path, origin.digest, producers.digest, epoch, string(nft), string(save), plan.digest}
	}
	plan, digest, err := bindLegacyIPTablesRecovery(origin, producers.digest, record)
	if err != nil {
		return fail(err)
	}
	if review != "" && digest != review {
		return fail(fmt.Errorf("historical iptables review changed; no mutation is authorized"))
	}
	session := &legacyIPTablesRecovery{host, origin, producers, observer.observe, currentNFTRemovalEpoch, plan, digest, record}
	if err := session.check(ctx); err != nil {
		return fail(err)
	}
	return session, nil
}

func InspectLegacyIPTablesRecovery(ctx context.Context, inputPath string) (LegacyIPTablesRecoverySummary, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	session, err := openLegacyIPTablesRecovery(ctx, inputPath, "")
	if err != nil {
		return LegacyIPTablesRecoverySummary{}, err
	}
	defer func() { _ = session.host.root.Close() }()
	return session.summary(ctx)
}

func ApplyLegacyIPTablesRecovery(ctx context.Context, inputPath, reviewed string, confirmed bool, prepare func() error) (LegacyIPTablesRecoverySummary, error) {
	var empty LegacyIPTablesRecoverySummary
	if !validLegacyRetirementDigest(reviewed) || !confirmed || prepare == nil {
		return empty, fmt.Errorf("historical iptables recovery requires exact review, original capture provenance and administrator ownership confirmation for all retained rules")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	session, err := openLegacyIPTablesRecovery(ctx, inputPath, reviewed)
	if err != nil {
		return empty, err
	}
	defer func() { _ = session.host.root.Close() }()
	if _, err := session.summary(ctx); err != nil {
		return empty, err
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
		return empty, fmt.Errorf("historical iptables producer or loader evidence changed during removal preparation")
	}
	session.producers = stopped
	if err := session.apply(ctx, reviewed, defaultLegacyRetirementFileOps(), func(ctx context.Context, inspect func(context.Context) ([]nftGenerationRuleTarget, error)) (nftRemovalFence, error) {
		return newNFTGenerationRuleFence(ctx, inspect)
	}); err != nil {
		return empty, err
	}
	return session.summary(ctx)
}
