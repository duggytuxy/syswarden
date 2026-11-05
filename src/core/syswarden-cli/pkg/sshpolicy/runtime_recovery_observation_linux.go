//go:build linux

package sshpolicy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"slices"

	"golang.org/x/sys/unix"
)

const (
	sshRuntimeRecoveryObservationName    = "runtime-recovery-observation.json"
	sshRuntimeRecoveryObservationPurpose = "syswarden-ssh-restoring-reload-observation-v1"
	sshRuntimeRecoveryObservationMethod  = "pidfd-sighup-retired-address-space-new-listeners-v1"
)

// This record preserves bounded kernel observations from the one permitted
// restoring request. It does not assert consumed policy, successful access or
// terminal recovery acceptance. Existing intent and target encodings stay v1/v4.
type sshRuntimeRecoveryObservation struct {
	Schema               int    `json:"schema"`
	Purpose              string `json:"purpose"`
	Transaction          string `json:"transaction"`
	Plan                 string `json:"plan_sha256"`
	Recovery             string `json:"recovery_sha256"`
	ReloadIntent         string `json:"reload_intent_sha256"`
	ReloadIntentImage    string `json:"reload_intent_image_sha256"`
	Restored             string `json:"restored_sha256"`
	Parser               string `json:"parser_sha256"`
	Target               string `json:"target_sha256"`
	Method               string `json:"method"`
	ProcessSummarySHA256 string `json:"process_summary_sha256"`
	BeforeSocketsSHA256  string `json:"before_sockets_sha256"`
	AfterSocketsSHA256   string `json:"after_sockets_sha256"`
}

// The production target alone constructs this private capability after its
// real kernel observations. Neither a public summary nor an access response
// can supply it. Retained handles keep its checks live through publication.
type sshRestoringReloadObservation struct {
	target, processSummary string
	listeners              *sshListenerReload
	execution              *sshExecReload
	after                  []sshListenerSocket
}

func (o *sshRestoringReloadObservation) recheck(ctx context.Context, guard func() error) error {
	if o == nil || ctx == nil || guard == nil || o.listeners == nil || o.listeners.read == nil ||
		o.execution == nil || !lowerDigest.MatchString(o.target) || !lowerDigest.MatchString(o.processSummary) {
		return ErrInventoryUnsafe
	}
	if err := errors.Join(ctx.Err(), guard(), o.execution.checkAfter()); err != nil {
		return err
	}
	current, err := o.listeners.read(ctx)
	if err != nil || !slices.Equal(current, o.after) {
		return errors.Join(ErrInventoryChanged, err)
	}
	replaced, err := o.listeners.replaced(current)
	if err != nil || !replaced {
		return errors.Join(ErrInventoryChanged, err)
	}
	return errors.Join(ctx.Err(), guard(), o.execution.checkAfter())
}

func (l *sshActivationTarget) restoringReloadObservation(ctx context.Context, guard func() error) (*sshRestoringReloadObservation, error) {
	if l == nil || ctx == nil || guard == nil {
		return nil, ErrInventoryUnsafe
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed || !l.attempted || l.ctx == nil {
		return nil, ErrInventoryClosed
	}
	if err := errors.Join(ctx.Err(), l.ctx.Err(), guard()); err != nil {
		return nil, err
	}
	if l.observation == nil {
		return nil, nil
	}
	if l.observation.target != l.target {
		return nil, ErrInventoryChanged
	}
	if err := l.observation.recheck(ctx, guard); err != nil {
		return nil, err
	}
	return l.observation, nil
}

// A missing record stays absent. Read-only inspection never backfills a past
// successful return, repairs synchronization or authorizes another signal.
func readSSHRuntimeRecoveryObservation(journal *sshJournal, intent sshRuntimeRecoveryIntent, recovery, restored string,
	reloadWire []byte) (sshRuntimeRecoveryObservation, *sshFileImage, error) {
	var record sshRuntimeRecoveryObservation
	if journal == nil || intent.Schema != 1 || intent.Domain != sshRuntimeRecoveryDomain {
		return record, nil, ErrInventoryUnsafe
	}
	for _, digest := range []string{intent.Transaction, intent.Plan, intent.Parser, intent.Target, recovery, restored} {
		if !lowerDigest.MatchString(digest) {
			return record, nil, ErrInventoryUnsafe
		}
	}
	if err := journal.recheck(); err != nil {
		return record, nil, err
	}
	image, err := readSSHPrivateChild(journal.directory, sshRuntimeRecoveryObservationName, journal.uid, maxSSHJournalBytes)
	if errors.Is(err, unix.ENOENT) {
		return record, nil, journal.recheck()
	}
	if err != nil {
		return record, nil, err
	}
	if err := json.Unmarshal(image.data, &record); err != nil {
		return sshRuntimeRecoveryObservation{}, nil, ErrInventoryUnsafe
	}
	canonical, err := json.Marshal(record)
	if err != nil || !bytes.Equal(canonical, image.data) {
		return sshRuntimeRecoveryObservation{}, nil, errors.Join(ErrInventoryUnsafe, err)
	}
	reload, err := readSSHPrivateChild(journal.directory, sshRuntimeRecoveryReloadName, journal.uid, maxSSHJournalBytes)
	if err != nil || !bytes.Equal(reload.data, reloadWire) {
		return sshRuntimeRecoveryObservation{}, nil, errors.Join(ErrInventoryChanged, err)
	}
	wantReload, err := json.Marshal(sshRuntimeRecoveryReload{1, recovery, restored, intent.Target})
	if err != nil || !bytes.Equal(reloadWire, wantReload) {
		return sshRuntimeRecoveryObservation{}, nil, errors.Join(ErrInventoryChanged, err)
	}
	for _, digest := range []string{record.ProcessSummarySHA256, record.BeforeSocketsSHA256, record.AfterSocketsSHA256} {
		if !lowerDigest.MatchString(digest) {
			return sshRuntimeRecoveryObservation{}, nil, ErrInventoryUnsafe
		}
	}
	if record.Schema != 1 || record.Purpose != sshRuntimeRecoveryObservationPurpose || record.Method != sshRuntimeRecoveryObservationMethod ||
		record.Transaction != intent.Transaction || record.Plan != intent.Plan || record.Recovery != recovery ||
		record.ReloadIntent != digestBytes(reloadWire) || record.ReloadIntentImage != sshImageDigest(reload) ||
		record.Restored != restored || record.Parser != intent.Parser || record.Target != intent.Target ||
		record.BeforeSocketsSHA256 == record.AfterSocketsSHA256 {
		return sshRuntimeRecoveryObservation{}, nil, ErrInventoryChanged
	}
	if err := journal.recheck(); err != nil {
		return sshRuntimeRecoveryObservation{}, nil, err
	}
	return record, &image, nil
}

func publishSSHRuntimeRecoveryObservation(ctx context.Context, journal *sshJournal, intent sshRuntimeRecoveryIntent,
	recovery, restored string, records map[string]string, observed *sshRestoringReloadObservation, guard func() error) (sshFileImage, error) {
	if journal == nil || observed == nil || observed.target != intent.Target || records == nil ||
		records[sshRuntimeRecoveryObservationName] != "" {
		return sshFileImage{}, ErrInventoryUnsafe
	}
	if err := observed.recheck(ctx, guard); err != nil {
		return sshFileImage{}, err
	}
	reload, err := readSSHPrivateChild(journal.directory, sshRuntimeRecoveryReloadName, journal.uid, maxSSHJournalBytes)
	if err != nil || records[sshRuntimeRecoveryReloadName] != sshImageDigest(reload) {
		return sshFileImage{}, errors.Join(ErrInventoryChanged, err)
	}
	before, beforeErr := sshActivationDigest(observed.listeners.before)
	after, afterErr := sshActivationDigest(observed.after)
	if err := errors.Join(beforeErr, afterErr, observed.recheck(ctx, guard)); err != nil {
		return sshFileImage{}, err
	}
	record := sshRuntimeRecoveryObservation{Schema: 1, Purpose: sshRuntimeRecoveryObservationPurpose,
		Transaction: intent.Transaction, Plan: intent.Plan, Recovery: recovery,
		ReloadIntent: digestBytes(reload.data), ReloadIntentImage: sshImageDigest(reload), Restored: restored,
		Parser: intent.Parser, Target: intent.Target, Method: sshRuntimeRecoveryObservationMethod,
		ProcessSummarySHA256: observed.processSummary, BeforeSocketsSHA256: before, AfterSocketsSHA256: after}
	wire, err := json.Marshal(record)
	if err != nil {
		return sshFileImage{}, err
	}
	image, err := journal.writeRecordImage(sshRuntimeRecoveryObservationName, wire)
	if err != nil {
		return sshFileImage{}, err
	}
	records[sshRuntimeRecoveryObservationName] = sshImageDigest(image)
	if err := observed.recheck(ctx, guard); err != nil {
		return sshFileImage{}, err
	}
	decoded, checked, err := readSSHRuntimeRecoveryObservation(journal, intent, recovery, restored, reload.data)
	if err != nil || checked == nil || decoded != record || sshImageDigest(*checked) != sshImageDigest(image) {
		return sshFileImage{}, errors.Join(ErrInventoryChanged, err)
	}
	if err := observed.recheck(ctx, guard); err != nil {
		return sshFileImage{}, err
	}
	return image, nil
}
