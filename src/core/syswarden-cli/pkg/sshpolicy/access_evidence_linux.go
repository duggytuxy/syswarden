//go:build linux

package sshpolicy

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"time"
)

const sshAccessEvidenceName = "access-evidence.json"
const sshAccessEvidenceDomain = "syswarden-ssh-access-evidence-v1"
const maxSSHAccessEvidenceBytes = 512 << 10

// Exact private request/challenge/receipt bytes are retained. Controller trust
// comes from the independently supplied key, never from this local record.
// No private authentication or controller signing key reaches this structure.
type sshAccessEvidence struct {
	Schema           int    `json:"schema"`
	Domain           string `json:"domain"`
	Transaction      string `json:"transaction"`
	Plan             string `json:"plan_sha256"`
	Parser           string `json:"parser_sha256"`
	Intent           string `json:"intent_sha256"`
	Target           string `json:"target_sha256"`
	Records          string `json:"records_sha256"`
	Controller       string `json:"controller_sha256"`
	AssessedAt       int64  `json:"assessed_at"`
	Request          []byte `json:"request"`
	Challenge        []byte `json:"challenge"`
	Receipt          []byte `json:"receipt"`
	RecoveryRequired bool   `json:"recovery_required"`
	Issuance         string `json:"issuance_image_sha256,omitempty"`
}

// A durable observation does not acknowledge policy consumption or authorize
// activation completion. A later error can coexist with acknowledged durability.
// Any write attempt retains recovery-required status and poisons the handle.
type sshAccessEvidenceResult struct {
	Transaction      string
	RecordSHA256     string
	RecordDurable    bool
	RecoveryRequired bool
}

// Bind the exact pinned evidence inode and original history. The read-only
// observer may pin an existing image, without adopting it as a new write.
func recheckSSHAccessEvidence(a *sshActivationAssessment) error {
	current, err := stableSSHPublication(a.owned.journal.root, a.owned.journal.uid, a.owned.stage)
	if err != nil || !reflect.DeepEqual(current, a.owned.inventory) {
		return errors.Join(ErrInventoryChanged, err)
	}
	records, err := observeSSHIssuedRecordMembership(a.owned.journal, true, a.evidence != nil, a.issuance != nil)
	if err != nil || records[sshActivationIntentName] != sshImageDigest(a.intent) {
		return errors.Join(ErrInventoryChanged, err)
	}
	if a.evidence != nil && records[sshAccessEvidenceName] != sshImageDigest(*a.evidence) {
		return ErrInventoryChanged
	}
	if a.issuance != nil && records[sshAccessIssuanceName] != sshImageDigest(*a.issuance) {
		return ErrInventoryChanged
	}
	delete(records, sshAccessIssuanceName)
	delete(records, sshAccessEvidenceName)
	delete(records, sshActivationIntentName)
	if !reflect.DeepEqual(records, a.owned.records) {
		return ErrInventoryChanged
	}
	return nil
}

// Record at most one verified observation in the existing protected transaction.
// The write uses a fixed no-replace name, synced anonymous inode and directory.
// Any existing evidence, including malformed or uncertain state after a crash,
// blocks all subsequent appraisal/recording through ordinary history validation.
// This internal boundary is not wired to a production command or installer.
func recordSSHActivationAccessEvidence(ctx context.Context, journal *sshJournal, approved, parser string,
	run sshParserRun, parserCheck func() error, observe sshEndpointObserver, pins []sshAccessRoutePins,
	input sshAccessReceiptInput, clock func() time.Time, authorize func() error) (result sshAccessEvidenceResult, err error) {
	return recordSSHIssuedAccessEvidence(ctx, journal, approved, parser, run, parserCheck, observe, pins, input, clock, authorize, nil)
}

func recordSSHIssuedAccessEvidence(ctx context.Context, journal *sshJournal, approved, parser string,
	run sshParserRun, parserCheck func() error, observe sshEndpointObserver, pins []sshAccessRoutePins,
	input sshAccessReceiptInput, clock func() time.Time, authorize func() error, issuance *sshFileImage) (result sshAccessEvidenceResult, err error) {
	_, err = withSSHIssuedAccessReceipt(ctx, journal, approved, parser, run, parserCheck, observe, pins, input, clock, authorize, issuance,
		func(a *sshActivationAssessment, frozen sshAccessReceiptInput, assessed time.Time, guard func() error) error {
			history, err := sshActivationDigest(a.owned.records)
			if err != nil {
				return err
			}
			record := sshAccessEvidence{1, sshAccessEvidenceDomain, a.owned.prepared.Transaction,
				approved, parser, digestBytes(a.intent.data), a.target, history, digestBytes(frozen.Controller),
				assessed.Unix(), frozen.Request, frozen.Challenge, frozen.Receipt, true, ""}
			if issuance != nil {
				record.Issuance = sshImageDigest(*issuance)
			}
			wire, err := json.Marshal(record)
			if err != nil || len(wire) > maxSSHAccessEvidenceBytes {
				return errors.Join(ErrInventoryUnsafe, err)
			}
			if err := guard(); err != nil {
				return err
			}
			result.Transaction, result.RecoveryRequired = record.Transaction, true
			image, err := journal.writeRecordImage(sshAccessEvidenceName, wire)
			if err != nil {
				return err
			}
			result.RecordSHA256, result.RecordDurable = digestBytes(wire), true
			a.evidence = &image
			return nil
		})
	if result.RecoveryRequired {
		// Do not reuse even a successful writer; reopening still encounters the
		// occupied one-time slot. Never remove evidence to make retry possible.
		journal.poisoned = true
	}
	return result, err
}
