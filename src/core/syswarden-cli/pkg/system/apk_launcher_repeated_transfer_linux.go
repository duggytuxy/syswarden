//go:build linux

package system

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"syscall"
)

const apkLauncherRepeatedTransferSchema = "syswarden-apk-launcher-transfer/v2"
const maximumAPKLauncherTransferDepth = 32

type apkLauncherPreviousExecution struct {
	Reference      apkLauncherLifecycleReference `json:"reference"`
	OriginalNative apkLauncherNativeRecord       `json:"original_native"`
	Depth          int                           `json:"depth"`
	Execution      []apkLauncherTransferRecord   `json:"execution_records"`
	Publication    []apkLauncherTransferRecord   `json:"publication_records"`
}

var apkLauncherPreviousExecutionNames = []string{
	"completed.json", "execution-approval.json", "execution-plan.json", "launcher-custody.json", "launcher-prepared.json",
	"launcher-target-observation.json", "launcher-target-originals.json", "native-child.json", "native-handoff.json",
	"native-hook-post-commit.json", "native-hook-post-upgrade.json", "native-hook-pre-commit.json", "native-hook-pre-upgrade.json",
	"native-result.json", "observed-host-snapshot.json", "post-attestation.json", "resources-closed.json", "terminal-closed.json",
	"terminal-finalized.json", "terminal-finalizing.json", "terminal-retire-dispatcher.json", "terminal-retire-gate.json", "terminal-retirement-intent.json",
}
var apkLauncherPreviousPublicationNames = []string{"displaced-current.json", "publication-intent.json", "publication.json"}

func apkLauncherTransferOriginalNative(proposal *apkLauncherTransferProposal) apkLauncherNativeRecord {
	if proposal.Previous != nil {
		return proposal.Previous.OriginalNative
	}
	return proposal.Native
}

func validAPKLauncherPreviousRecords(records []apkLauncherTransferRecord, names []string) bool {
	if len(records) != len(names) {
		return false
	}
	for i, record := range records {
		if record.Name != names[i] || !validSHA256(record.SHA256) || record.Identity.Inode == 0 || record.Identity.Mode != syscall.S_IFREG|0600 || record.Identity.Links != 1 || int64(record.Identity.UID) != int64(os.Geteuid()) || int64(record.Identity.GID) != int64(os.Getegid()) {
			return false
		}
	}
	return true
}

func validAPKLauncherTransferKind(proposal *apkLauncherTransferProposal) bool {
	if proposal.Previous == nil {
		return proposal.Schema == apkLauncherTransferSchema && proposal.Purpose == "same-identity-fresh-ownership-transfer"
	}
	p := proposal.Previous
	raw, err := apkLauncherCanonical(p.Reference)
	if err != nil || proposal.Schema != apkLauncherRepeatedTransferSchema || proposal.Purpose != "same-identity-execution-ownership-transfer" || p.Depth < 1 || p.Depth > maximumAPKLauncherTransferDepth || p.Reference.Schema != apkFreshLauncherSchema || p.Reference.Kind != "execution" || !validSHA256(p.Reference.PlanSHA256) || !validSHA256(p.Reference.ReceiptSHA256) || apkTransitionDigest(raw) != proposal.Lineage.ReferenceSHA256 || p.OriginalNative.Name != proposal.Native.Name || !validSHA256(p.OriginalNative.RecordSHA256) || !validAPKRetentionChecksum(p.OriginalNative.Checksum) {
		return false
	}
	if _, err := parseReleaseVersion(p.OriginalNative.Version); err != nil {
		return false
	}
	return validAPKLauncherPreviousRecords(p.Execution, apkLauncherPreviousExecutionNames) && validAPKLauncherPreviousRecords(p.Publication, apkLauncherPreviousPublicationNames)
}

func readAPKLauncherPreviousRecords(directory *pinnedServiceDirectory, names []string, expected []apkLauncherTransferRecord) ([]apkLauncherTransferRecord, map[string][]byte, error) {
	records := make([]apkLauncherTransferRecord, 0, len(names))
	raw := make(map[string][]byte, len(names))
	for _, name := range names {
		limit := int64(apkLauncherMaximumBytes)
		if name == "observed-host-snapshot.json" {
			limit = 2 * maximumAPKTransitionSnapshotBytes
		}
		value, err := readAPKTransitionBytes(directory, name, limit)
		if err != nil {
			return nil, nil, err
		}
		info, err := directory.root.Lstat(name)
		identity, identityErr := apkLauncherIdentity(info)
		if err != nil || identityErr != nil || identity.Mode != syscall.S_IFREG|0600 || identity.Links != 1 || !serviceFileOwnedByCurrentUser(info) {
			return nil, nil, errors.New("APK predecessor evidence is unsafe")
		}
		records = append(records, apkLauncherTransferRecord{name, identity, apkTransitionDigest(value)})
		raw[name] = value
	}
	if expected != nil && !reflect.DeepEqual(records, expected) {
		return nil, nil, errors.New("APK predecessor evidence identity or bytes changed")
	}
	return records, raw, nil
}

func captureAPKLauncherPreviousExecution(h *apkLauncherLifecycleRemoval, native apkLauncherNativeRecord) (_ *apkLauncherPreviousExecution, result error) {
	if h.ownership == nil || h.transfer == nil || h.transferExecutionDirectory == nil || h.publicationJournal == nil {
		return nil, errors.New("APK predecessor lacks original ownership")
	}
	depth := 1
	if h.transfer.Previous != nil {
		depth = h.transfer.Previous.Depth + 1
	}
	if depth > maximumAPKLauncherTransferDepth {
		return nil, errors.New("APK predecessor chain exceeds its bounded ancestry")
	}
	p := &apkLauncherPreviousExecution{Reference: h.currentReference, OriginalNative: h.receipt.Native, Depth: depth}
	var raw map[string][]byte
	var err error
	p.Execution, raw, err = readAPKLauncherPreviousRecords(h.transferExecutionDirectory, apkLauncherPreviousExecutionNames, nil)
	if err != nil {
		return nil, err
	}
	p.Publication, _, err = readAPKLauncherPreviousRecords(h.publicationJournal, apkLauncherPreviousPublicationNames, nil)
	if err != nil {
		return nil, err
	}
	if err := attestAPKLauncherPreviousNative(raw, native); err != nil {
		return nil, err
	}
	return p, h.revalidate()
}

// The next proposal retains identities and bytes, never a claim inferred from
// matching launcher paths. Every ancestor must remain independently closed.
func verifyAPKLauncherPreviousExecution(s *apkLauncherLifecycleStore, proposal *apkLauncherTransferProposal, successor string, seen map[string]bool) (result error) {
	if proposal.Previous == nil {
		return nil
	}
	if !validAPKLauncherTransferProposal(proposal) {
		return errors.New("APK repeated transfer proposal is invalid")
	}
	previous := proposal.Previous
	ref := previous.Reference
	if seen[ref.PlanSHA256] || len(seen) >= maximumAPKLauncherTransferDepth {
		return errors.New("APK predecessor ancestry is cyclic or excessive")
	}
	seen[ref.PlanSHA256] = true
	if _, err := s.directory.root.Lstat("transfer-removal-" + ref.PlanSHA256); !errors.Is(err, os.ErrNotExist) {
		return errors.New("APK predecessor has retirement or recovery debt")
	}
	path := filepath.Join(strings.TrimPrefix(apkTransitionRoot, "/"), "execution-"+ref.PlanSHA256)
	for _, parent := range []string{strings.TrimPrefix(apkTransitionRoot, "/"), path} {
		if err := s.pin(parent); err != nil {
			return err
		}
	}
	directory, err := openExistingPinnedServiceDirectory(filepath.Join(s.host, path))
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, closeAPKExecutionDirectory(directory)) }()
	if err := inspectAPKTerminalInventory(directory); err != nil {
		return err
	}
	_, raw, err := readAPKLauncherPreviousRecords(directory, apkLauncherPreviousExecutionNames, previous.Execution)
	if err != nil {
		return err
	}
	guard := &apkLauncherLifecycleRemoval{store: s, currentReference: ref}
	if err := guard.attestExecutionFinalizationForSuccessor(successor); err != nil {
		return err
	}
	var plan apkExecutionPlan
	var receipt apkLauncherReceipt
	var prepared apkLauncherReceipt
	if apkTransitionDigest(raw["execution-plan.json"]) != ref.PlanSHA256 || decodeAPKTransitionJSON(raw["execution-plan.json"], &plan) != nil || plan.Schema != apkExecutionSchema || plan.ProductAccepted || apkTransitionDigest(raw["launcher-custody.json"]) != ref.ReceiptSHA256 || decodeAPKTransitionJSON(raw["launcher-custody.json"], &receipt) != nil || receipt.Schema != apkLauncherCustodySchema || receipt.Purpose != "committed-launcher-custody" || !validAPKLauncherBinding(receipt.Binding) || receipt.Binding.PlanSHA256 != ref.PlanSHA256 {
		return errors.New("APK predecessor execution binding differs")
	}
	if apkTransitionDigest(raw["launcher-prepared.json"]) != receipt.PreparedSHA256 || decodeAPKTransitionJSON(raw["launcher-prepared.json"], &prepared) != nil || prepared.Purpose != "prepared-launcher-custody" || prepared.Schema != apkLauncherCustodySchema || prepared.Binding != receipt.Binding || prepared.Aliases != receipt.Aliases || prepared.Parents != receipt.Parents || prepared.TransferSHA256 != receipt.TransferSHA256 || prepared.TargetProposalSHA256 != receipt.TargetProposalSHA256 || prepared.TargetOriginalsSHA256 != receipt.TargetOriginalsSHA256 || prepared.TargetObservationSHA256 != "" || prepared.PreparedSHA256 != "" {
		return errors.New("APK predecessor prepared ownership differs")
	}
	if err := validateAPKLauncherTransferBinding(plan, receipt); err != nil {
		return err
	}
	prior := plan.LauncherTransfer
	if prior == nil || prior.Reference != proposal.Reference || prior.Parents != proposal.Parents || prior.Aliases != proposal.Aliases || !reflect.DeepEqual(prior.Records, proposal.Records) || apkLauncherTransferOriginalNative(prior) != previous.OriginalNative {
		return errors.New("APK predecessor adopted another original owner")
	}
	depth := 1
	if prior.Previous != nil {
		depth = prior.Previous.Depth + 1
	}
	if depth != previous.Depth {
		return errors.New("APK predecessor ancestry length differs")
	}
	reader := &APKLauncherCustody{ctx: s.ctx, host: s.host, journal: directory.root, record: receipt, transfer: prior, receipt: raw["launcher-custody.json"], prepared: raw["launcher-prepared.json"]}
	if err := reader.loadTargetRecordsForRemoval(); err != nil {
		return err
	}
	if err := attestAPKLauncherPreviousNative(raw, proposal.Native); err != nil {
		return err
	}
	publicationPath := filepath.Join(strings.TrimPrefix(apkLauncherLifecycleRoot, "/"), "fresh-"+ref.PlanSHA256)
	if err := s.pin(publicationPath); err != nil {
		return err
	}
	publication, err := openExistingPinnedServiceDirectory(filepath.Join(s.host, publicationPath))
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, closeAPKExecutionDirectory(publication)) }()
	_, pub, err := readAPKLauncherPreviousRecords(publication, apkLauncherPreviousPublicationNames, previous.Publication)
	if err != nil {
		return err
	}
	var intent apkLauncherLineagePublicationIntent
	var published apkLauncherLineagePublication
	if decodeAPKTransitionJSON(pub["publication-intent.json"], &intent) != nil || intent != (apkLauncherLineagePublicationIntent{apkFreshLauncherSchema, "terminal-execution-lineage-publication", plan.LauncherLineage, ref}) || decodeAPKTransitionJSON(pub["publication.json"], &published) != nil || published.Schema != apkFreshLauncherSchema || published.Purpose != "execution-lineage-published" || published.IntentSHA256 != apkTransitionDigest(pub["publication-intent.json"]) || published.Identity != proposal.Lineage.Identity || apkTransitionDigest(pub["displaced-current.json"]) != plan.LauncherLineage.ReferenceSHA256 || !sameAPKLauncherMovedIdentity(plan.LauncherLineage.Identity, previous.Publication[0].Identity) {
		return errors.New("APK predecessor publication lineage changed")
	}
	file, err := publication.root.Open(".")
	if err != nil {
		return err
	}
	names, readErr := file.Readdirnames(5)
	closeErr := file.Close()
	sort.Strings(names)
	if readErr != nil && !errors.Is(readErr, io.EOF) || closeErr != nil || !reflect.DeepEqual(names, apkLauncherPreviousPublicationNames) {
		return errors.New("APK predecessor publication inventory changed")
	}
	if err := verifyAPKLauncherPreviousExecution(s, prior, successor, seen); err != nil {
		return err
	}
	if _, _, err := readAPKLauncherPreviousRecords(directory, apkLauncherPreviousExecutionNames, previous.Execution); err != nil {
		return err
	}
	if _, _, err := readAPKLauncherPreviousRecords(publication, apkLauncherPreviousPublicationNames, previous.Publication); err != nil {
		return err
	}
	return s.check()
}

func attestAPKLauncherPreviousNative(raw map[string][]byte, native apkLauncherNativeRecord) error {
	var plan apkExecutionPlan
	var observation apkExecutionObservation
	var completed, closed apkExecutionEvent
	if decodeAPKTransitionJSON(raw["execution-plan.json"], &plan) != nil || decodeAPKTransitionJSON(raw["post-attestation.json"], &observation) != nil || observation.Schema != apkExecutionSchema || observation.CandidateVersion != native.Version || observation.CandidateCLISHA256 != plan.CandidateCLISHA256 || observation.CandidateCapabilitySHA256 != plan.CandidateCapabilitySHA256 || native.Checksum != plan.CandidateAPKChecksum {
		return errors.New("APK predecessor installed candidate binding changed")
	}
	if decodeAPKTransitionJSON(raw["completed.json"], &completed) != nil || completed.Schema != apkExecutionSchema || completed.State != "completed" || completed.ProductAccepted || completed.PlanSHA256 != apkTransitionDigest(raw["execution-plan.json"]) || completed.ApprovalSHA256 != apkTransitionDigest(raw["execution-approval.json"]) || completed.LauncherReceiptSHA256 != apkTransitionDigest(raw["launcher-custody.json"]) || completed.ObservationSHA256 != apkTransitionDigest(raw["post-attestation.json"]) || completed.NativeHandoffSHA256 != apkTransitionDigest(raw["native-handoff.json"]) {
		return errors.New("APK predecessor completion is not bound to its observation")
	}
	if decodeAPKTransitionJSON(raw["resources-closed.json"], &closed) != nil || closed.State != "resources-closed" {
		return errors.New("APK predecessor execution resources are unresolved")
	}
	closed.State = "completed"
	if closed != completed {
		return errors.New("APK predecessor execution closure changed")
	}
	var child apkNativeProcess
	var nativeResult apkNativeResultRecord
	if decodeAPKTransitionJSON(raw["native-child.json"], &child) != nil || child.PID <= 1 || decodeAPKTransitionJSON(raw["native-result.json"], &nativeResult) != nil || nativeResult.Schema != apkExecutionSchema || nativeResult.PlanSHA256 != completed.PlanSHA256 || nativeResult.ApprovalSHA256 != completed.ApprovalSHA256 || nativeResult.HandoffSHA256 != completed.NativeHandoffSHA256 || !nativeResult.NativeExited {
		return errors.New("APK predecessor native completion changed")
	}
	for index, phase := range []string{"pre-commit", "pre-upgrade", "post-upgrade", "post-commit"} {
		var ack apkNativeHookAcknowledgment
		if apkTransitionDigest(raw["native-hook-"+phase+".json"]) != nativeResult.Acknowledgments[index] || decodeAPKTransitionJSON(raw["native-hook-"+phase+".json"], &ack) != nil || ack.Native != child || ack.Helper.ParentPID != child.PID || ack.Helper.Executable.SHA256 != plan.CandidateCLISHA256 || ack.Request != (apkNativeHookPacket{apkNativeHandoffSchema, completed.PlanSHA256, completed.NativeHandoffSHA256, phase, "request"}) {
			return errors.New("APK predecessor native acknowledgment changed")
		}
	}
	snapshot := raw["observed-host-snapshot.json"]
	if apkTransitionDigest(snapshot) != observation.HostSnapshotSHA256 {
		return errors.New("APK predecessor installed snapshot changed")
	}
	var entries []apkTransitionHostEntry
	if decodeAPKTransitionJSON(snapshot, &entries) != nil {
		return errors.New("APK predecessor installed snapshot is invalid")
	}
	found := 0
	for _, entry := range entries {
		if entry.Path != "lib/apk/db/installed" {
			continue
		}
		found++
		records, err := parseAPKLauncherRegistrations(entry.Content)
		if err != nil {
			return err
		}
		record, ok := records[native.Name]
		if !ok || record.checksum != native.Checksum || apkTransitionDigest([]byte(record.raw)) != native.RecordSHA256 {
			return errors.New("APK predecessor native registration differs from the current source")
		}
	}
	if found != 1 {
		return errors.New("APK predecessor native snapshot is missing or duplicated")
	}
	return nil
}
