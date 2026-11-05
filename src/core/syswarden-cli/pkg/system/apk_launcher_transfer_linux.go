//go:build linux

package system

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"syscall"
)

const apkLauncherTransferSchema = "syswarden-apk-launcher-transfer/v1"

type apkLauncherTransferRecord struct {
	Name     string                `json:"name"`
	Identity apkTransitionIdentity `json:"identity"`
	SHA256   string                `json:"sha256"`
}

type apkLauncherTransferProposal struct {
	Schema    string                        `json:"schema"`
	Purpose   string                        `json:"purpose"`
	Lineage   apkLauncherLineageProposal    `json:"lineage"`
	Reference apkLauncherLifecycleReference `json:"reference"`
	Parents   [4]apkFreshLauncherParent     `json:"parents"`
	Aliases   [2]apkLauncherEntry           `json:"aliases"`
	Native    apkLauncherNativeRecord       `json:"native"`
	Records   []apkLauncherTransferRecord   `json:"records"`
	Previous  *apkLauncherPreviousExecution `json:"previous_execution,omitempty"`
}

func captureAPKLauncherOwnershipTransfer(ctx context.Context, host string, lineage apkLauncherLineageProposal, original []apkTransitionHostEntry) (_ *apkLauncherTransferProposal, result error) {
	if !validAPKLauncherLineageProposal(lineage) {
		return nil, errors.New("APK launcher transfer requires an exact original lineage")
	}
	if lineage.Absent {
		return nil, nil
	}
	h, err := inspectAPKLauncherLifecycleRemovalAt(ctx, host)
	if err != nil {
		return nil, err
	}
	defer func() { result = errors.Join(result, h.close()) }()
	if h.reference.Kind != "fresh" || h.execution != nil || len(h.retirement) != 0 || len(h.terminal) != 0 || h.currentIdentity != lineage.Identity {
		return nil, errors.New("APK launcher transfer requires complete active original ownership")
	}
	origin := h
	if h.currentReference != h.reference {
		if h.currentReference.Kind != "execution" || h.ownership == nil || h.transferExecution == nil {
			return nil, errors.New("APK launcher transfer lacks its closed predecessor")
		}
		origin = h.ownership
	}
	raw, err := apkLauncherCanonical(h.currentReference)
	if err != nil || apkTransitionDigest(raw) != lineage.ReferenceSHA256 || len(original) != 6 {
		return nil, errors.New("APK launcher transfer source differs from the approved snapshot")
	}
	files, err := captureAPKLauncherPayload(ctx, h.store.anchor)
	if err != nil || origin == h && !reflect.DeepEqual(files, h.intent.Payload) {
		return nil, errors.New("APK launcher transfer source payload differs from its fresh native receipt")
	}
	_, database, err := apkLauncherReadFile(ctx, h.store.anchor, "lib/apk/db/installed", maximumAPKInstalledDatabaseSize, 0, true)
	if err != nil {
		return nil, err
	}
	records, err := parseAPKLauncherRegistrations(database)
	if err != nil {
		return nil, err
	}
	native, err := attestAPKLauncherCommittedRegistration(records, files)
	if err != nil || origin == h && native != h.receipt.Native {
		return nil, errors.New("APK launcher transfer source native registration changed or disappeared")
	}
	for _, registration := range records {
		for _, alias := range h.receipt.Aliases {
			if _, exists := registration.entries[alias.Path]; exists {
				return nil, errors.New("APK launcher transfer refuses a natively registered shared alias")
			}
		}
		for _, parent := range h.receipt.Parents {
			if parent.CreationSHA256 != "" {
				if _, exists := registration.entries[parent.Path]; exists {
					return nil, errors.New("APK launcher transfer parent now has another native owner")
				}
			}
		}
	}
	proposal := &apkLauncherTransferProposal{Schema: apkLauncherTransferSchema, Purpose: "same-identity-fresh-ownership-transfer", Lineage: lineage, Reference: h.reference, Parents: h.receipt.Parents, Aliases: h.receipt.Aliases, Native: native}
	if origin != h {
		proposal.Previous, err = captureAPKLauncherPreviousExecution(h, native)
		if err != nil {
			return nil, err
		}
		proposal.Schema, proposal.Purpose = apkLauncherRepeatedTransferSchema, "same-identity-execution-ownership-transfer"
	}
	for i, parent := range proposal.Parents {
		if original[i].Path != parent.Path || original[i].Absent || !apkLauncherSameParent(original[i].Identity, parent.Identity) {
			return nil, errors.New("APK launcher transfer parent differs from the original snapshot")
		}
	}
	for i, alias := range proposal.Aliases {
		if alias.Disposition != "product-created" || !alias.Original.Absent || !validSHA256(alias.CreationSHA256) || alias.Committed.Absent || alias.Committed.LinkTarget != apkLauncherTargets[i] || original[i+4].Path != alias.Path || apkLauncherEntryEvidence(original[i+4]) != alias.Committed {
			return nil, errors.New("APK launcher transfer refuses inherited, changed, or partial alias ownership")
		}
	}
	names := make([]string, 0, len(origin.observed))
	for name := range origin.observed {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		info, err := origin.journal.root.Lstat(name)
		identity, identityErr := apkLauncherIdentity(info)
		if err != nil || identityErr != nil || info.Mode() != 0600 || !info.Mode().IsRegular() || !serviceFileOwnedByCurrentUser(info) || identity.Links != 1 {
			return nil, errors.New("APK launcher transfer source evidence is unsafe")
		}
		proposal.Records = append(proposal.Records, apkLauncherTransferRecord{name, identity, apkTransitionDigest(origin.observed[name])})
	}
	if err := h.revalidate(); err != nil {
		return nil, err
	}
	return proposal, nil
}

func validAPKLauncherTransferProposal(proposal *apkLauncherTransferProposal) bool {
	if proposal == nil || !validAPKLauncherTransferKind(proposal) || proposal.Lineage.Absent || !validAPKLauncherLineageProposal(proposal.Lineage) || proposal.Reference.Schema != apkFreshLauncherSchema || proposal.Reference.Kind != "fresh" || !validSHA256(proposal.Reference.PlanSHA256) || !validSHA256(proposal.Reference.ReceiptSHA256) || len(proposal.Records) < 5 || len(proposal.Records) > 64 {
		return false
	}
	reference, err := apkLauncherCanonical(proposal.Reference)
	if err != nil || proposal.Previous == nil && apkTransitionDigest(reference) != proposal.Lineage.ReferenceSHA256 {
		return false
	}
	if !validNativeProductPackageName(proposal.Native.Name) || !validSHA256(proposal.Native.RecordSHA256) || !validAPKRetentionChecksum(proposal.Native.Checksum) {
		return false
	}
	if _, err := parseReleaseVersion(proposal.Native.Version); err != nil {
		return false
	}
	previous := ""
	for _, record := range proposal.Records {
		if !safeAssetName(record.Name) || record.Name <= previous || !validSHA256(record.SHA256) || record.Identity.Inode == 0 || record.Identity.Mode != syscall.S_IFREG|0600 || record.Identity.Links != 1 || int64(record.Identity.UID) != int64(os.Geteuid()) || int64(record.Identity.GID) != int64(os.Getegid()) {
			return false
		}
		previous = record.Name
	}
	for i, parent := range proposal.Parents {
		if parent.Path != apkLauncherParents[i] || parent.Absent || parent.Identity.Mode&syscall.S_IFMT != syscall.S_IFDIR || parent.Identity.Mode&0022 != 0 || parent.Identity.Inode == 0 || parent.CreationSHA256 != "" && (i < 2 || !validSHA256(parent.CreationSHA256)) {
			return false
		}
	}
	for i, alias := range proposal.Aliases {
		if alias.Path != apkLauncherPaths[i] || alias.Disposition != "product-created" || alias.Original != (apkLauncherEvidence{Absent: true}) || !validAPKLauncherEvidence(alias.Committed) || alias.Committed.Absent || alias.Committed.LinkTarget != apkLauncherTargets[i] || alias.ProductDependency || !validSHA256(alias.CreationSHA256) {
			return false
		}
	}
	return true
}

func openAPKLauncherTransferSource(ctx context.Context, host string, proposal *apkLauncherTransferProposal, executionPlan, executionReceipt string) (_ *apkLauncherLifecycleRemoval, result error) {
	if !validAPKLauncherTransferProposal(proposal) {
		return nil, errors.New("APK launcher transfer source proposal is invalid")
	}
	s, err := openAPKLauncherLifecycleReadOnlyStore(ctx, host)
	if err != nil {
		return nil, err
	}
	defer func() {
		if result != nil {
			result = errors.Join(result, s.close())
		}
	}()
	h, err := inspectAPKLauncherLifecycleRemovalSourceStore(s, false, &proposal.Reference, true)
	if err != nil {
		return nil, err
	}
	if len(h.retirement) != 0 || len(h.terminal) != 0 || h.receipt.Parents != proposal.Parents || h.receipt.Aliases != proposal.Aliases || len(h.observed) != len(proposal.Records) || h.receipt.Native != apkLauncherTransferOriginalNative(proposal) {
		return nil, errors.New("APK fresh ownership source is changed, partial, or retired")
	}
	current, err := s.captureLineageProposal()
	if err != nil {
		return nil, err
	}
	if current != proposal.Lineage {
		want := apkLauncherLifecycleReference{apkFreshLauncherSchema, "execution", executionPlan, executionReceipt}
		if !validSHA256(executionPlan) || !validSHA256(executionReceipt) || h.currentReference != want {
			return nil, errors.New("APK launcher transfer source lineage was replaced by another operation")
		}
		path := filepath.Join(strings.TrimPrefix(apkLauncherLifecycleRoot, "/"), "fresh-"+executionPlan)
		if err := s.pin(path); err != nil {
			return nil, err
		}
		publication, err := openExistingPinnedServiceDirectory(filepath.Join(host, path))
		if err != nil {
			return nil, err
		}
		intent := apkLauncherLineagePublicationIntent{apkFreshLauncherSchema, "terminal-execution-lineage-publication", proposal.Lineage, want}
		err = errors.Join(s.attestPublishedLineageAt(publication, intent), closeAPKExecutionDirectory(publication))
		if err != nil {
			return nil, err
		}
	}
	for _, record := range proposal.Records {
		raw, exists := h.observed[record.Name]
		info, err := h.journal.root.Lstat(record.Name)
		identity, identityErr := apkLauncherIdentity(info)
		if !exists || err != nil || identityErr != nil || identity != record.Identity || apkTransitionDigest(raw) != record.SHA256 {
			return nil, errors.New("APK launcher source ownership evidence changed")
		}
	}
	if err := verifyAPKLauncherPreviousExecution(s, proposal, executionPlan, map[string]bool{}); err != nil {
		return nil, errors.Join(err, h.closeAuxiliary())
	}
	return h, h.revalidateEvidence()
}

func validateAPKLauncherTransferBinding(plan apkExecutionPlan, receipt apkLauncherReceipt) error {
	if plan.LauncherLineage.Absent {
		if plan.LauncherTransfer != nil || plan.LauncherTransferSHA256 != "" || receipt.TransferSHA256 != "" {
			return errors.New("APK launcher transfer cannot originate from an absent lineage")
		}
		for _, alias := range receipt.Aliases {
			if alias.Disposition == "product-transferred" {
				return errors.New("APK launcher transferred ownership lacks its source")
			}
		}
		return nil
	}
	proposal := plan.LauncherTransfer
	if !validAPKLauncherTransferProposal(proposal) || proposal.Lineage != plan.LauncherLineage || !validSHA256(plan.LauncherTransferSHA256) || receipt.TransferSHA256 != plan.LauncherTransferSHA256 {
		return errors.New("APK launcher transferred ownership differs from approved lineage")
	}
	raw, err := apkLauncherCanonical(proposal)
	if err != nil || apkTransitionDigest(raw) != plan.LauncherTransferSHA256 || plan.LauncherTargets == nil {
		return errors.New("APK launcher transfer proposal is not bound to target approval")
	}
	for i, alias := range receipt.Aliases {
		source := proposal.Aliases[i]
		if alias.Path != source.Path || alias.Disposition != "product-transferred" || alias.Original != source.Committed || alias.Committed != source.Committed || alias.CreationSHA256 != source.CreationSHA256 || !alias.ProductDependency {
			return errors.New("APK launcher transfer adopted an inherited or changed alias")
		}
		if plan.LauncherTargets.Aliases[i] != source.Committed {
			return errors.New("APK launcher target approval differs from transferred ownership")
		}
	}
	for i, parent := range receipt.Parents {
		if parent.Path != proposal.Parents[i].Path || !apkLauncherSameParent(parent.Identity, proposal.Parents[i].Identity) {
			return errors.New("APK launcher transfer parent ancestry changed")
		}
	}
	return nil
}

func (h *APKLauncherCustody) applyApprovedTransfer(plan apkExecutionPlan) error {
	if plan.LauncherLineage.Absent {
		return validateAPKLauncherTransferBinding(plan, h.record)
	}
	proposal := plan.LauncherTransfer
	if !validAPKLauncherTransferProposal(proposal) {
		return errors.New("APK launcher transfer requires independently captured fresh ownership")
	}
	for i, alias := range h.record.Aliases {
		if alias.Disposition != "retained-administrator" || alias.Original != proposal.Aliases[i].Committed || alias.Committed != alias.Original || alias.CreationSHA256 != "" || !alias.ProductDependency {
			return errors.New("APK launcher source snapshot changed before ownership transfer")
		}
		h.record.Aliases[i].Disposition = "product-transferred"
		h.record.Aliases[i].CreationSHA256 = proposal.Aliases[i].CreationSHA256
	}
	h.record.TransferSHA256 = plan.LauncherTransferSHA256
	if err := validateAPKLauncherTransferBinding(plan, h.record); err != nil {
		return err
	}
	h.transfer = proposal
	return h.revalidateTransferSource()
}

func (h *APKLauncherCustody) revalidateTransferSource() error {
	if h.record.TransferSHA256 == "" {
		if h.transfer != nil {
			return errors.New("APK launcher transfer has no receipt binding")
		}
		return nil
	}
	if h.transfer == nil {
		return errors.New("APK launcher source ownership is unavailable")
	}
	receipt := ""
	if len(h.receipt) != 0 {
		receipt = apkTransitionDigest(h.receipt)
	}
	source, err := openAPKLauncherTransferSource(h.ctx, h.host, h.transfer, h.record.Binding.PlanSHA256, receipt)
	if err != nil {
		return err
	}
	return source.close()
}

func (h *APKLauncherCustody) loadApprovedTransfer() error {
	if h.record.TransferSHA256 == "" {
		return nil
	}
	raw, err := h.readRecord("execution-plan.json")
	var plan apkExecutionPlan
	if err != nil || apkTransitionDigest(raw) != h.record.Binding.PlanSHA256 || decodeAPKTransitionJSON(raw, &plan) != nil || plan.Schema != apkExecutionSchema || plan.ProductAccepted {
		return errors.New("APK launcher transfer execution plan changed")
	}
	approvalRaw, err := h.readRecord("execution-approval.json")
	var approval apkExecutionApproval
	if err != nil || apkTransitionDigest(approvalRaw) != h.record.Binding.ApprovalSHA256 || decodeAPKTransitionJSON(approvalRaw, &approval) != nil || approval.Schema != apkExecutionSchema || approval.Purpose != "explicit-native-execution" || approval.ExecutionPlanSHA256 != h.record.Binding.PlanSHA256 || approval.EffectPlanSHA256 != plan.EffectPlanSHA256 {
		return errors.New("APK launcher transfer lacks exact execution approval")
	}
	if err := validateAPKLauncherTransferBinding(plan, h.record); err != nil {
		return err
	}
	h.transfer = plan.LauncherTransfer
	return h.revalidateTransferSource()
}

func (h *APKLauncherCustody) revalidateTransferredExecutionEvidence() error {
	if h == nil || h.transfer == nil {
		return errors.New("APK transferred execution evidence is unavailable")
	}
	for name, expected := range map[string][]byte{"launcher-prepared.json": h.prepared, "launcher-custody.json": h.receipt} {
		raw, err := h.readRecord(name)
		if err != nil || !bytes.Equal(raw, expected) {
			return errors.New("APK transferred execution custody changed")
		}
	}
	if err := h.revalidateTransferSource(); err != nil {
		return err
	}
	return h.revalidateTargetRecords(false)
}

type apkLauncherTransferRemovalBinding struct {
	Schema         string                        `json:"schema"`
	Purpose        string                        `json:"purpose"`
	Current        apkLauncherLifecycleReference `json:"current"`
	Source         apkLauncherLifecycleReference `json:"source"`
	TransferSHA256 string                        `json:"transfer_sha256"`
}

func (h *apkLauncherLifecycleRemoval) transferRemovalBinding() apkLauncherTransferRemovalBinding {
	return apkLauncherTransferRemovalBinding{apkLauncherTransferSchema, "source-owned-complete-removal", h.currentReference, h.reference, h.transferSHA256}
}

func (h *apkLauncherLifecycleRemoval) tryTransferredRemoval() (_ bool, result error) {
	path := filepath.Join(h.store.host, strings.TrimPrefix(apkTransitionRoot, "/"), "execution-"+h.currentReference.PlanSHA256)
	directory, err := openExistingPinnedServiceDirectory(path)
	if err != nil {
		return false, err
	}
	keep := false
	defer func() {
		if !keep {
			result = errors.Join(result, closeAPKExecutionDirectory(directory))
		}
	}()
	raw, err := readAPKTransitionBytes(directory, "launcher-custody.json", apkLauncherMaximumBytes)
	var receipt apkLauncherReceipt
	if err != nil || apkTransitionDigest(raw) != h.currentReference.ReceiptSHA256 || decodeAPKTransitionJSON(raw, &receipt) != nil || receipt.Schema != apkLauncherCustodySchema || receipt.Purpose != "committed-launcher-custody" || receipt.Binding.PlanSHA256 != h.currentReference.PlanSHA256 || !validAPKLauncherBinding(receipt.Binding) {
		return false, errors.New("APK transferred execution custody is invalid")
	}
	if receipt.TransferSHA256 == "" {
		return false, nil
	}
	reader := &APKLauncherCustody{ctx: h.store.ctx, host: h.store.host, journal: directory.root, record: receipt, receipt: raw}
	preparedRaw, err := reader.readRecord("launcher-prepared.json")
	var prepared apkLauncherReceipt
	if err != nil || apkTransitionDigest(preparedRaw) != receipt.PreparedSHA256 || decodeAPKTransitionJSON(preparedRaw, &prepared) != nil || prepared.Schema != apkLauncherCustodySchema || prepared.Purpose != "prepared-launcher-custody" || prepared.Binding != receipt.Binding || prepared.PreparedSHA256 != "" || prepared.TransferSHA256 != receipt.TransferSHA256 || prepared.Parents != receipt.Parents || prepared.Aliases != receipt.Aliases || prepared.TargetProposalSHA256 != receipt.TargetProposalSHA256 || prepared.TargetOriginalsSHA256 != receipt.TargetOriginalsSHA256 || prepared.TargetObservationSHA256 != "" {
		return false, errors.New("APK transferred original execution custody changed")
	}
	reader.prepared = preparedRaw
	if err := reader.loadApprovedTransfer(); err != nil {
		return false, err
	}
	if err := reader.loadTargetRecordsForRemoval(); err != nil {
		return false, err
	}
	source, err := openAPKLauncherTransferSource(h.store.ctx, h.store.host, reader.transfer, h.currentReference.PlanSHA256, h.currentReference.ReceiptSHA256)
	if err != nil {
		return false, err
	}
	h.ownership, h.transferSHA256, h.transfer = source, receipt.TransferSHA256, reader.transfer
	h.transferExecution, h.transferExecutionDirectory = reader, directory
	keep = true
	h.reference, h.intent, h.receipt = source.reference, source.intent, source.receipt
	h.publicationJournal = h.journal
	h.journal = nil
	h.observed = make(map[string][]byte)
	s := h.store
	publicationPath := s.journalPath
	if err := s.check(); err != nil {
		return true, err
	}
	if _, err := s.directory.root.Lstat("transfer-removal-" + h.currentReference.PlanSHA256); errors.Is(err, os.ErrNotExist) {
		return true, h.revalidate()
	} else if err != nil {
		return true, err
	}
	s.journal = nil
	if err := s.openNamedJournal("transfer-removal-", h.currentReference.PlanSHA256, false); err != nil {
		s.journal, s.journalPath = h.publicationJournal, publicationPath
		return true, err
	}
	h.journal = s.journal
	if err := h.loadTransferredRemovalJournal(); err != nil {
		return true, err
	}
	return true, h.revalidate()
}

func (h *apkLauncherLifecycleRemoval) loadTransferredRemovalJournal() error {
	want, err := apkLauncherCanonical(h.transferRemovalBinding())
	if err != nil {
		return err
	}
	binding, err := readAPKTransitionBytes(h.journal, "transfer-source.json", 4096)
	if err != nil || !bytes.Equal(binding, want) {
		return errors.New("APK transferred removal journal is missing its exact source binding")
	}
	allowed := map[string]bool{"transfer-source.json": true, "retirement.json": true, "terminal.json": true}
	for i := range h.receipt.Aliases {
		allowed[apkFreshQuarantineRecordName(i, false)] = true
	}
	for i, parent := range h.receipt.Parents {
		if parent.CreationSHA256 != "" {
			allowed[fmt.Sprintf("retire-parent-%d.json", i)] = true
			allowed[apkFreshQuarantineRecordName(i, true)] = true
		}
	}
	file, err := h.journal.root.Open(".")
	if err != nil {
		return err
	}
	names, readErr := file.Readdirnames(32)
	closeErr := file.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) || closeErr != nil || len(names) >= 32 {
		return errors.New("APK transferred removal journal inventory is incomplete")
	}
	for _, name := range names {
		if !allowed[name] {
			return errors.New("APK transferred removal journal contains unknown recovery evidence")
		}
		raw, err := readAPKTransitionBytes(h.journal, name, 4096)
		if err != nil {
			return err
		}
		h.observed[name] = raw
	}
	h.retirement, err = readAPKTransitionBytes(h.journal, "retirement.json", 4096)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if len(h.retirement) != 0 {
		var retirement apkFreshLauncherRetirement
		if decodeAPKTransitionJSON(h.retirement, &retirement) != nil || retirement.Schema != apkFreshLauncherSchema || retirement.Purpose != "owned-launcher-retirement" || retirement.ReceiptSHA256 != h.reference.ReceiptSHA256 || !validAPKLauncherEvidence(retirement.Barrier) || retirement.Barrier.Absent || retirement.Barrier.Identity.Mode != syscall.S_IFREG|0600 || retirement.Barrier.ContentSHA256 != apkTransitionDigest([]byte(RemovalTombstoneRecord)) {
			return errors.New("APK transferred launcher retirement intent is invalid")
		}
	}
	h.terminal, err = readAPKTransitionBytes(h.journal, "terminal.json", 4096)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if len(h.terminal) != 0 && (len(h.retirement) == 0 || !bytes.Equal(h.terminal, h.retirement)) {
		return errors.New("APK transferred launcher retirement terminal proof is invalid")
	}
	return nil
}

func (h *apkLauncherLifecycleRemoval) ensureTransferredRemovalJournal() error {
	if h.ownership == nil || h.journal != nil {
		return nil
	}
	s := h.store
	s.journal = nil
	if err := s.openNamedJournal("transfer-removal-", h.currentReference.PlanSHA256, true); err != nil {
		return err
	}
	h.journal = s.journal
	raw, err := s.publish(h.journal, "transfer-source.json", h.transferRemovalBinding())
	if err != nil {
		return err
	}
	h.observed["transfer-source.json"] = raw
	return nil
}

func attestAPKLauncherTransferRecords(source *apkLauncherLifecycleRemoval, proposal *apkLauncherTransferProposal) error {
	if source == nil || !validAPKLauncherTransferProposal(proposal) || len(source.observed) != len(proposal.Records) {
		return errors.New("APK transferred ownership source custody is unavailable")
	}
	if err := source.revalidateEvidence(); err != nil {
		return err
	}
	for _, record := range proposal.Records {
		info, err := source.journal.root.Lstat(record.Name)
		identity, identityErr := apkLauncherIdentity(info)
		if err != nil || identityErr != nil || identity != record.Identity || apkTransitionDigest(source.observed[record.Name]) != record.SHA256 {
			return errors.New("APK transferred source proof changed during removal")
		}
	}
	return nil
}
