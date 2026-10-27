//go:build linux

package system

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
)

const apkLauncherTargetSchema = "syswarden-apk-launcher-targets/v1"

var apkLauncherTargetParents = [3]string{"opt", "opt/syswarden", "opt/syswarden/bin"}

type apkLauncherTargetImage struct {
	Path     string                `json:"path"`
	Identity apkTransitionIdentity `json:"identity"`
	SHA256   string                `json:"sha256"`
}

type apkLauncherTargetReplacement struct {
	Original        apkLauncherTargetImage `json:"original"`
	CandidateSHA256 string                 `json:"candidate_sha256"`
	CandidateSize   int64                  `json:"candidate_size"`
	CandidateMode   int64                  `json:"candidate_mode"`
}

// The immutable proposal precedes execution approval. It describes only direct,
// role-correct target replacement, never ownership or arbitrary wrapper behavior.
// The enclosing execution plan binds the package, capability and effect plan.
type apkLauncherTargetProposal struct {
	Schema                 string                          `json:"schema"`
	Purpose                string                          `json:"purpose"`
	OriginalSnapshotSHA256 string                          `json:"original_snapshot_sha256"`
	InventorySHA256        string                          `json:"inventory_sha256"`
	Parents                [3]apkLauncherParent            `json:"parents"`
	Aliases                [2]apkLauncherEvidence          `json:"aliases"`
	Targets                [2]apkLauncherTargetReplacement `json:"targets"`
}

type apkLauncherTargetObservation struct {
	Schema         string                    `json:"schema"`
	Purpose        string                    `json:"purpose"`
	PlanSHA256     string                    `json:"plan_sha256"`
	ApprovalSHA256 string                    `json:"approval_sha256"`
	ProposalSHA256 string                    `json:"proposal_sha256"`
	Targets        [2]apkLauncherTargetImage `json:"targets"`
	Parents        [3]apkLauncherParent      `json:"parents"`
}

type apkLauncherTargetCapability struct {
	proposal apkLauncherTargetProposal
	files    [2]*os.File
	expected [2]apkLauncherTargetImage
	parents  [3]apkLauncherParent
}

type apkLauncherTargetRecords struct {
	plan, approval, observation, originals []byte
}

func closeAPKLauncherTargetFiles(files [2]*os.File) error {
	var result error
	for _, file := range files {
		if file != nil && file.Close() != nil {
			result = errors.Join(result, errors.New("APK launcher target descriptor close failed"))
		}
	}
	return result
}

func apkLauncherDirectTarget(index int, target string) bool {
	if target == apkLauncherTargets[index] {
		return true
	}
	// Do not lexically clean arbitrary link text: an intermediate symlink before
	// a parent traversal can resolve differently from the cleaned fixed path.
	relative, err := filepath.Rel("/"+filepath.Dir(apkLauncherPaths[index]), apkLauncherTargets[index])
	return err == nil && target == relative
}

func apkLauncherTargetMembers(inventory []apkTransitionMember) ([2]apkTransitionMember, error) {
	var members [2]apkTransitionMember
	for i, target := range apkLauncherTargets {
		count := 0
		for _, member := range inventory {
			if member.Stream == "apk-data" && member.Path == strings.TrimPrefix(target, "/") {
				count++
				members[i] = member
			}
		}
		if count != 1 || members[i].Directory || members[i].Mode != 0750 || members[i].Size <= 0 || members[i].Size > maximumStandalonePayloadBytes || !validSHA256(members[i].SHA256) {
			return members, errors.New("APK launcher target inventory is missing or ambiguous")
		}
	}
	return members, nil
}

func apkLauncherTargetIdentityValid(identity apkTransitionIdentity) bool {
	return identity.Mode&syscall.S_IFMT == syscall.S_IFREG && identity.Mode&0022 == 0 && identity.Mode&0111 != 0 &&
		identity.Inode != 0 && identity.Links == 1 && int64(identity.UID) == int64(os.Geteuid()) && int64(identity.GID) == int64(os.Getegid()) &&
		identity.Size > 0 && identity.Size <= maximumStandalonePayloadBytes && identity.ModifiedNS >= 0 && identity.ModifiedNS < 1e9 && identity.ChangedNS >= 0 && identity.ChangedNS < 1e9
}

func readAPKLauncherTargetFile(ctx context.Context, root *os.Root, path string, file *os.File) (apkLauncherTargetImage, error) {
	return readAPKLauncherTargetImage(ctx, root, path, file, true)
}

func readAPKLauncherTargetImage(ctx context.Context, root *os.Root, path string, file *os.File, executable bool) (apkLauncherTargetImage, error) {
	image := apkLauncherTargetImage{Path: path}
	before, err := file.Stat()
	identity, identityErr := apkLauncherIdentity(before)
	checkIdentity := identity
	if !executable {
		checkIdentity.Mode |= 0100
	}
	if err != nil || identityErr != nil || !apkLauncherTargetIdentityValid(checkIdentity) || !executable && identity.Mode != syscall.S_IFREG|0600 {
		return image, errors.New("APK launcher target identity is unsafe")
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return image, errors.New("APK launcher target descriptor cannot be read")
	}
	digest := sha256.New()
	buffer := make([]byte, 32*1024)
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return image, err
		}
		n, readErr := file.Read(buffer)
		if n > 0 {
			total += int64(n)
			if total > identity.Size {
				return image, errors.New("APK launcher target length changed")
			}
			_, _ = digest.Write(buffer[:n])
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return image, errors.New("APK launcher target bytes cannot be read")
		}
	}
	after, afterErr := file.Stat()
	named, namedErr := root.Lstat(path)
	afterIdentity, afterIdentityErr := apkLauncherIdentity(after)
	namedIdentity, namedIdentityErr := apkLauncherIdentity(named)
	if afterErr != nil || namedErr != nil || afterIdentityErr != nil || namedIdentityErr != nil || identity != afterIdentity || identity != namedIdentity || total != identity.Size {
		return image, errors.New("APK launcher target changed while reading")
	}
	image.Identity, image.SHA256 = identity, hex.EncodeToString(digest.Sum(nil))
	return image, nil
}

func (h *APKLauncherCustody) openTargetFiles() (files [2]*os.File, images [2]apkLauncherTargetImage, result error) {
	defer func() {
		if result != nil {
			result = errors.Join(result, closeAPKLauncherTargetFiles(files))
			files = [2]*os.File{}
		}
	}()
	for i, target := range apkLauncherTargets {
		path := strings.TrimPrefix(target, "/")
		file, err := h.anchor.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if err != nil {
			return files, images, errors.New("APK launcher target cannot be pinned")
		}
		files[i] = file
		images[i], err = readAPKLauncherTargetFile(h.ctx, h.anchor, path, file)
		if err != nil {
			return files, images, err
		}
	}
	// Hold both descriptors through the full pair check so a later capture cannot
	// silently replace an earlier image in the approved proposal.
	for i, file := range files {
		current, err := readAPKLauncherTargetFile(h.ctx, h.anchor, images[i].Path, file)
		if err != nil || current != images[i] {
			return files, images, errors.New("APK launcher target pair changed")
		}
	}
	return files, images, h.checkParents()
}

func captureAPKLauncherTargetProposalAt(ctx context.Context, hostPath string, original []apkTransitionHostEntry, inventory []apkTransitionMember) (_ *apkLauncherTargetProposal, result error) {
	h, err := openAPKLauncherHost(ctx, hostPath)
	if err != nil {
		return nil, err
	}
	defer func() { result = errors.Join(result, h.Close()) }()
	current, err := h.snapshot()
	if err != nil || !reflect.DeepEqual(current, original) {
		return nil, errors.New("APK launcher target proposal has stale original aliases")
	}
	proposal := &apkLauncherTargetProposal{Schema: apkLauncherTargetSchema, Purpose: "upgrade-direct-targets-only"}
	needed := false
	for i := range proposal.Aliases {
		proposal.Aliases[i] = apkLauncherEntryEvidence(original[i+4])
		if apkLauncherProductDependency(apkLauncherPaths[i], proposal.Aliases[i].LinkTarget) {
			if !apkLauncherDirectTarget(i, proposal.Aliases[i].LinkTarget) {
				return nil, errors.New("APK launcher product dependency is not a fixed role-correct direct target")
			}
			needed = true
		}
	}
	if !needed {
		return nil, nil
	}
	members, err := apkLauncherTargetMembers(inventory)
	if err != nil {
		return nil, err
	}
	originalBytes, err := apkLauncherCanonical(original)
	if err != nil {
		return nil, err
	}
	inventoryBytes, err := apkLauncherCanonical(inventory)
	if err != nil {
		return nil, err
	}
	proposal.OriginalSnapshotSHA256, proposal.InventorySHA256 = apkTransitionDigest(originalBytes), apkTransitionDigest(inventoryBytes)
	for i, path := range apkLauncherTargetParents {
		if err := h.pinParent(path, false); err != nil {
			return nil, err
		}
		proposal.Parents[i] = apkLauncherParent{path, h.parents[len(h.parents)-1].identity}
	}
	files, images, err := h.openTargetFiles()
	if err != nil {
		return nil, err
	}
	defer func() { result = errors.Join(result, closeAPKLauncherTargetFiles(files)) }()
	for i, member := range members {
		proposal.Targets[i] = apkLauncherTargetReplacement{images[i], member.SHA256, member.Size, member.Mode}
	}
	current, err = h.snapshot()
	if err != nil || !reflect.DeepEqual(current, original) {
		return nil, errors.New("APK aliases changed while target proposal was captured")
	}
	return proposal, h.checkParents()
}

func prepareAPKLauncherCustodyWithTargetsAt(ctx context.Context, hostPath, transactionPath string, binding apkLauncherCustodyBinding, original []apkTransitionHostEntry, inventory []apkTransitionMember, expectedEffectPlanSHA256 string) (*APKLauncherCustody, error) {
	return prepareAPKLauncherCustodyWithTargetsFaultAt(ctx, hostPath, transactionPath, binding, original, inventory, expectedEffectPlanSHA256, nil)
}

func prepareAPKLauncherCustodyWithTargetsFaultAt(ctx context.Context, hostPath, transactionPath string, binding apkLauncherCustodyBinding, original []apkTransitionHostEntry, inventory []apkTransitionMember, expectedEffectPlanSHA256 string, fault func(string) error) (*APKLauncherCustody, error) {
	return prepareAPKLauncherCustodyConfiguredAt(ctx, hostPath, transactionPath, binding, original, func(h *APKLauncherCustody) error {
		if !validSHA256(expectedEffectPlanSHA256) {
			return errors.New("APK launcher target effect authority is absent")
		}
		plan, records, err := h.readTargetExecutionApproval(expectedEffectPlanSHA256)
		if err != nil {
			return err
		}
		inventoryBytes, err := apkLauncherCanonical(inventory)
		if err != nil || apkTransitionDigest(inventoryBytes) != binding.InventorySHA256 {
			return errors.New("APK launcher target inventory does not match execution authority")
		}
		if err := h.applyApprovedTransfer(plan); err != nil {
			return err
		}
		if plan.LauncherTargets == nil {
			return nil
		}
		members, err := apkLauncherTargetMembers(inventory)
		if err != nil {
			return err
		}
		proposal := *plan.LauncherTargets
		for i, member := range members {
			if proposal.Targets[i].CandidateSHA256 != member.SHA256 || proposal.Targets[i].CandidateMode != member.Mode || proposal.Targets[i].CandidateSize != member.Size {
				return errors.New("APK launcher proposed target differs from authenticated inventory")
			}
		}
		for i, path := range apkLauncherTargetParents {
			if err := h.pinParent(path, false); err != nil {
				return err
			}
			if proposal.Parents[i].Identity != h.parents[len(h.parents)-1].identity {
				return errors.New("APK launcher original target parent changed")
			}
		}
		files, images, err := h.openTargetFiles()
		if err != nil {
			return err
		}
		for i, image := range images {
			if image != proposal.Targets[i].Original {
				return errors.Join(errors.New("APK launcher original target changed before approved execution"), closeAPKLauncherTargetFiles(files))
			}
		}
		h.targetAuthority = &apkLauncherTargetCapability{proposal, files, images, proposal.Parents}
		h.targetRecords = records
		h.record.TargetProposalSHA256 = plan.LauncherTargetsSHA256
		h.fault = fault
		return h.retainOriginalTargets()
	})
}

func (h *APKLauncherCustody) readTargetExecutionApproval(expectedEffect string) (apkExecutionPlan, *apkLauncherTargetRecords, error) {
	var plan apkExecutionPlan
	planBytes, err := h.readRecord("execution-plan.json")
	binding := h.record.Binding
	if err != nil || apkTransitionDigest(planBytes) != binding.PlanSHA256 || decodeAPKTransitionJSON(planBytes, &plan) != nil || plan.Schema != apkExecutionSchema || plan.ProductAccepted ||
		plan.EffectPlanSHA256 != expectedEffect || !validSHA256(expectedEffect) || plan.CandidateSHA256 != binding.CandidateSHA256 || plan.CandidateCLISHA256 != binding.CandidateCLISHA256 ||
		plan.CandidateCapabilitySHA256 != binding.CandidateCapabilitySHA256 || plan.InventorySHA256 != binding.InventorySHA256 || plan.OriginalLaunchersSHA256 != binding.OriginalSnapshotSHA256 {
		return plan, nil, errors.New("APK launcher target execution plan does not match independent authority")
	}
	approvalBytes, err := h.readRecord("execution-approval.json")
	var approval apkExecutionApproval
	if err != nil || apkTransitionDigest(approvalBytes) != binding.ApprovalSHA256 || decodeAPKTransitionJSON(approvalBytes, &approval) != nil ||
		approval.Schema != apkExecutionSchema || approval.Purpose != "explicit-native-execution" || approval.ExecutionPlanSHA256 != binding.PlanSHA256 || approval.EffectPlanSHA256 != expectedEffect {
		return plan, nil, errors.New("APK launcher target replacement lacks exact execution approval")
	}
	if plan.LauncherTargets == nil {
		if plan.LauncherTargetsSHA256 != "" {
			return plan, nil, errors.New("APK launcher target proposal is absent")
		}
	} else {
		raw, err := apkLauncherCanonical(plan.LauncherTargets)
		if err != nil || apkTransitionDigest(raw) != plan.LauncherTargetsSHA256 || h.validateTargetProposal(*plan.LauncherTargets) != nil {
			return plan, nil, errors.New("APK launcher target proposal is invalid")
		}
	}
	return plan, &apkLauncherTargetRecords{plan: planBytes, approval: approvalBytes}, nil
}

func (h *APKLauncherCustody) validateTargetProposal(proposal apkLauncherTargetProposal) error {
	binding := h.record.Binding
	if proposal.Schema != apkLauncherTargetSchema || proposal.Purpose != "upgrade-direct-targets-only" || proposal.OriginalSnapshotSHA256 != binding.OriginalSnapshotSHA256 || proposal.InventorySHA256 != binding.InventorySHA256 {
		return errors.New("APK launcher target proposal binding differs")
	}
	needed := false
	for i, alias := range h.record.Aliases {
		if proposal.Aliases[i] != alias.Original {
			return errors.New("APK launcher target proposal aliases differ")
		}
		if alias.ProductDependency {
			if (alias.Disposition != "retained-administrator" && !(alias.Disposition == "product-transferred" && h.transfer != nil && h.record.TransferSHA256 != "")) || !apkLauncherDirectTarget(i, alias.Original.LinkTarget) {
				return errors.New("APK launcher target role is unsupported")
			}
			needed = true
		}
		target := proposal.Targets[i]
		if target.Original.Path != strings.TrimPrefix(apkLauncherTargets[i], "/") || !apkLauncherTargetIdentityValid(target.Original.Identity) || !validSHA256(target.Original.SHA256) || !validSHA256(target.CandidateSHA256) || target.CandidateMode != 0750 || target.CandidateSize <= 0 || target.CandidateSize > maximumStandalonePayloadBytes {
			return errors.New("APK launcher target image is invalid")
		}
	}
	if !needed || proposal.Targets[0].CandidateSHA256 != binding.CandidateCLISHA256 {
		return errors.New("APK launcher target proposal does not match candidate CLI or dependency")
	}
	for i, parent := range proposal.Parents {
		if parent.Path != apkLauncherTargetParents[i] || parent.Identity.Mode&syscall.S_IFMT != syscall.S_IFDIR || parent.Identity.Mode&0022 != 0 || parent.Identity.Inode == 0 || int64(parent.Identity.UID) != int64(os.Geteuid()) || int64(parent.Identity.GID) != int64(os.Getegid()) {
			return errors.New("APK launcher target parent is invalid")
		}
	}
	return nil
}

func (h *APKLauncherCustody) revalidateTargetRecords(checkTargets bool) error {
	if h.targetRecords == nil {
		if h.record.TargetProposalSHA256 != "" || h.record.TargetObservationSHA256 != "" || h.record.TargetOriginalsSHA256 != "" {
			return errors.New("APK launcher target evidence is unavailable")
		}
		for _, name := range []string{"launcher-target-observation.json", "launcher-target-originals.json", "launcher-original-cli.bin", "launcher-original-tui.bin"} {
			if _, err := h.journal.Lstat(name); !errors.Is(err, os.ErrNotExist) {
				return errors.New("APK launcher has unexpected target evidence")
			}
		}
		return nil
	}
	for name, expected := range map[string][]byte{"execution-plan.json": h.targetRecords.plan, "execution-approval.json": h.targetRecords.approval, "launcher-target-observation.json": h.targetRecords.observation, "launcher-target-originals.json": h.targetRecords.originals} {
		if len(expected) == 0 {
			if _, err := h.journal.Lstat(name); !errors.Is(err, os.ErrNotExist) {
				return errors.New("APK launcher target observation appeared without attestation")
			}
			continue
		}
		actual, err := h.readRecord(name)
		if err != nil || !bytes.Equal(actual, expected) {
			return errors.New("APK launcher target authority record changed")
		}
	}
	if err := h.validateOriginalTargets(); err != nil {
		return err
	}
	if checkTargets && h.targetAuthority != nil {
		for _, parent := range h.targetAuthority.parents {
			info, err := h.anchor.Lstat(parent.Path)
			identity, identityErr := apkLauncherIdentity(info)
			if err != nil || identityErr != nil || identity != parent.Identity {
				return errors.New("APK launcher target parent metadata changed")
			}
		}
		for i, file := range h.targetAuthority.files {
			current, err := readAPKLauncherTargetFile(h.ctx, h.anchor, h.targetAuthority.expected[i].Path, file)
			if err != nil || current != h.targetAuthority.expected[i] {
				return errors.New("APK launcher approved target identity or bytes changed")
			}
		}
	}
	return nil
}

// AttestUpgradeTargets observes the exact candidate CLI and TUI through retained
// real parents. This mints upgrade evidence, never alias ownership or permission
// to delete a retained alias's target during removal.
func (h *APKLauncherCustody) AttestUpgradeTargets() (result error) {
	if h == nil {
		return errors.New("APK launcher custody is unavailable")
	}
	if h.targetAuthority == nil {
		return h.Revalidate()
	}
	defer func() {
		if result != nil {
			h.failed = true
		}
	}()
	if len(h.targetRecords.observation) != 0 {
		return h.Revalidate()
	}
	if err := h.revalidateCustody(false); err != nil {
		return err
	}
	files, images, err := h.openTargetFiles()
	if err != nil {
		return err
	}
	defer func() {
		if result != nil {
			result = errors.Join(result, closeAPKLauncherTargetFiles(files))
			h.failed = true
		}
	}()
	for i, image := range images {
		target := h.targetAuthority.proposal.Targets[i]
		if image.SHA256 != target.CandidateSHA256 || image.Identity.Size != target.CandidateSize || target.CandidateMode != 0750 || image.Identity.Mode != syscall.S_IFREG|0750 {
			return errors.New("APK installed launcher target differs from the approved candidate")
		}
	}
	if err := h.revalidateCustody(false); err != nil {
		return err
	}
	var parents [3]apkLauncherParent
	for i, path := range apkLauncherTargetParents {
		info, err := h.anchor.Lstat(path)
		identity, identityErr := apkLauncherIdentity(info)
		if err != nil || identityErr != nil || !apkLauncherSameParent(identity, h.targetAuthority.proposal.Parents[i].Identity) {
			return errors.New("APK upgraded launcher target parent changed identity")
		}
		parents[i] = apkLauncherParent{path, identity}
	}
	observation := apkLauncherTargetObservation{apkLauncherTargetSchema, "observed-upgrade-targets", h.record.Binding.PlanSHA256, h.record.Binding.ApprovalSHA256, h.record.TargetProposalSHA256, images, parents}
	raw, err := apkLauncherCanonical(observation)
	if err != nil {
		return err
	}
	closeErr := closeAPKLauncherTargetFiles(h.targetAuthority.files)
	h.targetAuthority.files = [2]*os.File{}
	if closeErr != nil {
		return closeErr
	}
	if err := h.publish("launcher-target-observation.json", raw); err != nil {
		return err
	}
	h.targetAuthority.files, h.targetAuthority.expected, h.targetAuthority.parents = files, images, parents
	h.targetRecords.observation = raw
	h.record.TargetObservationSHA256 = apkTransitionDigest(raw)
	if err := h.Revalidate(); err != nil {
		h.targetAuthority.files = [2]*os.File{}
		return err
	}
	return nil
}

func (h *APKLauncherCustody) loadTargetRecordsForRemoval() error {
	if h.record.TargetProposalSHA256 == "" {
		if h.record.TargetObservationSHA256 != "" || h.record.TargetOriginalsSHA256 != "" {
			return errors.New("APK launcher target receipt is incomplete")
		}
		return nil
	}
	// The lifecycle supplies the exact receipt and plan references. Reading an
	// upgrade receipt never reconstructs a live target-replacement capability.
	planBytes, err := h.readRecord("execution-plan.json")
	var saved apkExecutionPlan
	if err != nil || decodeAPKTransitionJSON(planBytes, &saved) != nil {
		return errors.New("APK launcher target execution evidence is unavailable")
	}
	plan, records, err := h.readTargetExecutionApproval(saved.EffectPlanSHA256)
	if err != nil || plan.LauncherTargets == nil || plan.LauncherTargetsSHA256 != h.record.TargetProposalSHA256 {
		return errors.New("APK launcher target receipt proposal differs")
	}
	raw, err := h.readRecord("launcher-target-observation.json")
	var observed apkLauncherTargetObservation
	if err != nil || apkTransitionDigest(raw) != h.record.TargetObservationSHA256 || decodeAPKTransitionJSON(raw, &observed) != nil || observed.Schema != apkLauncherTargetSchema || observed.Purpose != "observed-upgrade-targets" || observed.PlanSHA256 != h.record.Binding.PlanSHA256 || observed.ApprovalSHA256 != h.record.Binding.ApprovalSHA256 || observed.ProposalSHA256 != h.record.TargetProposalSHA256 {
		return errors.New("APK launcher target observation is invalid")
	}
	for i, parent := range observed.Parents {
		if parent.Path != apkLauncherTargetParents[i] || !apkLauncherSameParent(parent.Identity, plan.LauncherTargets.Parents[i].Identity) {
			return errors.New("APK launcher observed target ancestry differs")
		}
	}
	for i, image := range observed.Targets {
		target := plan.LauncherTargets.Targets[i]
		if image.Path != target.Original.Path || !apkLauncherTargetIdentityValid(image.Identity) || target.CandidateMode != 0750 || image.Identity.Mode != syscall.S_IFREG|0750 || image.Identity.Size != target.CandidateSize || image.SHA256 != target.CandidateSHA256 {
			return errors.New("APK launcher target observation does not match candidate")
		}
	}
	records.observation = raw
	records.originals, err = h.readRecord("launcher-target-originals.json")
	if err != nil || apkTransitionDigest(records.originals) != h.record.TargetOriginalsSHA256 {
		return errors.New("APK launcher retained original targets are unavailable")
	}
	h.targetRecords = records
	return h.validateOriginalTargets()
}

func (h *APKLauncherCustody) refuseRemovalTargetDependencies() error {
	if err := h.Revalidate(); err != nil {
		return err
	}
	for _, alias := range h.record.Aliases {
		if alias.Disposition == "retained-administrator" && alias.ProductDependency {
			return errors.New("APK upgrade target approval does not resolve retained launcher behavior for removal")
		}
	}
	return nil
}

type apkLauncherOriginalTargets struct {
	Schema         string                    `json:"schema"`
	Purpose        string                    `json:"purpose"`
	PlanSHA256     string                    `json:"plan_sha256"`
	ApprovalSHA256 string                    `json:"approval_sha256"`
	ProposalSHA256 string                    `json:"proposal_sha256"`
	Targets        [2]apkLauncherTargetImage `json:"targets"`
}

func apkLauncherOriginalTargetName(index int) string {
	if index == 0 {
		return "launcher-original-cli.bin"
	}
	return "launcher-original-tui.bin"
}

// Original target bytes are bounded private evidence. They are neither a full
// product backup nor an executable or automatic restoration mechanism.
func (h *APKLauncherCustody) retainOriginalTargets() error {
	originals := apkLauncherOriginalTargets{Schema: apkLauncherTargetSchema, Purpose: "retained-original-targets", PlanSHA256: h.record.Binding.PlanSHA256, ApprovalSHA256: h.record.Binding.ApprovalSHA256, ProposalSHA256: h.record.TargetProposalSHA256}
	for i, source := range h.targetAuthority.files {
		name := apkLauncherOriginalTargetName(i)
		want := h.targetAuthority.proposal.Targets[i].Original
		current, err := readAPKLauncherTargetFile(h.ctx, h.anchor, want.Path, source)
		if err != nil || current != want {
			return errors.New("APK original launcher target changed before retention")
		}
		if _, err := source.Seek(0, io.SeekStart); err != nil {
			return errors.New("APK original launcher target cannot be retained")
		}
		if h.fault != nil && h.fault("before-"+name) != nil {
			return errors.New("APK original launcher target retention requires recovery")
		}
		destination, err := h.journal.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
		if err != nil {
			return errors.New("APK original launcher target evidence already exists or cannot be retained")
		}
		copyErr := h.copyOriginalTarget(destination, source, name, want.Identity.Size)
		syncErr := destination.Sync()
		closeErr := destination.Close()
		parentErr := h.journalLock.Sync()
		if copyErr != nil || syncErr != nil || closeErr != nil || parentErr != nil {
			return errors.New("APK original launcher target retention is incomplete; retain custody")
		}
		current, err = readAPKLauncherTargetFile(h.ctx, h.anchor, want.Path, source)
		if err != nil || current != want {
			return errors.New("APK original launcher target changed during retention")
		}
		image, err := h.readRetainedOriginalTarget(name)
		if err != nil || image.SHA256 != want.SHA256 || image.Identity.Size != want.Identity.Size {
			return errors.New("APK retained launcher target bytes do not match original")
		}
		originals.Targets[i] = image
	}
	raw, err := apkLauncherCanonical(originals)
	if err != nil {
		return err
	}
	if err := h.publish("launcher-target-originals.json", raw); err != nil {
		return err
	}
	h.targetRecords.originals = raw
	h.record.TargetOriginalsSHA256 = apkTransitionDigest(raw)
	return h.checkParents()
}

func (h *APKLauncherCustody) copyOriginalTarget(destination, source *os.File, name string, size int64) error {
	buffer := make([]byte, 32*1024)
	var total int64
	for {
		if err := h.ctx.Err(); err != nil {
			return err
		}
		n, readErr := source.Read(buffer)
		if n > 0 {
			total += int64(n)
			if total > size {
				return errors.New("APK original target length changed during retention")
			}
			written, err := destination.Write(buffer[:n])
			if err != nil || written != n {
				return errors.New("APK original target evidence write failed")
			}
			if h.fault != nil && h.fault("copy-"+name) != nil {
				return errors.New("APK original target evidence copy interrupted")
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return errors.New("APK original target evidence read failed")
		}
	}
	if total != size {
		return errors.New("APK original target evidence is incomplete")
	}
	return nil
}

func (h *APKLauncherCustody) readRetainedOriginalTarget(name string) (_ apkLauncherTargetImage, result error) {
	file, err := h.journal.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return apkLauncherTargetImage{}, errors.New("APK original launcher target evidence cannot be pinned")
	}
	defer func() {
		if file.Close() != nil {
			result = errors.Join(result, errors.New("APK original launcher target evidence close failed"))
		}
	}()
	return readAPKLauncherTargetImage(h.ctx, h.journal, name, file, false)
}

func (h *APKLauncherCustody) validateOriginalTargets() error {
	var originals apkLauncherOriginalTargets
	if len(h.targetRecords.originals) == 0 || apkTransitionDigest(h.targetRecords.originals) != h.record.TargetOriginalsSHA256 || decodeAPKTransitionJSON(h.targetRecords.originals, &originals) != nil ||
		originals.Schema != apkLauncherTargetSchema || originals.Purpose != "retained-original-targets" || originals.PlanSHA256 != h.record.Binding.PlanSHA256 || originals.ApprovalSHA256 != h.record.Binding.ApprovalSHA256 || originals.ProposalSHA256 != h.record.TargetProposalSHA256 {
		return errors.New("APK retained original target receipt is invalid")
	}
	var plan apkExecutionPlan
	if decodeAPKTransitionJSON(h.targetRecords.plan, &plan) != nil || plan.LauncherTargets == nil {
		return errors.New("APK retained original target proposal is unavailable")
	}
	for i, want := range originals.Targets {
		source := plan.LauncherTargets.Targets[i].Original
		if want.Path != apkLauncherOriginalTargetName(i) || want.SHA256 != source.SHA256 || want.Identity.Size != source.Identity.Size {
			return errors.New("APK original launcher target evidence binding differs")
		}
		actual, err := h.readRetainedOriginalTarget(want.Path)
		if err != nil || actual != want {
			return errors.New("APK retained original launcher target evidence changed")
		}
	}
	return nil
}
