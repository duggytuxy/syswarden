//go:build linux

package system

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

const apkLauncherCustodySchema = "syswarden-apk-launcher-custody/v1"
const apkLauncherMaximumBytes = 1 << 20

var apkLauncherPaths = [2]string{"usr/local/bin/syswarden", "usr/local/bin/syswarden-tui"}
var apkLauncherTargets = [2]string{"/opt/syswarden/bin/syswarden-cli", "/opt/syswarden/bin/syswarden-tui"}
var apkLauncherParents = [4]string{".", "usr", "usr/local", "usr/local/bin"}

// This binding comes from a separately approved execution plan. None of its
// digests, nor preparation review, independently authorizes a native operation.
type apkLauncherCustodyBinding struct {
	PlanSHA256                string `json:"plan_sha256"`
	ApprovalSHA256            string `json:"approval_sha256"`
	CandidateSHA256           string `json:"candidate_sha256"`
	CandidateCLISHA256        string `json:"candidate_cli_sha256"`
	CandidateCapabilitySHA256 string `json:"candidate_capability_sha256"`
	InventorySHA256           string `json:"inventory_sha256"`
	OriginalSnapshotSHA256    string `json:"original_snapshot_sha256"`
}

type apkLauncherEvidence struct {
	Absent        bool                  `json:"absent"`
	Identity      apkTransitionIdentity `json:"identity"`
	ContentSHA256 string                `json:"content_sha256,omitempty"`
	LinkTarget    string                `json:"link_target,omitempty"`
}

type apkLauncherEntry struct {
	Path              string              `json:"path"`
	Disposition       string              `json:"disposition"`
	Original          apkLauncherEvidence `json:"original"`
	Committed         apkLauncherEvidence `json:"committed"`
	CreationSHA256    string              `json:"creation_sha256,omitempty"`
	ProductDependency bool                `json:"product_dependency"`
}

type apkLauncherParent struct {
	Path     string                `json:"path"`
	Identity apkTransitionIdentity `json:"identity"`
}

type apkLauncherReceipt struct {
	Schema                  string                    `json:"schema"`
	Purpose                 string                    `json:"purpose"`
	Binding                 apkLauncherCustodyBinding `json:"binding"`
	PreparedSHA256          string                    `json:"prepared_sha256"`
	TargetProposalSHA256    string                    `json:"target_proposal_sha256,omitempty"`
	TargetObservationSHA256 string                    `json:"target_observation_sha256,omitempty"`
	TargetOriginalsSHA256   string                    `json:"target_originals_sha256,omitempty"`
	TransferSHA256          string                    `json:"transfer_sha256,omitempty"`
	Parents                 [4]apkLauncherParent      `json:"parents"`
	Aliases                 [2]apkLauncherEntry       `json:"aliases"`
}

type apkLauncherCreation struct {
	Schema         string              `json:"schema"`
	Purpose        string              `json:"purpose"`
	PreparedSHA256 string              `json:"prepared_sha256"`
	Path           string              `json:"path"`
	Evidence       apkLauncherEvidence `json:"evidence"`
}

type apkLauncherRetirement struct {
	Schema        string              `json:"schema"`
	Purpose       string              `json:"purpose"`
	ReceiptSHA256 string              `json:"receipt_sha256"`
	Barrier       apkLauncherEvidence `json:"barrier"`
}

type apkLauncherPinnedParent struct {
	path     string
	identity apkTransitionIdentity
	root     *os.Root
}

// APKLauncherCustody retains only fixed launcher evidence. It cannot authorize
// native execution, authenticate wrapper behavior, or accept a migration.
// Callers must serialize use; the retained nonblocking journal lock excludes
// concurrent custody/removal handles for the same execution transaction.
type APKLauncherCustody struct {
	ctx             context.Context
	host            string
	transfer        *apkLauncherTransferProposal
	anchor          *os.Root
	parents         []apkLauncherPinnedParent
	journal         *os.Root
	journalLock     *os.File
	aliases         *os.Root
	record          apkLauncherReceipt
	prepared        []byte
	receipt         []byte
	retirement      []byte
	quarantines     [2][]byte
	targetAuthority *apkLauncherTargetCapability
	targetRecords   *apkLauncherTargetRecords
	closed          bool
	failed          bool
	// Private fault seam for publication and removal uncertainty.
	fault func(string) error
}

func apkLauncherCanonical(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, errors.New("APK launcher evidence cannot be encoded")
	}
	return append(raw, '\n'), nil
}

func validAPKLauncherBinding(binding apkLauncherCustodyBinding) bool {
	for _, digest := range []string{binding.PlanSHA256, binding.ApprovalSHA256, binding.CandidateSHA256,
		binding.CandidateCLISHA256, binding.CandidateCapabilitySHA256, binding.InventorySHA256, binding.OriginalSnapshotSHA256} {
		if !validSHA256(digest) {
			return false
		}
	}
	return true
}

func apkLauncherIdentity(info os.FileInfo) (apkTransitionIdentity, error) {
	if info == nil {
		return apkTransitionIdentity{}, errors.New("APK launcher metadata is unavailable")
	}
	status, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return apkTransitionIdentity{}, errors.New("APK launcher metadata is unsupported")
	}
	return apkTransitionStat(status), nil
}

func apkLauncherSameParent(left, right apkTransitionIdentity) bool {
	// Shared directory timestamps and entry counts may change during native
	// installation or an owned unlink. Access authority and directory identity
	// never change, and each fixed alias is compared independently in full.
	return left.Device == right.Device && left.Inode == right.Inode && left.Mode == right.Mode &&
		left.UID == right.UID && left.GID == right.GID
}

func openAPKLauncherHost(ctx context.Context, hostPath string) (_ *APKLauncherCustody, result error) {
	if ctx == nil || ctx.Err() != nil || !filepath.IsAbs(hostPath) || filepath.Clean(hostPath) != hostPath {
		return nil, errors.New("APK launcher observation context is unavailable")
	}
	before, err := os.Lstat(hostPath)
	if err != nil || !before.IsDir() || before.Mode()&os.ModeSymlink != 0 || !serviceFileOwnedByCurrentUser(before) || before.Mode().Perm()&0022 != 0 {
		return nil, errors.New("APK launcher observation root is unsafe")
	}
	anchor, err := os.OpenRoot(hostPath)
	if err != nil {
		return nil, errors.New("APK launcher observation root could not be pinned")
	}
	h := &APKLauncherCustody{ctx: ctx, host: hostPath, anchor: anchor}
	defer func() {
		if result != nil {
			result = errors.Join(result, h.Close())
		}
	}()
	opened, err := anchor.Stat(".")
	if err != nil || !os.SameFile(before, opened) {
		return nil, errors.New("APK launcher observation root changed")
	}
	for _, path := range apkLauncherParents {
		if err := h.pinParent(path, false); err != nil {
			return nil, err
		}
	}
	h.aliases = h.parents[len(h.parents)-1].root
	return h, nil
}

func (h *APKLauncherCustody) pinParent(path string, private bool) error {
	for _, parent := range h.parents {
		if parent.path == path {
			if private && parent.identity.Mode&0777 != 0700 {
				return errors.New("APK launcher custody directory is not private")
			}
			return h.checkParents()
		}
	}
	before, err := h.anchor.Lstat(path)
	if err != nil || !before.IsDir() || before.Mode()&os.ModeSymlink != 0 || !serviceFileOwnedByCurrentUser(before) ||
		before.Mode().Perm()&0022 != 0 || private && before.Mode().Perm() != 0700 {
		return errors.New("APK launcher ancestry is unsafe or unavailable")
	}
	identity, err := apkLauncherIdentity(before)
	if err != nil {
		return err
	}
	root, err := h.anchor.OpenRoot(path)
	if err != nil {
		return errors.New("APK launcher ancestry could not be pinned")
	}
	opened, openErr := root.Stat(".")
	after, afterErr := h.anchor.Lstat(path)
	openedIdentity, identityErr := apkLauncherIdentity(opened)
	afterIdentity, afterIdentityErr := apkLauncherIdentity(after)
	if openErr != nil || afterErr != nil || identityErr != nil || afterIdentityErr != nil || identity != openedIdentity || identity != afterIdentity {
		return errors.Join(errors.New("APK launcher ancestry changed while pinning"), root.Close())
	}
	h.parents = append(h.parents, apkLauncherPinnedParent{path, identity, root})
	return nil
}

func (h *APKLauncherCustody) checkParents() error {
	if h == nil || h.closed || h.failed || h.anchor == nil {
		return errors.New("APK launcher custody is closed or unresolved")
	}
	if err := h.ctx.Err(); err != nil {
		return err
	}
	for _, parent := range h.parents {
		named, namedErr := h.anchor.Lstat(parent.path)
		opened, openErr := parent.root.Stat(".")
		namedIdentity, identityErr := apkLauncherIdentity(named)
		openedIdentity, openedIdentityErr := apkLauncherIdentity(opened)
		if namedErr != nil || openErr != nil || identityErr != nil || openedIdentityErr != nil ||
			!apkLauncherSameParent(parent.identity, namedIdentity) || !apkLauncherSameParent(parent.identity, openedIdentity) {
			return errors.New("APK launcher pinned ancestry changed")
		}
	}
	return nil
}

func readAPKLauncherEntry(root *os.Root, path string) (apkTransitionHostEntry, error) {
	entry := apkTransitionHostEntry{Path: path}
	before, err := root.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		entry.Absent = true
		return entry, nil
	}
	if err != nil {
		return entry, errors.New("APK launcher entry cannot be inspected")
	}
	entry.Identity, err = apkLauncherIdentity(before)
	if err != nil || entry.Identity.Links != 1 || !serviceFileOwnedByCurrentUser(before) {
		return entry, errors.New("APK launcher entry ownership or link count is unsupported")
	}
	switch {
	case before.Mode()&os.ModeSymlink != 0:
		entry.LinkTarget, err = root.Readlink(path)
		if err != nil || entry.LinkTarget == "" || len(entry.LinkTarget) > 4096 || strings.IndexByte(entry.LinkTarget, 0) >= 0 {
			return entry, errors.New("APK launcher link text is unavailable or excessive")
		}
	case before.Mode().IsRegular():
		if before.Mode().Perm()&0022 != 0 || before.Size() < 0 || before.Size() > apkLauncherMaximumBytes {
			return entry, errors.New("APK launcher regular file is writable or excessive")
		}
		file, err := root.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if err != nil {
			return entry, errors.New("APK launcher regular file cannot be pinned")
		}
		opened, openErr := file.Stat()
		entry.Content, err = io.ReadAll(io.LimitReader(file, apkLauncherMaximumBytes+1))
		if len(entry.Content) == 0 {
			entry.Content = nil
		}
		finished, finishErr := file.Stat()
		closeErr := file.Close()
		openIdentity, identityErr := apkLauncherIdentity(opened)
		finishIdentity, finishIdentityErr := apkLauncherIdentity(finished)
		if openErr != nil || err != nil || finishErr != nil || closeErr != nil || identityErr != nil || finishIdentityErr != nil ||
			openIdentity != entry.Identity || finishIdentity != entry.Identity || int64(len(entry.Content)) != before.Size() {
			return entry, errors.New("APK launcher regular file changed while reading")
		}
	default:
		return entry, errors.New("APK launcher entry kind is unsupported")
	}
	after, err := root.Lstat(path)
	afterIdentity, identityErr := apkLauncherIdentity(after)
	if err != nil || identityErr != nil || afterIdentity != entry.Identity {
		return entry, errors.New("APK launcher entry changed during observation")
	}
	return entry, nil
}

func apkLauncherEntryEvidence(entry apkTransitionHostEntry) apkLauncherEvidence {
	evidence := apkLauncherEvidence{Absent: entry.Absent, Identity: entry.Identity, LinkTarget: entry.LinkTarget}
	if !entry.Absent && entry.Identity.Mode&syscall.S_IFMT == syscall.S_IFREG {
		evidence.ContentSHA256 = apkTransitionDigest(entry.Content)
	}
	return evidence
}

func (h *APKLauncherCustody) snapshot() ([]apkTransitionHostEntry, error) {
	if err := h.checkParents(); err != nil {
		return nil, err
	}
	entries := make([]apkTransitionHostEntry, 0, 6)
	for _, parent := range h.parents[:4] {
		info, err := parent.root.Stat(".")
		identity, identityErr := apkLauncherIdentity(info)
		if err != nil || identityErr != nil {
			return nil, errors.New("APK launcher parent snapshot is unavailable")
		}
		entries = append(entries, apkTransitionHostEntry{Path: parent.path, Identity: identity})
	}
	for _, path := range apkLauncherPaths {
		entry, err := readAPKLauncherEntry(h.anchor, path)
		if err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}
	return entries, h.checkParents()
}

// captureAPKLauncherCustodyAt is read-only and returns the six sorted entries
// embedded by the execution planner. It never creates a journal or launcher.

func captureAPKLauncherCustodyAt(ctx context.Context, hostPath string) (_ []apkTransitionHostEntry, result error) {
	h, err := openAPKLauncherHost(ctx, hostPath)
	if err != nil {
		return nil, err
	}
	defer func() { result = errors.Join(result, h.Close()) }()
	return h.snapshot()
}

func prepareAPKLauncherCustodyAt(ctx context.Context, hostPath, transactionPath string, binding apkLauncherCustodyBinding, original []apkTransitionHostEntry) (*APKLauncherCustody, error) {
	return prepareAPKLauncherCustodyConfiguredAt(ctx, hostPath, transactionPath, binding, original, nil)
}

func prepareAPKLauncherCustodyConfiguredAt(ctx context.Context, hostPath, transactionPath string, binding apkLauncherCustodyBinding, original []apkTransitionHostEntry, configure func(*APKLauncherCustody) error) (_ *APKLauncherCustody, result error) {
	originalBytes, err := apkLauncherCanonical(original)
	if err != nil || !validAPKLauncherBinding(binding) || apkTransitionDigest(originalBytes) != binding.OriginalSnapshotSHA256 {
		return nil, errors.New("APK launcher snapshot does not match the approved binding")
	}
	// Retain an independent canonical copy, not caller-owned slice or byte data.
	var capturedOriginal []apkTransitionHostEntry
	if err := decodeAPKTransitionJSON(originalBytes, &capturedOriginal); err != nil {
		return nil, errors.New("APK launcher original snapshot is not canonical")
	}
	original = capturedOriginal
	h, err := openAPKLauncherHost(ctx, hostPath)
	if err != nil {
		return nil, err
	}
	defer func() {
		if result != nil {
			result = errors.Join(result, h.Close())
		}
	}()
	current, err := h.snapshot()
	if err != nil || !reflect.DeepEqual(original, current) {
		return nil, errors.New("APK launcher original snapshot changed before custody")
	}
	h.record = apkLauncherReceipt{Schema: apkLauncherCustodySchema, Purpose: "committed-launcher-custody", Binding: binding}
	for i := range h.record.Parents {
		h.record.Parents[i] = apkLauncherParent{original[i].Path, original[i].Identity}
	}
	for i, path := range apkLauncherPaths {
		evidence := apkLauncherEntryEvidence(original[i+4])
		disposition := "retained-administrator"
		if evidence.Absent {
			disposition = "absent"
		}
		h.record.Aliases[i] = apkLauncherEntry{Path: path, Disposition: disposition, Original: evidence, Committed: evidence,
			ProductDependency: apkLauncherProductDependency(path, evidence.LinkTarget)}
	}
	if err := h.openJournal(hostPath, transactionPath, binding.PlanSHA256); err != nil {
		return nil, err
	}
	if configure != nil {
		if err := configure(h); err != nil {
			return nil, err
		}
	}
	prepared := h.record
	prepared.Purpose = "prepared-launcher-custody"
	h.prepared, err = apkLauncherCanonical(prepared)
	if err != nil {
		return nil, err
	}
	if err := h.publish("launcher-prepared.json", h.prepared); err != nil {
		return nil, err
	}
	h.record.PreparedSHA256 = apkTransitionDigest(h.prepared)
	if err := h.Revalidate(); err != nil {
		return nil, err
	}
	return h, nil
}

func (h *APKLauncherCustody) openJournal(hostPath, transactionPath, planSHA256 string) error {
	want := filepath.Join(hostPath, strings.TrimPrefix(apkTransitionRoot, "/"), "execution-"+planSHA256)
	if !validSHA256(planSHA256) || transactionPath != want {
		return errors.New("APK launcher execution custody path is not fixed")
	}
	for _, path := range []string{"var", "var/backups", strings.TrimPrefix(apkTransitionRoot, "/"), strings.TrimPrefix(apkTransitionRoot, "/") + "/execution-" + planSHA256} {
		if err := h.pinParent(path, strings.HasPrefix(path, strings.TrimPrefix(apkTransitionRoot, "/"))); err != nil {
			return err
		}
	}
	h.journal = h.parents[len(h.parents)-1].root
	lock, err := h.journal.Open(".")
	if err != nil {
		return errors.New("APK launcher custody lock is unavailable")
	}
	h.journalLock = lock
	fd := lock.Fd()
	if fd > uintptr(^uint(0)>>1) || unix.Flock(int(fd), unix.LOCK_EX|unix.LOCK_NB) != nil {
		return errors.New("APK launcher custody is already held")
	}
	return h.checkParents()
}

func (h *APKLauncherCustody) publish(name string, raw []byte) error {
	if err := h.checkParents(); err != nil {
		return err
	}
	if h.fault != nil {
		if err := h.fault("before-" + name); err != nil {
			h.failed = true
			return errors.New("APK launcher publication requires recovery")
		}
	}
	file, err := h.journal.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		h.failed = true
		return errors.New("APK launcher evidence already exists or cannot be published")
	}
	n, writeErr := file.Write(raw)
	syncErr := file.Sync()
	closeErr := file.Close()
	journalErr := h.journalLock.Sync()
	if writeErr != nil || syncErr != nil || closeErr != nil || journalErr != nil || n != len(raw) {
		h.failed = true
		return errors.New("APK launcher evidence publication is incomplete; retain custody")
	}
	if h.fault != nil {
		if err := h.fault("after-" + name); err != nil {
			h.failed = true
			return errors.New("APK launcher publication outcome requires recovery")
		}
	}
	return h.checkParents()
}

func (h *APKLauncherCustody) readRecord(name string) ([]byte, error) {
	entry, err := readAPKLauncherEntry(h.journal, name)
	if err != nil || entry.Absent || entry.Identity.Mode != syscall.S_IFREG|0600 {
		return nil, errors.New("APK launcher custody record is missing or unsafe")
	}
	return entry.Content, nil
}

func validAPKLauncherEvidence(evidence apkLauncherEvidence) bool {
	if evidence.Absent {
		return evidence == (apkLauncherEvidence{Absent: true})
	}
	identity := evidence.Identity
	if identity.Inode == 0 || identity.Links != 1 || int64(identity.UID) != int64(os.Geteuid()) ||
		int64(identity.GID) != int64(os.Getegid()) || identity.Size < 0 || identity.Size > apkLauncherMaximumBytes ||
		identity.ModifiedNS < 0 || identity.ModifiedNS >= 1e9 || identity.ChangedNS < 0 || identity.ChangedNS >= 1e9 {
		return false
	}
	switch identity.Mode & syscall.S_IFMT {
	case syscall.S_IFREG:
		return identity.Mode&0022 == 0 && evidence.LinkTarget == "" && validSHA256(evidence.ContentSHA256)
	case syscall.S_IFLNK:
		return evidence.ContentSHA256 == "" && evidence.LinkTarget != "" && len(evidence.LinkTarget) <= 4096 &&
			strings.IndexByte(evidence.LinkTarget, 0) < 0 && identity.Size == int64(len(evidence.LinkTarget))
	default:
		return false
	}
}

func apkLauncherProductDependency(path, target string) bool {
	if target == "" {
		return false
	}
	if !filepath.IsAbs(target) {
		target = filepath.Join("/", filepath.Dir(path), target)
	}
	target = filepath.Clean(target)
	return target == "/opt/syswarden" || strings.HasPrefix(target, "/opt/syswarden/")
}

// RefuseProductTargetDependencies never follows or executes an administrator
// link. It identifies a known unresolved dependency, not proof that all other
// opaque wrappers or link chains are behaviorally independent of the product.
func (h *APKLauncherCustody) RefuseProductTargetDependencies() error {
	if err := h.Revalidate(); err != nil {
		return err
	}
	for _, alias := range h.record.Aliases {
		if alias.Disposition == "retained-administrator" && alias.ProductDependency && h.targetAuthority == nil {
			return errors.New("retained APK launcher depends on the product target; explicit behavior recovery is required")
		}
	}
	return nil
}

func (h *APKLauncherCustody) checkRecordInventory() error {
	file, err := h.journal.Open(".")
	if err != nil {
		return errors.New("APK launcher custody inventory is unavailable")
	}
	names, readErr := file.Readdirnames(65)
	closeErr := file.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) || closeErr != nil || len(names) > 64 {
		return errors.New("APK launcher custody inventory is incomplete or excessive")
	}
	allowed := map[string]bool{
		"launcher-prepared.json": true, "launcher-custody.json": true, "launcher-retirement.json": true,
		"launcher-target-observation.json": true, "launcher-target-originals.json": true, "launcher-original-cli.bin": true, "launcher-original-tui.bin": true,
		"launcher-created-cli.json": true, "launcher-created-tui.json": true,
		"launcher-quarantine-cli.json": true, "launcher-quarantine-tui.json": true,
		"intent-launcher-created-cli.json": true, "intent-launcher-created-tui.json": true,
	}
	for _, name := range names {
		if (strings.HasPrefix(name, "launcher-") || strings.HasPrefix(name, "intent-launcher-")) && !allowed[name] {
			return errors.New("APK launcher custody contains unknown launcher evidence")
		}
	}
	return nil
}

// Revalidate compares exact alias identities and bytes without executing them.
func (h *APKLauncherCustody) Revalidate() error {
	return h.revalidateCustody(true)
}

func (h *APKLauncherCustody) revalidateCustody(checkTargets bool) error {
	if err := h.checkParents(); err != nil {
		return err
	}
	if err := h.checkRecordInventory(); err != nil {
		return err
	}
	prepared, err := h.readRecord("launcher-prepared.json")
	if err != nil || !bytes.Equal(prepared, h.prepared) {
		return errors.New("APK launcher prepared evidence changed")
	}
	if len(h.receipt) != 0 {
		receipt, err := h.readRecord("launcher-custody.json")
		if err != nil || !bytes.Equal(receipt, h.receipt) {
			return errors.New("APK launcher committed evidence changed")
		}
	}
	if len(h.retirement) != 0 {
		retirement, err := h.readRecord("launcher-retirement.json")
		if err != nil || !bytes.Equal(retirement, h.retirement) {
			return errors.New("APK launcher retirement evidence changed")
		}
	}
	if err := h.revalidateTransferSource(); err != nil {
		return err
	}
	for i, alias := range h.record.Aliases {
		entry, err := readAPKLauncherEntry(h.aliases, filepath.Base(alias.Path))
		if err != nil {
			return err
		}
		actual := apkLauncherEntryEvidence(entry)
		quarantine, hasQuarantine, quarantineErr := h.readQuarantine(i)
		if quarantineErr != nil {
			return quarantineErr
		}
		if hasQuarantine {
			if _, err := h.aliases.Lstat(quarantine.Name); err == nil {
				if !actual.Absent {
					return errors.New("APK launcher quarantine conflicts with a live entry")
				}
				if err := h.attestQuarantine(quarantine); err != nil {
					return err
				}
			} else if !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
		if actual.Absent && alias.Disposition == "product-created" && len(h.retirement) != 0 && !hasQuarantine {
			return errors.New("APK launcher absence has no exact quarantine intent")
		}
		if actual != alias.Committed && !(len(h.retirement) != 0 && alias.Disposition == "product-created" && actual.Absent) {
			return errors.New("APK launcher identity or content changed")
		}
		if len(h.receipt) != 0 && alias.Disposition != "product-created" {
			for _, name := range []string{apkLauncherCreationName(i), "intent-" + apkLauncherCreationName(i)} {
				if _, err := h.journal.Lstat(name); !errors.Is(err, os.ErrNotExist) {
					return errors.New("APK launcher non-owned disposition has contradictory creation evidence")
				}
			}
		}
		if alias.Disposition == "product-created" {
			raw, err := h.readRecord(apkLauncherCreationName(i))
			var creation apkLauncherCreation
			if err != nil || apkTransitionDigest(raw) != alias.CreationSHA256 || decodeAPKTransitionJSON(raw, &creation) != nil ||
				creation.Schema != apkLauncherCustodySchema || creation.Purpose != "exclusive-launcher-created" ||
				creation.PreparedSHA256 != h.record.PreparedSHA256 || creation.Path != alias.Path || creation.Evidence != alias.Committed {
				return errors.New("APK launcher exclusive creation provenance changed")
			}
			intentRaw, err := h.readRecord("intent-" + apkLauncherCreationName(i))
			var intent apkLauncherCreation
			if err != nil || decodeAPKTransitionJSON(intentRaw, &intent) != nil || intent.Schema != apkLauncherCustodySchema ||
				intent.Purpose != "exclusive-launcher-create-intent" || intent.PreparedSHA256 != h.record.PreparedSHA256 ||
				intent.Path != alias.Path || intent.Evidence != (apkLauncherEvidence{Absent: true}) {
				return errors.New("APK launcher exclusive creation intent changed")
			}
		}
	}
	if err := h.revalidateTargetRecords(checkTargets); err != nil {
		return err
	}
	return h.checkParents()
}

func apkLauncherCreationName(index int) string {
	if index == 0 {
		return "launcher-created-cli.json"
	}
	return "launcher-created-tui.json"
}

// CreateAbsent is an optional, separate effect. Only this exclusive creator can
// mint product-created provenance; a matching preexisting link never qualifies.
// The execution coordinator must separately authorize this effect.
func (h *APKLauncherCustody) CreateAbsent() error {
	if h != nil && h.targetAuthority != nil {
		return errors.New("APK target replacement authority cannot create launcher aliases")
	}
	if h == nil {
		return errors.New("APK launcher custody is unavailable")
	}
	if len(h.receipt) != 0 || len(h.retirement) != 0 {
		return errors.New("APK launcher creation is closed after commitment")
	}
	if err := h.RefuseProductTargetDependencies(); err != nil {
		return err
	}
	for i, alias := range h.record.Aliases {
		if alias.Disposition != "absent" {
			continue
		}
		intent := apkLauncherCreation{apkLauncherCustodySchema, "exclusive-launcher-create-intent", h.record.PreparedSHA256, alias.Path, alias.Original}
		raw, err := apkLauncherCanonical(intent)
		if err != nil {
			return err
		}
		if err := h.publish("intent-"+apkLauncherCreationName(i), raw); err != nil {
			return err
		}
		if err := h.Revalidate(); err != nil {
			return err
		}
		if err := h.aliases.Symlink(apkLauncherTargets[i], filepath.Base(alias.Path)); err != nil {
			h.failed = true
			return errors.New("APK launcher exclusive creation failed; retain custody")
		}
		directory, err := h.aliases.Open(".")
		if err != nil {
			h.failed = true
			return errors.New("APK launcher creation synchronization is unavailable")
		}
		if err := errors.Join(directory.Sync(), directory.Close()); err != nil {
			h.failed = true
			return errors.New("APK launcher creation synchronization failed")
		}
		entry, err := readAPKLauncherEntry(h.aliases, filepath.Base(alias.Path))
		if err != nil || entry.Absent || entry.LinkTarget != apkLauncherTargets[i] {
			h.failed = true
			return errors.New("APK launcher exclusive creation changed before observation")
		}
		created := apkLauncherCreation{apkLauncherCustodySchema, "exclusive-launcher-created", h.record.PreparedSHA256, alias.Path, apkLauncherEntryEvidence(entry)}
		raw, err = apkLauncherCanonical(created)
		if err != nil {
			return err
		}
		if err := h.publish(apkLauncherCreationName(i), raw); err != nil {
			return err
		}
		h.record.Aliases[i].Disposition = "product-created"
		h.record.Aliases[i].Committed = created.Evidence
		h.record.Aliases[i].CreationSHA256 = apkTransitionDigest(raw)
		if err := h.Revalidate(); err != nil {
			return err
		}
	}
	return nil
}

// Commit returns the digest of immutable alias-custody evidence. A caller must
// bind it into a separately verified native completion record; this is not that
// completion record and does not authorize a successful update result.
func (h *APKLauncherCustody) Commit() (string, error) {
	if h == nil {
		return "", errors.New("APK launcher custody is unavailable")
	}
	if len(h.receipt) != 0 || len(h.retirement) != 0 {
		return "", errors.New("APK launcher custody cannot be committed twice")
	}
	if err := h.RefuseProductTargetDependencies(); err != nil {
		return "", err
	}
	if h.targetAuthority != nil && len(h.targetRecords.observation) == 0 {
		return "", errors.New("APK launcher target replacement has not been independently observed")
	}
	raw, err := apkLauncherCanonical(h.record)
	if err != nil {
		return "", err
	}
	if err := h.publish("launcher-custody.json", raw); err != nil {
		return "", err
	}
	h.receipt = raw
	if err := h.Revalidate(); err != nil {
		h.failed = true
		return "", err
	}
	return apkTransitionDigest(raw), nil
}

// InspectAPKLaunchersForRemoval consumes exact references from the caller's
// verified lifecycle receipt. It never searches backups or adopts current
// aliases to repair a missing record. Inspection does not authorize removal.
func InspectAPKLaunchersForRemoval(planSHA256, receiptSHA256 string) (*APKLauncherCustody, error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("APK launcher removal inspection requires root")
	}
	return inspectAPKLaunchersForRemovalAt(context.Background(), "/", planSHA256, receiptSHA256)
}

func inspectAPKLaunchersForRemovalAt(ctx context.Context, hostPath, planSHA256, receiptSHA256 string) (_ *APKLauncherCustody, result error) {
	if !validSHA256(planSHA256) || !validSHA256(receiptSHA256) {
		return nil, errors.New("APK launcher removal requires exact lifecycle receipt references")
	}
	h, err := openAPKLauncherHost(ctx, hostPath)
	if err != nil {
		return nil, err
	}
	defer func() {
		if result != nil {
			result = errors.Join(result, h.Close())
		}
	}()
	path := filepath.Join(hostPath, strings.TrimPrefix(apkTransitionRoot, "/"), "execution-"+planSHA256)
	if err := h.openJournal(hostPath, path, planSHA256); err != nil {
		return nil, err
	}
	h.receipt, err = h.readRecord("launcher-custody.json")
	if err != nil || apkTransitionDigest(h.receipt) != receiptSHA256 || decodeAPKTransitionJSON(h.receipt, &h.record) != nil ||
		h.record.Schema != apkLauncherCustodySchema || h.record.Purpose != "committed-launcher-custody" ||
		!validAPKLauncherBinding(h.record.Binding) || h.record.Binding.PlanSHA256 != planSHA256 || !validSHA256(h.record.PreparedSHA256) {
		return nil, errors.New("APK launcher committed receipt is invalid or does not match lifecycle authority")
	}
	h.prepared, err = h.readRecord("launcher-prepared.json")
	var prepared apkLauncherReceipt
	if err != nil || apkTransitionDigest(h.prepared) != h.record.PreparedSHA256 || decodeAPKTransitionJSON(h.prepared, &prepared) != nil ||
		prepared.Schema != apkLauncherCustodySchema || prepared.Purpose != "prepared-launcher-custody" || prepared.Binding != h.record.Binding ||
		prepared.PreparedSHA256 != "" || prepared.TransferSHA256 != h.record.TransferSHA256 || prepared.Parents != h.record.Parents || prepared.TargetProposalSHA256 != h.record.TargetProposalSHA256 || prepared.TargetObservationSHA256 != "" || prepared.TargetOriginalsSHA256 != h.record.TargetOriginalsSHA256 {
		return nil, errors.New("APK launcher original custody receipt is invalid")
	}
	if err := h.loadApprovedTransfer(); err != nil {
		return nil, err
	}
	for i, path := range apkLauncherParents {
		if h.record.Parents[i].Path != path || !apkLauncherSameParent(h.record.Parents[i].Identity, h.parents[i].identity) {
			return nil, errors.New("APK launcher original parent binding changed")
		}
	}
	for i, path := range apkLauncherPaths {
		alias, original := h.record.Aliases[i], prepared.Aliases[i]
		if !validAPKLauncherEvidence(alias.Original) || !validAPKLauncherEvidence(alias.Committed) ||
			alias.Path != path || original.Path != path || alias.Original != original.Original || original.Committed != original.Original ||
			original.CreationSHA256 != "" && original.Disposition != "product-transferred" || original.ProductDependency != apkLauncherProductDependency(path, original.Original.LinkTarget) {
			return nil, errors.New("APK launcher original alias binding is invalid")
		}
		switch alias.Disposition {
		case "absent":
			if original.Disposition != "absent" || !alias.Original.Absent || alias.Original != (apkLauncherEvidence{Absent: true}) || alias.Committed != alias.Original || alias.CreationSHA256 != "" || alias.ProductDependency {
				return nil, errors.New("APK launcher absence record is invalid")
			}
		case "retained-administrator":
			if original.Disposition != "retained-administrator" || alias.Original.Absent || alias.Committed != alias.Original || alias.CreationSHA256 != "" || alias.ProductDependency != original.ProductDependency {
				return nil, errors.New("APK launcher retained administrator record is invalid")
			}
		case "product-transferred":
			if h.transfer == nil || original.Disposition != "product-transferred" || alias.Original.Absent || alias.Committed != alias.Original || original.CreationSHA256 != alias.CreationSHA256 || !alias.ProductDependency {
				return nil, errors.New("APK launcher source ownership transfer is invalid")
			}
		case "product-created":
			if original.Disposition != "absent" || alias.Original != (apkLauncherEvidence{Absent: true}) || alias.Committed.Absent ||
				alias.Committed.LinkTarget != apkLauncherTargets[i] || alias.Committed.ContentSHA256 != "" || !validSHA256(alias.CreationSHA256) || alias.ProductDependency {
				return nil, errors.New("APK launcher creation cannot adopt an inherited alias")
			}
		default:
			return nil, errors.New("APK launcher disposition is unknown")
		}
	}
	if err := h.loadTargetRecordsForRemoval(); err != nil {
		return nil, err
	}
	if _, err := h.journal.Lstat("launcher-retirement.json"); err == nil {
		h.retirement, err = h.readRecord("launcher-retirement.json")
		var retirement apkLauncherRetirement
		if err != nil || decodeAPKTransitionJSON(h.retirement, &retirement) != nil || retirement.Schema != apkLauncherCustodySchema ||
			retirement.Purpose != "owned-launcher-retirement" || retirement.ReceiptSHA256 != receiptSHA256 || retirement.Barrier.Absent ||
			!validAPKLauncherEvidence(retirement.Barrier) || retirement.Barrier.Identity.Mode != syscall.S_IFREG|0600 ||
			retirement.Barrier.ContentSHA256 != apkTransitionDigest([]byte(RemovalTombstoneRecord)) {
			return nil, errors.New("APK launcher retirement intent is invalid")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("APK launcher retirement intent cannot be inspected")
	}
	if err := h.Revalidate(); err != nil {
		return nil, err
	}
	return h, nil
}

func (h *APKLauncherCustody) removalBarrier() (apkLauncherEvidence, error) {
	for _, path := range []string{"var", "var/lib", "var/lib/syswarden"} {
		if err := h.pinParent(path, false); err != nil {
			return apkLauncherEvidence{}, err
		}
	}
	entry, err := readAPKLauncherEntry(h.anchor, strings.TrimPrefix(RemovalTombstonePath, "/"))
	if err != nil || entry.Absent || entry.Identity.Mode != syscall.S_IFREG|0600 || string(entry.Content) != RemovalTombstoneRecord {
		return apkLauncherEvidence{}, errors.New("APK launcher retirement requires the exact durable removal barrier")
	}
	return apkLauncherEntryEvidence(entry), nil
}

// RetireOwned removes only aliases created by this custody transaction. The
// immutable intent precedes unlinking, so retry can distinguish permitted
// absence from an unrecorded deletion without adopting a replacement.
func (h *APKLauncherCustody) RetireOwned() error {
	if h == nil {
		return errors.New("APK launcher custody is unavailable")
	}
	if h.transfer != nil {
		return errors.New("APK transferred launcher removal requires the complete lifecycle source authority")
	}
	if len(h.receipt) == 0 {
		return errors.New("APK launcher retirement requires committed custody")
	}
	if err := h.refuseRemovalTargetDependencies(); err != nil {
		return err
	}
	barrier, err := h.removalBarrier()
	if err != nil {
		return err
	}
	intent := apkLauncherRetirement{apkLauncherCustodySchema, "owned-launcher-retirement", apkTransitionDigest(h.receipt), barrier}
	raw, err := apkLauncherCanonical(intent)
	if err != nil {
		return err
	}
	if len(h.retirement) == 0 {
		if err := h.publish("launcher-retirement.json", raw); err != nil {
			return err
		}
		h.retirement = raw
	} else if !bytes.Equal(raw, h.retirement) {
		return errors.New("APK launcher removal barrier differs from the retained intent")
	}
	for i, alias := range h.record.Aliases {
		if alias.Disposition != "product-created" {
			continue
		}
		if err := h.Revalidate(); err != nil {
			return err
		}
		if err := h.retireOwnedAlias(i, barrier); err != nil {
			return err
		}
	}
	return h.AttestTerminal()
}

// AttestTerminal accepts exact retained administrator entries and absence of
// every receipt-created entry. It does not finalize the surrounding removal or
// erase private custody, and does not claim arbitrary wrapper behavior.
func (h *APKLauncherCustody) AttestTerminal() error {
	if h == nil {
		return errors.New("APK launcher custody is unavailable")
	}
	if h.transfer != nil {
		return errors.New("APK transferred launcher terminal check requires the complete lifecycle source authority")
	}
	if len(h.receipt) == 0 {
		return errors.New("APK launcher terminal check requires committed custody")
	}
	if err := h.refuseRemovalTargetDependencies(); err != nil {
		return err
	}
	for i, alias := range h.record.Aliases {
		if alias.Disposition == "product-created" {
			record, exists, err := h.readQuarantine(i)
			if err != nil || !exists {
				return errors.New("APK launcher terminal removal lacks quarantine custody")
			}
			if _, err := h.aliases.Lstat(record.Name); !errors.Is(err, os.ErrNotExist) {
				return errors.New("APK launcher quarantine remains unresolved")
			}
			entry, err := readAPKLauncherEntry(h.aliases, filepath.Base(alias.Path))
			if err != nil || !entry.Absent || len(h.retirement) == 0 {
				return errors.New("APK launcher owned entry is not durably retired")
			}
		}
	}
	return h.checkParents()
}

// Close releases every retained descriptor and reports closure failures.
func (h *APKLauncherCustody) Close() error {
	if h == nil || h.closed {
		return nil
	}
	h.closed = true
	var failures []error
	if h.targetAuthority != nil {
		failures = append(failures, closeAPKLauncherTargetFiles(h.targetAuthority.files))
	}
	if h.journalLock != nil {
		if err := h.journalLock.Close(); err != nil {
			failures = append(failures, errors.New("APK launcher custody lock close failed"))
		}
	}
	for i := len(h.parents) - 1; i >= 0; i-- {
		if err := h.parents[i].root.Close(); err != nil {
			failures = append(failures, errors.New("APK launcher parent close failed"))
		}
	}
	if h.anchor != nil {
		if err := h.anchor.Close(); err != nil {
			failures = append(failures, errors.New("APK launcher anchor close failed"))
		}
	}
	return errors.Join(failures...)
}

type apkLauncherQuarantine struct {
	Schema        string              `json:"schema"`
	Purpose       string              `json:"purpose"`
	ReceiptSHA256 string              `json:"receipt_sha256"`
	Path          string              `json:"path"`
	Name          string              `json:"name"`
	Evidence      apkLauncherEvidence `json:"evidence"`
}

func apkLauncherQuarantineName(index int) string {
	if index == 0 {
		return "launcher-quarantine-cli.json"
	}
	return "launcher-quarantine-tui.json"
}

func (h *APKLauncherCustody) readQuarantine(index int) (apkLauncherQuarantine, bool, error) {
	var record apkLauncherQuarantine
	name := apkLauncherQuarantineName(index)
	if _, err := h.journal.Lstat(name); errors.Is(err, os.ErrNotExist) {
		if len(h.quarantines[index]) != 0 {
			return record, false, errors.New("APK launcher quarantine intent disappeared")
		}
		return record, false, nil
	} else if err != nil {
		return record, false, err
	}
	raw, err := h.readRecord(name)
	alias := h.record.Aliases[index]
	if err != nil || decodeAPKTransitionJSON(raw, &record) != nil || record.Schema != apkLauncherCustodySchema || record.Purpose != "owned-launcher-quarantine" || len(h.retirement) == 0 || len(h.receipt) == 0 || record.ReceiptSHA256 != apkTransitionDigest(h.receipt) || alias.Disposition != "product-created" || record.Path != alias.Path || record.Evidence != alias.Committed || !strings.HasPrefix(record.Name, ".syswarden-apk-retire-") || len(record.Name) != len(".syswarden-apk-retire-")+32 || !safeAssetName(record.Name) {
		return record, false, errors.New("APK launcher quarantine intent is invalid")
	}
	if len(h.quarantines[index]) != 0 && !bytes.Equal(h.quarantines[index], raw) {
		return record, false, errors.New("APK launcher quarantine intent changed")
	}
	h.quarantines[index] = raw
	return record, true, nil
}

func (h *APKLauncherCustody) attestQuarantine(record apkLauncherQuarantine) error {
	entry, err := readAPKLauncherEntry(h.aliases, record.Name)
	actual := apkLauncherEntryEvidence(entry)
	if err != nil || entry.Absent || !sameAPKLauncherMovedIdentity(record.Evidence.Identity, actual.Identity) || actual.LinkTarget != record.Evidence.LinkTarget || actual.ContentSHA256 != record.Evidence.ContentSHA256 {
		return errors.New("APK launcher quarantine identity changed; retain the exact quarantine and intent for recovery")
	}
	return h.checkParents()
}

func (h *APKLauncherCustody) retireOwnedAlias(index int, barrier apkLauncherEvidence) (result error) {
	alias := h.record.Aliases[index]
	record, exists, err := h.readQuarantine(index)
	if err != nil {
		return err
	}
	if !exists {
		entry, err := readAPKLauncherEntry(h.aliases, filepath.Base(alias.Path))
		if err != nil || apkLauncherEntryEvidence(entry) != alias.Committed {
			return errors.New("APK launcher changed before quarantine intent")
		}
		name, err := randomServiceArtifactName(".syswarden-apk-retire-")
		if err != nil {
			return err
		}
		record = apkLauncherQuarantine{apkLauncherCustodySchema, "owned-launcher-quarantine", apkTransitionDigest(h.receipt), alias.Path, name, alias.Committed}
		raw, err := apkLauncherCanonical(record)
		if err != nil {
			return err
		}
		if err := h.publish(apkLauncherQuarantineName(index), raw); err != nil {
			return err
		}
		h.quarantines[index] = raw
	}
	directory, err := h.aliases.Open(".")
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, directory.Close()) }()
	info, err := directory.Stat()
	identity, identityErr := apkLauncherIdentity(info)
	if err != nil || identityErr != nil || !apkLauncherSameParent(h.record.Parents[3].Identity, identity) {
		return errors.New("APK launcher quarantine parent changed")
	}
	descriptor := directory.Fd()
	if descriptor > uintptr(^uint(0)>>1) {
		return errors.New("APK launcher quarantine descriptor is invalid")
	}
	fd := int(descriptor)
	name := filepath.Base(alias.Path)
	_, quarantineErr := h.aliases.Lstat(record.Name)
	_, namedErr := h.aliases.Lstat(name)
	if errors.Is(quarantineErr, os.ErrNotExist) && errors.Is(namedErr, os.ErrNotExist) {
		return h.Revalidate()
	}
	if quarantineErr != nil && !errors.Is(quarantineErr, os.ErrNotExist) {
		return quarantineErr
	}
	if errors.Is(quarantineErr, os.ErrNotExist) {
		if err := h.Revalidate(); err != nil {
			return err
		}
		entry, err := readAPKLauncherEntry(h.aliases, name)
		if err != nil || apkLauncherEntryEvidence(entry) != alias.Committed {
			return errors.New("APK launcher changed before atomic quarantine")
		}
		if currentBarrier, err := h.removalBarrier(); err != nil || currentBarrier != barrier {
			return errors.New("APK launcher removal barrier changed before quarantine")
		}
		if h.fault != nil {
			if err := h.fault("before-quarantine-" + name); err != nil {
				return err
			}
		}
		if err := unix.Renameat2(fd, name, fd, record.Name, unix.RENAME_NOREPLACE); err != nil {
			return err
		}
		if err := directory.Sync(); err != nil {
			return err
		}
		if h.fault != nil {
			if err := h.fault("after-quarantine-" + name); err != nil {
				return err
			}
		}
	} else if namedErr == nil {
		return errors.New("APK launcher quarantine conflicts with a live replacement")
	}
	attestErr := h.attestQuarantine(record)
	currentBarrier, barrierErr := h.removalBarrier()
	_, namedErr = h.aliases.Lstat(name)
	if attestErr != nil || barrierErr != nil || currentBarrier != barrier || !errors.Is(namedErr, os.ErrNotExist) {
		restoreErr := unix.Renameat2(fd, record.Name, fd, name, unix.RENAME_NOREPLACE)
		return errors.Join(errors.New("APK launcher quarantine changed; preserve its recorded location for bounded recovery"), attestErr, barrierErr, restoreErr, directory.Sync())
	}
	if err := unix.Unlinkat(fd, record.Name, 0); err != nil {
		restoreErr := unix.Renameat2(fd, record.Name, fd, name, unix.RENAME_NOREPLACE)
		return errors.Join(err, restoreErr, directory.Sync())
	}
	if err := directory.Sync(); err != nil {
		return err
	}
	if h.fault != nil && h.fault("after-unlink-"+name) != nil {
		return errors.New("APK launcher unlink interrupted; retain removal intent")
	}
	return h.Revalidate()
}
