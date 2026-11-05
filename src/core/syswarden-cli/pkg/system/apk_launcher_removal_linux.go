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
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

type apkLauncherLifecycleRemoval struct {
	store                      *apkLauncherLifecycleStore
	journal                    *pinnedServiceDirectory
	currentIdentity            apkTransitionIdentity
	reference                  apkLauncherLifecycleReference
	currentReference           apkLauncherLifecycleReference
	intent                     apkFreshLauncherIntent
	receipt                    apkFreshLauncherReceipt
	retirement                 []byte
	terminal                   []byte
	execution                  *APKLauncherCustody
	publication                *apkLauncherLineagePublicationIntent
	finalization               map[string]apkLauncherFinalizationRecord
	observed                   map[string][]byte
	publicationJournal         *pinnedServiceDirectory
	ownership                  *apkLauncherLifecycleRemoval
	transfer                   *apkLauncherTransferProposal
	transferSHA256             string
	transferExecution          *APKLauncherCustody
	transferExecutionDirectory *pinnedServiceDirectory
}

func (h *apkLauncherLifecycleRemoval) closeAuxiliary() error {
	if h == nil {
		return nil
	}
	var err error
	if h.execution != nil {
		err = errors.Join(err, h.execution.Close())
		h.execution = nil
	}
	if h.ownership != nil {
		err = errors.Join(err, h.ownership.close())
		h.ownership = nil
	}
	if h.transferExecutionDirectory != nil {
		err = errors.Join(err, closeAPKExecutionDirectory(h.transferExecutionDirectory))
		h.transferExecutionDirectory = nil
	}
	if h.publicationJournal != nil && h.publicationJournal != h.store.journal {
		err = errors.Join(err, closeAPKExecutionDirectory(h.publicationJournal))
		h.publicationJournal = nil
	}
	return err
}

func (h *apkLauncherLifecycleRemoval) close() error {
	if h == nil {
		return nil
	}
	return errors.Join(h.closeAuxiliary(), h.store.close())
}

func apkLauncherLifecycleAppliesAt(host string) (bool, error) {
	for _, path := range []string{strings.TrimPrefix(apkLauncherLifecycleRoot, "/"), "etc/alpine-release", "lib/apk/db/installed"} {
		_, err := os.Lstat(filepath.Join(host, path))
		if err == nil {
			return true, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return false, err
		}
	}
	return false, nil
}

// PreflightAPKLauncherRemoval refuses ambiguous APK launcher provenance before
// runtime teardown. Matching targets and absent aliases never replace receipts.
func PreflightAPKLauncherRemoval() error {
	applicable, err := apkLauncherLifecycleAppliesAt("/")
	if err != nil || !applicable {
		return err
	}
	if os.Geteuid() != 0 {
		return errors.New("APK launcher removal requires root")
	}
	return preflightAPKLauncherRemovalAt(context.Background(), "/")
}

func preflightAPKLauncherRemovalAt(ctx context.Context, host string) (result error) {
	applicable, err := apkLauncherLifecycleAppliesAt(host)
	if err != nil || !applicable {
		return err
	}
	h, err := inspectAPKLauncherLifecycleRemovalAt(ctx, host)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, h.close()) }()
	return h.revalidate()
}

// RetireAPKLaunchersForRemoval consumes the fixed current lifecycle reference
// after the durable removal barrier. Private evidence is retained for recovery;
// only receipt-created aliases and empty receipt-created parents are removed.
func RetireAPKLaunchersForRemoval() error {
	applicable, err := apkLauncherLifecycleAppliesAt("/")
	if err != nil || !applicable {
		return err
	}
	if os.Geteuid() != 0 {
		return errors.New("APK launcher removal requires root")
	}
	return retireAPKLaunchersForRemovalAt(context.Background(), "/")
}

func retireAPKLaunchersForRemovalAt(ctx context.Context, host string) (result error) {
	applicable, err := apkLauncherLifecycleAppliesAt(host)
	if err != nil || !applicable {
		return err
	}
	h, err := inspectAPKLauncherLifecycleRemovalAt(ctx, host)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, h.close()) }()
	return h.retire()
}

// attestAPKLauncherRetirement returns true only for the APK lineage boundary.
// Generic target-based unlinking must not run when this boundary applies.
func attestAPKLauncherRetirement() (bool, error) {
	applicable, err := apkLauncherLifecycleAppliesAt("/")
	if err != nil || !applicable {
		return applicable, err
	}
	h, err := inspectAPKLauncherLifecycleRemovalAt(context.Background(), "/")
	if err != nil {
		return true, err
	}
	return true, errors.Join(h.attestTerminal(), h.close())
}

func inspectAPKLauncherLifecycleRemovalAt(ctx context.Context, host string) (_ *apkLauncherLifecycleRemoval, result error) {
	s, err := openAPKLauncherLifecycleStore(ctx, host, false)
	if err != nil {
		return nil, fmt.Errorf("APK launcher ownership evidence is unavailable; preserve aliases and product targets: %w", err)
	}
	defer func() {
		if result != nil {
			result = errors.Join(result, s.close())
		}
	}()
	return inspectAPKLauncherLifecycleRemovalStore(s, false)
}

func inspectAPKLauncherLifecycleRemovalStore(s *apkLauncherLifecycleStore, allowPending bool) (*apkLauncherLifecycleRemoval, error) {
	return inspectAPKLauncherLifecycleRemovalSourceStore(s, allowPending, nil, false)
}

func inspectAPKLauncherLifecycleRemovalSourceStore(s *apkLauncherLifecycleStore, allowPending bool, source *apkLauncherLifecycleReference, sourceOnly bool) (*apkLauncherLifecycleRemoval, error) {
	h := &apkLauncherLifecycleRemoval{store: s, observed: make(map[string][]byte)}
	if _, err := s.directory.root.Lstat("pending.json"); !allowPending && !errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("APK launcher lifecycle has pending recovery debt")
	}
	raw, err := readAPKTransitionBytes(s.directory, "current.json", 4096)
	if err != nil || decodeAPKTransitionJSON(raw, &h.reference) != nil || h.reference.Schema != apkFreshLauncherSchema || !validSHA256(h.reference.PlanSHA256) || !validSHA256(h.reference.ReceiptSHA256) {
		return nil, errors.New("APK current launcher lineage is missing or invalid")
	}
	h.currentReference = h.reference
	if source != nil {
		if source.Schema != apkFreshLauncherSchema || source.Kind != "fresh" || !validSHA256(source.PlanSHA256) || !validSHA256(source.ReceiptSHA256) {
			return nil, errors.New("APK launcher ownership source reference is invalid")
		}
		h.reference = *source
	}
	currentInfo, err := s.directory.root.Lstat("current.json")
	if err != nil {
		return nil, err
	}
	h.currentIdentity, err = apkLauncherIdentity(currentInfo)
	if err != nil {
		return nil, err
	}
	if h.reference.Kind == "execution" {
		if err := s.openJournal(h.reference.PlanSHA256, false); err != nil {
			return nil, err
		}
		h.journal = s.journal
		publicationRaw, err := readAPKTransitionBytes(h.journal, "publication-intent.json", 4096)
		var publication apkLauncherLineagePublicationIntent
		if err != nil || decodeAPKTransitionJSON(publicationRaw, &publication) != nil || publication.Reference != h.reference {
			return nil, errors.New("APK execution launcher publication evidence is unavailable")
		}
		if err := s.attestPublishedLineage(publication); err != nil {
			return nil, err
		}
		h.publication = &publication
		h.publicationJournal = h.journal
		if err := h.attestExecutionFinalization(); err != nil {
			return nil, err
		}
		if transferred, err := h.tryTransferredRemoval(); err != nil {
			return nil, errors.Join(err, h.closeAuxiliary())
		} else if transferred {
			return h, nil
		}
		h.execution, err = inspectAPKLaunchersForRemovalAt(s.ctx, s.host, h.reference.PlanSHA256, h.reference.ReceiptSHA256)
		if err != nil {
			return nil, err
		}
		if err := h.revalidate(); err != nil {
			return nil, errors.Join(err, h.execution.Close())
		}
		return h, nil
	}
	if h.reference.Kind != "fresh" {
		return nil, errors.New("APK current launcher lineage kind is unsupported")
	}
	if err := s.openJournal(h.reference.PlanSHA256, false); err != nil {
		return nil, err
	}
	h.journal = s.journal
	raw, err = readAPKTransitionBytes(s.journal, "intent.json", apkLauncherMaximumBytes)
	if err != nil || apkTransitionDigest(raw) != h.reference.PlanSHA256 || decodeAPKTransitionJSON(raw, &h.intent) != nil || h.intent.Schema != apkFreshLauncherSchema || h.intent.Purpose != "fresh-intent-no-alias-mutation" || !validFreshAPKPreviousIntent(h.intent) {
		return nil, errors.New("APK original fresh launcher intent is invalid")
	}
	before, err := readAPKTransitionBytes(s.journal, "before-installed", maximumAPKInstalledDatabaseSize)
	if err != nil || apkTransitionDigest(before) != h.intent.DatabaseSHA256 {
		return nil, errors.New("APK original native absence evidence changed")
	}
	previous, err := parseAPKLauncherRegistrations(before)
	if err != nil {
		return nil, err
	}
	for name := range previous {
		if validNativeProductPackageName(name) {
			return nil, errors.New("APK fresh launcher receipt adopted an installed product")
		}
	}
	raw, err = readAPKTransitionBytes(s.journal, "receipt.json", apkLauncherMaximumBytes)
	if err != nil || apkTransitionDigest(raw) != h.reference.ReceiptSHA256 || decodeAPKTransitionJSON(raw, &h.receipt) != nil || h.receipt.Schema != apkFreshLauncherSchema || h.receipt.Purpose != "exclusive-fresh-launcher-ownership" || h.receipt.IntentSHA256 != h.reference.PlanSHA256 || !validNativeProductPackageName(h.receipt.Native.Name) || !validSHA256(h.receipt.Native.RecordSHA256) || !validAPKRetentionChecksum(h.receipt.Native.Checksum) {
		return nil, errors.New("APK committed fresh launcher receipt is invalid")
	}
	if _, err := parseReleaseVersion(h.receipt.Native.Version); err != nil {
		return nil, errors.New("APK fresh launcher receipt version is invalid")
	}
	allowed := map[string]bool{"intent.json": true, "before-installed": true, "receipt.json": true, "retirement.json": true, "terminal.json": true}
	if h.intent.PreviousSHA256 != "" {
		allowed["previous-current.json"], allowed["displaced-current.json"] = true, true
		if err := h.store.verifyPreviousFreshLineage(h.journal, h.intent); err != nil {
			return nil, err
		}
	}
	for i, path := range apkLauncherParents {
		original, committed := h.intent.Parents[i], h.receipt.Parents[i]
		if original.Path != path || committed.Path != path || committed.Absent || original.CreationSHA256 != "" || committed.Identity.Mode&syscall.S_IFMT != syscall.S_IFDIR || committed.Identity.Mode&0022 != 0 || int(committed.Identity.UID) != os.Geteuid() || int(committed.Identity.GID) != os.Getegid() || committed.Identity.Inode == 0 {
			return nil, errors.New("APK fresh launcher parent receipt is invalid")
		}
		if original.Absent {
			if i < 2 || original.Identity != (apkTransitionIdentity{}) || !validSHA256(committed.CreationSHA256) || committed.Identity.Mode != syscall.S_IFDIR|0755 {
				return nil, errors.New("APK fresh launcher parent creation adopted an existing directory")
			}
			name := fmt.Sprintf("parent-%d", i)
			allowed["intent-"+name+".json"], allowed["created-"+name+".json"], allowed["retire-"+name+".json"] = true, true, true
			allowed[apkFreshQuarantineRecordName(i, true)] = true
			var observed apkFreshLauncherParent
			intentRaw, err := readAPKTransitionBytes(s.journal, "intent-"+name+".json", 4096)
			if err != nil || decodeAPKTransitionJSON(intentRaw, &observed) != nil || observed != original {
				return nil, errors.New("APK fresh launcher parent creation intent changed")
			}
			created, err := readAPKTransitionBytes(s.journal, "created-"+name+".json", 4096)
			want := committed
			want.CreationSHA256 = ""
			if err != nil || apkTransitionDigest(created) != committed.CreationSHA256 || decodeAPKTransitionJSON(created, &observed) != nil || observed != want {
				return nil, errors.New("APK fresh launcher parent creation proof changed")
			}
		} else if committed.CreationSHA256 != "" || !apkLauncherSameParent(original.Identity, committed.Identity) {
			return nil, errors.New("APK fresh launcher receipt adopted inherited ancestry")
		}
	}
	for i, path := range apkLauncherPaths {
		original, committed := h.intent.Aliases[i], h.receipt.Aliases[i]
		if original.Path != path || committed.Path != path || !validAPKLauncherEvidence(original.Original) || !validAPKLauncherEvidence(committed.Committed) || original.Committed != original.Original || original.CreationSHA256 != "" || committed.Original != original.Original || original.ProductDependency != apkLauncherProductDependency(path, original.Original.LinkTarget) {
			return nil, errors.New("APK fresh launcher original alias binding is invalid")
		}
		if original.Original.Absent {
			if original.Disposition != "absent" || committed.Disposition != "product-created" || committed.Committed.LinkTarget != apkLauncherTargets[i] || committed.Committed.ContentSHA256 != "" || committed.ProductDependency || !validSHA256(committed.CreationSHA256) {
				return nil, errors.New("APK fresh launcher receipt does not prove exclusive creation")
			}
			name := apkLauncherCreationName(i)
			allowed[name], allowed["intent-"+name] = true, true
			allowed[apkFreshQuarantineRecordName(i, false)] = true
			var created apkLauncherCreation
			creationRaw, err := readAPKTransitionBytes(s.journal, name, 4096)
			want := apkLauncherCreation{apkFreshLauncherSchema, "exclusive-launcher-created", h.reference.PlanSHA256, path, committed.Committed}
			if err != nil || apkTransitionDigest(creationRaw) != committed.CreationSHA256 || decodeAPKTransitionJSON(creationRaw, &created) != nil || created != want {
				return nil, errors.New("APK fresh launcher exclusive creation proof changed")
			}
			intentRaw, err := readAPKTransitionBytes(s.journal, "intent-"+name, 4096)
			want.Purpose, want.Evidence = "exclusive-launcher-create-intent", apkLauncherEvidence{Absent: true}
			created = apkLauncherCreation{}
			if err != nil || decodeAPKTransitionJSON(intentRaw, &created) != nil || created != want {
				return nil, errors.New("APK fresh launcher exclusive creation intent changed")
			}
		} else if original.Disposition != "retained-administrator" || committed.Disposition != "retained-administrator" || committed.Committed != original.Original || committed.CreationSHA256 != "" || committed.ProductDependency != original.ProductDependency {
			return nil, errors.New("APK fresh launcher receipt adopted an inherited alias")
		}
	}
	file, err := s.journal.root.Open(".")
	if err != nil {
		return nil, err
	}
	names, readErr := file.Readdirnames(65)
	if err := errors.Join(readErr, file.Close()); err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if len(names) >= 65 {
		return nil, errors.New("APK fresh launcher journal exceeds its inventory bound")
	}
	for _, name := range names {
		if !allowed[name] {
			return nil, errors.New("APK fresh launcher journal contains unknown evidence")
		}
		limit := int64(apkLauncherMaximumBytes)
		if name == "before-installed" {
			limit = maximumAPKInstalledDatabaseSize
		}
		contents, err := readAPKTransitionBytes(s.journal, name, limit)
		if err != nil {
			return nil, err
		}
		h.observed[name] = contents
	}
	h.retirement, err = readAPKTransitionBytes(s.journal, "retirement.json", 4096)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if len(h.retirement) != 0 {
		var retirement apkFreshLauncherRetirement
		if decodeAPKTransitionJSON(h.retirement, &retirement) != nil || retirement.Schema != apkFreshLauncherSchema || retirement.Purpose != "owned-launcher-retirement" || retirement.ReceiptSHA256 != h.reference.ReceiptSHA256 || !validAPKLauncherEvidence(retirement.Barrier) || retirement.Barrier.Absent || retirement.Barrier.Identity.Mode != syscall.S_IFREG|0600 || retirement.Barrier.ContentSHA256 != apkTransitionDigest([]byte(RemovalTombstoneRecord)) {
			return nil, errors.New("APK fresh launcher retirement intent is invalid")
		}
	}
	h.terminal, err = readAPKTransitionBytes(s.journal, "terminal.json", 4096)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if len(h.terminal) != 0 && (len(h.retirement) == 0 || !bytes.Equal(h.terminal, h.retirement)) {
		return nil, errors.New("APK fresh launcher terminal evidence is invalid")
	}
	if sourceOnly {
		return h, h.revalidateEvidence()
	}
	return h, h.revalidate()
}

func (h *apkLauncherLifecycleRemoval) revalidateEvidence() error {
	if h == nil || h.store == nil {
		return errors.New("APK launcher removal custody is unavailable")
	}
	if err := h.store.check(); err != nil {
		return err
	}
	current, err := readAPKTransitionBytes(h.store.directory, "current.json", 4096)
	want, _ := apkLauncherCanonical(h.currentReference)
	info, statErr := h.store.directory.root.Lstat("current.json")
	identity, identityErr := apkLauncherIdentity(info)
	if err != nil || statErr != nil || identityErr != nil || identity != h.currentIdentity || !bytes.Equal(current, want) {
		return errors.New("APK current launcher lineage changed")
	}
	if h.publication != nil {
		if err := h.store.attestPublishedLineageAt(h.publicationJournal, *h.publication); err != nil {
			return err
		}
		if err := h.attestExecutionFinalization(); err != nil {
			return err
		}
	}
	if h.execution != nil {
		return h.execution.refuseRemovalTargetDependencies()
	}
	if h.ownership != nil {
		if err := attestAPKLauncherTransferRecords(h.ownership, h.transfer); err != nil {
			return err
		}
		if err := h.transferExecution.revalidateTransferredExecutionEvidence(); err != nil {
			return err
		}
	}
	for name, want := range h.observed {
		actual, err := readAPKTransitionBytes(h.journal, name, int64(len(want))+1)
		if err != nil || !bytes.Equal(actual, want) {
			return errors.New("APK launcher ownership evidence changed")
		}
	}
	if h.ownership == nil && h.intent.PreviousSHA256 != "" {
		return h.store.verifyPreviousFreshLineage(h.journal, h.intent)
	}
	return nil
}

func (h *apkLauncherLifecycleRemoval) revalidate() error {
	if err := h.revalidateEvidence(); err != nil {
		return err
	}
	if h.execution != nil {
		return h.execution.refuseRemovalTargetDependencies()
	}
	parents, aliases, err := captureFreshAPKLauncherPaths(h.store.anchor)
	if err != nil {
		return err
	}
	for i, want := range h.receipt.Parents {
		if parents[i].Absent {
			if want.CreationSHA256 == "" || len(h.retirement) == 0 {
				return errors.New("APK launcher ancestry disappeared without owned retirement")
			}
			if _, err := h.readQuarantine(i, true); err != nil {
				return errors.New("APK launcher parent absence has no exact quarantine intent")
			}
			var retired apkFreshLauncherParent
			raw, err := readAPKTransitionBytes(h.journal, fmt.Sprintf("retire-parent-%d.json", i), 4096)
			if err != nil || decodeAPKTransitionJSON(raw, &retired) != nil || retired != want {
				return errors.New("APK launcher parent absence has no exact retirement intent")
			}
		} else if !apkLauncherSameParent(want.Identity, parents[i].Identity) {
			return errors.New("APK launcher parent identity changed")
		}
	}
	for i, want := range h.receipt.Aliases {
		if want.Disposition == "retained-administrator" {
			// A target string is not a proof of behavioral independence. An
			// opaque wrapper or indirect link can still invoke product targets.
			return errors.New("retained administrator APK launcher behavior is unresolved; preserve the alias and product targets until explicit recovery establishes independence")
		}
		actual := aliases[i].Original
		if actual.Absent && len(h.retirement) != 0 {
			if _, err := h.readQuarantine(i, false); err != nil {
				return errors.New("APK launcher absence has no exact quarantine intent")
			}
		}
		if actual != want.Committed && !(want.Disposition == "product-created" && actual.Absent && len(h.retirement) != 0) {
			return errors.New("APK launcher identity changed before removal")
		}
	}
	if err := h.revalidateQuarantines(); err != nil {
		return err
	}
	return h.store.check()
}

func (h *apkLauncherLifecycleRemoval) barrier() (apkLauncherEvidence, error) {
	_, raw, err := apkLauncherReadFile(h.store.ctx, h.store.anchor, strings.TrimPrefix(RemovalTombstonePath, "/"), 4096, syscall.S_IFREG|0600, true)
	if err != nil || string(raw) != RemovalTombstoneRecord {
		return apkLauncherEvidence{}, errors.New("APK launcher retirement requires the exact removal barrier")
	}
	entry, err := readAPKLauncherEntry(h.store.anchor, strings.TrimPrefix(RemovalTombstonePath, "/"))
	if err != nil || string(entry.Content) != RemovalTombstoneRecord {
		return apkLauncherEvidence{}, errors.New("APK launcher removal barrier changed")
	}
	return apkLauncherEntryEvidence(entry), nil
}

func (h *apkLauncherLifecycleRemoval) retire() error {
	if err := h.revalidate(); err != nil {
		return err
	}
	if h.execution != nil {
		return h.execution.RetireOwned()
	}
	if len(h.terminal) != 0 {
		return h.attestTerminal()
	}
	barrier, err := h.barrier()
	if err != nil {
		return err
	}
	if err := h.ensureTransferredRemovalJournal(); err != nil {
		return err
	}
	retirement := apkFreshLauncherRetirement{apkFreshLauncherSchema, "owned-launcher-retirement", h.reference.ReceiptSHA256, barrier}
	raw, err := apkLauncherCanonical(retirement)
	if err != nil {
		return err
	}
	if len(h.retirement) == 0 {
		h.retirement, err = h.store.publish(h.journal, "retirement.json", retirement)
		if err != nil {
			return err
		}
		h.observed["retirement.json"] = h.retirement
	} else if !bytes.Equal(raw, h.retirement) {
		return errors.New("APK launcher removal barrier differs from retained retirement")
	}
	for i, alias := range h.receipt.Aliases {
		if alias.Disposition != "product-created" {
			continue
		}
		if err := h.revalidate(); err != nil {
			return err
		}
		if _, err := h.store.anchor.Lstat(filepath.Dir(alias.Path)); errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err := h.quarantineOwned(i, false, barrier); err != nil {
			return err
		}
	}
	for i := len(h.receipt.Parents) - 1; i >= 2; i-- {
		parent := h.receipt.Parents[i]
		if parent.CreationSHA256 == "" {
			continue
		}
		if err := h.revalidate(); err != nil {
			return err
		}
		if _, err := h.store.anchor.Lstat(parent.Path); errors.Is(err, os.ErrNotExist) {
			record, err := h.readQuarantine(i, true)
			if err != nil {
				return err
			}
			if _, err := h.store.anchor.Lstat(filepath.Join(filepath.Dir(parent.Path), record.Name)); errors.Is(err, os.ErrNotExist) {
				continue
			} else if err != nil {
				return err
			}
		}
		name := fmt.Sprintf("retire-parent-%d.json", i)
		if _, err := h.journal.root.Lstat(name); errors.Is(err, os.ErrNotExist) {
			if _, err := h.store.publish(h.journal, name, parent); err != nil {
				return err
			}
		} else if err != nil {
			return err
		}
		retiredRaw, err := readAPKTransitionBytes(h.journal, name, 4096)
		var retired apkFreshLauncherParent
		if err != nil || decodeAPKTransitionJSON(retiredRaw, &retired) != nil || retired != parent {
			return errors.New("APK created parent retirement evidence changed")
		}
		h.observed[name] = retiredRaw
		if err := h.quarantineOwned(i, true, barrier); err != nil {
			return err
		}
	}
	if err := h.attestRetiredAliases(); err != nil {
		return err
	}
	h.terminal, err = h.store.publish(h.journal, "terminal.json", retirement)
	if err == nil {
		h.observed["terminal.json"] = h.terminal
	}
	return err
}

func (h *apkLauncherLifecycleRemoval) attestRetiredAliases() error {
	if err := h.revalidate(); err != nil {
		return err
	}
	for i, alias := range h.receipt.Aliases {
		if alias.Disposition == "product-created" {
			record, err := h.readQuarantine(i, false)
			if err != nil {
				return err
			}
			if _, err := h.store.anchor.Lstat(filepath.Join(filepath.Dir(alias.Path), record.Name)); !errors.Is(err, os.ErrNotExist) {
				return errors.New("APK launcher quarantine remains unresolved")
			}
			entry, err := readAPKLauncherEntry(h.store.anchor, alias.Path)
			if err != nil || !entry.Absent {
				return errors.New("APK receipt-created launcher remains")
			}
		}
	}
	for i, parent := range h.receipt.Parents {
		if parent.CreationSHA256 == "" {
			continue
		}
		record, err := h.readQuarantine(i, true)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		if _, err := h.store.anchor.Lstat(filepath.Join(filepath.Dir(parent.Path), record.Name)); !errors.Is(err, os.ErrNotExist) {
			return errors.New("APK launcher parent quarantine remains unresolved")
		}
	}
	return nil
}

func (h *apkLauncherLifecycleRemoval) attestTerminal() error {
	if h.execution != nil {
		return h.execution.AttestTerminal()
	}
	if len(h.terminal) == 0 {
		return errors.New("APK launcher removal is not terminal")
	}
	return h.attestRetiredAliases()
}

type apkFreshLauncherQuarantine struct {
	Schema        string                `json:"schema"`
	Purpose       string                `json:"purpose"`
	ReceiptSHA256 string                `json:"receipt_sha256"`
	Path          string                `json:"path"`
	Name          string                `json:"name"`
	Directory     bool                  `json:"directory"`
	Identity      apkTransitionIdentity `json:"identity"`
	LinkTarget    string                `json:"link_target,omitempty"`
}

func apkFreshQuarantineRecordName(index int, directory bool) string {
	if directory {
		return fmt.Sprintf("quarantine-parent-%d.json", index)
	}
	return fmt.Sprintf("retire-alias-%d.json", index)
}

func (h *apkLauncherLifecycleRemoval) readQuarantine(index int, directory bool) (apkFreshLauncherQuarantine, error) {
	var record apkFreshLauncherQuarantine
	if h.journal == nil {
		return record, os.ErrNotExist
	}
	raw, err := readAPKTransitionBytes(h.journal, apkFreshQuarantineRecordName(index, directory), 4096)
	if err != nil {
		return record, err
	}
	if decodeAPKTransitionJSON(raw, &record) != nil || record.Schema != apkFreshLauncherSchema || record.Purpose != "owned-entry-quarantine" || record.ReceiptSHA256 != h.reference.ReceiptSHA256 || record.Directory != directory || !strings.HasPrefix(record.Name, ".syswarden-apk-retire-") || len(record.Name) != len(".syswarden-apk-retire-")+32 || !safeAssetName(record.Name) {
		return record, errors.New("APK launcher quarantine intent is invalid")
	}
	if directory {
		if index < 2 || index >= len(h.receipt.Parents) || record.Path != h.receipt.Parents[index].Path || record.Identity != h.receipt.Parents[index].Identity || record.LinkTarget != "" || h.receipt.Parents[index].CreationSHA256 == "" {
			return record, errors.New("APK launcher quarantine adopted a shared parent")
		}
	} else if index < 0 || index >= len(h.receipt.Aliases) || record.Path != h.receipt.Aliases[index].Path || record.Identity != h.receipt.Aliases[index].Committed.Identity || record.LinkTarget != h.receipt.Aliases[index].Committed.LinkTarget || h.receipt.Aliases[index].Disposition != "product-created" {
		return record, errors.New("APK launcher quarantine adopted an administrator alias")
	}
	return record, nil
}

func (h *apkLauncherLifecycleRemoval) pinRemovalParent(index int, directory bool) (*pinnedServiceDirectory, error) {
	parentIndex := 3
	if directory {
		parentIndex = index - 1
	}
	want := h.receipt.Parents[parentIndex]
	// Pin every ancestor independently. OpenRoot alone permits an intermediate
	// symlink within its root, so named and opened parents must also match.
	for i := 0; i <= parentIndex; i++ {
		info, err := h.store.anchor.Lstat(h.receipt.Parents[i].Path)
		identity, identityErr := apkLauncherIdentity(info)
		if err != nil || identityErr != nil || !apkLauncherSameParent(h.receipt.Parents[i].Identity, identity) {
			return nil, errors.New("APK launcher quarantine ancestry changed")
		}
	}
	parent, err := openExistingPinnedServiceDirectory(filepath.Join(h.store.host, want.Path))
	if err != nil {
		return nil, err
	}
	info, err := parent.file.Stat()
	identity, identityErr := apkLauncherIdentity(info)
	if err != nil || identityErr != nil || !apkLauncherSameParent(want.Identity, identity) {
		parent.close()
		return nil, errors.New("APK launcher quarantine parent changed while pinning")
	}
	return parent, nil
}

func (h *apkLauncherLifecycleRemoval) checkRemovalParent(parent *pinnedServiceDirectory, index int, directory bool) error {
	parentIndex := 3
	if directory {
		parentIndex = index - 1
	}
	for i := 0; i <= parentIndex; i++ {
		info, err := h.store.anchor.Lstat(h.receipt.Parents[i].Path)
		identity, identityErr := apkLauncherIdentity(info)
		if err != nil || identityErr != nil || !apkLauncherSameParent(h.receipt.Parents[i].Identity, identity) {
			return errors.New("APK launcher quarantine ancestry changed")
		}
	}
	info, err := parent.file.Stat()
	identity, identityErr := apkLauncherIdentity(info)
	if err != nil || identityErr != nil || !apkLauncherSameParent(h.receipt.Parents[parentIndex].Identity, identity) {
		return errors.New("APK launcher quarantine pinned parent changed")
	}
	return h.revalidateEvidence()
}

func attestAPKFreshQuarantine(parent *pinnedServiceDirectory, name string, record apkFreshLauncherQuarantine, moved bool) error {
	if record.Directory {
		info, err := parent.root.Lstat(name)
		identity, identityErr := apkLauncherIdentity(info)
		if err != nil || identityErr != nil || !apkLauncherSameParent(record.Identity, identity) {
			return errors.New("APK receipt-created directory identity changed")
		}
		root, err := parent.root.OpenRoot(name)
		if err != nil {
			return err
		}
		defer func() { _ = root.Close() }()
		opened, err := root.Stat(".")
		if err != nil || !os.SameFile(info, opened) {
			return errors.New("APK receipt-created directory changed while pinning")
		}
		file, err := root.Open(".")
		if err != nil {
			return err
		}
		names, readErr := file.Readdirnames(1)
		closeErr := file.Close()
		if len(names) != 0 {
			return unix.ENOTEMPTY
		}
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return readErr
		}
		return closeErr
	}
	entry, err := readAPKLauncherEntry(parent.root, name)
	if err != nil || entry.Absent || entry.LinkTarget != record.LinkTarget || len(entry.Content) != 0 || (!moved && entry.Identity != record.Identity) || (moved && !sameAPKLauncherMovedIdentity(record.Identity, entry.Identity)) {
		return errors.New("APK receipt-created launcher changed at quarantine boundary")
	}
	return nil
}

func (h *apkLauncherLifecycleRemoval) quarantineOwned(index int, directory bool, barrier apkLauncherEvidence) error {
	parent, err := h.pinRemovalParent(index, directory)
	if err != nil {
		return err
	}
	defer parent.close()
	var path string
	var identity apkTransitionIdentity
	var target string
	if directory {
		path, identity = h.receipt.Parents[index].Path, h.receipt.Parents[index].Identity
	} else {
		path, identity, target = h.receipt.Aliases[index].Path, h.receipt.Aliases[index].Committed.Identity, h.receipt.Aliases[index].Committed.LinkTarget
	}
	record, err := h.readQuarantine(index, directory)
	if errors.Is(err, os.ErrNotExist) {
		name, err := randomServiceArtifactName(".syswarden-apk-retire-")
		if err != nil {
			return err
		}
		record = apkFreshLauncherQuarantine{apkFreshLauncherSchema, "owned-entry-quarantine", h.reference.ReceiptSHA256, path, name, directory, identity, target}
		if err := attestAPKFreshQuarantine(parent, filepath.Base(path), record, false); err != nil {
			if directory && errors.Is(err, unix.ENOTEMPTY) {
				return nil
			}
			return err
		}
		raw, err := h.store.publish(h.journal, apkFreshQuarantineRecordName(index, directory), record)
		if err != nil {
			return err
		}
		h.observed[apkFreshQuarantineRecordName(index, directory)] = raw
	} else if err != nil {
		return err
	}
	name := filepath.Base(path)
	_, quarantineErr := parent.root.Lstat(record.Name)
	_, namedErr := parent.root.Lstat(name)
	if errors.Is(quarantineErr, os.ErrNotExist) && errors.Is(namedErr, os.ErrNotExist) {
		return nil
	}
	if quarantineErr != nil && !errors.Is(quarantineErr, os.ErrNotExist) {
		return quarantineErr
	}
	if errors.Is(quarantineErr, os.ErrNotExist) {
		if err := attestAPKFreshQuarantine(parent, name, record, false); err != nil {
			if directory && errors.Is(err, unix.ENOTEMPTY) {
				return nil
			}
			return err
		}
		if err := h.checkRemovalParent(parent, index, directory); err != nil {
			return err
		}
		if observed, err := h.barrier(); err != nil || observed != barrier {
			return errors.New("APK removal barrier changed before quarantine")
		}
		if h.store.fault != nil {
			if err := h.store.fault("before-quarantine-" + path); err != nil {
				return err
			}
		}
		if err := unix.Renameat2(parent.fd, name, parent.fd, record.Name, unix.RENAME_NOREPLACE); err != nil {
			return err
		}
		if err := parent.sync(); err != nil {
			return err
		}
		if h.store.fault != nil {
			if err := h.store.fault("after-quarantine-" + path); err != nil {
				return err
			}
		}
	} else if namedErr == nil {
		return fmt.Errorf("APK launcher quarantine conflicts with a live entry; preserve %s for recovery", record.Name)
	}
	attestErr := attestAPKFreshQuarantine(parent, record.Name, record, true)
	ancestryErr := h.checkRemovalParent(parent, index, directory)
	observed, barrierErr := h.barrier()
	if attestErr != nil || ancestryErr != nil || barrierErr != nil || observed != barrier {
		// Restoration never overwrites a newly created administrator entry.
		restoreErr := unix.Renameat2(parent.fd, record.Name, parent.fd, name, unix.RENAME_NOREPLACE)
		syncErr := parent.sync()
		return errors.Join(fmt.Errorf("APK launcher quarantine changed; preserve %s and its retirement record for recovery", record.Name), attestErr, ancestryErr, barrierErr, restoreErr, syncErr)
	}
	flags := 0
	if directory {
		flags = unix.AT_REMOVEDIR
	}
	if err := unix.Unlinkat(parent.fd, record.Name, flags); err != nil {
		restoreErr := unix.Renameat2(parent.fd, record.Name, parent.fd, name, unix.RENAME_NOREPLACE)
		return errors.Join(err, restoreErr, parent.sync())
	}
	if err := parent.sync(); err != nil {
		return err
	}
	if h.store.fault != nil {
		if err := h.store.fault("after-retire-" + path); err != nil {
			return err
		}
	}
	return h.checkRemovalParent(parent, index, directory)
}

func (h *apkLauncherLifecycleRemoval) revalidateQuarantines() error {
	for _, directory := range []bool{false, true} {
		start, end := 0, len(h.receipt.Aliases)
		if directory {
			start, end = 2, len(h.receipt.Parents)
		}
		for i := start; i < end; i++ {
			record, err := h.readQuarantine(i, directory)
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil {
				return err
			}
			if len(h.retirement) == 0 {
				return errors.New("APK launcher quarantine has no retirement authority")
			}
			path := filepath.Join(filepath.Dir(record.Path), record.Name)
			if _, err := h.store.anchor.Lstat(path); errors.Is(err, os.ErrNotExist) {
				continue
			} else if err != nil {
				return err
			}
			if len(h.terminal) != 0 {
				return errors.New("APK terminal launcher lineage retains unresolved quarantine")
			}
			if _, err := h.store.anchor.Lstat(record.Path); !errors.Is(err, os.ErrNotExist) {
				return errors.New("APK launcher quarantine conflicts with a live replacement")
			}
			parent, err := h.pinRemovalParent(i, directory)
			if err != nil {
				return err
			}
			err = attestAPKFreshQuarantine(parent, record.Name, record, true)
			parent.close()
			if err != nil {
				return fmt.Errorf("APK launcher quarantine %s requires bounded recovery: %w", record.Name, err)
			}
		}
	}
	return nil
}

type apkLauncherFinalizationRecord struct {
	Identity apkTransitionIdentity
	SHA256   string
}

// A published launcher reference precedes gate retirement. Removal requires
// independent terminal finalization and absence of every recorded gate object.
func (h *apkLauncherLifecycleRemoval) attestExecutionFinalization() error {
	return h.attestExecutionFinalizationForSuccessor("")
}

// Historical evidence may coexist only with the exact separately approved
// successor dispatcher. Its own quarantine and unresolved debt must be absent.
func (h *apkLauncherLifecycleRemoval) attestExecutionFinalizationForSuccessor(successor string) (result error) {
	if successor != "" && !validSHA256(successor) {
		return errors.New("APK finalization successor binding is invalid")
	}
	if h == nil || h.store == nil {
		return errors.New("APK execution finalization custody is unavailable")
	}
	reference := h.currentReference
	if reference.Kind == "" {
		reference = h.reference
	}
	if reference.Kind != "execution" {
		return errors.New("APK execution finalization custody is unavailable")
	}
	s := h.store
	base := strings.TrimPrefix(apkTransitionRoot, "/")
	path := filepath.Join(base, "execution-"+reference.PlanSHA256)
	for _, name := range []string{base, path} {
		if err := s.pin(name); err != nil {
			return err
		}
	}
	directory, err := openExistingPinnedServiceDirectory(filepath.Join(s.host, path))
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, closeAPKExecutionDirectory(directory)) }()
	info, err := directory.file.Stat()
	if err != nil || info.Mode() != os.ModeDir|0700 {
		return errors.New("APK execution finalization journal is not private")
	}
	for _, name := range []string{"unresolved.json", "pre-dispatch-refused.json", "terminal-unresolved.json", "terminal-closed.pending"} {
		if _, err := directory.root.Lstat(name); !errors.Is(err, os.ErrNotExist) {
			return errors.New("APK execution launcher removal refuses unresolved terminal debt")
		}
	}
	observed := make(map[string]apkLauncherFinalizationRecord)
	read := func(name string, limit int64) ([]byte, error) {
		raw, err := readAPKTransitionBytes(directory, name, limit)
		if err != nil {
			return nil, err
		}
		info, err := directory.root.Lstat(name)
		identity, identityErr := apkLauncherIdentity(info)
		if err != nil || identityErr != nil {
			return nil, errors.New("APK execution finalization evidence changed")
		}
		observed[name] = apkLauncherFinalizationRecord{identity, apkTransitionDigest(raw)}
		if h.finalization != nil && h.finalization[name] != observed[name] {
			return nil, errors.New("APK execution finalization evidence identity changed")
		}
		return raw, nil
	}
	finalized, err := read("terminal-finalized.json", 4096)
	if err != nil {
		return errors.New("APK execution launcher lineage is not terminally finalized")
	}
	retirement, err := read("terminal-retirement-intent.json", 4096)
	if err != nil || !bytes.Equal(finalized, retirement) {
		return errors.New("APK execution finalization differs from its retirement intent")
	}
	finalizing, err := read("terminal-finalizing.json", 4096)
	if err != nil || !bytes.Equal(finalized, finalizing) {
		return errors.New("APK execution finalization lacks its exact resource retirement boundary")
	}
	handoffRaw, err := read("native-handoff.json", 16384)
	var handoff apkNativeHandoffRecord
	if err != nil || decodeAPKTransitionJSON(handoffRaw, &handoff) != nil || handoff.Schema != apkNativeHandoffSchema || handoff.PlanSHA256 != reference.PlanSHA256 {
		return errors.New("APK execution finalization handoff is invalid")
	}
	custodyRaw, err := read("launcher-custody.json", apkLauncherMaximumBytes)
	var custody apkLauncherReceipt
	if err != nil || apkTransitionDigest(custodyRaw) != reference.ReceiptSHA256 || decodeAPKTransitionJSON(custodyRaw, &custody) != nil || custody.Binding.PlanSHA256 != reference.PlanSHA256 {
		return errors.New("APK finalized execution launcher custody changed")
	}
	planRaw, err := read("execution-plan.json", apkLauncherMaximumBytes)
	if err != nil || apkTransitionDigest(planRaw) != reference.PlanSHA256 {
		return errors.New("APK finalized execution plan changed")
	}
	approvalRaw, err := read("execution-approval.json", 4096)
	if err != nil || apkTransitionDigest(approvalRaw) != handoff.ApprovalSHA256 {
		return errors.New("APK finalized execution approval changed")
	}
	preparedRaw, err := read("launcher-prepared.json", apkLauncherMaximumBytes)
	if err != nil || apkTransitionDigest(preparedRaw) != custody.PreparedSHA256 {
		return errors.New("APK finalized original launcher custody changed")
	}
	want, err := apkExecutionJSON(struct {
		Schema                string `json:"schema"`
		PlanSHA256            string `json:"plan_sha256"`
		HandoffSHA256         string `json:"handoff_sha256"`
		LauncherReceiptSHA256 string `json:"launcher_receipt_sha256"`
	}{apkExecutionSchema, reference.PlanSHA256, apkTransitionDigest(handoffRaw), reference.ReceiptSHA256})
	if err != nil || !bytes.Equal(finalized, want) {
		return errors.New("APK execution terminal receipt does not bind the current launcher lineage")
	}
	closed, err := read("terminal-closed.json", 4096)
	wantClosed, canonicalErr := apkExecutionJSON(apkTerminalClosureRecord{apkExecutionSchema, reference.PlanSHA256, apkTransitionDigest(handoffRaw), reference.ReceiptSHA256, apkTransitionDigest(finalized)})
	if err != nil || canonicalErr != nil || !bytes.Equal(closed, wantClosed) {
		return errors.New("APK execution launcher removal requires exact successful terminal resource closure")
	}
	body, err := apkTransitionGateBytes(reference.PlanSHA256)
	if err != nil {
		return err
	}
	for _, item := range []struct {
		parent, name, record string
		original             apkTransitionHostEntry
		mode                 uint32
	}{
		{base, "active-hook", "terminal-retire-dispatcher.json", handoff.Active, syscall.S_IFREG | 0700},
		{apkTransitionGateDirectory, apkTransitionGateName, "terminal-retire-gate.json", handoff.Hook, syscall.S_IFREG | 0755},
	} {
		if item.original.Path != item.name || item.original.Absent || item.original.Identity.Mode != item.mode || item.original.Identity.Links != 1 || item.original.LinkTarget != "" || !bytes.Equal(item.original.Content, body) {
			return errors.New("APK execution terminal gate differs from the compiled dispatcher")
		}
		raw, err := read(item.record, 16384)
		var record apkTerminalGateRetirement
		if err != nil || decodeAPKTransitionJSON(raw, &record) != nil || record.Schema != apkExecutionSchema || record.Name != item.name || !reflect.DeepEqual(record.Original, item.original) || !safeAssetName(record.Quarantine) || !strings.HasPrefix(record.Quarantine, ".syswarden-apk-retired-") || len(record.Quarantine) != len(".syswarden-apk-retired-")+32 {
			return errors.New("APK execution terminal gate quarantine proof is invalid")
		}
		canonical, err := apkExecutionJSON(record)
		if err != nil || !bytes.Equal(raw, canonical) {
			return errors.New("APK execution terminal gate quarantine proof is not canonical")
		}
		parentPath := ""
		for _, component := range strings.Split(item.parent, "/") {
			parentPath = filepath.Join(parentPath, component)
			if err := s.pin(parentPath); err != nil {
				return err
			}
		}
		parent, err := s.anchor.OpenRoot(item.parent)
		if err != nil {
			return err
		}
		info, statErr := parent.Stat(".")
		identity, identityErr := apkLauncherIdentity(info)
		if statErr != nil || identityErr != nil || !apkLauncherSameParent(record.Parent, identity) {
			return errors.Join(errors.New("APK execution terminal gate ancestry changed"), parent.Close())
		}
		_, namedErr := parent.Lstat(item.name)
		namedSafe := errors.Is(namedErr, os.ErrNotExist)
		if namedErr == nil && successor != "" && successor != reference.PlanSHA256 {
			entry, readErr := readAPKNativeHookMode(parent, item.name, os.FileMode(item.mode&0777))
			body, bodyErr := apkTransitionGateBytes(successor)
			namedSafe = readErr == nil && bodyErr == nil && !entry.Absent && entry.LinkTarget == "" && bytes.Equal(entry.Content, body)
		}
		_, quarantineErr := parent.Lstat(record.Quarantine)
		closeErr := parent.Close()
		if !namedSafe || !errors.Is(quarantineErr, os.ErrNotExist) || closeErr != nil {
			return errors.Join(errors.New("APK execution launcher removal refuses retained gate or quarantine debt"), closeErr)
		}
	}
	if err := s.check(); err != nil {
		return err
	}
	h.finalization = observed
	return nil
}
