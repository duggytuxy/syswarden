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

	"golang.org/x/sys/unix"
)

const apkLauncherLifecycleRoot = "/var/backups/syswarden-apk-launchers-v1"
const apkFreshLauncherSchema = "syswarden-apk-fresh-launchers/v1"

type apkFreshLauncherParent struct {
	Path           string                `json:"path"`
	Absent         bool                  `json:"absent"`
	Identity       apkTransitionIdentity `json:"identity"`
	CreationSHA256 string                `json:"creation_sha256,omitempty"`
}

type apkFreshLauncherIntent struct {
	Schema                 string                    `json:"schema"`
	Purpose                string                    `json:"purpose"`
	PreviousSHA256         string                    `json:"previous_sha256,omitempty"`
	PreviousIdentity       *apkTransitionIdentity    `json:"previous_identity,omitempty"`
	PreviousTerminalSHA256 string                    `json:"previous_terminal_sha256,omitempty"`
	DatabaseSHA256         string                    `json:"database_sha256"`
	Payload                []apkLauncherPayloadFile  `json:"payload"`
	Parents                [4]apkFreshLauncherParent `json:"parents"`
	Aliases                [2]apkLauncherEntry       `json:"aliases"`
}

type apkFreshLauncherReceipt struct {
	Schema       string                    `json:"schema"`
	Purpose      string                    `json:"purpose"`
	IntentSHA256 string                    `json:"intent_sha256"`
	Native       apkLauncherNativeRecord   `json:"native"`
	Parents      [4]apkFreshLauncherParent `json:"parents"`
	Aliases      [2]apkLauncherEntry       `json:"aliases"`
}

type apkLauncherLifecycleReference struct {
	Schema        string `json:"schema"`
	Kind          string `json:"kind"`
	PlanSHA256    string `json:"plan_sha256"`
	ReceiptSHA256 string `json:"receipt_sha256"`
}

type apkFreshLauncherRetirement struct {
	Schema        string              `json:"schema"`
	Purpose       string              `json:"purpose"`
	ReceiptSHA256 string              `json:"receipt_sha256"`
	Barrier       apkLauncherEvidence `json:"barrier"`
}

type apkLauncherLifecycleStore struct {
	ctx         context.Context
	host        string
	anchor      *os.Root
	directory   *pinnedServiceDirectory
	journal     *pinnedServiceDirectory
	journalPath string
	parents     []apkLauncherPinnedParent
	fault       func(string) error
}

func openAPKLauncherLifecycleAnchor(ctx context.Context, host string) (*os.Root, error) {
	if ctx == nil || ctx.Err() != nil || !filepath.IsAbs(host) || filepath.Clean(host) != host {
		return nil, errors.New("APK launcher lifecycle context is invalid")
	}
	before, err := os.Lstat(host)
	if err != nil || !before.IsDir() || before.Mode()&os.ModeSymlink != 0 || !serviceFileOwnedByCurrentUser(before) || before.Mode().Perm()&0022 != 0 {
		return nil, errors.New("APK launcher lifecycle root is unsafe")
	}
	root, err := os.OpenRoot(host)
	if err != nil {
		return nil, err
	}
	opened, err := root.Stat(".")
	if err != nil || !os.SameFile(before, opened) {
		return nil, errors.Join(errors.New("APK launcher lifecycle root changed"), root.Close())
	}
	return root, nil
}

func (s *apkLauncherLifecycleStore) close() error {
	if s == nil {
		return nil
	}
	var failures []error
	if s.journal != nil {
		failures = append(failures, s.journal.file.Close(), s.journal.root.Close())
	}
	if s.directory != nil {
		failures = append(failures, s.directory.file.Close(), s.directory.root.Close())
	}
	for i := len(s.parents) - 1; i >= 0; i-- {
		failures = append(failures, s.parents[i].root.Close())
	}
	if s.anchor != nil {
		failures = append(failures, s.anchor.Close())
	}
	return errors.Join(failures...)
}

func (s *apkLauncherLifecycleStore) pin(path string) error {
	for _, parent := range s.parents {
		if parent.path == path {
			return s.check()
		}
	}
	before, err := s.anchor.Lstat(path)
	identity, identityErr := apkLauncherIdentity(before)
	if err != nil || identityErr != nil || !before.IsDir() || before.Mode()&os.ModeSymlink != 0 || !serviceFileOwnedByCurrentUser(before) || before.Mode().Perm()&0022 != 0 {
		return errors.New("APK launcher lifecycle ancestry is unsafe")
	}
	root, err := s.anchor.OpenRoot(path)
	if err != nil {
		return err
	}
	opened, err := root.Stat(".")
	if err != nil || !os.SameFile(before, opened) {
		return errors.Join(errors.New("APK launcher lifecycle ancestry changed"), root.Close())
	}
	s.parents = append(s.parents, apkLauncherPinnedParent{path, identity, root})
	return s.check()
}

func (s *apkLauncherLifecycleStore) check() error {
	if s == nil || s.ctx == nil || s.anchor == nil {
		return errors.New("APK launcher lifecycle custody is unavailable")
	}
	if err := s.ctx.Err(); err != nil {
		return err
	}
	namedHost, hostErr := os.Lstat(s.host)
	openedHost, openHostErr := s.anchor.Stat(".")
	if hostErr != nil || openHostErr != nil || !os.SameFile(namedHost, openedHost) || namedHost.Mode()&os.ModeSymlink != 0 {
		return errors.New("APK launcher lifecycle host root changed")
	}
	for _, pinned := range []struct {
		directory *pinnedServiceDirectory
		path      string
	}{{s.directory, strings.TrimPrefix(apkLauncherLifecycleRoot, "/")}, {s.journal, s.journalPath}} {
		if pinned.directory == nil {
			continue
		}
		named, namedErr := s.anchor.Lstat(pinned.path)
		opened, openedErr := pinned.directory.root.Stat(".")
		file, fileErr := pinned.directory.file.Stat()
		if namedErr != nil || openedErr != nil || fileErr != nil || !os.SameFile(named, opened) || !os.SameFile(opened, file) || named.Mode() != os.ModeDir|0700 {
			return errors.New("APK launcher lifecycle evidence directory changed")
		}
	}
	for _, parent := range s.parents {
		named, err := s.anchor.Lstat(parent.path)
		actual, identityErr := apkLauncherIdentity(named)
		opened, openErr := parent.root.Stat(".")
		pinned, pinnedErr := apkLauncherIdentity(opened)
		if err != nil || identityErr != nil || openErr != nil || pinnedErr != nil || !apkLauncherSameParent(parent.identity, actual) || !apkLauncherSameParent(parent.identity, pinned) {
			return errors.New("APK launcher lifecycle pinned ancestry changed")
		}
	}
	return nil
}

func openAPKLauncherLifecycleStore(ctx context.Context, host string, create bool) (*apkLauncherLifecycleStore, error) {
	return openAPKLauncherLifecycleStoreMode(ctx, host, create, true)
}

func openAPKLauncherLifecycleReadOnlyStore(ctx context.Context, host string) (*apkLauncherLifecycleStore, error) {
	return openAPKLauncherLifecycleStoreMode(ctx, host, false, false)
}

func openAPKLauncherLifecycleStoreMode(ctx context.Context, host string, create, lock bool) (_ *apkLauncherLifecycleStore, result error) {
	anchor, err := openAPKLauncherLifecycleAnchor(ctx, host)
	if err != nil {
		return nil, err
	}
	s := &apkLauncherLifecycleStore{ctx: ctx, host: host, anchor: anchor}
	defer func() {
		if result != nil {
			result = errors.Join(result, s.close())
		}
	}()
	for _, path := range []string{".", "var"} {
		if err := s.pin(path); err != nil {
			return nil, err
		}
	}
	base := strings.TrimPrefix(apkLauncherLifecycleRoot, "/")
	for _, path := range []string{"var/backups", base} {
		if _, err := anchor.Lstat(path); errors.Is(err, os.ErrNotExist) && create {
			parent := s.parents[len(s.parents)-1].root
			if err := parent.Mkdir(filepath.Base(path), 0700); err != nil {
				return nil, err
			}
			file, err := parent.Open(".")
			if err != nil {
				return nil, err
			}
			if err := errors.Join(file.Sync(), file.Close()); err != nil {
				return nil, err
			}
		} else if err != nil {
			return nil, err
		}
		if err := s.pin(path); err != nil {
			return nil, err
		}
	}
	directory, err := openExistingPinnedServiceDirectory(filepath.Join(host, base))
	if err != nil {
		return nil, err
	}
	s.directory = directory
	info, err := directory.file.Stat()
	if err != nil || info.Mode() != os.ModeDir|0700 {
		return nil, errors.New("APK launcher lifecycle evidence is not private")
	}
	if lock {
		if err := unix.Flock(directory.fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
			return nil, errors.New("APK launcher lifecycle evidence is busy")
		}
	}
	return s, s.check()
}

func (s *apkLauncherLifecycleStore) openJournal(digest string, create bool) error {
	return s.openNamedJournal("fresh-", digest, create)
}

func (s *apkLauncherLifecycleStore) openNamedJournal(prefix, digest string, create bool) error {
	if !validSHA256(digest) || s.journal != nil || (prefix != "fresh-" && prefix != "transfer-removal-") {
		return errors.New("APK launcher journal reference is invalid")
	}
	name := prefix + digest
	if create {
		if err := s.directory.root.Mkdir(name, 0700); err != nil {
			return err
		}
		if err := s.directory.sync(); err != nil {
			return err
		}
	}
	path := filepath.Join(strings.TrimPrefix(apkLauncherLifecycleRoot, "/"), name)
	if err := s.pin(path); err != nil {
		return err
	}
	directory, err := openExistingPinnedServiceDirectory(filepath.Join(s.host, path))
	if err != nil {
		return err
	}
	s.journal = directory
	s.journalPath = path
	info, err := directory.file.Stat()
	if err != nil || info.Mode() != os.ModeDir|0700 {
		return errors.New("APK fresh launcher journal is not private")
	}
	return s.check()
}

func (s *apkLauncherLifecycleStore) publish(directory *pinnedServiceDirectory, name string, value any) ([]byte, error) {
	if err := s.check(); err != nil {
		return nil, err
	}
	raw, err := apkLauncherCanonical(value)
	if err != nil {
		return nil, err
	}
	if s.fault != nil {
		if err := s.fault("before-" + name); err != nil {
			return nil, err
		}
	}
	if err := writeAPKTransitionBytes(directory, name, raw); err != nil {
		return nil, err
	}
	if s.fault != nil {
		if err := s.fault("after-" + name); err != nil {
			return nil, err
		}
	}
	actual, err := readAPKTransitionBytes(directory, name, apkLauncherMaximumBytes)
	if err != nil || !bytes.Equal(actual, raw) {
		return nil, errors.New("APK launcher lifecycle publication is uncertain")
	}
	return raw, s.check()
}

func captureFreshAPKLauncherPaths(root *os.Root) ([4]apkFreshLauncherParent, [2]apkLauncherEntry, error) {
	var parents [4]apkFreshLauncherParent
	var aliases [2]apkLauncherEntry
	missing := false
	for i, path := range apkLauncherParents {
		info, err := root.Lstat(path)
		if errors.Is(err, os.ErrNotExist) && i >= 2 {
			parents[i] = apkFreshLauncherParent{Path: path, Absent: true}
			missing = true
			continue
		}
		identity, identityErr := apkLauncherIdentity(info)
		if err != nil || identityErr != nil || missing || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || !serviceFileOwnedByCurrentUser(info) || info.Mode().Perm()&0022 != 0 {
			return parents, aliases, errors.New("fresh APK launcher ancestry is unsafe")
		}
		parents[i] = apkFreshLauncherParent{Path: path, Identity: identity}
	}
	for i, path := range apkLauncherPaths {
		entry, err := readAPKLauncherEntry(root, path)
		if err != nil {
			return parents, aliases, err
		}
		evidence := apkLauncherEntryEvidence(entry)
		disposition := "retained-administrator"
		if evidence.Absent {
			disposition = "absent"
		}
		aliases[i] = apkLauncherEntry{Path: path, Disposition: disposition, Original: evidence, Committed: evidence, ProductDependency: apkLauncherProductDependency(path, evidence.LinkTarget)}
	}
	return parents, aliases, nil
}

func sameFreshAPKParents(want, actual [4]apkFreshLauncherParent) bool {
	for i := range want {
		if want[i].Path != actual[i].Path || want[i].Absent != actual[i].Absent || !want[i].Absent && !apkLauncherSameParent(want[i].Identity, actual[i].Identity) {
			return false
		}
	}
	return true
}

// StageFreshAPKLaunchers writes intent only. The actual native installed
// database must still have no product owner, and no launcher is created here.
// A caller's environment or a package-version string grants no ownership.
func StageFreshAPKLaunchers(ctx context.Context) error {
	if os.Geteuid() != 0 {
		return errors.New("fresh APK launcher staging requires root")
	}
	return stageFreshAPKLaunchersAt(ctx, "/")
}

// PreflightAPKLauncherTransition prevents an upgrade from consuming a pending
// fresh post-commit intent. It grants no install, alias or execution authority.
func PreflightAPKLauncherTransition(ctx context.Context) (result error) {
	if os.Geteuid() != 0 {
		return errors.New("APK launcher transition preflight requires root")
	}
	s, err := openAPKLauncherLifecycleStore(ctx, "/", false)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, s.close()) }()
	if _, err := s.directory.root.Lstat("pending.json"); !errors.Is(err, os.ErrNotExist) {
		return errors.New("APK transition refuses unresolved fresh launcher intent")
	}
	return s.check()
}

func stageFreshAPKLaunchersAt(ctx context.Context, host string) (result error) {
	root, err := openAPKLauncherLifecycleAnchor(ctx, host)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, root.Close()) }()
	database, raw, err := apkLauncherReadFile(ctx, root, "lib/apk/db/installed", maximumAPKInstalledDatabaseSize, 0, true)
	if err != nil {
		return err
	}
	records, err := parseAPKLauncherRegistrations(raw)
	if err != nil {
		return err
	}
	for name := range records {
		if validNativeProductPackageName(name) {
			return errors.New("fresh APK launcher staging refuses an already installed product")
		}
	}
	files, err := captureAPKLauncherPayload(ctx, root)
	if err != nil {
		return err
	}
	parents, aliases, err := captureFreshAPKLauncherPaths(root)
	if err != nil {
		return err
	}
	for _, record := range records {
		for i, path := range apkLauncherPaths {
			if _, owned := record.entries[path]; owned && aliases[i].Original.Absent {
				return errors.New("fresh APK launcher creation would occupy another package's registered path")
			}
		}
	}
	s, err := openAPKLauncherLifecycleStore(ctx, host, true)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, s.close()) }()
	if _, err := s.directory.root.Lstat("pending.json"); !errors.Is(err, os.ErrNotExist) {
		return errors.New("fresh APK launcher staging requires recovery of existing pending intent")
	}
	var previous []byte
	if previous, err = readAPKTransitionBytes(s.directory, "current.json", 4096); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	intent := apkFreshLauncherIntent{Schema: apkFreshLauncherSchema, Purpose: "fresh-intent-no-alias-mutation", DatabaseSHA256: database.SHA256, Payload: files, Parents: parents, Aliases: aliases}
	var predecessor *apkLauncherLifecycleRemoval
	if len(previous) != 0 {
		predecessor, err = inspectAPKLauncherLifecycleRemovalStore(s, false)
		if err != nil {
			return err
		}
		if predecessor.execution != nil {
			return errors.Join(errors.New("fresh APK reinstall requires supported terminal fresh lineage"), predecessor.execution.Close())
		}
		if err := predecessor.attestTerminal(); err != nil {
			return err
		}
		if err := s.verifyPreviousFreshLineageBound(predecessor.journal, predecessor.intent, 31); err != nil {
			return err
		}
		intent.PreviousSHA256 = apkTransitionDigest(previous)
		identity := predecessor.currentIdentity
		intent.PreviousIdentity = &identity
		intent.PreviousTerminalSHA256 = apkTransitionDigest(predecessor.terminal)
		priorJournal := s.journal
		defer priorJournal.close()
		s.journal = nil
	}
	intentRaw, err := apkLauncherCanonical(intent)
	if err != nil {
		return err
	}
	digest := apkTransitionDigest(intentRaw)
	if err := s.openJournal(digest, true); err != nil {
		return err
	}
	if len(previous) != 0 {
		if err := writeAPKTransitionBytes(s.journal, "previous-current.json", previous); err != nil {
			return err
		}
	}
	if err := writeAPKTransitionBytes(s.journal, "before-installed", raw); err != nil {
		return err
	}
	if _, err := s.publish(s.journal, "intent.json", intent); err != nil {
		return err
	}
	after, _, err := apkLauncherReadFile(ctx, root, "lib/apk/db/installed", maximumAPKInstalledDatabaseSize, 0, false)
	if err != nil || after != database {
		return errors.New("APK database changed while staging fresh launcher intent")
	}
	observedParents, observedAliases, err := captureFreshAPKLauncherPaths(root)
	if err != nil || !sameFreshAPKParents(parents, observedParents) || aliases != observedAliases {
		return errors.New("APK launchers changed while staging fresh intent")
	}
	if predecessor != nil {
		if err := predecessor.attestTerminal(); err != nil {
			return err
		}
	}
	_, err = s.publish(s.directory, "pending.json", apkLauncherLifecycleReference{apkFreshLauncherSchema, "fresh-pending", digest, digest})
	return err
}

// CompleteFreshAPKLaunchers is invoked only by the fixed post-commit ingress.
// With no pending fresh intent it is a no-op, including coordinated upgrades.
// It never invokes install/reload, reads configuration, or activates policy.
func CompleteFreshAPKLaunchers(ctx context.Context) error {
	if os.Geteuid() != 0 {
		return errors.New("fresh APK launcher completion requires root")
	}
	return completeFreshAPKLaunchersAt(ctx, "/", nil)
}

func completeFreshAPKLaunchersAt(ctx context.Context, host string, fault func(string) error) (result error) {
	s, err := openAPKLauncherLifecycleStore(ctx, host, false)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	s.fault = fault
	defer func() { result = errors.Join(result, s.close()) }()
	pending, err := readAPKTransitionBytes(s.directory, "pending.json", 4096)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	pendingIdentity, err := s.directory.root.Lstat("pending.json")
	if err != nil {
		return err
	}
	var reference apkLauncherLifecycleReference
	if decodeAPKTransitionJSON(pending, &reference) != nil || reference.Schema != apkFreshLauncherSchema || reference.Kind != "fresh-pending" || !validSHA256(reference.PlanSHA256) || reference.ReceiptSHA256 != reference.PlanSHA256 {
		return errors.New("fresh APK pending launcher reference is invalid")
	}
	if err := s.openJournal(reference.PlanSHA256, false); err != nil {
		return err
	}
	intentRaw, err := readAPKTransitionBytes(s.journal, "intent.json", apkLauncherMaximumBytes)
	var intent apkFreshLauncherIntent
	if err != nil || apkTransitionDigest(intentRaw) != reference.PlanSHA256 || decodeAPKTransitionJSON(intentRaw, &intent) != nil || intent.Schema != apkFreshLauncherSchema || intent.Purpose != "fresh-intent-no-alias-mutation" || !validFreshAPKPreviousIntent(intent) {
		return errors.New("fresh APK launcher intent is invalid")
	}
	proposal := apkLauncherLineageProposal{Absent: true}
	var predecessor *apkLauncherLifecycleRemoval
	if intent.PreviousSHA256 != "" {
		proposal = apkLauncherLineageProposal{ReferenceSHA256: intent.PreviousSHA256, Identity: *intent.PreviousIdentity}
		if err := s.compareLineage(proposal); err != nil {
			return err
		}
		previousRaw, err := readAPKTransitionBytes(s.journal, "previous-current.json", 4096)
		if err != nil || apkTransitionDigest(previousRaw) != intent.PreviousSHA256 {
			return errors.New("fresh APK prior reference evidence changed")
		}
		journal, journalPath := s.journal, s.journalPath
		s.journal = nil
		predecessor, err = inspectAPKLauncherLifecycleRemovalStore(s, true)
		priorJournal := s.journal
		s.journal, s.journalPath = journal, journalPath
		if priorJournal != nil {
			defer priorJournal.close()
		}
		if err != nil {
			return err
		}
		if predecessor.execution != nil {
			return errors.Join(errors.New("fresh APK prior lineage is unsupported"), predecessor.execution.Close())
		}
		if err := predecessor.attestTerminal(); err != nil {
			return err
		}
		if apkTransitionDigest(predecessor.terminal) != intent.PreviousTerminalSHA256 {
			return errors.New("fresh APK prior terminal evidence changed")
		}
	} else if err := s.compareLineage(proposal); err != nil {
		return err
	}
	before, err := readAPKTransitionBytes(s.journal, "before-installed", maximumAPKInstalledDatabaseSize)
	if err != nil || apkTransitionDigest(before) != intent.DatabaseSHA256 {
		return errors.New("fresh APK launcher native absence evidence changed")
	}
	previous, err := parseAPKLauncherRegistrations(before)
	if err != nil {
		return err
	}
	for name := range previous {
		if validNativeProductPackageName(name) {
			return errors.New("fresh APK launcher intent cannot adopt an installed product")
		}
	}
	files, err := captureAPKLauncherPayload(ctx, s.anchor)
	if err != nil || !reflect.DeepEqual(files, intent.Payload) {
		return errors.New("fresh APK launcher payload changed since intent")
	}
	database, raw, err := apkLauncherReadFile(ctx, s.anchor, "lib/apk/db/installed", maximumAPKInstalledDatabaseSize, 0, true)
	if err != nil {
		return err
	}
	records, err := parseAPKLauncherRegistrations(raw)
	if err != nil {
		return err
	}
	native, err := attestAPKLauncherCommittedRegistration(records, files)
	if err != nil {
		return err
	}
	parents, aliases, err := captureFreshAPKLauncherPaths(s.anchor)
	if err != nil || !sameFreshAPKParents(intent.Parents, parents) || aliases != intent.Aliases {
		return errors.New("fresh APK launcher observation changed before creation")
	}
	for _, record := range records {
		for i, path := range apkLauncherPaths {
			if _, owned := record.entries[path]; owned && aliases[i].Original.Absent {
				return errors.New("fresh APK launcher path became registered to another package")
			}
		}
	}
	if err := s.createFreshParents(&parents, reference.PlanSHA256); err != nil {
		return err
	}
	if err := s.createFreshAliases(&aliases, reference.PlanSHA256); err != nil {
		return err
	}
	after, _, err := apkLauncherReadFile(ctx, s.anchor, "lib/apk/db/installed", maximumAPKInstalledDatabaseSize, 0, false)
	if err != nil || after != database {
		return errors.New("APK native registration changed during launcher creation; retain pending intent")
	}
	if err := s.verifyFreshCreatedState(intent.Payload, parents, aliases); err != nil {
		return err
	}
	receipt := apkFreshLauncherReceipt{apkFreshLauncherSchema, "exclusive-fresh-launcher-ownership", reference.PlanSHA256, native, parents, aliases}
	rawReceipt, err := s.publish(s.journal, "receipt.json", receipt)
	if err != nil {
		return err
	}
	current := apkLauncherLifecycleReference{apkFreshLauncherSchema, "fresh", reference.PlanSHA256, apkTransitionDigest(rawReceipt)}
	if err := s.verifyFreshCreatedState(intent.Payload, parents, aliases); err != nil {
		return err
	}
	if predecessor != nil {
		if err := predecessor.revalidateEvidence(); err != nil {
			return err
		}
	}
	if err := s.publishCurrent(current, proposal); err != nil {
		return err
	}
	if err := s.verifyFreshCreatedState(intent.Payload, parents, aliases); err != nil {
		return err
	}
	if intent.PreviousSHA256 != "" {
		if err := s.verifyPreviousFreshLineage(s.journal, intent); err != nil {
			return err
		}
	}
	return quarantineAndRemoveServiceArtifact(s.directory, "pending.json", false,
		func(directory *pinnedServiceDirectory, name string) (os.FileInfo, error) {
			before, err := directory.root.Lstat(name)
			if err != nil || !sameServiceArtifactIdentity(pendingIdentity, before) {
				return nil, errors.New("fresh APK launcher pending reference identity changed")
			}
			actual, err := readAPKTransitionBytes(directory, name, 4096)
			after, statErr := directory.root.Lstat(name)
			if err != nil || statErr != nil || !bytes.Equal(actual, pending) || !sameServiceArtifactIdentity(before, after) {
				return nil, errors.New("fresh APK launcher pending reference changed")
			}
			return after, s.check()
		})
}

func (s *apkLauncherLifecycleStore) verifyFreshCreatedState(payload []apkLauncherPayloadFile, parents [4]apkFreshLauncherParent, aliases [2]apkLauncherEntry) error {
	files, err := captureAPKLauncherPayload(s.ctx, s.anchor)
	if err != nil || !reflect.DeepEqual(files, payload) {
		return errors.New("fresh APK payload changed before launcher receipt publication; retain pending intent")
	}
	actualParents, actualAliases, err := captureFreshAPKLauncherPaths(s.anchor)
	if err != nil || !sameFreshAPKParents(parents, actualParents) {
		return errors.New("fresh APK launcher ancestry changed before receipt publication")
	}
	for i := range aliases {
		if aliases[i].Committed != actualAliases[i].Original {
			return errors.New("fresh APK launcher changed before receipt publication; retain pending intent")
		}
	}
	return s.check()
}

func (s *apkLauncherLifecycleStore) createFreshParents(parents *[4]apkFreshLauncherParent, intent string) error {
	for i, path := range apkLauncherParents {
		if !parents[i].Absent {
			if err := s.pin(path); err != nil {
				return err
			}
			continue
		}
		if i < 2 {
			return errors.New("fresh APK launcher cannot create a host root")
		}
		name := fmt.Sprintf("parent-%d", i)
		if _, err := s.publish(s.journal, "intent-"+name+".json", parents[i]); err != nil {
			return err
		}
		parent := s.parents[len(s.parents)-1].root
		if err := parent.Mkdir(filepath.Base(path), 0755); err != nil {
			return errors.New("fresh APK launcher parent exclusive creation failed; retain intent")
		}
		file, err := parent.Open(".")
		if err != nil {
			return err
		}
		if err := errors.Join(file.Sync(), file.Close()); err != nil {
			return err
		}
		if err := s.pin(path); err != nil {
			return err
		}
		identity := s.parents[len(s.parents)-1].identity
		created := apkFreshLauncherParent{Path: path, Identity: identity}
		raw, err := s.publish(s.journal, "created-"+name+".json", created)
		if err != nil {
			return err
		}
		created.CreationSHA256 = apkTransitionDigest(raw)
		parents[i] = created
		if s.fault != nil {
			if err := s.fault("after-create-" + path); err != nil {
				return err
			}
		}
	}
	return s.check()
}

func (s *apkLauncherLifecycleStore) createFreshAliases(aliases *[2]apkLauncherEntry, intent string) error {
	parent := s.parents[len(s.parents)-1].root
	for i, alias := range aliases {
		if err := s.check(); err != nil {
			return err
		}
		entry, err := readAPKLauncherEntry(parent, filepath.Base(alias.Path))
		if err != nil || apkLauncherEntryEvidence(entry) != alias.Original {
			return errors.New("fresh APK launcher changed before exclusive creation")
		}
		if alias.Disposition != "absent" {
			continue
		}
		name := apkLauncherCreationName(i)
		if _, err := s.publish(s.journal, "intent-"+name, apkLauncherCreation{apkFreshLauncherSchema, "exclusive-launcher-create-intent", intent, alias.Path, alias.Original}); err != nil {
			return err
		}
		if err := parent.Symlink(apkLauncherTargets[i], filepath.Base(alias.Path)); err != nil {
			return errors.New("fresh APK launcher exclusive creation failed; retain intent")
		}
		file, err := parent.Open(".")
		if err != nil {
			return err
		}
		if err := errors.Join(file.Sync(), file.Close()); err != nil {
			return err
		}
		entry, err = readAPKLauncherEntry(parent, filepath.Base(alias.Path))
		if err != nil || entry.Absent || entry.LinkTarget != apkLauncherTargets[i] {
			return errors.New("fresh APK launcher changed after exclusive creation")
		}
		creation := apkLauncherCreation{apkFreshLauncherSchema, "exclusive-launcher-created", intent, alias.Path, apkLauncherEntryEvidence(entry)}
		raw, err := s.publish(s.journal, name, creation)
		if err != nil {
			return err
		}
		aliases[i].Disposition, aliases[i].Committed, aliases[i].CreationSHA256 = "product-created", creation.Evidence, apkTransitionDigest(raw)
		if s.fault != nil {
			if err := s.fault("after-create-" + alias.Path); err != nil {
				return err
			}
		}
	}
	return s.check()
}

type apkLauncherLineageProposal struct {
	Absent          bool                  `json:"absent"`
	ReferenceSHA256 string                `json:"reference_sha256,omitempty"`
	Identity        apkTransitionIdentity `json:"identity"`
}

func validAPKLauncherLineageProposal(proposal apkLauncherLineageProposal) bool {
	if proposal.Absent {
		return proposal.ReferenceSHA256 == "" && proposal.Identity == (apkTransitionIdentity{})
	}
	return validSHA256(proposal.ReferenceSHA256) && proposal.Identity.Inode != 0 && proposal.Identity.Mode == unix.S_IFREG|0600 && proposal.Identity.Links == 1 && int(proposal.Identity.UID) == os.Geteuid() && int(proposal.Identity.GID) == os.Getegid()
}

func captureAPKLauncherLineageProposal(ctx context.Context, host string) (_ apkLauncherLineageProposal, result error) {
	s, err := openAPKLauncherLifecycleStore(ctx, host, false)
	if errors.Is(err, os.ErrNotExist) {
		return apkLauncherLineageProposal{Absent: true}, nil
	}
	if err != nil {
		return apkLauncherLineageProposal{}, err
	}
	defer func() { result = errors.Join(result, s.close()) }()
	if _, err := s.directory.root.Lstat("pending.json"); !errors.Is(err, os.ErrNotExist) {
		return apkLauncherLineageProposal{}, errors.New("APK launcher lineage has pending recovery debt")
	}
	return s.captureLineageProposal()
}

func (s *apkLauncherLifecycleStore) captureLineageProposal() (apkLauncherLineageProposal, error) {
	raw, err := readAPKTransitionBytes(s.directory, "current.json", 4096)
	if errors.Is(err, os.ErrNotExist) {
		return apkLauncherLineageProposal{Absent: true}, s.check()
	}
	if err != nil {
		return apkLauncherLineageProposal{}, err
	}
	var reference apkLauncherLifecycleReference
	if decodeAPKTransitionJSON(raw, &reference) != nil || reference.Schema != apkFreshLauncherSchema || (reference.Kind != "fresh" && reference.Kind != "execution") || !validSHA256(reference.PlanSHA256) || !validSHA256(reference.ReceiptSHA256) {
		return apkLauncherLineageProposal{}, errors.New("APK current launcher lineage is invalid")
	}
	canonical, _ := apkLauncherCanonical(reference)
	info, err := s.directory.root.Lstat("current.json")
	identity, identityErr := apkLauncherIdentity(info)
	if err != nil || identityErr != nil || !bytes.Equal(raw, canonical) {
		return apkLauncherLineageProposal{}, errors.New("APK current launcher lineage changed")
	}
	return apkLauncherLineageProposal{ReferenceSHA256: apkTransitionDigest(raw), Identity: identity}, s.check()
}

func validFreshAPKPreviousIntent(intent apkFreshLauncherIntent) bool {
	if intent.PreviousSHA256 == "" {
		return intent.PreviousIdentity == nil && intent.PreviousTerminalSHA256 == ""
	}
	return validSHA256(intent.PreviousSHA256) && validSHA256(intent.PreviousTerminalSHA256) && intent.PreviousIdentity != nil && intent.PreviousIdentity.Inode != 0
}

func sameAPKLauncherMovedIdentity(want, actual apkTransitionIdentity) bool {
	// Rename changes ctime. Every other identity field remains bound to the
	// observed source, including inode, link count, mode and content metadata.
	actual.ChangedSec, actual.ChangedNS = want.ChangedSec, want.ChangedNS
	return actual == want
}

func (s *apkLauncherLifecycleStore) compareLineage(proposal apkLauncherLineageProposal) error {
	if !validAPKLauncherLineageProposal(proposal) {
		return errors.New("APK launcher lineage proposal is invalid")
	}
	actual, err := s.captureLineageProposal()
	if err != nil || actual != proposal {
		return errors.New("APK current launcher lineage changed before compare-and-swap")
	}
	return nil
}

func (s *apkLauncherLifecycleStore) publishCurrent(reference apkLauncherLifecycleReference, proposal apkLauncherLineageProposal) error {
	if err := s.compareLineage(proposal); err != nil {
		return err
	}
	if proposal.Absent {
		_, err := s.publish(s.directory, "current.json", reference)
		return err
	}
	if s.journal == nil {
		return errors.New("APK launcher lineage replacement lacks durable custody")
	}
	raw, err := s.publish(s.journal, "displaced-current.json", reference)
	if err != nil {
		return err
	}
	created, err := s.journal.root.Lstat("displaced-current.json")
	if err != nil {
		return err
	}
	createdIdentity, err := apkLauncherIdentity(created)
	if err != nil {
		return err
	}
	if s.fault != nil {
		if err := s.fault("before-current-swap"); err != nil {
			return err
		}
	}
	if err := s.compareLineage(proposal); err != nil {
		return err
	}
	if s.fault != nil {
		if err := s.fault("at-current-swap"); err != nil {
			return err
		}
	}
	if err := unix.Renameat2(s.journal.fd, "displaced-current.json", s.directory.fd, "current.json", unix.RENAME_EXCHANGE); err != nil {
		return err
	}
	if err := errors.Join(s.journal.sync(), s.directory.sync()); err != nil {
		return err
	}
	if s.fault != nil {
		if err := s.fault("after-current-swap"); err != nil {
			return err
		}
	}
	prior, priorErr := readAPKTransitionBytes(s.journal, "displaced-current.json", 4096)
	oldInfo, oldErr := s.journal.root.Lstat("displaced-current.json")
	oldIdentity, oldIdentityErr := apkLauncherIdentity(oldInfo)
	current, currentErr := readAPKTransitionBytes(s.directory, "current.json", 4096)
	newInfo, newErr := s.directory.root.Lstat("current.json")
	newIdentity, newIdentityErr := apkLauncherIdentity(newInfo)
	if priorErr != nil || oldErr != nil || oldIdentityErr != nil || currentErr != nil || newErr != nil || newIdentityErr != nil || apkTransitionDigest(prior) != proposal.ReferenceSHA256 || !sameAPKLauncherMovedIdentity(proposal.Identity, oldIdentity) || !bytes.Equal(current, raw) || !sameAPKLauncherMovedIdentity(createdIdentity, newIdentity) {
		// Restore the displaced reference only while both exchanged names still
		// denote the exact observed objects. Otherwise preserve both for recovery.
		if newErr == nil && newIdentityErr == nil && sameAPKLauncherMovedIdentity(createdIdentity, newIdentity) && oldErr == nil && oldIdentityErr == nil {
			if err := unix.Renameat2(s.journal.fd, "displaced-current.json", s.directory.fd, "current.json", unix.RENAME_EXCHANGE); err != nil {
				return errors.Join(errors.New("APK launcher lineage exchange could not be restored"), err)
			}
			if err := errors.Join(s.journal.sync(), s.directory.sync()); err != nil {
				return err
			}
		}
		return errors.New("APK launcher lineage exchange is uncertain; retain displaced-current.json and pending recovery evidence")
	}
	return s.check()
}

func publishAPKExecutionLauncherLineage(ctx context.Context, authority *apkTerminalAuthority) (result error) {
	if authority == nil {
		return errors.New("APK execution launcher publication requires terminal authority")
	}
	reference, err := authority.launcherReference(ctx)
	if err != nil {
		return err
	}
	s, err := openAPKLauncherLifecycleStore(ctx, authority.launcherHost(), true)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, s.close()) }()
	if _, err := s.directory.root.Lstat("pending.json"); !errors.Is(err, os.ErrNotExist) {
		return errors.New("APK execution launcher publication refuses pending fresh recovery")
	}
	intent := apkLauncherLineagePublicationIntent{apkFreshLauncherSchema, "terminal-execution-lineage-publication", authority.launcherProposal(), reference}
	if err := s.openJournal(reference.PlanSHA256, true); errors.Is(err, os.ErrExist) {
		if err := s.openJournal(reference.PlanSHA256, false); err != nil {
			return err
		}
		if err := s.attestPublishedLineage(intent); err != nil {
			return err
		}
		verified, err := authority.launcherReference(ctx)
		if err != nil || verified != reference {
			return errors.New("APK terminal authority changed during lineage recovery")
		}
		return s.attestPublishedLineage(intent)
	} else if err != nil {
		return err
	}
	raw, err := s.publish(s.journal, "publication-intent.json", intent)
	if err != nil {
		return err
	}
	verified, err := authority.launcherReference(ctx)
	if err != nil || verified != reference {
		return errors.New("APK terminal authority changed before lineage publication")
	}
	if err := s.publishCurrent(reference, intent.Proposal); err != nil {
		return err
	}
	published, err := s.captureLineageProposal()
	expected, _ := apkLauncherCanonical(reference)
	if err != nil || published.Absent || published.ReferenceSHA256 != apkTransitionDigest(expected) {
		return errors.New("APK execution launcher publication is uncertain")
	}
	if _, err := s.publish(s.journal, "publication.json", apkLauncherLineagePublication{apkFreshLauncherSchema, "execution-lineage-published", apkTransitionDigest(raw), published.Identity}); err != nil {
		return err
	}
	return s.attestPublishedLineage(intent)
}

func (s *apkLauncherLifecycleStore) verifyPreviousFreshLineage(journal *pinnedServiceDirectory, intent apkFreshLauncherIntent) error {
	return s.verifyPreviousFreshLineageBound(journal, intent, 32)
}

func (s *apkLauncherLifecycleStore) verifyPreviousFreshLineageBound(journal *pinnedServiceDirectory, intent apkFreshLauncherIntent, maximum int) error {
	if !validFreshAPKPreviousIntent(intent) {
		return errors.New("APK prior launcher lineage binding is invalid")
	}
	if intent.PreviousSHA256 == "" {
		return nil
	}
	previous, err := readAPKTransitionBytes(journal, "previous-current.json", 4096)
	displaced, displacedErr := readAPKTransitionBytes(journal, "displaced-current.json", 4096)
	info, infoErr := journal.root.Lstat("displaced-current.json")
	identity, identityErr := apkLauncherIdentity(info)
	if err != nil || displacedErr != nil || infoErr != nil || identityErr != nil || !bytes.Equal(previous, displaced) || !sameAPKLauncherMovedIdentity(*intent.PreviousIdentity, identity) {
		return errors.New("APK prior launcher compare-and-swap evidence changed")
	}
	for depth := 0; depth < maximum; depth++ {
		if apkTransitionDigest(previous) != intent.PreviousSHA256 {
			return errors.New("APK previous launcher reference digest changed")
		}
		var reference apkLauncherLifecycleReference
		if decodeAPKTransitionJSON(previous, &reference) != nil || reference.Schema != apkFreshLauncherSchema || reference.Kind != "fresh" || !validSHA256(reference.PlanSHA256) || !validSHA256(reference.ReceiptSHA256) {
			return errors.New("APK prior fresh launcher lineage is unsupported")
		}
		path := filepath.Join(strings.TrimPrefix(apkLauncherLifecycleRoot, "/"), "fresh-"+reference.PlanSHA256)
		if err := s.pin(path); err != nil {
			return err
		}
		prior, err := openExistingPinnedServiceDirectory(filepath.Join(s.host, path))
		if err != nil {
			return err
		}
		info, err := prior.file.Stat()
		if err != nil || info.Mode() != os.ModeDir|0700 {
			prior.close()
			return errors.New("APK previous launcher journal is not private")
		}
		terminal, terminalErr := readAPKTransitionBytes(prior, "terminal.json", 4096)
		retirement, retirementErr := readAPKTransitionBytes(prior, "retirement.json", 4096)
		receipt, receiptErr := readAPKTransitionBytes(prior, "receipt.json", apkLauncherMaximumBytes)
		intentRaw, intentErr := readAPKTransitionBytes(prior, "intent.json", apkLauncherMaximumBytes)
		var retired apkFreshLauncherRetirement
		var parentIntent apkFreshLauncherIntent
		if terminalErr != nil || retirementErr != nil || receiptErr != nil || intentErr != nil || !bytes.Equal(terminal, retirement) || apkTransitionDigest(terminal) != intent.PreviousTerminalSHA256 || apkTransitionDigest(receipt) != reference.ReceiptSHA256 || apkTransitionDigest(intentRaw) != reference.PlanSHA256 || decodeAPKTransitionJSON(terminal, &retired) != nil || retired.Schema != apkFreshLauncherSchema || retired.Purpose != "owned-launcher-retirement" || retired.ReceiptSHA256 != reference.ReceiptSHA256 || decodeAPKTransitionJSON(intentRaw, &parentIntent) != nil || !validFreshAPKPreviousIntent(parentIntent) {
			prior.close()
			return errors.New("APK previous terminal launcher evidence changed")
		}
		if parentIntent.PreviousSHA256 == "" {
			prior.close()
			return s.check()
		}
		previous, err = readAPKTransitionBytes(prior, "previous-current.json", 4096)
		displaced, displacedErr := readAPKTransitionBytes(prior, "displaced-current.json", 4096)
		info, infoErr := prior.root.Lstat("displaced-current.json")
		identity, identityErr := apkLauncherIdentity(info)
		prior.close()
		if err != nil || displacedErr != nil || infoErr != nil || identityErr != nil || !bytes.Equal(previous, displaced) || !sameAPKLauncherMovedIdentity(*parentIntent.PreviousIdentity, identity) {
			return errors.New("APK ancestor launcher compare-and-swap evidence changed")
		}
		intent = parentIntent
	}
	return errors.New("APK previous launcher lineage exceeds its bounded ancestry")
}

type apkLauncherLineagePublicationIntent struct {
	Schema    string                        `json:"schema"`
	Purpose   string                        `json:"purpose"`
	Proposal  apkLauncherLineageProposal    `json:"proposal"`
	Reference apkLauncherLifecycleReference `json:"reference"`
}

type apkLauncherLineagePublication struct {
	Schema       string                `json:"schema"`
	Purpose      string                `json:"purpose"`
	IntentSHA256 string                `json:"intent_sha256"`
	Identity     apkTransitionIdentity `json:"identity"`
}

func (s *apkLauncherLifecycleStore) attestPublishedLineage(intent apkLauncherLineagePublicationIntent) error {
	return s.attestPublishedLineageAt(s.journal, intent)
}

func (s *apkLauncherLifecycleStore) attestPublishedLineageAt(journal *pinnedServiceDirectory, intent apkLauncherLineagePublicationIntent) error {
	if intent.Schema != apkFreshLauncherSchema || intent.Purpose != "terminal-execution-lineage-publication" || intent.Reference.Schema != apkFreshLauncherSchema || intent.Reference.Kind != "execution" || !validSHA256(intent.Reference.PlanSHA256) || !validSHA256(intent.Reference.ReceiptSHA256) || !validAPKLauncherLineageProposal(intent.Proposal) {
		return errors.New("APK execution launcher publication binding is invalid")
	}
	want, err := apkLauncherCanonical(intent)
	if err != nil {
		return err
	}
	raw, err := readAPKTransitionBytes(journal, "publication-intent.json", 4096)
	if err != nil || !bytes.Equal(raw, want) {
		return errors.New("APK execution launcher publication intent is missing or contradictory")
	}
	publishedRaw, err := readAPKTransitionBytes(journal, "publication.json", 4096)
	var published apkLauncherLineagePublication
	if err != nil || decodeAPKTransitionJSON(publishedRaw, &published) != nil || published.Schema != apkFreshLauncherSchema || published.Purpose != "execution-lineage-published" || published.IntentSHA256 != apkTransitionDigest(raw) {
		return errors.New("APK execution launcher publication remains incomplete")
	}
	proposal, err := s.captureLineageProposal()
	current, _ := apkLauncherCanonical(intent.Reference)
	if err != nil || proposal.Absent || proposal.Identity != published.Identity || proposal.ReferenceSHA256 != apkTransitionDigest(current) {
		return errors.New("APK published execution launcher lineage changed")
	}
	allowed := map[string]bool{"publication-intent.json": true, "publication.json": true}
	if !intent.Proposal.Absent {
		allowed["displaced-current.json"] = true
		displaced, err := readAPKTransitionBytes(journal, "displaced-current.json", 4096)
		info, statErr := journal.root.Lstat("displaced-current.json")
		identity, identityErr := apkLauncherIdentity(info)
		if err != nil || statErr != nil || identityErr != nil || apkTransitionDigest(displaced) != intent.Proposal.ReferenceSHA256 || !sameAPKLauncherMovedIdentity(intent.Proposal.Identity, identity) {
			return errors.New("APK execution launcher displaced lineage evidence changed")
		}
	}
	file, err := journal.root.Open(".")
	if err != nil {
		return err
	}
	names, readErr := file.Readdirnames(5)
	closeErr := file.Close()
	if closeErr != nil || readErr != nil && !errors.Is(readErr, io.EOF) || len(names) != len(allowed) {
		return errors.New("APK execution launcher publication inventory is incomplete")
	}
	for _, name := range names {
		if !allowed[name] {
			return errors.New("APK execution launcher publication has unknown recovery evidence")
		}
	}
	return s.check()
}
