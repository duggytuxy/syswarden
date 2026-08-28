//go:build linux

package firewall

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	nftTransactionJournalName          = ".firewall-transaction.journal"
	nftTransactionJournalSchemaVersion = 2
	maximumNFTJournalFieldBytes        = 48 << 20
	maximumNFTJournalBytes             = 128 << 20
)

type nftTransactionPhase string

const (
	nftTransactionPrepared  nftTransactionPhase = "prepared"
	nftTransactionApplied   nftTransactionPhase = "applied"
	nftTransactionVerified  nftTransactionPhase = "verified"
	nftTransactionPersisted nftTransactionPhase = "persisted"
)

var nftTransactionIDPattern = regexp.MustCompile(`^[0-9a-f]{16}$`)

var nftJournalRemove = os.Remove
var nftJournalWriteDirectorySync = syncDirectory
var nftJournalRemovalDirectorySync = syncDirectory

type nftDynamicSetPresence struct {
	InetIPv4   bool `json:"inet_ipv4"`
	InetIPv6   bool `json:"inet_ipv6"`
	NetdevIPv4 bool `json:"netdev_ipv4"`
	NetdevIPv6 bool `json:"netdev_ipv6"`
}

func (presence nftDynamicSetPresence) contains(key nftObjectKey) bool {
	switch key {
	case nftObjectKey{family: "inet", table: "syswarden", name: "banned_ips"}:
		return presence.InetIPv4
	case nftObjectKey{family: "inet", table: "syswarden", name: "banned_ips6"}:
		return presence.InetIPv6
	case nftObjectKey{family: "netdev", table: "syswarden_hw_drop", name: "banned_ips"}:
		return presence.NetdevIPv4
	case nftObjectKey{family: "netdev", table: "syswarden_hw_drop", name: "banned_ips6"}:
		return presence.NetdevIPv6
	default:
		return false
	}
}

func (presence nftDynamicSetPresence) any() bool {
	return presence.InetIPv4 || presence.InetIPv6 || presence.NetdevIPv4 || presence.NetdevIPv6
}

type nftJournalRemovalError struct {
	unlinked bool
	err      error
}

type nftJournalWriteError struct {
	err error
}

func (failure *nftJournalWriteError) Error() string {
	if failure == nil || failure.err == nil {
		return "firewall transaction journal was published but directory durability is uncertain"
	}
	return fmt.Sprintf("firewall transaction journal was published but directory durability is uncertain: %v", failure.err)
}

func (failure *nftJournalWriteError) Unwrap() error {
	if failure == nil {
		return nil
	}
	return failure.err
}

func nftJournalWriteWasPublished(err error) bool {
	var failure *nftJournalWriteError
	return errors.As(err, &failure)
}

func (failure *nftJournalRemovalError) Error() string {
	if failure == nil || failure.err == nil {
		return "remove durable firewall transaction journal"
	}
	if failure.unlinked {
		return fmt.Sprintf("firewall transaction journal was unlinked but directory durability is uncertain: %v", failure.err)
	}
	return failure.err.Error()
}

func (failure *nftJournalRemovalError) Unwrap() error {
	if failure == nil {
		return nil
	}
	return failure.err
}

func nftJournalWasUnlinked(err error) bool {
	var failure *nftJournalRemovalError
	return errors.As(err, &failure) && failure.unlinked
}

// nftTransactionJournal is deliberately self-contained. If the process stops
// after the atomic kernel apply, the next reload can restore the exact previous
// persistent policy before attempting a fresh transaction. Dynamic bans are
// captured from the live ruleset during recovery so their remaining TTL keeps
// aging instead of being extended from stale journal data.
type nftTransactionJournal struct {
	SchemaVersion             int                   `json:"schema_version"`
	TransactionID             string                `json:"transaction_id"`
	Phase                     nftTransactionPhase   `json:"phase"`
	CreatedAt                 string                `json:"created_at"`
	HadPreviousTables         bool                  `json:"had_previous_tables"`
	PreviousDynamicSets       nftDynamicSetPresence `json:"previous_dynamic_sets"`
	RollbackRules             []byte                `json:"rollback_rules"`
	RollbackSHA256            string                `json:"rollback_sha256"`
	CandidatePersistentSHA256 string                `json:"candidate_persistent_sha256"`
	PreviousPersistentExists  bool                  `json:"previous_persistent_exists"`
	PreviousPersistent        []byte                `json:"previous_persistent"`
	PreviousPersistentSHA256  string                `json:"previous_persistent_sha256"`
}

func nftSHA256Hex(content []byte) string {
	digest := sha256.Sum256(content)
	return hex.EncodeToString(digest[:])
}

func nftTransactionJournalPath(stateDirectory string) string {
	return filepath.Join(stateDirectory, nftTransactionJournalName)
}

func newNFTTransactionJournal(
	stateDirectory, transactionID, rollbackRules string,
	hadPreviousTables bool,
	previousDynamicSets nftDynamicSetPresence,
	candidatePersistent []byte,
) (*nftTransactionJournal, error) {
	if err := attestNFTStateDirectory(stateDirectory); err != nil {
		return nil, fmt.Errorf("attest firewall state directory: %w", err)
	}
	if !nftTransactionIDPattern.MatchString(transactionID) {
		return nil, fmt.Errorf("invalid firewall transaction identifier %q", transactionID)
	}
	rollback := []byte(rollbackRules)
	if len(rollback) > maximumNFTJournalFieldBytes || len(candidatePersistent) > maximumNFTJournalFieldBytes {
		return nil, fmt.Errorf("firewall transaction journal input exceeds the bounded field size")
	}
	statePath := filepath.Join(stateDirectory, filepath.Base(nftStateFile))
	previous, readErr := readPrivateRootedNFTFile(statePath, maximumNFTJournalFieldBytes)
	previousExists := readErr == nil
	if readErr != nil && !errors.Is(readErr, fs.ErrNotExist) {
		return nil, fmt.Errorf("read previous persistent firewall policy: %w", readErr)
	}
	if len(previous) > maximumNFTJournalFieldBytes {
		return nil, fmt.Errorf("previous persistent firewall policy exceeds the bounded journal field size")
	}
	journal := &nftTransactionJournal{
		SchemaVersion:             nftTransactionJournalSchemaVersion,
		TransactionID:             transactionID,
		Phase:                     nftTransactionPrepared,
		CreatedAt:                 time.Now().UTC().Format(time.RFC3339Nano),
		HadPreviousTables:         hadPreviousTables,
		PreviousDynamicSets:       previousDynamicSets,
		RollbackRules:             bytes.Clone(rollback),
		RollbackSHA256:            nftSHA256Hex(rollback),
		CandidatePersistentSHA256: nftSHA256Hex(candidatePersistent),
		PreviousPersistentExists:  previousExists,
		PreviousPersistent:        bytes.Clone(previous),
		PreviousPersistentSHA256:  nftSHA256Hex(previous),
	}
	if err := writeNFTTransactionJournal(stateDirectory, journal, true); err != nil {
		return nil, err
	}
	return journal, nil
}

func validateNFTTransactionJournal(journal *nftTransactionJournal) error {
	if journal == nil {
		return fmt.Errorf("firewall transaction journal is nil")
	}
	if journal.SchemaVersion != nftTransactionJournalSchemaVersion {
		return fmt.Errorf("unsupported firewall transaction journal schema %d", journal.SchemaVersion)
	}
	if !nftTransactionIDPattern.MatchString(journal.TransactionID) {
		return fmt.Errorf("invalid firewall transaction journal identifier")
	}
	switch journal.Phase {
	case nftTransactionPrepared, nftTransactionApplied, nftTransactionVerified, nftTransactionPersisted:
	default:
		return fmt.Errorf("invalid firewall transaction journal phase %q", journal.Phase)
	}
	if parsed, err := time.Parse(time.RFC3339Nano, journal.CreatedAt); err != nil || parsed.IsZero() {
		return fmt.Errorf("invalid firewall transaction journal creation time")
	}
	if len(journal.RollbackRules) > maximumNFTJournalFieldBytes || len(journal.PreviousPersistent) > maximumNFTJournalFieldBytes {
		return fmt.Errorf("firewall transaction journal field exceeds the bounded size")
	}
	if journal.RollbackSHA256 != nftSHA256Hex(journal.RollbackRules) ||
		journal.PreviousPersistentSHA256 != nftSHA256Hex(journal.PreviousPersistent) {
		return fmt.Errorf("firewall transaction journal digest mismatch")
	}
	if err := validateNFTPersistentDigest(journal.CandidatePersistentSHA256); err != nil {
		return fmt.Errorf("invalid candidate persistent policy digest in firewall transaction journal")
	}
	if !journal.PreviousPersistentExists && len(journal.PreviousPersistent) != 0 {
		return fmt.Errorf("firewall transaction journal contains an impossible previous policy state")
	}
	if !journal.HadPreviousTables && journal.PreviousDynamicSets.any() {
		return fmt.Errorf("firewall transaction journal contains dynamic sets without previous tables")
	}
	return nil
}

func marshalNFTTransactionJournal(journal *nftTransactionJournal) ([]byte, error) {
	if err := validateNFTTransactionJournal(journal); err != nil {
		return nil, err
	}
	content, err := json.Marshal(journal)
	if err != nil {
		return nil, err
	}
	content = append(content, '\n')
	if len(content) > maximumNFTJournalBytes {
		return nil, fmt.Errorf("firewall transaction journal exceeds the bounded size")
	}
	return content, nil
}

func writeNFTTransactionJournal(stateDirectory string, journal *nftTransactionJournal, create bool) error {
	if err := attestNFTStateDirectory(stateDirectory); err != nil {
		return fmt.Errorf("attest firewall state directory: %w", err)
	}
	content, err := marshalNFTTransactionJournal(journal)
	if err != nil {
		return err
	}
	target := nftTransactionJournalPath(stateDirectory)
	if !create {
		current, currentErr := readNFTTransactionJournal(stateDirectory)
		if currentErr != nil {
			return fmt.Errorf("inspect firewall transaction journal before update: %w", currentErr)
		}
		if current.TransactionID != journal.TransactionID {
			return fmt.Errorf("refuse to replace a different firewall transaction journal")
		}
	}
	temporary, err := os.CreateTemp(stateDirectory, ".firewall-transaction.journal-")
	if err != nil {
		return fmt.Errorf("create firewall transaction journal update: %w", err)
	}
	temporaryPath := temporary.Name()
	defer func() { _ = os.Remove(temporaryPath) }()
	if err := temporary.Chmod(0600); err != nil {
		_ = temporary.Close()
		return err
	}
	if written, err := temporary.Write(content); err != nil || written != len(content) {
		_ = temporary.Close()
		if err != nil {
			return err
		}
		return io.ErrShortWrite
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if create {
		if err := unix.Renameat2(unix.AT_FDCWD, temporaryPath, unix.AT_FDCWD, target, unix.RENAME_NOREPLACE); err != nil {
			return fmt.Errorf("publish new firewall transaction journal without replacement: %w", err)
		}
	} else if err := os.Rename(temporaryPath, target); err != nil {
		return fmt.Errorf("replace firewall transaction journal: %w", err)
	}
	if err := nftJournalWriteDirectorySync(stateDirectory); err != nil {
		return &nftJournalWriteError{err: err}
	}
	return nil
}

func updateNFTTransactionJournal(stateDirectory string, journal *nftTransactionJournal, phase nftTransactionPhase) error {
	wanted := map[nftTransactionPhase]nftTransactionPhase{
		nftTransactionPrepared: nftTransactionApplied,
		nftTransactionApplied:  nftTransactionVerified,
		nftTransactionVerified: nftTransactionPersisted,
	}[journal.Phase]
	if wanted != phase {
		return fmt.Errorf("invalid firewall transaction journal phase transition %q to %q", journal.Phase, phase)
	}
	updated := *journal
	updated.Phase = phase
	if err := writeNFTTransactionJournal(stateDirectory, &updated, false); err != nil {
		return err
	}
	journal.Phase = phase
	return nil
}

func readNFTTransactionJournal(stateDirectory string) (*nftTransactionJournal, error) {
	if err := attestNFTStateDirectory(stateDirectory); err != nil {
		return nil, fmt.Errorf("attest firewall state directory: %w", err)
	}
	path := nftTransactionJournalPath(stateDirectory)
	content, err := readPrivateRootedNFTFile(path, maximumNFTJournalBytes)
	if err != nil {
		return nil, fmt.Errorf("read bounded private firewall transaction journal: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	var journal nftTransactionJournal
	if err := decoder.Decode(&journal); err != nil {
		return nil, fmt.Errorf("decode firewall transaction journal: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("firewall transaction journal contains trailing data")
	}
	if err := validateNFTTransactionJournal(&journal); err != nil {
		return nil, err
	}
	return &journal, nil
}

func removeNFTTransactionJournal(stateDirectory string) error {
	if err := attestNFTStateDirectory(stateDirectory); err != nil {
		return &nftJournalRemovalError{err: fmt.Errorf("attest firewall state directory: %w", err)}
	}
	path := nftTransactionJournalPath(stateDirectory)
	if err := nftJournalRemove(path); err != nil {
		return &nftJournalRemovalError{err: err}
	}
	if err := nftJournalRemovalDirectorySync(stateDirectory); err != nil {
		return &nftJournalRemovalError{unlinked: true, err: err}
	}
	return nil
}

func restoreNFTJournalPersistentPolicy(stateDirectory string, journal *nftTransactionJournal) error {
	if err := validateNFTTransactionJournal(journal); err != nil {
		return err
	}
	statePath := filepath.Join(stateDirectory, filepath.Base(nftStateFile))
	if err := restoreNftablesFile(
		stateDirectory,
		statePath,
		journal.PreviousPersistent,
		journal.PreviousPersistentExists,
	); err != nil {
		return err
	}
	return verifyNFTPersistentPolicy(
		statePath,
		journal.PreviousPersistentExists,
		journal.PreviousPersistentSHA256,
	)
}

func rollbackJournaledNftables(
	runner nftCommandRunner,
	stateDirectory string,
	journal *nftTransactionJournal,
	dynamic nftDynamicSnapshot,
) error {
	if err := rollbackNftables(runner, string(journal.RollbackRules), dynamic, journal.PreviousDynamicSets); err != nil {
		return err
	}
	if err := restoreNFTJournalPersistentPolicy(stateDirectory, journal); err != nil {
		return err
	}
	return removeNFTTransactionJournal(stateDirectory)
}

// recoverPendingNftablesTransaction rolls an interrupted, uncommitted operation
// back to its previous persistent policy. A persisted journal instead proves
// that the candidate crossed every commit boundary, so recovery verifies the
// published candidate and removes only the stale journal. A subsequent normal
// reload can then build and attest a fresh candidate from the current
// configuration.
func recoverPendingNftablesTransaction(ctx context.Context, runner nftCommandRunner, stateDirectory string) error {
	if err := attestNFTStateDirectory(stateDirectory); err != nil {
		return fmt.Errorf("attest firewall state directory before recovery: %w", err)
	}
	journal, err := readNFTTransactionJournal(stateDirectory)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect pending firewall transaction: %w", err)
	}
	if journal.Phase == nftTransactionPersisted {
		statePath := filepath.Join(stateDirectory, filepath.Base(nftStateFile))
		if err := verifyNFTPersistentPolicy(statePath, true, journal.CandidatePersistentSHA256); err != nil {
			return fmt.Errorf(
				"recover committed firewall transaction %s: verify published candidate before journal cleanup: %w",
				journal.TransactionID,
				err,
			)
		}
		if err := removeNFTTransactionJournal(stateDirectory); err != nil {
			if nftJournalWasUnlinked(err) {
				return fmt.Errorf(
					"recover committed firewall transaction %s: candidate remains committed, but journal cleanup durability is uncertain: %w",
					journal.TransactionID,
					err,
				)
			}
			return fmt.Errorf(
				"recover committed firewall transaction %s: remove durable journal: %w",
				journal.TransactionID,
				err,
			)
		}
		return nil
	}
	dynamic := newNFTDynamicSnapshot(time.Now())
	if journal.HadPreviousTables {
		dynamic, err = snapshotNFTDynamicBans(ctx, runner, time.Now())
		if err != nil {
			return fmt.Errorf("recover firewall transaction %s: snapshot live dynamic bans: %w", journal.TransactionID, err)
		}
	}
	if err := rollbackNftables(runner, string(journal.RollbackRules), dynamic, journal.PreviousDynamicSets); err != nil {
		return fmt.Errorf("recover firewall transaction %s: restore previous kernel policy: %w", journal.TransactionID, err)
	}
	if err := restoreNFTJournalPersistentPolicy(stateDirectory, journal); err != nil {
		return fmt.Errorf("recover firewall transaction %s: restore previous persistent policy: %w", journal.TransactionID, err)
	}
	if err := removeNFTTransactionJournal(stateDirectory); err != nil {
		return fmt.Errorf("recover firewall transaction %s: remove durable journal: %w", journal.TransactionID, err)
	}
	return nil
}

func verifyNFTPersistentPolicy(path string, expectedExists bool, expectedSHA256 string) error {
	if !expectedExists {
		if _, err := os.Lstat(path); errors.Is(err, fs.ErrNotExist) {
			return nil
		} else if err != nil {
			return fmt.Errorf("inspect absent persistent firewall policy: %w", err)
		}
		return fmt.Errorf("persistent firewall policy exists but absence was expected")
	}
	content, err := readPrivateRootedNFTFile(path, maximumNFTJournalFieldBytes)
	if err != nil {
		return fmt.Errorf("read restored persistent firewall policy: %w", err)
	}
	if actual := nftSHA256Hex(content); actual != expectedSHA256 {
		return fmt.Errorf("persistent firewall policy digest mismatch: got %s, expected %s", actual, expectedSHA256)
	}
	return nil
}

func attestNFTStateDirectory(path string) error {
	clean := filepath.Clean(path)
	if !filepath.IsAbs(clean) || clean != path {
		return fmt.Errorf("firewall state directory is not absolute and canonical: %q", path)
	}
	before, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.IsDir() || before.Mode().Perm()&0022 != 0 {
		return fmt.Errorf("firewall state directory has unsafe type or write permissions")
	}
	beforeStat, ok := before.Sys().(*syscall.Stat_t)
	if !ok || int64(beforeStat.Uid) != int64(os.Geteuid()) || beforeStat.Nlink == 0 {
		return fmt.Errorf("firewall state directory has unexpected ownership or identity")
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	directory := os.NewFile(uintptr(fd), path)
	if directory == nil {
		_ = unix.Close(fd)
		return fmt.Errorf("pin firewall state directory")
	}
	opened, statErr := directory.Stat()
	closeErr := directory.Close()
	after, lstatErr := os.Lstat(path)
	if statErr != nil || closeErr != nil || lstatErr != nil ||
		!sameNFTFileIdentity(before, opened) || !sameNFTFileIdentity(opened, after) {
		return fmt.Errorf("firewall state directory changed while attesting")
	}
	return nil
}

func readPrivateRootedNFTFile(path string, maximum int) ([]byte, error) {
	if maximum < 0 {
		return nil, fmt.Errorf("invalid nftables file size limit")
	}
	if err := attestNFTStateDirectory(filepath.Dir(path)); err != nil {
		return nil, err
	}
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if err := validatePrivateNFTFileIdentity(before, int64(maximum)); err != nil {
		return nil, err
	}
	file, err := openRootedNFTFile(path, os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	opened, openStatErr := file.Stat()
	if openStatErr != nil || !sameNFTFileIdentity(before, opened) {
		_ = file.Close()
		return nil, fmt.Errorf("private nftables file changed before reading")
	}
	content, readErr := io.ReadAll(io.LimitReader(file, int64(maximum)+1))
	afterOpen, statErr := file.Stat()
	closeErr := file.Close()
	after, lstatErr := os.Lstat(path)
	if readErr != nil {
		return nil, readErr
	}
	if statErr != nil || closeErr != nil || lstatErr != nil || len(content) > maximum ||
		!sameNFTFileIdentity(before, afterOpen) || !sameNFTFileIdentity(afterOpen, after) {
		return nil, fmt.Errorf("private nftables file changed while reading or exceeds %d bytes", maximum)
	}
	if int64(len(content)) != after.Size() {
		return nil, fmt.Errorf("private nftables file size changed while reading")
	}
	return content, nil
}

func validatePrivateNFTFileIdentity(info os.FileInfo, maximum int64) error {
	if info == nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() ||
		info.Mode().Perm() != 0600 || info.Size() < 0 || info.Size() > maximum {
		return fmt.Errorf("nftables file is not a bounded private regular file")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int64(stat.Uid) != int64(os.Geteuid()) || stat.Nlink != 1 {
		return fmt.Errorf("nftables file has unexpected ownership or link count")
	}
	return nil
}

func sameNFTFileIdentity(left, right os.FileInfo) bool {
	if left == nil || right == nil || !os.SameFile(left, right) || left.Mode() != right.Mode() ||
		left.Size() != right.Size() || !left.ModTime().Equal(right.ModTime()) {
		return false
	}
	leftStat, leftOK := left.Sys().(*syscall.Stat_t)
	rightStat, rightOK := right.Sys().(*syscall.Stat_t)
	return leftOK && rightOK && leftStat.Uid == rightStat.Uid && leftStat.Gid == rightStat.Gid &&
		leftStat.Nlink == rightStat.Nlink && leftStat.Dev == rightStat.Dev && leftStat.Ino == rightStat.Ino
}

func nftDynamicSetPresenceFromSnapshot(snapshot nftDynamicSnapshot) nftDynamicSetPresence {
	return nftDynamicSetPresence{
		InetIPv4:   snapshot.present[nftObjectKey{family: "inet", table: "syswarden", name: "banned_ips"}],
		InetIPv6:   snapshot.present[nftObjectKey{family: "inet", table: "syswarden", name: "banned_ips6"}],
		NetdevIPv4: snapshot.present[nftObjectKey{family: "netdev", table: "syswarden_hw_drop", name: "banned_ips"}],
		NetdevIPv6: snapshot.present[nftObjectKey{family: "netdev", table: "syswarden_hw_drop", name: "banned_ips6"}],
	}
}

func validateNFTPersistentDigest(value string) error {
	if len(value) != sha256.Size*2 || value != strings.ToLower(value) {
		return fmt.Errorf("invalid lowercase SHA-256 digest")
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != sha256.Size {
		return fmt.Errorf("invalid SHA-256 digest")
	}
	return nil
}
