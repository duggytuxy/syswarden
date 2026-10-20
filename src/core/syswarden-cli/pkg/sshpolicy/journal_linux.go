//go:build linux

package sshpolicy

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"reflect"

	"golang.org/x/sys/unix"
)

const (
	sshJournalDirectory = "/var/lib/syswarden/ssh-policy-v1"
	sshPreparedRecord   = "prepared.json"
	maxSSHJournalBytes  = 8 * MaxBytes
)

// An immutable preparation record is not a receipt for active configuration.
// It records the exact before-image and the unnamed replacement inodes before
// any active or staging name can be published. Only the future transaction
// adapter may advance it using separate durable records and fresh observations.
type sshPreparation struct {
	Schema       int              `json:"schema"`
	Transaction  string           `json:"transaction"`
	PlanSHA256   string           `json:"plan_sha256"`
	ParserSHA256 string           `json:"parser_sha256"`
	MainBefore   sshRecoveryImage `json:"main_before"`
	MainAfter    sshRecoveryImage `json:"main_after"`
	DropIn       sshRecoveryImage `json:"drop_in"`
}

type sshRecoveryImage struct {
	Device     uint64            `json:"device"`
	Inode      uint64            `json:"inode"`
	Links      uint64            `json:"links"`
	Mode       uint32            `json:"mode"`
	UID        uint32            `json:"uid"`
	GID        uint32            `json:"gid"`
	Modified   unix.Timespec     `json:"modified"`
	Changed    unix.Timespec     `json:"changed"`
	Data       []byte            `json:"data"`
	Attributes map[string][]byte `json:"attributes"`
}

func recoveryImage(image sshFileImage) sshRecoveryImage {
	s := image.state
	attrs := make(map[string][]byte, len(image.attrs))
	for name, value := range image.attrs {
		attrs[name] = bytes.Clone(value)
	}
	return sshRecoveryImage{s.dev, s.ino, s.links, s.mode, s.uid, s.gid,
		s.modified, s.changed, bytes.Clone(image.data), attrs}
}

func (image sshRecoveryImage) validate(uid int, links uint64) error {
	if image.Inode == 0 || image.Links != links || int64(image.UID) != int64(uid) ||
		image.Mode&unix.S_IFMT != unix.S_IFREG || image.Mode&07133 != 0 || image.Mode&0400 == 0 ||
		len(image.Data) > MaxBytes || image.Data == nil || image.Attributes == nil ||
		image.Modified.Nsec < 0 || image.Modified.Nsec >= 1e9 || image.Changed.Nsec < 0 || image.Changed.Nsec >= 1e9 {
		return ErrInventoryUnsafe
	}
	return validateSSHAttributes(image.Attributes, true)
}

func (record sshPreparation) validate(uid int) error {
	if record.Schema != 1 || !lowerDigest.MatchString(record.Transaction) ||
		!lowerDigest.MatchString(record.PlanSHA256) || !lowerDigest.MatchString(record.ParserSHA256) {
		return ErrInventoryUnsafe
	}
	if err := record.MainBefore.validate(uid, 1); err != nil {
		return err
	}
	if err := record.MainAfter.validate(uid, 0); err != nil {
		return err
	}
	if err := record.DropIn.validate(uid, 0); err != nil {
		return err
	}
	if record.MainBefore.Mode != record.MainAfter.Mode || record.MainBefore.GID != record.MainAfter.GID ||
		!reflect.DeepEqual(record.MainBefore.Attributes, record.MainAfter.Attributes) ||
		record.MainBefore.Device != record.MainAfter.Device {
		return ErrInventoryUnsafe
	}
	images := []sshRecoveryImage{record.MainBefore, record.MainAfter, record.DropIn}
	for i, a := range images {
		for _, b := range images[i+1:] {
			if a.Device == b.Device && a.Inode == b.Inode {
				return ErrInventoryUnsafe
			}
		}
	}
	return nil
}

// prepareSSHRecord binds already inspected images to the exact approved plan.
// This helper does not grant approval, run a parser or authorize a live write.
func prepareSSHRecord(plan migrationPlan, approved, parser string, before sshFileImage, main, drop *sshAnonymousStage, uid int) (sshPreparation, error) {
	if plan.intent.Owner != "syswarden" || approved != plan.summary.PlanSHA256 || approved != planDigest(plan) ||
		main == nil || main.file == nil || drop == nil || drop.file == nil ||
		before.state != plan.inventory.nodes[MainPath] || !bytes.Equal(before.data, plan.inventory.files[MainPath]) ||
		!reflect.DeepEqual(before.attrs, plan.inventory.attributes[MainPath]) {
		return sshPreparation{}, ErrInventoryChanged
	}
	mainImage, err := readSSHImage(main.file, uid, 0, MaxBytes)
	if err != nil || !reflect.DeepEqual(mainImage, main.image) || !bytes.Equal(mainImage.data, plan.main) {
		return sshPreparation{}, errors.Join(ErrInventoryChanged, err)
	}
	dropImage, err := readSSHImage(drop.file, uid, 0, MaxBytes)
	if err != nil || !reflect.DeepEqual(dropImage, drop.image) || !bytes.Equal(dropImage.data, plan.candidate.Bytes()) {
		return sshPreparation{}, errors.Join(ErrInventoryChanged, err)
	}
	var random [32]byte
	if _, err := rand.Read(random[:]); err != nil {
		return sshPreparation{}, err
	}
	record := sshPreparation{1, hex.EncodeToString(random[:]), approved, parser,
		recoveryImage(before), recoveryImage(mainImage), recoveryImage(dropImage)}
	if err := record.validate(uid); err != nil {
		return sshPreparation{}, err
	}
	if err := checkSSHPublicationIsolation(plan, record.Transaction); err != nil {
		return sshPreparation{}, err
	}
	return record, nil
}

// sshJournal holds a nonblocking exclusive lock on a fixed protected directory.
// It requires the independent sibling receipt and exact private marker. It
// does not create or repair storage; the internal provisioner owns that step.
// This lock coordinates product processes only, not administrator tools.
type sshJournal struct {
	root      *os.File // borrowed for the handle lifetime
	directory *os.File
	uid       int
	poisoned  bool
	owner     sshFileImage
	// Sync injection is private to filesystem failure tests.
	syncDirectory func(*os.File) error
}

func openSSHJournal(root *os.File, uid int) (*sshJournal, error) {
	if root == nil {
		return nil, ErrInventoryUnsafe
	}
	owner, err := verifySSHStateOwner(root, uid)
	if err != nil {
		return nil, err
	}
	reader := inventoryReader{root: root, uid: uid, state: inventorySnapshot{nodes: make(map[string]inventoryStamp)}}
	directory, err := reader.openDirectory(sshJournalDirectory)
	if err != nil || directory == nil {
		return nil, errors.Join(ErrInventoryUnsafe, err)
	}
	keep := false
	defer func() {
		if !keep {
			_ = directory.Close()
		}
	}()
	var state unix.Stat_t
	if err := unix.Fstat(int(directory.Fd()), &state); err != nil || state.Mode&07777 != 0700 || int64(state.Gid) != int64(uid) {
		return nil, errors.Join(ErrInventoryUnsafe, err)
	}
	if err := unix.Flock(int(directory.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return nil, fmt.Errorf("SSH transaction directory is busy or cannot be locked: %w", err)
	}
	journal := &sshJournal{root: root, directory: directory, uid: uid, owner: owner, syncDirectory: (*os.File).Sync}
	if err := journal.recheck(); err != nil {
		return nil, err
	}
	keep = true
	return journal, nil
}

func (journal *sshJournal) recheck() error {
	if journal == nil || journal.directory == nil || journal.root == nil || journal.poisoned {
		return ErrInventoryClosed
	}
	journal.poisoned = true
	owner, err := verifySSHStateOwner(journal.root, journal.uid)
	if err != nil || !reflect.DeepEqual(owner, journal.owner) {
		return errors.Join(ErrInventoryChanged, err)
	}
	reader := inventoryReader{root: journal.root, uid: journal.uid, state: inventorySnapshot{nodes: make(map[string]inventoryStamp)}}
	current, err := reader.openDirectory(sshJournalDirectory)
	if err != nil || current == nil {
		return errors.Join(ErrInventoryChanged, err)
	}
	defer current.Close()
	var held, named unix.Stat_t
	err = errors.Join(unix.Fstat(int(journal.directory.Fd()), &held), unix.Fstat(int(current.Fd()), &named))
	if err != nil || held.Dev != named.Dev || held.Ino != named.Ino || held.Mode&07777 != 0700 ||
		held.Mode != named.Mode || held.Uid != named.Uid || held.Gid != named.Gid || int64(held.Gid) != int64(journal.uid) {
		return errors.Join(ErrInventoryChanged, err)
	}
	journal.poisoned = false
	return nil
}

func (journal *sshJournal) Close() error {
	if journal == nil || journal.directory == nil {
		return nil
	}
	err := journal.directory.Close() // releases the directory lock
	journal.directory = nil
	return err
}

func (journal *sshJournal) read() (sshPreparation, error) {
	data, err := journal.readRecord(sshPreparedRecord)
	if err != nil {
		return sshPreparation{}, err
	}
	return decodeSSHPreparation(data, journal.uid)
}

func sshRecordName(name string) bool {
	if name == sshPreparedRecord {
		return true
	}
	for step := 1; step <= 3; step++ {
		if name == sshPublicationName(step, false) || name == sshPublicationName(step, true) {
			return true
		}
	}
	return false
}

func (journal *sshJournal) readRecord(name string) ([]byte, error) {
	if !sshRecordName(name) {
		return nil, ErrInventoryUnsafe
	}
	if err := journal.recheck(); err != nil {
		return nil, err
	}
	fd, err := unix.Openat(int(journal.directory.Fd()), name,
		unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC|unix.O_NOCTTY, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "ssh-private-recovery-record")
	defer file.Close()
	image, err := readSSHImage(file, journal.uid, 1, maxSSHJournalBytes)
	if err != nil || image.state.mode&07777 != 0600 || int64(image.state.gid) != int64(journal.uid) {
		return nil, errors.Join(ErrInventoryUnsafe, err)
	}
	var named unix.Stat_t
	if err := unix.Fstatat(int(journal.directory.Fd()), name, &named, unix.AT_SYMLINK_NOFOLLOW); err != nil || stamp(named) != image.state {
		return nil, errors.Join(ErrInventoryChanged, err)
	}
	if err := journal.recheck(); err != nil {
		return nil, err
	}
	return image.data, nil
}

func decodeSSHPreparation(data []byte, uid int) (sshPreparation, error) {
	if len(data) == 0 || len(data) > maxSSHJournalBytes {
		return sshPreparation{}, ErrInventoryBounds
	}
	var record sshPreparation
	if err := json.Unmarshal(data, &record); err != nil {
		return sshPreparation{}, ErrInventoryUnsafe
	}
	// The only accepted on-disk form is our canonical encoding. This rejects
	// unknown/duplicate keys, aliases, nulls, whitespace and trailing values.
	encoded, err := json.Marshal(record)
	if err != nil || !bytes.Equal(encoded, data) {
		return sshPreparation{}, ErrInventoryUnsafe
	}
	if err := record.validate(uid); err != nil {
		return sshPreparation{}, err
	}
	return record, nil
}

func (journal *sshJournal) write(record sshPreparation) error {
	if err := journal.recheck(); err != nil {
		return err
	}
	if err := record.validate(journal.uid); err != nil {
		return err
	}
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	return journal.writeRecord(sshPreparedRecord, data)
}

func (journal *sshJournal) writeRecord(name string, data []byte) error {
	if !sshRecordName(name) {
		return ErrInventoryUnsafe
	}
	if err := journal.recheck(); err != nil {
		return err
	}
	uid := journal.uid
	if uid < 0 || uid > math.MaxUint32 {
		return ErrInventoryUnsafe
	}
	if len(data) == 0 || len(data) > maxSSHJournalBytes {
		return ErrInventoryBounds
	}
	file, err := openSSHAnonymous(journal.directory, journal.uid)
	if err != nil {
		return err
	}
	attrs, err := readSSHAttributes(int(file.Fd()))
	if err != nil {
		return errors.Join(err, file.Close())
	}
	if err := validateSSHAttributes(attrs, true); err != nil {
		return errors.Join(err, file.Close())
	}
	// Keep only the kernel-assigned label for this new private journal inode.
	// Do not transplant a directory's label or inherit discretionary ACLs.
	wanted := make(map[string][]byte)
	if label, exists := attrs["security.selinux"]; exists {
		wanted["security.selinux"] = label
	}
	stage, err := finishSSHAnonymous(file, data, 0600, uint32(uid), wanted, uid)
	if err != nil {
		return err
	}
	defer stage.Close()
	if err := journal.recheck(); err != nil {
		return err
	}
	// The proc path identifies only our retained unnamed descriptor. linkat
	// cannot overwrite an existing record, including an unrecognized one.
	if err := unix.Linkat(unix.AT_FDCWD, fmt.Sprintf("/proc/self/fd/%d", stage.file.Fd()),
		int(journal.directory.Fd()), name, unix.AT_SYMLINK_FOLLOW); err != nil {
		return err
	}
	if err := journal.syncDirectory(journal.directory); err != nil {
		journal.poisoned = true
		return fmt.Errorf("SSH journal durability is uncertain; retain the record for recovery: %w", err)
	}
	got, err := journal.readRecord(name)
	if err != nil || !bytes.Equal(got, data) {
		journal.poisoned = true
		return errors.Join(ErrInventoryChanged, err)
	}
	var named, retained unix.Stat_t
	err = errors.Join(unix.Fstatat(int(journal.directory.Fd()), name, &named, unix.AT_SYMLINK_NOFOLLOW),
		unix.Fstat(int(stage.file.Fd()), &retained))
	if err != nil || stamp(named) != stamp(retained) || retained.Dev != stage.image.state.dev ||
		retained.Ino != stage.image.state.ino || retained.Nlink != 1 {
		journal.poisoned = true
		return errors.Join(ErrInventoryChanged, err)
	}
	return nil
}
