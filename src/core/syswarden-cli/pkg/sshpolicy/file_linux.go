//go:build linux

package sshpolicy

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"
	"unicode/utf8"

	"golang.org/x/sys/unix"
)

const maxSSHAttributes = 32 << 10

// Attribute values can contain private labels. Errors deliberately omit names
// and values. Reading integrity attributes is permitted; rewriting them is not.
func readSSHAttributes(fd int) (map[string][]byte, error) {
	buffer := make([]byte, maxSSHAttributes)
	n, err := unix.Flistxattr(fd, buffer)
	if errors.Is(err, unix.ENOTSUP) {
		return map[string][]byte{}, nil
	}
	if err != nil || n < 0 || n > len(buffer) {
		return nil, errors.Join(ErrInventoryBounds, err)
	}
	result := make(map[string][]byte)
	remaining := maxSSHAttributes - n
	if n == 0 {
		return result, nil
	}
	names, terminated := strings.CutSuffix(string(buffer[:n]), "\x00")
	if !terminated {
		return nil, ErrInventoryUnsafe
	}
	for _, name := range strings.Split(names, "\x00") {
		if name == "" {
			return nil, ErrInventoryUnsafe
		}
		if _, exists := result[name]; exists {
			return nil, ErrInventoryUnsafe
		}
		// A zero-length syscall buffer asks for a size instead of reading bytes.
		// Keep one byte allocated even when the total bound has been consumed.
		value := make([]byte, max(1, remaining))
		size, err := unix.Fgetxattr(fd, name, value)
		if err != nil || size < 0 || size > remaining {
			return nil, errors.Join(ErrInventoryBounds, err)
		}
		result[name] = value[:size]
		remaining -= size
	}
	return result, nil
}

func validateSSHAttributes(attrs map[string][]byte, rewrite bool) error {
	remaining := maxSSHAttributes
	for name, value := range attrs {
		if name == "" || !utf8.ValidString(name) || strings.ContainsRune(name, 0) || len(name) > 255 {
			return ErrInventoryUnsafe
		}
		remaining -= len(name) + 1 + len(value)
		if remaining < 0 {
			return ErrInventoryBounds
		}
		if rewrite {
			switch name {
			case "security.ima", "security.evm", "security.capability", "system.posix_acl_default":
				return fmt.Errorf("SSH replacement cannot transplant integrity, capability or directory-only attributes")
			}
		}
	}
	return nil
}

// replaceSSHAttributes operates only on an unnamed, newly created inode.
// Inherited ACLs/labels absent from the reviewed image must not survive. A host
// refusing an exact attribute operation fails closed without a weaker fallback.
func replaceSSHAttributes(fd int, wanted map[string][]byte) error {
	if err := validateSSHAttributes(wanted, true); err != nil {
		return err
	}
	current, err := readSSHAttributes(fd)
	if err != nil {
		return err
	}
	if err := validateSSHAttributes(current, true); err != nil {
		return err
	}
	for _, name := range sortedKeys(current) {
		if _, keep := wanted[name]; !keep {
			if err := unix.Fremovexattr(fd, name); err != nil {
				return fmt.Errorf("remove inherited SSH stage attribute: %w", err)
			}
		}
	}
	for _, name := range sortedKeys(wanted) {
		if value, exists := current[name]; exists && bytes.Equal(value, wanted[name]) {
			continue
		}
		if err := unix.Fsetxattr(fd, name, wanted[name], 0); err != nil {
			return fmt.Errorf("preserve SSH stage attribute: %w", err)
		}
	}
	actual, err := readSSHAttributes(fd)
	if err != nil || !reflect.DeepEqual(actual, wanted) {
		return errors.Join(ErrInventoryChanged, err)
	}
	return nil
}

// sshFileImage is private recovery data, never a public command result.
type sshFileImage struct {
	state inventoryStamp
	data  []byte
	attrs map[string][]byte
}

func readSSHImage(file *os.File, uid int, links uint64, maximum int) (sshFileImage, error) {
	if file == nil || maximum < 1 || maximum > maxSSHJournalBytes || links > 1 {
		return sshFileImage{}, ErrInventoryUnsafe
	}
	fd := int(file.Fd())
	var before, after unix.Stat_t
	if err := unix.Fstat(fd, &before); err != nil {
		return sshFileImage{}, err
	}
	if int64(before.Uid) != int64(uid) || before.Mode&unix.S_IFMT != unix.S_IFREG ||
		before.Mode&07133 != 0 || before.Nlink != links || before.Size < 0 || before.Size > int64(maximum) {
		return sshFileImage{}, ErrInventoryUnsafe
	}
	attrs, err := readSSHAttributes(fd)
	if err != nil {
		return sshFileImage{}, err
	}
	data, err := io.ReadAll(io.NewSectionReader(file, 0, int64(maximum)+1))
	if err != nil || int64(len(data)) != before.Size {
		return sshFileImage{}, errors.Join(ErrInventoryChanged, err)
	}
	lastAttrs, err := readSSHAttributes(fd)
	if err != nil || !reflect.DeepEqual(attrs, lastAttrs) {
		return sshFileImage{}, errors.Join(ErrInventoryChanged, err)
	}
	if err := unix.Fstat(fd, &after); err != nil || stamp(before) != stamp(after) {
		return sshFileImage{}, errors.Join(ErrInventoryChanged, err)
	}
	return sshFileImage{stamp(after), data, attrs}, nil
}

type sshAnonymousStage struct {
	file  *os.File
	image sshFileImage
}

// newSSHAnonymousStage prepares a complete inode without any directory entry.
// It neither overwrites nor publishes a configuration. Later publication must
// first retain this exact inode identity in a durable approved journal.
func newSSHAnonymousStage(directory *os.File, data []byte, mode, gid uint32, attrs map[string][]byte, uid int) (*sshAnonymousStage, error) {
	if directory == nil || len(data) > maxSSHJournalBytes || mode&^uint32(0666) != 0 || mode&0022 != 0 || mode&0400 == 0 || attrs == nil {
		return nil, ErrInventoryUnsafe
	}
	if err := validateSSHAttributes(attrs, true); err != nil {
		return nil, err
	}
	file, err := openSSHAnonymous(directory, uid)
	if err != nil {
		return nil, err
	}
	return finishSSHAnonymous(file, data, mode, gid, attrs, uid)
}

func openSSHAnonymous(directory *os.File, uid int) (*os.File, error) {
	if directory == nil {
		return nil, ErrInventoryUnsafe
	}
	var parent unix.Stat_t
	if err := unix.Fstat(int(directory.Fd()), &parent); err != nil ||
		!(&inventoryReader{uid: uid}).trusted(parent, true) {
		return nil, errors.Join(ErrInventoryUnsafe, err)
	}
	fd, err := unix.Openat(int(directory.Fd()), ".", unix.O_RDWR|unix.O_CLOEXEC|unix.O_TMPFILE, 0600)
	if err != nil {
		return nil, fmt.Errorf("unnamed SSH staging is unavailable: %w", err)
	}
	return os.NewFile(uintptr(fd), "ssh-private-stage"), nil
}

// finishSSHAnonymous takes ownership of the unnamed descriptor on every path.
func finishSSHAnonymous(file *os.File, data []byte, mode, gid uint32, attrs map[string][]byte, uid int) (*sshAnonymousStage, error) {
	fd := int(file.Fd())
	keep := false
	defer func() {
		if !keep {
			_ = file.Close()
		}
	}()
	if err := file.Chown(uid, int(gid)); err != nil {
		return nil, err
	}
	if n, err := file.Write(data); err != nil || n != len(data) {
		return nil, errors.Join(io.ErrShortWrite, err)
	}
	if err := file.Chmod(os.FileMode(mode)); err != nil {
		return nil, err
	}
	if err := replaceSSHAttributes(fd, attrs); err != nil {
		return nil, err
	}
	if err := file.Sync(); err != nil {
		return nil, err
	}
	image, err := readSSHImage(file, uid, 0, maxSSHJournalBytes)
	if err != nil || image.state.mode&07777 != mode || image.state.gid != gid ||
		!bytes.Equal(image.data, data) || !reflect.DeepEqual(image.attrs, attrs) {
		return nil, errors.Join(ErrInventoryChanged, err)
	}
	keep = true
	return &sshAnonymousStage{file, image}, nil
}

func (stage *sshAnonymousStage) Close() error {
	if stage == nil || stage.file == nil {
		return nil
	}
	err := stage.file.Close()
	stage.file = nil
	return err
}
