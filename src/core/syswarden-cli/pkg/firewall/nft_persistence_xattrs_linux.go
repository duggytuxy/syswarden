//go:build linux

package firewall

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"sort"
	"strings"
	"unicode/utf8"

	"golang.org/x/sys/unix"
)

type nftPersistenceXattr struct {
	Name  string `json:"name"`
	Value []byte `json:"value"`
}

// Configuration replacement must retain ACLs, labels and administrator xattrs.
// A filesystem that cannot expose them is not silently treated as having none,
// except for the kernel's explicit unsupported-filesystem result.
func readNFTPersistenceXattrs(file *os.File) ([]nftPersistenceXattr, error) {
	if file == nil {
		return nil, fmt.Errorf("nftables persistence metadata requires a pinned file")
	}
	names := make([]byte, 65536)
	count, err := unix.Flistxattr(int(file.Fd()), names)
	if errors.Is(err, unix.ENOTSUP) {
		return []nftPersistenceXattr{}, nil
	}
	if err != nil || count < 0 || count > len(names) {
		return nil, fmt.Errorf("cannot inspect bounded nftables persistence extended attributes")
	}
	if count == 0 {
		return []nftPersistenceXattr{}, nil
	}
	encodedNames := string(names[:count])
	if !strings.HasSuffix(encodedNames, "\x00") {
		return nil, fmt.Errorf("nftables persistence extended attribute names are incomplete")
	}
	list := strings.Split(strings.TrimSuffix(encodedNames, "\x00"), "\x00")
	if len(list) > 256 {
		return nil, fmt.Errorf("nftables persistence extended attribute count exceeds its bound")
	}
	sort.Strings(list)
	var attrs []nftPersistenceXattr
	total := 0
	for index, name := range list {
		if name == "" || len(name) > 255 || !utf8.ValidString(name) || index > 0 && list[index-1] == name {
			return nil, fmt.Errorf("nftables persistence extended attribute names are invalid or ambiguous")
		}
		value := make([]byte, 65536)
		size, err := unix.Fgetxattr(int(file.Fd()), name, value)
		if err != nil || size < 0 || size > len(value) || total+size+len(name) > 1<<20 {
			return nil, fmt.Errorf("cannot inspect bounded nftables persistence extended attribute values")
		}
		value = bytes.Clone(value[:size])
		attrs = append(attrs, nftPersistenceXattr{name, value})
		total += size + len(name)
	}
	return attrs, nil
}

func nftPersistenceXattrDigest(attrs []nftPersistenceXattr) string {
	content, err := json.Marshal(attrs)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%x", sha256.Sum256(content))
}

// This helper accepts only a new, unpublished staging file. Removing inherited
// attributes from that private candidate never changes the active source.
func copyNFTPersistenceXattrs(stage *os.File, expected []nftPersistenceXattr) error {
	current, err := readNFTPersistenceXattrs(stage)
	if err != nil {
		return err
	}
	wanted := make(map[string][]byte, len(expected))
	already := make(map[string][]byte, len(current))
	for _, attr := range expected {
		if _, duplicate := wanted[attr.Name]; duplicate {
			return fmt.Errorf("duplicate nftables persistence staging attribute")
		}
		wanted[attr.Name] = attr.Value
	}
	for _, attr := range current {
		already[attr.Name] = attr.Value
		if _, retain := wanted[attr.Name]; !retain {
			if err := unix.Fremovexattr(int(stage.Fd()), attr.Name); err != nil {
				return fmt.Errorf("cannot preserve exact nftables persistence staging metadata")
			}
		}
	}
	for _, attr := range expected {
		if value, present := already[attr.Name]; present && bytes.Equal(value, attr.Value) {
			continue
		}
		if err := unix.Fsetxattr(int(stage.Fd()), attr.Name, attr.Value, 0); err != nil {
			return fmt.Errorf("cannot copy exact nftables persistence extended attributes")
		}
	}
	confirmed, err := readNFTPersistenceXattrs(stage)
	if err != nil || !reflect.DeepEqual(expected, confirmed) {
		return fmt.Errorf("nftables persistence staging metadata differs from the original")
	}
	return nil
}
