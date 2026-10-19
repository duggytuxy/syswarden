//go:build linux

package sshpolicy

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"reflect"
	"sort"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

const (
	MaxInventoryNodes   = 512
	MaxDirectoryEntries = 4096
)

var (
	ErrInventoryUnsafe  = errors.New("SSH inventory has unsafe storage or unsupported layout")
	ErrInventoryChanged = errors.New("SSH inventory changed; close and inspect again")
	ErrInventoryClosed  = errors.New("SSH inventory is closed")
	ErrInventoryBounds  = errors.New("SSH inventory exceeds resource bounds")
)

// Inventory retains a read-only root descriptor and immutable configuration
// observations. Do not copy it. It protects against ordinary unrelated UIDs,
// not root, the kernel, or a cooperating external writer. It is not a lock,
// role declaration, migration approval or publication transaction.
type Inventory struct {
	mu       sync.Mutex
	root     *os.File
	uid      int
	snapshot inventorySnapshot
	poisoned bool
}

type inventoryStamp struct {
	exists            bool
	dev, ino, links   uint64
	mode, uid, gid    uint32
	size              int64
	modified, changed unix.Timespec
}

func stamp(st unix.Stat_t) inventoryStamp {
	return inventoryStamp{true, uint64(st.Dev), st.Ino, uint64(st.Nlink), st.Mode, st.Uid, st.Gid, st.Size, st.Mtim, st.Ctim}
}

type inventorySnapshot struct {
	files   map[string][]byte
	nodes   map[string]inventoryStamp
	entries map[string][]string
	links   map[string]string
}

// OpenInventory reads the fixed production SSH configuration graph beneath /.
// Every ancestor and file must be root-owned and not group/other writable.
// It neither creates files nor runs sshd. Close the returned handle after use.
func OpenInventory() (*Inventory, error) {
	root, err := os.Open("/")
	if err != nil {
		return nil, err
	}
	defer root.Close()
	return openInventory(root, 0)
}

// The private fixture boundary accepts an already-open root and expected UID.
// Production never accepts a caller-supplied path, UID or environment override.
func openInventory(root *os.File, uid int) (*Inventory, error) {
	if root == nil {
		return nil, ErrInventoryUnsafe
	}
	raw, err := root.SyscallConn()
	if err != nil {
		return nil, errors.Join(ErrInventoryUnsafe, err)
	}
	fd := -1
	var openErr error
	err = raw.Control(func(parent uintptr) {
		fd, openErr = unix.Openat(int(parent), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	})
	if err != nil || openErr != nil {
		return nil, errors.Join(ErrInventoryUnsafe, err, openErr)
	}
	inventory := &Inventory{root: os.NewFile(uintptr(fd), "ssh-inventory-root"), uid: uid}
	inventory.snapshot, err = collectInventory(inventory.root, uid)
	if err == nil {
		err = inventory.recheck()
	}
	if err != nil {
		return nil, errors.Join(err, inventory.Close())
	}
	return inventory, nil
}

// Prepare first rereads all files, ancestor metadata, negative lookups and
// enumerated directory membership. Success is an inactive fixed-policy result,
// not permission to apply it to an undeclared host role.
func (inventory *Inventory) Prepare(profile Profile) (Candidate, error) {
	if inventory == nil {
		return Candidate{}, ErrInventoryClosed
	}
	inventory.mu.Lock()
	defer inventory.mu.Unlock()
	if err := inventory.recheck(); err != nil {
		return Candidate{}, err
	}
	return Prepare(profile, inventory.snapshot.files)
}

// Recheck detects persistent changes since capture. A detected change poisons
// the handle even if the old bytes are restored later. It does not serialize
// external managers or protect a later write; publication needs its own CAS.
func (inventory *Inventory) Recheck() error {
	if inventory == nil {
		return ErrInventoryClosed
	}
	inventory.mu.Lock()
	defer inventory.mu.Unlock()
	return inventory.recheck()
}

func (inventory *Inventory) recheck() error {
	if inventory.root == nil {
		return ErrInventoryClosed
	}
	if inventory.poisoned {
		return ErrInventoryChanged
	}
	inventory.poisoned = true
	current, err := collectInventory(inventory.root, inventory.uid)
	if err != nil || !reflect.DeepEqual(current, inventory.snapshot) {
		return errors.Join(ErrInventoryChanged, err)
	}
	inventory.poisoned = false
	return nil
}

func (inventory *Inventory) Close() error {
	if inventory == nil {
		return nil
	}
	inventory.mu.Lock()
	defer inventory.mu.Unlock()
	if inventory.root == nil {
		return nil
	}
	err := inventory.root.Close()
	inventory.root = nil
	inventory.snapshot = inventorySnapshot{}
	return err
}

type inventoryReader struct {
	root                            *os.File
	uid                             int
	state                           inventorySnapshot
	active, walked                  map[string]bool
	bytes, visits, patterns, listed int
}

func collectInventory(root *os.File, uid int) (inventorySnapshot, error) {
	reader := inventoryReader{root: root, uid: uid,
		state: inventorySnapshot{files: make(map[string][]byte), nodes: make(map[string]inventoryStamp),
			entries: make(map[string][]string), links: make(map[string]string)},
		active: make(map[string]bool), walked: make(map[string]bool)}
	// Record the reserved path even when the existing Include graph misses it.
	if _, _, err := reader.readFile(DropInPath); err != nil {
		return inventorySnapshot{}, err
	}
	if err := reader.walk(MainPath, 0, true); err != nil {
		return inventorySnapshot{}, err
	}
	return reader.state, nil
}

func (reader *inventoryReader) observe(name string, value inventoryStamp) error {
	if previous, exists := reader.state.nodes[name]; exists {
		if previous != value {
			return ErrInventoryChanged
		}
		return nil
	}
	if len(reader.state.nodes) >= MaxInventoryNodes {
		return ErrInventoryBounds
	}
	reader.state.nodes[name] = value
	return nil
}

func (reader *inventoryReader) trusted(st unix.Stat_t, directory bool) bool {
	if int64(st.Uid) != int64(reader.uid) || st.Mode&07022 != 0 || st.Nlink == 0 {
		return false
	}
	if directory {
		return st.Mode&unix.S_IFMT == unix.S_IFDIR && st.Mode&0100 != 0
	}
	return st.Mode&unix.S_IFMT == unix.S_IFREG && st.Mode&0111 == 0 && st.Nlink == 1 && st.Size >= 0 && st.Size <= MaxBytes
}

func (reader *inventoryReader) openDirectory(name string) (*os.File, error) {
	fd, err := unix.Openat(int(reader.root.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errors.Join(ErrInventoryUnsafe, err)
	}
	current := os.NewFile(uintptr(fd), "ssh-inventory-directory")
	defer func() {
		if current != nil {
			_ = current.Close()
		}
	}()
	var rootStamp unix.Stat_t
	if err := unix.Fstat(fd, &rootStamp); err != nil || !reader.trusted(rootStamp, true) {
		return nil, errors.Join(ErrInventoryUnsafe, err)
	}
	if err := reader.observe("/", stamp(rootStamp)); err != nil {
		return nil, err
	}
	prefix := ""
	for _, part := range strings.Split(strings.TrimPrefix(name, "/"), "/") {
		if part == "" {
			continue
		}
		prefix += "/" + part
		var before, opened, after unix.Stat_t
		err := unix.Fstatat(int(current.Fd()), part, &before, unix.AT_SYMLINK_NOFOLLOW)
		if errors.Is(err, unix.ENOENT) {
			return nil, reader.observe(prefix, inventoryStamp{})
		}
		if err != nil || !reader.trusted(before, true) {
			return nil, errors.Join(ErrInventoryUnsafe, err)
		}
		nextFD, err := unix.Openat(int(current.Fd()), part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return nil, errors.Join(ErrInventoryUnsafe, err)
		}
		next := os.NewFile(uintptr(nextFD), "ssh-inventory-directory")
		err = errors.Join(unix.Fstat(nextFD, &opened), unix.Fstatat(int(current.Fd()), part, &after, unix.AT_SYMLINK_NOFOLLOW))
		if err != nil || stamp(before) != stamp(opened) || stamp(opened) != stamp(after) {
			return nil, errors.Join(ErrInventoryChanged, err, next.Close())
		}
		if err := reader.observe(prefix, stamp(opened)); err != nil {
			return nil, errors.Join(err, next.Close())
		}
		if err := current.Close(); err != nil {
			return nil, errors.Join(err, next.Close())
		}
		current = next
	}
	result := current
	current = nil
	return result, nil
}

func (reader *inventoryReader) readFile(name string) ([]byte, bool, error) {
	if !safePath(name) {
		return nil, false, ErrInventoryUnsafe
	}
	if content, exists := reader.state.files[name]; exists {
		return content, true, nil
	}
	parent, err := reader.openDirectory(path.Dir(name))
	if err != nil || parent == nil {
		return nil, false, err
	}
	defer parent.Close()
	var before, opened, after unix.Stat_t
	err = unix.Fstatat(int(parent.Fd()), path.Base(name), &before, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return nil, false, reader.observe(name, inventoryStamp{})
	}
	if err != nil {
		return nil, false, errors.Join(ErrInventoryUnsafe, err)
	}
	if before.Mode&unix.S_IFMT == unix.S_IFLNK {
		return reader.readVendorLink(parent, name, before)
	}
	if !reader.trusted(before, false) {
		return nil, false, ErrInventoryUnsafe
	}
	if len(reader.state.files) >= MaxFiles || before.Size > int64(MaxBytes-reader.bytes) {
		return nil, false, ErrInventoryBounds
	}
	fd, err := unix.Openat(int(parent.Fd()), path.Base(name), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK|unix.O_NOCTTY, 0)
	if err != nil {
		return nil, false, errors.Join(ErrInventoryUnsafe, err)
	}
	file := os.NewFile(uintptr(fd), "ssh-inventory-configuration")
	defer file.Close()
	if err := unix.Fstat(fd, &opened); err != nil || stamp(before) != stamp(opened) {
		return nil, false, errors.Join(ErrInventoryChanged, err)
	}
	content, err := io.ReadAll(io.LimitReader(file, int64(MaxBytes-reader.bytes)+1))
	if err != nil || int64(len(content)) != opened.Size {
		return nil, false, errors.Join(ErrInventoryChanged, err)
	}
	err = errors.Join(unix.Fstat(fd, &after), unix.Fstatat(int(parent.Fd()), path.Base(name), &before, unix.AT_SYMLINK_NOFOLLOW))
	if err != nil || stamp(opened) != stamp(after) || stamp(after) != stamp(before) {
		return nil, false, errors.Join(ErrInventoryChanged, err)
	}
	if err := reader.observe(name, stamp(after)); err != nil {
		return nil, false, err
	}
	reader.bytes += len(content)
	reader.state.files[name] = content
	return content, true, nil
}

func (reader *inventoryReader) matches(pattern string) ([]string, error) {
	directory, base := path.Dir(pattern), path.Base(pattern)
	if strings.ContainsAny(directory, "*?") {
		return nil, ErrInventoryUnsafe
	}
	if !strings.ContainsAny(base, "*?") {
		return []string{pattern}, nil
	}
	names, exists := reader.state.entries[directory]
	if !exists {
		parent, err := reader.openDirectory(directory)
		if err != nil || parent == nil {
			return nil, err
		}
		defer parent.Close()
		var before, after unix.Stat_t
		if err := unix.Fstat(int(parent.Fd()), &before); err != nil {
			return nil, err
		}
		names = []string{}
		for {
			entries, err := parent.ReadDir(128)
			if err != nil && !errors.Is(err, io.EOF) {
				return nil, err
			}
			reader.listed += len(entries)
			if reader.listed > MaxDirectoryEntries {
				return nil, ErrInventoryBounds
			}
			for _, entry := range entries {
				// Avoid locale-dependent glob matching differences, even for
				// names the Go matcher would currently consider unmatched.
				if !printableASCII(entry.Name()) {
					return nil, ErrInventoryUnsafe
				}
				names = append(names, entry.Name())
			}
			if errors.Is(err, io.EOF) {
				break
			}
		}
		if err := unix.Fstat(int(parent.Fd()), &after); err != nil || stamp(before) != stamp(after) {
			return nil, errors.Join(ErrInventoryChanged, err)
		}
		sort.Strings(names)
		reader.state.entries[directory] = names
	}
	var matched []string
	for _, name := range names {
		ok, err := path.Match(base, name)
		if err != nil {
			return nil, err
		}
		if ok {
			matched = append(matched, path.Join(directory, name))
		}
	}
	return matched, nil
}

func (reader *inventoryReader) walk(name string, depth int, required bool) error {
	reader.visits++
	if depth > MaxIncludeDepth || reader.visits > MaxExpansions {
		return ErrInventoryBounds
	}
	if reader.active[name] {
		return fmt.Errorf("%w: cyclic Include graph", ErrInventoryUnsafe)
	}
	if reader.walked[name] {
		return nil
	}
	content, exists, err := reader.readFile(name)
	if err != nil {
		return err
	}
	if !exists {
		if required {
			return fmt.Errorf("%w: main configuration is missing", ErrInventoryUnsafe)
		}
		return nil
	}
	reader.active[name] = true
	defer delete(reader.active, name)
	if strings.IndexByte(string(content), 0) >= 0 {
		return ErrInventoryUnsafe
	}
	for _, line := range strings.Split(string(content), "\n") {
		if len(line) > MaxLineBytes {
			return ErrInventoryBounds
		}
		key, rest := splitDirective(line)
		if key != "include" {
			continue
		}
		patterns, err := arguments(rest)
		if err != nil || len(patterns) == 0 {
			return errors.Join(ErrInventoryUnsafe, err)
		}
		for _, input := range patterns {
			reader.patterns++
			if reader.patterns > MaxExpansions {
				return ErrInventoryBounds
			}
			pattern, err := includePattern(input)
			if err != nil {
				return errors.Join(ErrInventoryUnsafe, err)
			}
			matched, err := reader.matches(pattern)
			if err != nil {
				return err
			}
			for _, name := range matched {
				if err := reader.walk(name, depth+1, false); err != nil {
					return err
				}
			}
		}
	}
	reader.walked[name] = true
	return nil
}
