//go:build linux

package system

import (
	"bytes"
	"context"
	"crypto/sha1" // #nosec G505 -- native installed-file identity only; SHA-256 binds retained source bytes
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
)

// The APK payload omits the complete shared launcher subtree. This exact map
// also constrains fresh post-commit registration, independently of apk's
// symlink-target ownership query and without executing a product binary.
var apkLauncherPayloadModes = map[string]uint32{
	"opt": syscall.S_IFDIR | 0755, "opt/syswarden": syscall.S_IFDIR | 0755,
	"opt/syswarden/bin": syscall.S_IFDIR | 0755, "usr": syscall.S_IFDIR | 0755,
	"usr/share": syscall.S_IFDIR | 0755, "usr/share/bash-completion": syscall.S_IFDIR | 0755,
	"usr/share/bash-completion/completions": syscall.S_IFDIR | 0755,
	"usr/share/doc":                         syscall.S_IFDIR | 0755, "usr/share/doc/syswarden": syscall.S_IFDIR | 0755,
	"etc": syscall.S_IFDIR | 0755, "etc/apk": syscall.S_IFDIR | 0755,
	"etc/apk/commit_hooks.d":                          syscall.S_IFDIR | 0755,
	"opt/syswarden/bin/syswarden-cli":                 syscall.S_IFREG | 0750,
	"opt/syswarden/bin/syswarden-core":                syscall.S_IFREG | 0750,
	"opt/syswarden/bin/syswarden-tui":                 syscall.S_IFREG | 0750,
	"opt/syswarden/signatures.json":                   syscall.S_IFREG | 0640,
	"opt/syswarden/activation-contract-v1.json":       syscall.S_IFREG | 0644,
	"usr/share/bash-completion/completions/syswarden": syscall.S_IFREG | 0644,
	"usr/share/doc/syswarden/GEOIP-DATA-LICENSE.txt":  syscall.S_IFREG | 0644,
	"usr/share/doc/syswarden/LICENSE.txt":             syscall.S_IFREG | 0644,
	"etc/apk/commit_hooks.d/syswarden-recovery":       syscall.S_IFREG | 0755,
}

type apkLauncherPayloadFile struct {
	Path            string                `json:"path"`
	Identity        apkTransitionIdentity `json:"identity"`
	SHA256          string                `json:"sha256"`
	NativeSHA1      string                `json:"native_sha1"`
	NativeSHA256160 string                `json:"native_sha256_160"`
}

type apkLauncherNativeRecord struct {
	Name         string `json:"name"`
	Version      string `json:"version"`
	Checksum     string `json:"checksum"`
	RecordSHA256 string `json:"record_sha256"`
}

// apkLauncherReadFile pins each ancestor and uses no-follow, nonblocking opens
// for the final leaf. It never reads a FIFO, follows an alias, or writes state.
func apkLauncherReadFile(ctx context.Context, anchor *os.Root, path string, maximum int64, mode uint32, retain bool) (_ apkLauncherPayloadFile, content []byte, result error) {
	var value apkLauncherPayloadFile
	if ctx == nil || ctx.Err() != nil || anchor == nil || path == "." || filepath.IsAbs(path) || filepath.Clean(path) != path || strings.HasPrefix(path, "../") {
		return value, nil, errors.New("APK launcher source path or context is invalid")
	}
	type binding struct {
		parent, root *os.Root
		name         string
		identity     apkTransitionIdentity
	}
	var parents []binding
	defer func() {
		for i := len(parents) - 1; i >= 0; i-- {
			result = errors.Join(result, parents[i].root.Close())
		}
	}()
	current := anchor
	parts := strings.Split(path, "/")
	for _, name := range parts[:len(parts)-1] {
		before, err := current.Lstat(name)
		identity, identityErr := apkLauncherIdentity(before)
		if err != nil || identityErr != nil || !before.IsDir() || before.Mode()&os.ModeSymlink != 0 || !serviceFileOwnedByCurrentUser(before) || before.Mode().Perm()&0022 != 0 {
			return value, nil, errors.New("APK launcher source ancestry is unsafe")
		}
		next, err := current.OpenRoot(name)
		if err != nil {
			return value, nil, err
		}
		parents = append(parents, binding{current, next, name, identity})
		opened, err := next.Stat(".")
		if err != nil || !os.SameFile(before, opened) {
			return value, nil, errors.New("APK launcher source ancestry changed")
		}
		current = next
	}
	name := parts[len(parts)-1]
	before, err := current.Lstat(name)
	identity, identityErr := apkLauncherIdentity(before)
	if err != nil || identityErr != nil || !before.Mode().IsRegular() || !serviceFileOwnedByCurrentUser(before) || identity.Links != 1 || identity.Mode&0022 != 0 || identity.Size < 0 || identity.Size > maximum || mode != 0 && identity.Mode != mode {
		return value, nil, errors.New("APK launcher source file metadata is unsafe")
	}
	file, err := current.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return value, nil, err
	}
	defer func() { result = errors.Join(result, file.Close()) }()
	opened, err := file.Stat()
	openedIdentity, identityErr := apkLauncherIdentity(opened)
	if err != nil || identityErr != nil || openedIdentity != identity {
		return value, nil, errors.New("APK launcher source changed while opening")
	}
	sha, native := sha256.New(), sha1.New() // #nosec G401 -- APK installed checksum consistency, not release authentication
	var output bytes.Buffer
	writers := []io.Writer{sha, native}
	if retain {
		writers = append(writers, &output)
	}
	reader := io.LimitReader(file, identity.Size+1)
	buffer := make([]byte, 64<<10)
	var count int64
	for {
		if err := ctx.Err(); err != nil {
			return value, nil, err
		}
		n, readErr := reader.Read(buffer)
		if n > 0 {
			if _, err := io.MultiWriter(writers...).Write(buffer[:n]); err != nil {
				return value, nil, err
			}
			count += int64(n)
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return value, nil, readErr
		}
	}
	finished, err := file.Stat()
	finishedIdentity, identityErr := apkLauncherIdentity(finished)
	after, afterErr := current.Lstat(name)
	afterIdentity, afterIdentityErr := apkLauncherIdentity(after)
	if count != identity.Size || err != nil || identityErr != nil || afterErr != nil || afterIdentityErr != nil || finishedIdentity != identity || afterIdentity != identity {
		return value, nil, errors.New("APK launcher source changed during read")
	}
	for _, parent := range parents {
		named, err := parent.parent.Lstat(parent.name)
		namedIdentity, identityErr := apkLauncherIdentity(named)
		opened, openErr := parent.root.Stat(".")
		openedIdentity, openIdentityErr := apkLauncherIdentity(opened)
		if err != nil || identityErr != nil || openErr != nil || openIdentityErr != nil || !apkLauncherSameParent(parent.identity, namedIdentity) || !apkLauncherSameParent(parent.identity, openedIdentity) {
			return value, nil, errors.New("APK launcher source parent binding changed")
		}
	}
	digest := sha.Sum(nil)
	value = apkLauncherPayloadFile{path, identity, hex.EncodeToString(digest), "Q1" + base64.StdEncoding.EncodeToString(native.Sum(nil)), "Q1" + base64.StdEncoding.EncodeToString(digest[:20])}
	return value, output.Bytes(), nil
}

func captureAPKLauncherPayload(ctx context.Context, root *os.Root) ([]apkLauncherPayloadFile, error) {
	var names []string
	for path, mode := range apkLauncherPayloadModes {
		if mode&syscall.S_IFMT == syscall.S_IFREG {
			names = append(names, path)
		}
	}
	sort.Strings(names)
	files := make([]apkLauncherPayloadFile, 0, len(names))
	var candidate NativeActivationCandidate
	for _, path := range names {
		maximum := int64(maximumStandalonePayloadBytes)
		if path == nativeActivationDescriptorPath {
			maximum = maximumNativeActivationDescriptorBytes
		}
		file, raw, err := apkLauncherReadFile(ctx, root, path, maximum, apkLauncherPayloadModes[path], path == nativeActivationDescriptorPath)
		if err != nil {
			return nil, fmt.Errorf("attest fresh APK payload %s: %w", path, err)
		}
		if file.Identity.Size == 0 {
			return nil, errors.New("fresh APK payload is empty")
		}
		if path == nativeActivationDescriptorPath {
			candidate, err = parseNativeActivationDescriptor(raw)
			if err != nil {
				return nil, err
			}
		}
		files = append(files, file)
	}
	for _, file := range files {
		if file.Path == "etc/apk/commit_hooks.d/syswarden-recovery" && file.SHA256 != APKRecoveryHookSHA256() {
			return nil, errors.New("fresh APK recovery hook is not the fixed compiled consumer")
		}
		if file.Path == qualificationPackageCLIPath && file.SHA256 != candidate.descriptor.CLISHA256 || file.Path == nativeActivationCorePath && file.SHA256 != candidate.descriptor.CoreSHA256 {
			return nil, errors.New("fresh APK descriptor does not bind its actual runtimes")
		}
		current, _, err := apkLauncherReadFile(ctx, root, file.Path, int64(maximumStandalonePayloadBytes), apkLauncherPayloadModes[file.Path], false)
		if err != nil || current != file {
			return nil, errors.New("fresh APK payload set changed during capture")
		}
	}
	return files, nil
}

type apkLauncherRegistration struct {
	name, version, architecture, checksum, flags string
	fields                                       map[string]string
	entries                                      map[string]apkLauncherRegisteredEntry
	raw                                          string
}
type apkLauncherRegisteredEntry struct {
	mode         uint32
	checksum     string
	metadata     bool
	checksumSeen bool
}

// APK's F/R fields name the entry itself. Its a/M ACL defaults are 0644/0755
// with uid/gid zero. Native Q1 file digests use SHA-1, or SHA-256/160 when f:S
// selects that format. These identities never authenticate a release.
func parseAPKLauncherRegistrations(raw []byte) (map[string]apkLauncherRegistration, error) {
	if len(raw) == 0 || len(raw) > maximumAPKInstalledDatabaseSize || bytes.ContainsAny(raw, "\x00\r") {
		return nil, errors.New("APK launcher native database is malformed")
	}
	records := map[string]apkLauncherRegistration{}
	for _, block := range strings.Split(strings.TrimRight(string(raw), "\n"), "\n\n") {
		if block == "" {
			return nil, errors.New("APK launcher native record is empty")
		}
		record := apkLauncherRegistration{fields: map[string]string{}, entries: map[string]apkLauncherRegisteredEntry{}, raw: block}
		directory, entry := "", ""
		for _, line := range strings.Split(block, "\n") {
			if len(line) < 2 || line[1] != ':' || len(line) > 64<<10 {
				return nil, errors.New("APK launcher native field is malformed")
			}
			key, value := line[:1], line[2:]
			switch key {
			case "P", "V", "A", "C", "f":
				if _, exists := record.fields[key]; exists {
					return nil, errors.New("APK launcher native identity is duplicated")
				}
				record.fields[key] = value
			case "F":
				if value == "" || filepath.IsAbs(value) || filepath.Clean(value) != value || value == "." || value == ".." || strings.HasPrefix(value, "../") {
					return nil, errors.New("APK launcher native directory is not canonical")
				}
				directory, entry = value, value
				if _, exists := record.entries[entry]; exists {
					return nil, errors.New("APK launcher native directory is duplicated")
				}
				record.entries[entry] = apkLauncherRegisteredEntry{mode: syscall.S_IFDIR | 0755}
			case "R":
				if directory == "" || value == "" || filepath.Base(value) != value || value == "." || value == ".." {
					return nil, errors.New("APK launcher native leaf is not canonical")
				}
				entry = directory + "/" + value
				if _, exists := record.entries[entry]; exists {
					return nil, errors.New("APK launcher native leaf is duplicated")
				}
				record.entries[entry] = apkLauncherRegisteredEntry{mode: syscall.S_IFREG | 0644}
			case "M", "a":
				previous, exists := record.entries[entry]
				kind := uint32(syscall.S_IFREG)
				if key == "M" {
					kind = syscall.S_IFDIR
				}
				if !exists || previous.metadata || previous.mode&syscall.S_IFMT != kind {
					return nil, errors.New("APK launcher native metadata is misplaced")
				}
				parts := strings.Split(value, ":")
				if len(parts) < 3 || len(parts) > 4 {
					return nil, errors.New("APK launcher native ACL has unsupported attributes")
				}
				mode, err := strconv.ParseUint(parts[2], 8, 32)
				if err != nil || mode > 07777 || strconv.FormatUint(mode, 8) != parts[2] {
					return nil, errors.New("APK launcher native mode is not canonical")
				}
				// Preserve foreign package metadata without interpreting its ACL as
				// product authority. Product entries are checked exactly below.
				if parts[0] != "0" || parts[1] != "0" || len(parts) != 3 {
					mode |= 1 << 20
				}
				previous.mode, previous.metadata = kind|uint32(mode), true
				record.entries[entry] = previous
			case "Z":
				previous, exists := record.entries[entry]
				if !exists || previous.checksumSeen || previous.mode&syscall.S_IFMT != syscall.S_IFREG {
					return nil, errors.New("APK launcher native checksum is misplaced")
				}
				previous.checksum, previous.checksumSeen = value, true
				record.entries[entry] = previous
			}
		}
		record.name, record.version, record.architecture, record.checksum, record.flags = record.fields["P"], record.fields["V"], record.fields["A"], record.fields["C"], record.fields["f"]
		if record.name == "" || record.version == "" {
			return nil, errors.New("APK launcher native identity is incomplete")
		}
		if _, exists := records[record.name]; exists {
			return nil, errors.New("APK launcher native package is duplicated")
		}
		records[record.name] = record
	}
	return records, nil
}

func attestAPKLauncherCommittedRegistration(records map[string]apkLauncherRegistration, files []apkLauncherPayloadFile) (apkLauncherNativeRecord, error) {
	var selected apkLauncherRegistration
	count := 0
	for name, record := range records {
		if validNativeProductPackageName(name) {
			selected = record
			count++
		}
	}
	if count != 1 || selected.architecture != "x86_64" || !validAPKRetentionChecksum(selected.checksum) || selected.flags != "" && selected.flags != "S" {
		return apkLauncherNativeRecord{}, errors.New("fresh APK committed product identity is missing, ambiguous or unhealthy")
	}
	version, err := canonicalInstalledAPKVersionForName(selected.version, selected.name)
	if err != nil || version != Version {
		return apkLauncherNativeRecord{}, errors.New("fresh APK committed version differs from the running package")
	}
	if len(selected.entries) != len(apkLauncherPayloadModes) {
		return apkLauncherNativeRecord{}, errors.New("fresh APK committed payload inventory is not exact")
	}
	byPath := map[string]apkLauncherPayloadFile{}
	for _, file := range files {
		byPath[file.Path] = file
	}
	for path, mode := range apkLauncherPayloadModes {
		entry, exists := selected.entries[path]
		if !exists || entry.mode != mode {
			return apkLauncherNativeRecord{}, errors.New("fresh APK committed payload metadata differs")
		}
		if mode&syscall.S_IFMT == syscall.S_IFREG {
			file, exists := byPath[path]
			want := file.NativeSHA1
			if selected.flags == "S" {
				want = file.NativeSHA256160
			}
			if !exists || !entry.checksumSeen || entry.checksum != want {
				return apkLauncherNativeRecord{}, errors.New("fresh APK committed payload checksum differs from actual bytes")
			}
		} else if entry.checksumSeen {
			return apkLauncherNativeRecord{}, errors.New("fresh APK directory carries a file checksum")
		}
	}
	return apkLauncherNativeRecord{selected.name, version, selected.checksum, apkTransitionDigest([]byte(selected.raw))}, nil
}
