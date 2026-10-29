//go:build linux

package system

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path"
	"strings"
	"syscall"
)

// The historical path remains stable; the strict schema inside distinguishes capabilities.
const nativeActivationDescriptorPath = "opt/syswarden/activation-contract-v1.json"
const nativeActivationCorePath = "opt/syswarden/bin/syswarden-core"
const maximumNativeActivationDescriptorBytes = 4096
const nativePublicationExclusion = "config-directory-flock-and-native-debt-v1"

// This descriptor classifies authenticated runtime bytes. It never grants
// administrator approval, package replacement, service changes or activation.
type nativeActivationDescriptor struct {
	Schema               string `json:"schema"`
	Architecture         string `json:"architecture"`
	ApprovalSchema       string `json:"approval_schema"`
	SourceContract       string `json:"source_contract"`
	Environment          string `json:"environment"`
	CLISHA256            string `json:"cli_sha256"`
	CoreSHA256           string `json:"core_sha256"`
	PublicationExclusion string `json:"publication_exclusion,omitempty"`
}

// NativeActivationCandidate contains only a private immutable value captured
// from an already authenticated native package. A zero value has no capability.
type NativeActivationCandidate struct {
	descriptor nativeActivationDescriptor
	digest     string
}

type NativeActivationCandidateReview struct {
	Schema               string `json:"schema"`
	Architecture         string `json:"architecture"`
	ApprovalSchema       string `json:"approval_schema"`
	SourceContract       string `json:"source_contract"`
	Environment          string `json:"environment"`
	CLISHA256            string `json:"cli_sha256"`
	CoreSHA256           string `json:"core_sha256"`
	DescriptorSHA256     string `json:"descriptor_sha256"`
	PublicationExclusion string `json:"publication_exclusion,omitempty"`
}

func (candidate NativeActivationCandidate) Review() NativeActivationCandidateReview {
	d := candidate.descriptor
	return NativeActivationCandidateReview{d.Schema, d.Architecture, d.ApprovalSchema, d.SourceContract, d.Environment, d.CLISHA256, d.CoreSHA256, candidate.digest, d.PublicationExclusion}
}

// SHA256 binds the exact descriptor, not an approval or the complete package.
// The consuming transaction must separately bind its authenticated artifact.
func (candidate NativeActivationCandidate) SHA256() string { return candidate.digest }

func nativeActivationLegacyDescriptorFor(cli, core string) nativeActivationDescriptor {
	return nativeActivationDescriptor{Schema: "syswarden-native-activation-v1", Architecture: "linux-amd64",
		ApprovalSchema: "syswarden-activation-approval-v1", SourceContract: "syswarden-toml-source-v1",
		Environment: "toml-only-reject-modular-environment-v1", CLISHA256: cli, CoreSHA256: core}
}

func nativeActivationDescriptorFor(cli, core string) nativeActivationDescriptor {
	descriptor := nativeActivationLegacyDescriptorFor(cli, core)
	descriptor.Schema = "syswarden-native-activation-v2"
	descriptor.PublicationExclusion = nativePublicationExclusion
	return descriptor
}

func canonicalNativeActivationDescriptor(descriptor nativeActivationDescriptor) ([]byte, error) {
	if !validSHA256(descriptor.CLISHA256) || !validSHA256(descriptor.CoreSHA256) ||
		(descriptor != nativeActivationDescriptorFor(descriptor.CLISHA256, descriptor.CoreSHA256) &&
			descriptor != nativeActivationLegacyDescriptorFor(descriptor.CLISHA256, descriptor.CoreSHA256)) {
		return nil, errors.New("native activation descriptor has an unsupported runtime contract")
	}
	raw, err := json.Marshal(descriptor)
	return append(raw, '\n'), err
}

// publicationExclusion proves only the declared cooperative protocol of exact
// authenticated runtime bytes. It is neither inactive-host proof nor consent.
// Legacy v1 remains readable without acquiring this new capability implicitly.
func (candidate NativeActivationCandidate) publicationExclusion() bool {
	if candidate.descriptor != nativeActivationDescriptorFor(candidate.descriptor.CLISHA256, candidate.descriptor.CoreSHA256) {
		return false
	}
	raw, err := canonicalNativeActivationDescriptor(candidate.descriptor)
	return err == nil && apkTransitionDigest(raw) == candidate.digest
}

func parseNativeActivationDescriptor(raw []byte) (NativeActivationCandidate, error) {
	var empty NativeActivationCandidate
	if len(raw) == 0 || len(raw) > maximumNativeActivationDescriptorBytes {
		return empty, errors.New("native activation descriptor is absent or excessive")
	}
	var descriptor nativeActivationDescriptor
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&descriptor); err != nil {
		return empty, fmt.Errorf("decode native activation descriptor: %w", err)
	}
	canonical, err := canonicalNativeActivationDescriptor(descriptor)
	if err != nil {
		return empty, err
	}
	if !bytes.Equal(canonical, raw) {
		return empty, errors.New("native activation descriptor is not exact canonical JSON")
	}
	digest := sha256.Sum256(raw)
	return NativeActivationCandidate{descriptor: descriptor, digest: hex.EncodeToString(digest[:])}, nil
}

type nativeActivationPayload struct {
	seen       map[string]bool
	hashes     map[string]hash.Hash
	descriptor bytes.Buffer
}

func newNativeActivationPayload() *nativeActivationPayload {
	return &nativeActivationPayload{seen: map[string]bool{}, hashes: map[string]hash.Hash{}}
}

func (payload *nativeActivationPayload) member(name string, mode int64, uid, gid, links uint64, size int64, regular, directory bool, linkname string) (io.Writer, error) {
	name = strings.TrimPrefix(name, "./")
	if directory {
		name = strings.TrimSuffix(name, "/")
	}
	if name == "" || strings.HasPrefix(name, "/") || path.Clean(name) != name || name == ".." || strings.HasPrefix(name, "../") || strings.ContainsAny(name, "\x00\r\n\t") {
		return nil, errors.New("native activation payload contains an ambiguous path")
	}
	for _, target := range []string{qualificationPackageCLIPath, nativeActivationCorePath, nativeActivationDescriptorPath} {
		if strings.HasPrefix(target, name+"/") && (!directory || linkname != "" || uid != 0 || gid != 0 || mode != 0755) {
			return nil, errors.New("native activation payload has an unsafe runtime parent")
		}
		if strings.HasPrefix(name, target+"/") {
			return nil, errors.New("native activation payload places members below a runtime file")
		}
	}
	wantedMode := int64(0750)
	if name == nativeActivationDescriptorPath {
		wantedMode = 0644
	} else if name != qualificationPackageCLIPath && name != nativeActivationCorePath {
		return io.Discard, nil
	}
	if payload.seen[name] || !regular || linkname != "" || uid != 0 || gid != 0 || links != 1 || mode != wantedMode || size <= 0 || size > maximumStandalonePayloadBytes {
		return nil, fmt.Errorf("native activation payload has a duplicate or unsafe runtime member %q", name)
	}
	payload.seen[name] = true
	if name == nativeActivationDescriptorPath {
		if size > maximumNativeActivationDescriptorBytes {
			return nil, errors.New("native activation descriptor exceeds its bound")
		}
		return &payload.descriptor, nil
	}
	digest := sha256.New()
	payload.hashes[name] = digest
	return digest, nil
}

func (payload *nativeActivationPayload) tarMember(stream, name string, header *tar.Header) (io.Writer, error) {
	if stream != "apk-data" {
		return io.Discard, nil
	}
	if header.Uid < 0 || header.Gid < 0 {
		return nil, errors.New("native activation payload has negative ownership")
	}
	if name == qualificationPackageCLIPath || name == nativeActivationCorePath || name == nativeActivationDescriptorPath {
		for key := range header.PAXRecords {
			if key != "APK-TOOLS.checksum.SHA1" {
				return nil, errors.New("native activation runtime member has unsupported extended metadata")
			}
		}
		if header.Format == tar.FormatGNU {
			return nil, errors.New("native activation runtime member has unsupported GNU metadata")
		}
	}
	return payload.member(name, header.Mode, uint64(header.Uid), uint64(header.Gid), 1, header.Size, qualificationTarHeaderIsRegular(header.Typeflag), header.Typeflag == tar.TypeDir, header.Linkname)
}

func (payload *nativeActivationPayload) finish() (NativeActivationCandidate, error) {
	var empty NativeActivationCandidate
	if !payload.seen[nativeActivationDescriptorPath] {
		return empty, errors.New("candidate lacks a supported native activation descriptor; legacy artifacts are not activation-authorized")
	}
	candidate, err := parseNativeActivationDescriptor(payload.descriptor.Bytes())
	if err != nil {
		return empty, err
	}
	for name, want := range map[string]string{qualificationPackageCLIPath: candidate.descriptor.CLISHA256, nativeActivationCorePath: candidate.descriptor.CoreSHA256} {
		digest := payload.hashes[name]
		if digest == nil || hex.EncodeToString(digest.Sum(nil)) != want {
			return empty, fmt.Errorf("native activation descriptor disagrees with actual runtime bytes %q", name)
		}
	}
	return candidate, nil
}

// The caller must authenticate and revalidate the entire package descriptor
// using the signed artifact before and after this read-only classification.
func attestNativeActivationCandidate(ctx context.Context, target packageTarget, file *os.File) (NativeActivationCandidate, error) {
	return attestNativeActivationCandidateWith(ctx, target, file, runQualificationRPM2CPIO)
}

func attestNativeActivationCandidateWith(ctx context.Context, target packageTarget, file *os.File, convert qualificationRPMPayloadConverter) (NativeActivationCandidate, error) {
	var empty NativeActivationCandidate
	if ctx == nil {
		return empty, errors.New("native activation classification requires a context")
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	if _, err := qualificationPackageDescriptorSize(file, "native activation"); err != nil {
		return empty, err
	}
	payload := newNativeActivationPayload()
	var err error
	switch target.format {
	case packageFormatAPK:
		_, err = readAuthenticatedAPKObserved(ctx, file, payload.tarMember)
	case packageFormatDEB:
		err = readNativeActivationDEB(ctx, file, payload)
	case packageFormatRPM:
		err = readNativeActivationRPM(ctx, file, payload, convert)
	default:
		err = errors.New("native activation package format is unsupported")
	}
	if err != nil {
		return empty, err
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	return payload.finish()
}

func readNativeActivationDEB(ctx context.Context, file *os.File, payload *nativeActivationPayload) error {
	member, err := qualificationDEBDataMember(ctx, file)
	if err != nil {
		return err
	}
	compressedCount := int64(0)
	compressed := bufio.NewReader(qualificationExpandedReader{reader: member, total: &compressedCount, ctx: ctx})
	stream, err := gzip.NewReader(compressed)
	if err != nil {
		return err
	}
	stream.Multistream(false)
	expanded := int64(0)
	// DEB data uses the same complete, bounded tar framing as APK data. Only
	// payload entries are observed here; package identity is checked separately.
	_, _, readErr := readNativeHeaderTarObserved(&nativeHeaderReader{reader: stream, ctx: ctx, limit: maximumQualificationPackageExpandedBytes, total: &expanded}, "apk-data", payload.tarMember)
	if err := errors.Join(readErr, stream.Close()); err != nil {
		return err
	}
	if _, err := compressed.Peek(1); !errors.Is(err, io.EOF) {
		return errors.New("native activation DEB has trailing compressed data")
	}
	return ctx.Err()
}

func readNativeActivationRPM(ctx context.Context, file *os.File, payload *nativeActivationPayload, convert qualificationRPMPayloadConverter) error {
	if convert == nil {
		return errors.New("native activation RPM decoder is unavailable")
	}
	bounded, cancel := context.WithCancel(ctx)
	defer cancel()
	reader, writer := io.Pipe()
	converted := make(chan error, 1)
	go func() { err := convert(bounded, file, writer); _ = writer.CloseWithError(err); converted <- err }()
	parseErr := readNativeActivationCPIO(bounded, reader, payload)
	_ = reader.CloseWithError(parseErr)
	if parseErr != nil {
		cancel()
	}
	return errors.Join(parseErr, <-converted)
}

func readNativeActivationCPIO(ctx context.Context, input io.Reader, payload *nativeActivationPayload) error {
	expanded := int64(0)
	reader := qualificationExpandedReader{reader: input, total: &expanded, ctx: ctx}
	for entries := 0; entries < 200000; entries++ {
		var header [110]byte
		if _, err := io.ReadFull(reader, header[:]); err != nil {
			return err
		}
		if string(header[:6]) != "070701" {
			return errors.New("native activation RPM requires canonical newc cpio")
		}
		var fields [13]uint64
		for i := range fields {
			value, err := parseQualificationCPIOHex(header[6+i*8 : 14+i*8])
			if err != nil {
				return err
			}
			fields[i] = value
		}
		size, nameSize := fields[6], fields[11]
		if nameSize < 2 || nameSize > 4096 || size > uint64(maximumQualificationPackageExpandedBytes) || fields[12] != 0 || fields[1]&^uint64(0177777) != 0 {
			return errors.New("native activation cpio member exceeds bounds")
		}
		nameBytes := make([]byte, nameSize)
		if _, err := io.ReadFull(reader, nameBytes); err != nil {
			return err
		}
		if nameBytes[len(nameBytes)-1] != 0 || bytes.IndexByte(nameBytes[:len(nameBytes)-1], 0) >= 0 {
			return errors.New("native activation cpio name is malformed")
		}
		if err := readQualificationCPIOPadding(reader, 110+nameSize); err != nil {
			return err
		}
		name := string(nameBytes[:len(nameBytes)-1])
		if name == "TRAILER!!!" {
			if size != 0 {
				return errors.New("native activation cpio trailer has content")
			}
			trailing, err := io.ReadAll(io.LimitReader(reader, 4097))
			if err != nil {
				return err
			}
			if len(trailing) > 4096 || !bytes.Equal(trailing, make([]byte, len(trailing))) {
				return errors.New("native activation cpio trailer has foreign data")
			}
			return ctx.Err()
		}
		sink, err := payload.member(name, int64(fields[1]&07777), fields[2], fields[3], fields[4], int64(size), fields[1]&0170000 == 0100000, fields[1]&0170000 == 0040000, "")
		if err != nil {
			return err
		}
		if _, err := io.CopyN(sink, reader, int64(size)); err != nil {
			return err
		}
		if err := readQualificationCPIOPadding(reader, size); err != nil {
			return err
		}
	}
	return errors.New("native activation cpio inventory exceeds bounds")
}

// VerifyInstalled rechecks exact descriptor and both runtimes through protected
// pinned ancestry. It neither executes binaries nor grants approval to apply.
func (candidate NativeActivationCandidate) VerifyInstalled(ctx context.Context) error {
	return candidate.verifyInstalledAt(ctx, "/", 0, 0)
}

func (candidate NativeActivationCandidate) verifyInstalledAt(ctx context.Context, anchor string, uid, gid uint32) (returnErr error) {
	if ctx == nil {
		return errors.New("installed native activation verification requires a context")
	}
	raw, err := canonicalNativeActivationDescriptor(candidate.descriptor)
	if err != nil {
		return err
	}
	validated, err := parseNativeActivationDescriptor(raw)
	if err != nil || validated != candidate {
		return errors.New("native activation candidate is unclassified")
	}
	root, err := os.OpenRoot(anchor)
	if err != nil {
		return err
	}
	defer func() { returnErr = errors.Join(returnErr, root.Close()) }()
	identities := make(map[string]removalArtifactIdentity)
	// Recheck the complete captured set after its first pass. A replacement or
	// edit of an earlier member while reading a later member cannot be accepted.
	for pass := 0; pass < 2; pass++ {
		for name, want := range map[string]string{nativeActivationDescriptorPath: candidate.digest, qualificationPackageCLIPath: candidate.descriptor.CLISHA256, nativeActivationCorePath: candidate.descriptor.CoreSHA256} {
			if err := ctx.Err(); err != nil {
				return err
			}
			if err := verifyInstalledNativeActivationFile(ctx, root, name, want, uid, gid, identities); err != nil {
				return err
			}
		}
	}
	return ctx.Err()
}

func verifyInstalledNativeActivationFile(ctx context.Context, anchor *os.Root, name, want string, uid, gid uint32, identities map[string]removalArtifactIdentity) (returnErr error) {
	remember := func(name string, identity removalArtifactIdentity) error {
		if prior, found := identities[name]; found && prior != identity {
			return errors.New("installed native activation source set changed")
		}
		identities[name] = identity
		return nil
	}
	current := anchor
	var roots []*os.Root
	defer func() {
		for i := len(roots) - 1; i >= 0; i-- {
			returnErr = errors.Join(returnErr, roots[i].Close())
		}
	}()
	type directoryBinding struct {
		parent   *os.Root
		name     string
		identity removalArtifactIdentity
	}
	var bindings []directoryBinding
	checkDirectory := func(info os.FileInfo) (removalArtifactIdentity, error) {
		identity, err := exactRemovalArtifactIdentity(info)
		if err != nil || !info.IsDir() || identity.uid != uid || info.Mode().Perm()&0022 != 0 {
			return identity, errors.New("installed native activation ancestry is unsafe")
		}
		return identity, nil
	}
	info, err := anchor.Stat(".")
	if err != nil {
		return err
	}
	anchorIdentity, err := checkDirectory(info)
	if err != nil {
		return err
	}
	if err := remember(".", anchorIdentity); err != nil {
		return err
	}
	parts := strings.Split(name, "/")
	for index, component := range parts[:len(parts)-1] {
		info, err := current.Lstat(component)
		if err != nil {
			return err
		}
		before, err := checkDirectory(info)
		if err != nil {
			return err
		}
		if err := remember(strings.Join(parts[:index+1], "/"), before); err != nil {
			return err
		}
		next, err := current.OpenRoot(component)
		if err != nil {
			return err
		}
		roots = append(roots, next)
		opened, err := next.Stat(".")
		if err != nil {
			return err
		}
		after, err := checkDirectory(opened)
		if err != nil || after != before {
			return errors.New("installed native activation ancestry changed")
		}
		bindings = append(bindings, directoryBinding{current, component, before})
		current = next
	}
	leaf := parts[len(parts)-1]
	before, err := current.Lstat(leaf)
	if err != nil {
		return err
	}
	identity, err := exactRemovalArtifactIdentity(before)
	if err != nil {
		return err
	}
	wantMode := os.FileMode(0750)
	maximum := int64(maximumStandalonePayloadBytes)
	if name == nativeActivationDescriptorPath {
		wantMode = 0644
		maximum = maximumNativeActivationDescriptorBytes
	}
	if !before.Mode().IsRegular() || before.Mode() != wantMode || identity.uid != uid || identity.gid != gid || identity.nlink != 1 || identity.size <= 0 || identity.size > maximum {
		return errors.New("installed native activation runtime metadata is unsafe")
	}
	if err := remember(name, identity); err != nil {
		return err
	}
	file, err := current.OpenFile(leaf, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer func() { returnErr = errors.Join(returnErr, file.Close()) }()
	opened, err := file.Stat()
	if err != nil {
		return err
	}
	actual, err := exactRemovalArtifactIdentity(opened)
	if err != nil || actual != identity {
		return errors.New("installed native activation file changed while opening")
	}
	digest := sha256.New()
	count := int64(0)
	buffer := make([]byte, 64<<10)
	for count <= identity.size {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, readErr := file.Read(buffer)
		count += int64(n)
		_, _ = digest.Write(buffer[:n])
		if count > identity.size {
			return errors.New("installed native activation file grew")
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return readErr
		}
	}
	if count != identity.size || hex.EncodeToString(digest.Sum(nil)) != want {
		return errors.New("installed native activation bytes disagree with authenticated candidate")
	}
	for _, stat := range []func() (os.FileInfo, error){file.Stat, func() (os.FileInfo, error) { return current.Lstat(leaf) }} {
		info, err := stat()
		if err != nil {
			return err
		}
		actual, err := exactRemovalArtifactIdentity(info)
		if err != nil || actual != identity {
			return errors.New("installed native activation file changed during hashing")
		}
	}
	for _, binding := range bindings {
		info, err := binding.parent.Lstat(binding.name)
		if err != nil {
			return err
		}
		actual, err := checkDirectory(info)
		if err != nil || actual != binding.identity {
			return errors.New("installed native activation ancestry changed during hashing")
		}
	}
	info, err = anchor.Stat(".")
	if err != nil {
		return err
	}
	actual, err = checkDirectory(info)
	if err != nil || actual != anchorIdentity {
		return errors.New("installed native activation anchor changed during hashing")
	}
	return ctx.Err()
}
