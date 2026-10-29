package system

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	maximumNativeHeaderMetadataBytes = 64 << 10
	maximumNativeControlBytes        = 8 << 20
	maximumNativeTarPaddingBytes     = 64 << 10
)

// nativeHeaderReader bounds each archive and the complete expanded package.
// It reads through SectionReader, so the caller's descriptor offset is preserved.
type nativeHeaderReader struct {
	reader io.Reader
	ctx    context.Context
	limit  int64
	count  int64
	total  *int64
}

func (reader *nativeHeaderReader) Read(buffer []byte) (int, error) {
	if err := reader.ctx.Err(); err != nil {
		return 0, err
	}
	remaining := min(reader.limit-reader.count, maximumQualificationPackageExpandedBytes-*reader.total)
	if remaining < 0 {
		return 0, errors.New("authenticated package header archive exceeds its expanded bound")
	}
	if int64(len(buffer)) > remaining+1 {
		buffer = buffer[:remaining+1]
	}
	n, err := reader.reader.Read(buffer)
	reader.count += int64(n)
	*reader.total += int64(n)
	if reader.count > reader.limit || *reader.total > maximumQualificationPackageExpandedBytes {
		return n, errors.New("authenticated package header archive exceeds its expanded bound")
	}
	if contextErr := reader.ctx.Err(); contextErr != nil {
		return n, contextErr
	}
	return n, err
}

func nativeHeaderTextIsSafe(text string, allowWhitespace bool) bool {
	if !utf8.ValidString(text) {
		return false
	}
	for _, character := range text {
		if allowWhitespace && (character == '\n' || character == '\t') {
			continue
		}
		if unicode.IsControl(character) || character == '\u2028' || character == '\u2029' ||
			(!allowWhitespace && unicode.IsSpace(character)) {
			return false
		}
	}
	return true
}

func nativeHeaderValue(value string) bool {
	return value != "" && len(value) <= 1024 && nativeHeaderTextIsSafe(value, false)
}

func nativeHeaderFieldName(name string) bool {
	if name == "" {
		return false
	}
	for _, character := range name {
		if !((character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '-' || character == '_') {
			return false
		}
	}
	return true
}

func parseAuthenticatedDEBControl(data []byte) (nativePackageHeaderIdentity, error) {
	identity := nativePackageHeaderIdentity{}
	if len(data) == 0 || len(data) > maximumNativeHeaderMetadataBytes || data[len(data)-1] != '\n' || !nativeHeaderTextIsSafe(string(data), true) {
		return identity, errors.New("authenticated DEB control metadata is malformed or excessive")
	}
	seen := make(map[string]bool)
	previous, ended := "", false
	for _, line := range strings.Split(strings.TrimSuffix(string(data), "\n"), "\n") {
		if line == "" {
			ended = true
			continue
		}
		if ended {
			return nativePackageHeaderIdentity{}, errors.New("authenticated DEB control contains multiple paragraphs")
		}
		if line[0] == ' ' || line[0] == '\t' {
			if previous == "" || previous == "package" || previous == "version" || previous == "architecture" {
				return nativePackageHeaderIdentity{}, errors.New("authenticated DEB identity field is continued or ambiguous")
			}
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		key = strings.ToLower(key)
		if !ok || !nativeHeaderFieldName(key) || seen[key] {
			return nativePackageHeaderIdentity{}, errors.New("authenticated DEB control field is malformed or duplicated")
		}
		seen[key], previous = true, key
		value = strings.Trim(value, " \t")
		switch key {
		case "package", "version", "architecture":
			if !nativeHeaderValue(value) {
				return nativePackageHeaderIdentity{}, errors.New("authenticated DEB identity field is invalid")
			}
			switch key {
			case "package":
				identity.name = value
			case "version":
				identity.version = value
			case "architecture":
				identity.architecture = value
			}
		}
	}
	if identity.name == "" || identity.version == "" || identity.architecture == "" {
		return nativePackageHeaderIdentity{}, errors.New("authenticated DEB control lacks an exact package identity")
	}
	return identity, nil
}

func parseAuthenticatedAPKInfo(data []byte) (nativePackageHeaderIdentity, error) {
	identity := nativePackageHeaderIdentity{}
	if len(data) == 0 || len(data) > maximumNativeHeaderMetadataBytes || data[len(data)-1] != '\n' || !nativeHeaderTextIsSafe(string(data), true) {
		return identity, errors.New("authenticated APK metadata is malformed or excessive")
	}
	seen := make(map[string]bool)
	for _, line := range strings.Split(strings.TrimSuffix(string(data), "\n"), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, " = ")
		if !ok || !nativeHeaderFieldName(key) {
			return nativePackageHeaderIdentity{}, errors.New("authenticated APK metadata field is malformed")
		}
		lowerKey := strings.ToLower(key)
		if lowerKey != "pkgname" && lowerKey != "pkgver" && lowerKey != "arch" {
			continue // Repeated dependency and provide fields are valid APK metadata.
		}
		if key != lowerKey || seen[key] || !nativeHeaderValue(value) {
			return nativePackageHeaderIdentity{}, errors.New("authenticated APK identity field is invalid or duplicated")
		}
		seen[key] = true
		switch key {
		case "pkgname":
			identity.name = value
		case "pkgver":
			identity.version = value
		case "arch":
			identity.architecture = value
		}
	}
	if identity.name == "" || identity.version == "" || identity.architecture == "" {
		return nativePackageHeaderIdentity{}, errors.New("authenticated APK metadata lacks an exact package identity")
	}
	return identity, nil
}

func nativeHeaderTarName(header *tar.Header) (string, error) {
	if header.Typeflag == tar.TypeDir && (header.Name == "." || header.Name == "./") {
		return ".", nil
	}
	name := strings.TrimPrefix(header.Name, "./")
	if header.Typeflag == tar.TypeDir {
		name = strings.TrimSuffix(name, "/")
	}
	if name == "" || !nativeHeaderTextIsSafe(name, true) || strings.ContainsAny(name, "\n\t") || strings.HasPrefix(name, "/") ||
		path.Clean(name) != name || name == ".." || strings.HasPrefix(name, "../") {
		return "", errors.New("authenticated package header archive has an unsafe member name")
	}
	return name, nil
}

// kind is deb-control, apk-first, apk-control, apk-signature, or apk-data.
// APK signature/control archives may be cut tar streams without end blocks,
// as emitted by nfpm; DEB control and APK data require a complete tar ending.
func readNativeHeaderTar(reader *nativeHeaderReader, kind string) ([]byte, string, error) {
	return readNativeHeaderTarObserved(reader, kind, nil)
}

type nativeHeaderMemberObserver func(string, string, *tar.Header) (io.Writer, error)

func readNativeHeaderTarObserved(reader *nativeHeaderReader, kind string, observe nativeHeaderMemberObserver) ([]byte, string, error) {
	return readNativeHeaderTarObservedFraming(reader, kind, observe, false)
}

func readNativeHeaderTarObservedFraming(reader *nativeHeaderReader, kind string, observe nativeHeaderMemberObserver, strictAPKCut bool) ([]byte, string, error) {
	archive := tar.NewReader(reader)
	var metadata []byte
	var padding int64
	entries := 0
	for {
		before := reader.count
		header, err := archive.Next()
		if errors.Is(err, io.EOF) {
			ending := reader.count - before - padding
			if entries == 0 || (ending != 0 && ending != 1024) ||
				((kind == "deb-control" || kind == "apk-data") && ending != 1024) ||
				(strictAPKCut && (kind == "apk-signature" || kind == "apk-control") && ending != 0) {
				return nil, kind, errors.New("authenticated package header tar ending is invalid")
			}
			break
		}
		if err != nil {
			return nil, kind, fmt.Errorf("read authenticated package header tar: %w", err)
		}
		// archive/tar synthesizes sparse holes without reading through the
		// expanded-byte counter. Current package builders emit no sparse files.
		if header.Typeflag == tar.TypeGNUSparse {
			return nil, kind, errors.New("authenticated package tar uses unsupported sparse framing")
		}
		for key := range header.PAXRecords {
			if strings.HasPrefix(key, "GNU.sparse.") {
				return nil, kind, errors.New("authenticated package tar uses unsupported sparse framing")
			}
		}
		entries++
		if entries > 200000 || (kind != "apk-data" && entries > 256) {
			return nil, kind, errors.New("authenticated package header tar has too many entries")
		}
		if header.Size > reader.limit-reader.count || header.Size > maximumQualificationPackageExpandedBytes-*reader.total {
			return nil, kind, errors.New("authenticated package archive member exceeds its expanded bound")
		}
		name, err := nativeHeaderTarName(header)
		if err != nil {
			return nil, kind, err
		}
		if kind == "apk-first" {
			kind = "apk-control"
			if strings.HasPrefix(name, ".SIGN.") {
				kind = "apk-signature"
			}
		}
		isMetadata := (kind == "deb-control" && name == "control") || (kind == "apk-control" && name == ".PKGINFO")
		if kind == "apk-data" && (path.Base(name) == ".PKGINFO" || strings.HasPrefix(path.Base(name), ".SIGN.")) {
			return nil, kind, errors.New("authenticated APK metadata occurs in its data archive")
		}
		if kind != "apk-data" {
			rootDirectory := name == "." && header.Typeflag == tar.TypeDir && header.Size == 0
			if !rootDirectory && (strings.Contains(name, "/") || !qualificationTarHeaderIsRegular(header.Typeflag) || header.Linkname != "") {
				return nil, kind, errors.New("authenticated package control member is not a plain root-level file")
			}
			if (kind == "apk-signature" && !strings.HasPrefix(name, ".SIGN.")) ||
				(kind == "apk-control" && (strings.HasPrefix(name, ".SIGN.") || !strings.HasPrefix(name, "."))) {
				return nil, kind, errors.New("authenticated APK signature and control framing disagree")
			}
		}
		var sink io.Writer = io.Discard
		if observe != nil {
			sink, err = observe(kind, name, header)
			if err != nil {
				return nil, kind, err
			}
			if sink == nil {
				return nil, kind, errors.New("authenticated package observer has no bounded content sink")
			}
		}
		if isMetadata {
			if metadata != nil || header.Size <= 0 || header.Size > maximumNativeHeaderMetadataBytes {
				return nil, kind, errors.New("authenticated package metadata is duplicated or excessive")
			}
			metadata, err = io.ReadAll(io.LimitReader(archive, header.Size+1))
			if err != nil {
				return nil, kind, fmt.Errorf("read authenticated package metadata: %w", err)
			}
			if int64(len(metadata)) != header.Size {
				return nil, kind, errors.New("authenticated package metadata is truncated")
			}
			if _, err := sink.Write(metadata); err != nil {
				return nil, kind, err
			}
		} else if _, err := io.CopyN(sink, archive, header.Size); err != nil {
			return nil, kind, fmt.Errorf("read authenticated package archive member: %w", err)
		}
		padding = (512 - header.Size%512) % 512
	}
	var buffer, zero [4096]byte
	trailing := 0
	for {
		n, err := reader.Read(buffer[:])
		trailing += n
		if trailing > maximumNativeTarPaddingBytes || !bytes.Equal(buffer[:n], zero[:n]) {
			return nil, kind, errors.New("authenticated package tar contains foreign trailing data")
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, kind, fmt.Errorf("finish authenticated package gzip stream: %w", err)
		}
	}
	if reader.count%512 != 0 || ((kind == "deb-control" || kind == "apk-control") && metadata == nil) {
		return nil, kind, errors.New("authenticated package header archive is incomplete")
	}
	return metadata, kind, reader.ctx.Err()
}

func readAuthenticatedDEBIdentity(ctx context.Context, file *os.File) (nativePackageHeaderIdentity, error) {
	if ctx == nil {
		return nativePackageHeaderIdentity{}, errors.New("authenticated DEB header context is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return nativePackageHeaderIdentity{}, err
	}
	size, err := qualificationPackageDescriptorSize(file, "DEB")
	if err != nil {
		return nativePackageHeaderIdentity{}, err
	}
	var magic [8]byte
	if _, err := file.ReadAt(magic[:], 0); err != nil || string(magic[:]) != "!<arch>\n" {
		return nativePackageHeaderIdentity{}, errors.New("authenticated DEB ar signature is invalid")
	}
	offset := int64(len(magic))
	var control *io.SectionReader
	for _, expected := range []string{"debian-binary", "control.tar.gz", "data.tar.gz"} {
		if err := ctx.Err(); err != nil {
			return nativePackageHeaderIdentity{}, err
		}
		var header [60]byte
		if offset > size-60 {
			return nativePackageHeaderIdentity{}, errors.New("authenticated DEB ar header is truncated")
		}
		if _, err := file.ReadAt(header[:], offset); err != nil || string(header[58:]) != "`\n" {
			return nativePackageHeaderIdentity{}, errors.New("authenticated DEB ar header is invalid")
		}
		name := strings.TrimSuffix(strings.TrimRight(string(header[:16]), " "), "/")
		memberSize, err := parseQualificationARMemberSize(header[48:58])
		offset += 60
		if err != nil || name != expected || memberSize <= 0 || memberSize > size-offset {
			return nativePackageHeaderIdentity{}, errors.New("authenticated DEB member identity, order or size is invalid")
		}
		switch name {
		case "debian-binary":
			var version [4]byte
			if memberSize != 4 {
				return nativePackageHeaderIdentity{}, errors.New("authenticated DEB format version is unsupported")
			}
			if _, err := file.ReadAt(version[:], offset); err != nil || string(version[:]) != "2.0\n" {
				return nativePackageHeaderIdentity{}, errors.New("authenticated DEB format version is invalid")
			}
		case "control.tar.gz":
			if memberSize > maximumNativeControlBytes {
				return nativePackageHeaderIdentity{}, errors.New("authenticated DEB compressed control archive is excessive")
			}
			control = io.NewSectionReader(file, offset, memberSize)
		}
		offset += memberSize
		if memberSize%2 != 0 {
			var pad [1]byte
			if _, err := file.ReadAt(pad[:], offset); err != nil || pad[0] != '\n' {
				return nativePackageHeaderIdentity{}, errors.New("authenticated DEB ar padding is invalid")
			}
			offset++
		}
	}
	if offset != size || control == nil {
		return nativePackageHeaderIdentity{}, errors.New("authenticated DEB contains extra or missing members")
	}
	compressedTotal := int64(0)
	compressed := bufio.NewReader(qualificationExpandedReader{reader: control, total: &compressedTotal, ctx: ctx})
	stream, err := gzip.NewReader(compressed)
	if err != nil {
		return nativePackageHeaderIdentity{}, fmt.Errorf("open authenticated DEB control stream: %w", err)
	}
	stream.Multistream(false)
	expandedTotal := int64(0)
	metadata, _, parseErr := readNativeHeaderTar(&nativeHeaderReader{reader: stream, ctx: ctx, limit: maximumNativeControlBytes, total: &expandedTotal}, "deb-control")
	closeErr := stream.Close()
	if parseErr != nil || closeErr != nil {
		return nativePackageHeaderIdentity{}, errors.Join(parseErr, closeErr)
	}
	if _, err := compressed.Peek(1); !errors.Is(err, io.EOF) {
		return nativePackageHeaderIdentity{}, errors.New("authenticated DEB control contains trailing compressed data")
	}
	if err := ctx.Err(); err != nil {
		return nativePackageHeaderIdentity{}, err
	}
	identity, err := parseAuthenticatedDEBControl(metadata)
	if contextErr := ctx.Err(); contextErr != nil {
		return nativePackageHeaderIdentity{}, contextErr
	}
	return identity, err
}

func readAuthenticatedAPKIdentity(ctx context.Context, file *os.File) (nativePackageHeaderIdentity, error) {
	return readAuthenticatedAPKObserved(ctx, file, nil)
}

func readAuthenticatedAPKObserved(ctx context.Context, file *os.File, observe nativeHeaderMemberObserver) (nativePackageHeaderIdentity, error) {
	return readAuthenticatedAPKObservedRegistration(ctx, file, observe, nil)
}

func readAuthenticatedAPKObservedRegistration(ctx context.Context, file *os.File, observe nativeHeaderMemberObserver, registration *apkRegistrationCapture) (nativePackageHeaderIdentity, error) {
	if ctx == nil {
		return nativePackageHeaderIdentity{}, errors.New("authenticated APK header context is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return nativePackageHeaderIdentity{}, err
	}
	size, err := qualificationPackageDescriptorSize(file, "APK")
	if err != nil {
		return nativePackageHeaderIdentity{}, err
	}
	compressedTotal, expandedTotal := int64(0), int64(0)
	compressed := bufio.NewReader(qualificationExpandedReader{reader: io.NewSectionReader(file, 0, size), total: &compressedTotal, ctx: ctx})
	kind := "apk-first"
	var metadata []byte
	for members := 0; ; members++ {
		if err := ctx.Err(); err != nil {
			return nativePackageHeaderIdentity{}, err
		}
		if _, err := compressed.Peek(1); errors.Is(err, io.EOF) {
			if kind != "complete" {
				return nativePackageHeaderIdentity{}, errors.New("authenticated APK lacks complete control and data streams")
			}
			break
		} else if err != nil {
			return nativePackageHeaderIdentity{}, err
		}
		if kind == "complete" || members >= 3 {
			return nativePackageHeaderIdentity{}, errors.New("authenticated APK contains extra gzip streams")
		}
		var compressedStream io.Reader = compressed
		var capturedStream *apkRegistrationStreamReader
		if registration != nil {
			capturedStream = newAPKRegistrationStreamReader(compressed, kind == "apk-data")
			compressedStream = capturedStream
		}
		stream, err := gzip.NewReader(compressedStream)
		if err != nil {
			return nativePackageHeaderIdentity{}, fmt.Errorf("open authenticated APK gzip stream: %w", err)
		}
		stream.Multistream(false)
		limit := int64(maximumNativeControlBytes)
		if kind == "apk-data" {
			limit = maximumQualificationPackageExpandedBytes
		}
		found, actualKind, parseErr := readNativeHeaderTarObservedFraming(&nativeHeaderReader{reader: stream, ctx: ctx, limit: limit, total: &expandedTotal}, kind, observe, registration != nil)
		closeErr := stream.Close()
		if parseErr != nil || closeErr != nil {
			return nativePackageHeaderIdentity{}, errors.Join(parseErr, closeErr)
		}
		if registration != nil {
			registration.observe(actualKind, found, capturedStream)
		}
		switch actualKind {
		case "apk-signature":
			kind = "apk-control"
		case "apk-control":
			metadata, kind = found, "apk-data"
		case "apk-data":
			kind = "complete"
		}
	}
	if err := ctx.Err(); err != nil {
		return nativePackageHeaderIdentity{}, err
	}
	identity, err := parseAuthenticatedAPKInfo(metadata)
	if contextErr := ctx.Err(); contextErr != nil {
		return nativePackageHeaderIdentity{}, contextErr
	}
	return identity, err
}
