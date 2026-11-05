package system

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"sort"
	"unicode/utf8"
)

const (
	authenticatedRPMMaxIndexes = 4096
	authenticatedRPMMaxData    = 16 << 20
	authenticatedRPMMaxArray   = 1 << 20
)

type authenticatedRPMEntry struct {
	tag, kind, offset, count uint32
	end                      uint32
}

type authenticatedRPMHeader struct {
	entries map[uint32]authenticatedRPMEntry
	data    []byte
	end     int64
}

// readAuthenticatedRPMIdentity inspects only an already authenticated descriptor.
// It neither verifies RPM signatures nor replaces the installer's native checks.
// Only the standard V4 binary package shape is supported. RPM's lead identity
// fields are historical; the typed main header is authoritative.
// Format: https://rpm.org/docs/4.20.x/manual/format_v4.html
// Entries/regions: https://rpm.org/docs/4.20.x/manual/format_header.html
func readAuthenticatedRPMIdentity(ctx context.Context, file *os.File) (nativePackageHeaderIdentity, error) {
	var empty nativePackageHeaderIdentity
	if ctx == nil {
		return empty, errors.New("authenticated RPM identity requires a context")
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	size, err := qualificationPackageDescriptorSize(file, "RPM")
	if err != nil {
		return empty, err
	}
	var lead [96]byte
	if err := authenticatedRPMReadAt(ctx, file, lead[:], 0, size); err != nil {
		return empty, err
	}
	if !bytes.Equal(lead[:6], []byte{0xed, 0xab, 0xee, 0xdb, 3, 0}) ||
		binary.BigEndian.Uint16(lead[6:8]) != 0 || binary.BigEndian.Uint16(lead[78:80]) != 5 {
		return empty, errors.New("authenticated RPM lead is not a supported binary package")
	}
	signature, err := readAuthenticatedRPMHeader(ctx, file, 96, size, 62)
	if err != nil {
		return empty, fmt.Errorf("authenticated RPM signature framing: %w", err)
	}
	mainOffset := (signature.end + 7) &^ int64(7)
	var padding [7]byte
	if err := authenticatedRPMReadAt(ctx, file, padding[:mainOffset-signature.end], signature.end, size); err != nil {
		return empty, err
	}
	if !bytes.Equal(padding[:], make([]byte, len(padding))) {
		return empty, errors.New("authenticated RPM signature padding is nonzero")
	}
	header, err := readAuthenticatedRPMHeader(ctx, file, mainOffset, size, 63)
	if err != nil {
		return empty, fmt.Errorf("authenticated RPM main header: %w", err)
	}
	values := make(map[uint32]string, 7)
	for _, tag := range []uint32{1000, 1001, 1002, 1021, 1022, 1124, 1125} {
		value, err := header.scalarString(tag)
		if err != nil {
			return empty, err
		}
		values[tag] = value
	}
	// The manifest does not bind an RPM release or epoch. The standard builders
	// use release 1 with no epoch; alternative release channels remain refused.
	if values[1002] != "1" || values[1021] != "linux" {
		return empty, errors.New("authenticated RPM release or operating system is unsupported")
	}
	if epoch, present := header.entries[1003]; present {
		if epoch.kind != 4 || epoch.count != 1 || binary.BigEndian.Uint32(header.data[epoch.offset:epoch.end]) != 0 {
			return empty, errors.New("authenticated RPM epoch is unsupported")
		}
	}
	if values[1124] != "cpio" {
		return empty, errors.New("authenticated RPM payload format is unsupported")
	}
	if err := authenticatedRPMPayloadPrefix(ctx, file, header.end, size, values[1125]); err != nil {
		return empty, err
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	return nativePackageHeaderIdentity{name: values[1000], version: values[1001], architecture: values[1022]}, nil
}

// ReadAt leaves the caller's descriptor offset unchanged on success and failure.
func authenticatedRPMReadAt(ctx context.Context, file *os.File, data []byte, offset, size int64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if offset < 0 || offset > size || int64(len(data)) > size-offset {
		return errors.New("authenticated RPM structure is truncated or out of bounds")
	}
	for len(data) != 0 {
		chunk := len(data)
		if chunk > 64<<10 {
			chunk = 64 << 10
		}
		if _, err := file.ReadAt(data[:chunk], offset); err != nil {
			return fmt.Errorf("read authenticated RPM structure: %w", err)
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		offset += int64(chunk)
		data = data[chunk:]
	}
	return nil
}

func readAuthenticatedRPMHeader(ctx context.Context, file *os.File, offset, size int64, region uint32) (authenticatedRPMHeader, error) {
	var empty authenticatedRPMHeader
	var intro [16]byte
	if err := authenticatedRPMReadAt(ctx, file, intro[:], offset, size); err != nil {
		return empty, err
	}
	if !bytes.Equal(intro[:8], []byte{0x8e, 0xad, 0xe8, 1, 0, 0, 0, 0}) {
		return empty, errors.New("RPM header magic is invalid")
	}
	count := binary.BigEndian.Uint32(intro[8:12])
	length := binary.BigEndian.Uint32(intro[12:16])
	if count < 1 || count > authenticatedRPMMaxIndexes || length < 16 || length > authenticatedRPMMaxData {
		return empty, errors.New("RPM header index or data size exceeds supported bounds")
	}
	indexSize := int64(count) * 16
	totalSize := indexSize + int64(length)
	if offset+16 > size || totalSize > size-(offset+16) {
		return empty, errors.New("RPM header index or data is truncated")
	}
	index := make([]byte, indexSize)
	data := make([]byte, length)
	if err := authenticatedRPMReadAt(ctx, file, index, offset+16, size); err != nil {
		return empty, err
	}
	if err := authenticatedRPMReadAt(ctx, file, data, offset+16+indexSize, size); err != nil {
		return empty, err
	}
	entries := make([]authenticatedRPMEntry, count)
	for position := range entries {
		wire := index[position*16 : (position+1)*16]
		entries[position] = authenticatedRPMEntry{
			tag: binary.BigEndian.Uint32(wire[:4]), kind: binary.BigEndian.Uint32(wire[4:8]),
			offset: binary.BigEndian.Uint32(wire[8:12]), count: binary.BigEndian.Uint32(wire[12:16]),
		}
		if position > 0 && (entries[position].tag < 100 || entries[position].tag <= entries[position-1].tag) {
			return empty, errors.New("RPM header contains duplicate, unordered or reserved tags")
		}
	}
	first := entries[0]
	if first.tag != region || first.kind != 7 || first.count != 16 || first.offset != length-16 {
		return empty, errors.New("RPM header has no exact immutable region")
	}
	trailer := data[first.offset:]
	if binary.BigEndian.Uint32(trailer[:4]) != region || binary.BigEndian.Uint32(trailer[4:8]) != 7 ||
		binary.BigEndian.Uint32(trailer[8:12]) != uint32(0)-count*16 || binary.BigEndian.Uint32(trailer[12:16]) != 16 {
		return empty, errors.New("RPM header immutable region trailer is invalid")
	}
	// Disjoint value spans bound aggregate string scanning to the data size and
	// reject aliases or overlays that could produce a different native identity.
	values := entries[1:]
	sort.Slice(values, func(i, j int) bool { return values[i].offset < values[j].offset })
	header := authenticatedRPMHeader{entries: make(map[uint32]authenticatedRPMEntry, len(values)), data: data, end: offset + 16 + totalSize}
	for position, entry := range values {
		if err := ctx.Err(); err != nil {
			return empty, err
		}
		limit := first.offset
		if position+1 < len(values) {
			limit = values[position+1].offset
		}
		if entry.offset >= limit || limit > first.offset || entry.count == 0 || entry.count > length {
			return empty, errors.New("RPM header value span or count is invalid")
		}
		end, err := authenticatedRPMValueEnd(ctx, entry, data[entry.offset:limit])
		if err != nil {
			return empty, err
		}
		entry.end = entry.offset + end
		header.entries[entry.tag] = entry
	}
	return header, nil
}

func authenticatedRPMValueEnd(ctx context.Context, entry authenticatedRPMEntry, data []byte) (uint32, error) {
	if entry.kind != 7 && entry.count > authenticatedRPMMaxArray {
		return 0, errors.New("RPM header array exceeds supported bounds")
	}
	width := uint32(1)
	switch entry.kind {
	case 1, 2, 7:
	case 3:
		width = 2
	case 4:
		width = 4
	case 5:
		width = 8
	case 6, 8, 9:
		if entry.kind == 6 && entry.count != 1 {
			return 0, errors.New("RPM scalar string has an invalid count")
		}
		end := 0
		for item := uint32(0); item < entry.count; item++ {
			if item%256 == 0 {
				if err := ctx.Err(); err != nil {
					return 0, err
				}
			}
			terminator := bytes.IndexByte(data[end:], 0)
			if terminator < 0 {
				return 0, errors.New("RPM header string is not terminated within its value span")
			}
			end += terminator + 1
		}
		if end < 0 || end > authenticatedRPMMaxData {
			return 0, errors.New("RPM header string extent exceeds supported bounds")
		}
		return uint32(end), nil
	default:
		return 0, errors.New("RPM header contains an unsupported value type")
	}
	length := uint64(entry.count) * uint64(width)
	if entry.offset%width != 0 || length > uint64(len(data)) || length > authenticatedRPMMaxData {
		return 0, errors.New("RPM header numeric or binary value is misaligned or truncated")
	}
	return uint32(length), nil
}

func (header authenticatedRPMHeader) scalarString(tag uint32) (string, error) {
	entry, present := header.entries[tag]
	if !present || entry.kind != 6 || entry.count != 1 || entry.end-entry.offset < 2 || entry.end-entry.offset > 4096 {
		return "", fmt.Errorf("authenticated RPM identity tag %d is absent or not a bounded scalar string", tag)
	}
	value := header.data[entry.offset : entry.end-1]
	if !utf8.Valid(value) || bytes.ContainsAny(value, "\x00\t\r\n") {
		return "", fmt.Errorf("authenticated RPM identity tag %d is malformed", tag)
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return "", fmt.Errorf("authenticated RPM identity tag %d contains a control character", tag)
		}
	}
	return string(value), nil
}

func authenticatedRPMPayloadPrefix(ctx context.Context, file *os.File, offset, size int64, compressor string) error {
	var magic []byte
	switch compressor {
	case "gzip":
		magic = []byte{0x1f, 0x8b, 8}
	case "xz":
		magic = []byte{0xfd, '7', 'z', 'X', 'Z', 0}
	case "bzip2":
		magic = []byte{'B', 'Z', 'h'}
	case "zstd":
		magic = []byte{0x28, 0xb5, 0x2f, 0xfd}
	default:
		return errors.New("authenticated RPM payload compressor is unsupported")
	}
	var prefix [6]byte
	if err := authenticatedRPMReadAt(ctx, file, prefix[:len(magic)], offset, size); err != nil {
		return err
	}
	if !bytes.Equal(prefix[:len(magic)], magic) {
		return errors.New("authenticated RPM payload does not match its declared compressor")
	}
	return nil
}
