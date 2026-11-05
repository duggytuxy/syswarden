package system

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"testing"
)

type rpmIdentityFixtureTag struct {
	tag, kind, count uint32
	data             []byte
}

func rpmIdentityFixtureUint32(value int) uint32 {
	if value < 0 || value > 1<<30 {
		panic("synthetic RPM fixture exceeds its integer bounds")
	}
	return uint32(value)
}

func rpmIdentityFixtureString(tag uint32, value string) rpmIdentityFixtureTag {
	return rpmIdentityFixtureTag{tag: tag, kind: 6, count: 1, data: append([]byte(value), 0)}
}

func rpmIdentityFixtureTags(name string) []rpmIdentityFixtureTag {
	return []rpmIdentityFixtureTag{
		rpmIdentityFixtureString(1000, name), rpmIdentityFixtureString(1001, "5.00.0"),
		rpmIdentityFixtureString(1002, "1"), rpmIdentityFixtureString(1021, "linux"),
		rpmIdentityFixtureString(1022, "x86_64"), rpmIdentityFixtureString(1124, "cpio"),
		rpmIdentityFixtureString(1125, "gzip"),
	}
}

// These are synthetic V4 framing fixtures, not native-signed RPM packages.
// The immutable trailer covers the region entry plus all ordinary entries.
func rpmIdentityFixtureHeader(region uint32, input []rpmIdentityFixtureTag) []byte {
	tags := append([]rpmIdentityFixtureTag(nil), input...)
	sort.SliceStable(tags, func(i, j int) bool { return tags[i].tag < tags[j].tag })
	var index, data []byte
	put := func(value uint32) { index = binary.BigEndian.AppendUint32(index, value) }
	for _, tag := range tags {
		alignment := 1
		if tag.kind >= 3 && tag.kind <= 5 {
			alignment = 1 << (tag.kind - 2)
		}
		for len(data)%alignment != 0 {
			data = append(data, 0)
		}
		put(tag.tag)
		put(tag.kind)
		put(rpmIdentityFixtureUint32(len(data)))
		put(tag.count)
		data = append(data, tag.data...)
	}
	trailerOffset := rpmIdentityFixtureUint32(len(data))
	count := rpmIdentityFixtureUint32(len(tags) + 1)
	for _, value := range []uint32{region, 7, uint32(0) - count*16, 16} {
		data = binary.BigEndian.AppendUint32(data, value)
	}
	header := []byte{0x8e, 0xad, 0xe8, 1, 0, 0, 0, 0}
	header = binary.BigEndian.AppendUint32(header, count)
	header = binary.BigEndian.AppendUint32(header, rpmIdentityFixtureUint32(len(data)))
	for _, value := range []uint32{region, 7, trailerOffset, 16} {
		header = binary.BigEndian.AppendUint32(header, value)
	}
	header = append(header, index...)
	return append(header, data...)
}

func rpmIdentityFixture(t *testing.T, tags []rpmIdentityFixtureTag) []byte {
	t.Helper()
	lead := make([]byte, 96)
	copy(lead, []byte{0xed, 0xab, 0xee, 0xdb, 3, 0})
	binary.BigEndian.PutUint16(lead[78:80], 5)
	// Deliberately misleading legacy name/architecture: neither is authority.
	copy(lead[10:76], "legacy-lead-name-is-not-an-identity")
	binary.BigEndian.PutUint16(lead[8:10], 1)
	signature := rpmIdentityFixtureHeader(62, []rpmIdentityFixtureTag{
		// Keep the signature size unaligned so its zero padding is exercised.
		rpmIdentityFixtureString(269, "synthetic-header-digest!"),
		{tag: 1004, kind: 7, count: 16, data: make([]byte, 16)},
	})
	file := append(lead, signature...)
	for len(file)%8 != 0 {
		file = append(file, 0)
	}
	file = append(file, rpmIdentityFixtureHeader(63, tags)...)
	var payload bytes.Buffer
	writer := gzip.NewWriter(&payload)
	if _, err := writer.Write(qualificationCPIOFixture(t, nil)); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return append(file, payload.Bytes()...)
}

func rpmIdentityFixtureMainOffset(file []byte) int {
	count := binary.BigEndian.Uint32(file[104:108])
	length := binary.BigEndian.Uint32(file[108:112])
	return (96 + 16 + int(count)*16 + int(length) + 7) &^ 7
}

func rpmIdentityFixtureEntry(file []byte, tag uint32) int {
	main := rpmIdentityFixtureMainOffset(file)
	count := int(binary.BigEndian.Uint32(file[main+8 : main+12]))
	for index := 0; index < count; index++ {
		offset := main + 16 + index*16
		if binary.BigEndian.Uint32(file[offset:offset+4]) == tag {
			return offset
		}
	}
	panic("fixture entry is absent")
}

func rpmIdentityFixtureFile(t *testing.T, data []byte) *os.File {
	t.Helper()
	file, err := os.OpenFile(filepath.Join(t.TempDir(), "synthetic.rpm"), os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = file.Close() })
	if _, err := file.Write(data); err != nil {
		t.Fatal(err)
	}
	if _, err := file.Seek(7, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	return file
}

func TestAuthenticatedRPMIdentityReadsMainHeaderWithoutSeeking(t *testing.T) {
	for _, name := range []string{"syswarden", "syswarden-base"} {
		for _, epoch := range []bool{false, true} {
			t.Run(name+"/zero-epoch-"+strconv.FormatBool(epoch), func(t *testing.T) {
				tags := rpmIdentityFixtureTags(name)
				if epoch {
					tags = append(tags, rpmIdentityFixtureTag{tag: 1003, kind: 4, count: 1, data: make([]byte, 4)})
				}
				wire := rpmIdentityFixture(t, tags)
				file := rpmIdentityFixtureFile(t, wire)
				identity, err := readAuthenticatedRPMIdentity(t.Context(), file)
				want := nativePackageHeaderIdentity{name: name, version: "5.00.0", architecture: "x86_64"}
				if err != nil || identity != want {
					t.Fatalf("RPM identity = %#v, want %#v: %v", identity, want, err)
				}
				position, err := file.Seek(0, io.SeekCurrent)
				if err != nil || position != 7 {
					t.Fatalf("RPM identity changed descriptor position: %d, %v", position, err)
				}
				unchanged := make([]byte, len(wire))
				if _, err := file.ReadAt(unchanged, 0); err != nil || !bytes.Equal(unchanged, wire) {
					t.Fatalf("RPM identity changed input bytes: %v", err)
				}
			})
		}
	}
}

func TestAuthenticatedRPMIdentityRejectsAmbiguousTypedTags(t *testing.T) {
	for _, tag := range []uint32{1000, 1001, 1002, 1021, 1022, 1124, 1125} {
		for _, mutation := range []string{"missing", "duplicate", "array-type", "count", "unterminated", "empty", "control", "invalid-utf8"} {
			t.Run(strconv.FormatUint(uint64(tag), 10)+"/"+mutation, func(t *testing.T) {
				tags := rpmIdentityFixtureTags("syswarden")
				for index := range tags {
					if tags[index].tag != tag {
						continue
					}
					switch mutation {
					case "missing":
						tags = append(tags[:index], tags[index+1:]...)
					case "duplicate":
						tags = append(tags, tags[index])
					case "array-type":
						tags[index].kind = 8
					case "count":
						tags[index].count = 2
					case "unterminated":
						tags[index].data = bytes.TrimSuffix(tags[index].data, []byte{0})
					case "empty":
						tags[index].data = []byte{0}
					case "control":
						tags[index].data = []byte{'x', '\n', 0}
					case "invalid-utf8":
						tags[index].data = []byte{0xff, 0}
					}
					break
				}
				assertRPMIdentityFixtureRefused(t, rpmIdentityFixture(t, tags))
			})
		}
	}
	for _, tc := range []struct {
		name string
		tag  rpmIdentityFixtureTag
	}{
		{"nonzero-epoch", rpmIdentityFixtureTag{tag: 1003, kind: 4, count: 1, data: []byte{0, 0, 0, 1}}},
		{"string-epoch", rpmIdentityFixtureString(1003, "0")},
		{"wide-epoch", rpmIdentityFixtureTag{tag: 1003, kind: 5, count: 1, data: make([]byte, 8)}},
		{"variant-release", rpmIdentityFixtureString(1002, "1.rhelpo")},
		{"other-release", rpmIdentityFixtureString(1002, "2")},
		{"other-os", rpmIdentityFixtureString(1021, "freebsd")},
		{"other-payload", rpmIdentityFixtureString(1124, "tar")},
		{"other-compressor", rpmIdentityFixtureString(1125, "unknown")},
		{"compressor-mismatch", rpmIdentityFixtureString(1125, "xz")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tags := rpmIdentityFixtureTags("syswarden")
			filtered := tags[:0]
			for _, tag := range tags {
				if tag.tag != tc.tag.tag {
					filtered = append(filtered, tag)
				}
			}
			assertRPMIdentityFixtureRefused(t, rpmIdentityFixture(t, append(filtered, tc.tag)))
		})
	}
}

func assertRPMIdentityFixtureRefused(t *testing.T, wire []byte) {
	t.Helper()
	file := rpmIdentityFixtureFile(t, wire)
	identity, err := readAuthenticatedRPMIdentity(t.Context(), file)
	if err == nil || identity != (nativePackageHeaderIdentity{}) {
		t.Fatalf("invalid RPM identity accepted: %#v, %v", identity, err)
	}
	position, err := file.Seek(0, io.SeekCurrent)
	if err != nil || position != 7 {
		t.Fatalf("refused RPM changed descriptor position: %d, %v", position, err)
	}
}

func TestAuthenticatedRPMIdentityRejectsMalformedFraming(t *testing.T) {
	valid := rpmIdentityFixture(t, rpmIdentityFixtureTags("syswarden"))
	main := rpmIdentityFixtureMainOffset(valid)
	entry := rpmIdentityFixtureEntry(valid, 1000)
	for _, tc := range []struct {
		name   string
		offset int
		value  uint32
	}{
		{"lead-magic", 0, 0}, {"source-lead", 4, 0x03000001},
		{"signature-magic", 96, 0}, {"signature-index-overflow", 104, 0xffffffff},
		{"signature-data-overflow", 108, 0xffffffff},
		{"main-magic", main, 0}, {"header-version", main, 0x8eade802},
		{"reserved-intro", main + 4, 1}, {"main-index-overflow", main + 8, 0xffffffff},
		{"main-data-overflow", main + 12, 0xffffffff},
		{"main-no-region", main + 16, 62}, {"main-region-count", main + 28, 15},
		{"tag-negative-offset", entry + 8, 0xffffffff}, {"tag-count-overflow", entry + 12, 0xffffffff},
		{"tag-invalid-type", entry + 4, 0}, {"tag-invalid-type-high", entry + 4, 10},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wire := append([]byte(nil), valid...)
			binary.BigEndian.PutUint32(wire[tc.offset:tc.offset+4], tc.value)
			assertRPMIdentityFixtureRefused(t, wire)
		})
	}
	count := int(binary.BigEndian.Uint32(valid[main+8 : main+12]))
	length := int(binary.BigEndian.Uint32(valid[main+12 : main+16]))
	end := main + 16 + count*16 + length
	for _, cut := range []int{0, 4, 95, 96, 111, main - 1, main, main + 15, main + 16 + count*16 - 1, end - 1, end, end + 2} {
		t.Run("truncated-"+strconv.Itoa(cut), func(t *testing.T) { assertRPMIdentityFixtureRefused(t, valid[:cut]) })
	}
	t.Run("overlapping-values", func(t *testing.T) {
		wire := append([]byte(nil), valid...)
		version := rpmIdentityFixtureEntry(wire, 1001)
		copy(wire[version+8:version+12], wire[entry+8:entry+12])
		assertRPMIdentityFixtureRefused(t, wire)
	})
	t.Run("region-trailer-does-not-cover-all-indexes", func(t *testing.T) {
		wire := append([]byte(nil), valid...)
		binary.BigEndian.PutUint32(wire[end-8:end-4], 0xfffffff0)
		assertRPMIdentityFixtureRefused(t, wire)
	})
	t.Run("signature-padding", func(t *testing.T) {
		wire := append([]byte(nil), valid...)
		signatureEnd := 112 + int(binary.BigEndian.Uint32(wire[104:108]))*16 + int(binary.BigEndian.Uint32(wire[108:112]))
		if signatureEnd == main {
			t.Fatal("fixture needs signature padding for this mutation")
		}
		wire[signatureEnd] = 1
		assertRPMIdentityFixtureRefused(t, wire)
	})
}

type rpmIdentityCancelContext struct {
	context.Context
	cancel context.CancelFunc
	checks int
}

func (ctx *rpmIdentityCancelContext) Err() error {
	ctx.checks++
	if ctx.checks == 8 {
		ctx.cancel()
	}
	return ctx.Context.Err()
}

func TestAuthenticatedRPMIdentityCancellationAndDescriptorErrors(t *testing.T) {
	var missingContext context.Context
	if identity, err := readAuthenticatedRPMIdentity(missingContext, nil); err == nil || identity != (nativePackageHeaderIdentity{}) {
		t.Fatal("missing context was accepted")
	}
	if identity, err := readAuthenticatedRPMIdentity(t.Context(), nil); err == nil || identity != (nativePackageHeaderIdentity{}) {
		t.Fatal("missing descriptor was accepted")
	}
	for _, midway := range []bool{false, true} {
		t.Run("midway-"+strconv.FormatBool(midway), func(t *testing.T) {
			base, cancel := context.WithCancel(t.Context())
			defer cancel()
			var ctx context.Context = base
			if midway {
				ctx = &rpmIdentityCancelContext{Context: base, cancel: cancel}
			} else {
				cancel()
			}
			file := rpmIdentityFixtureFile(t, rpmIdentityFixture(t, rpmIdentityFixtureTags("syswarden")))
			identity, err := readAuthenticatedRPMIdentity(ctx, file)
			if !errors.Is(err, context.Canceled) || identity != (nativePackageHeaderIdentity{}) {
				t.Fatalf("canceled RPM read returned evidence: %#v, %v", identity, err)
			}
			if position, err := file.Seek(0, io.SeekCurrent); err != nil || position != 7 {
				t.Fatalf("canceled RPM read changed descriptor position: %d, %v", position, err)
			}
		})
	}
	file := rpmIdentityFixtureFile(t, rpmIdentityFixture(t, rpmIdentityFixtureTags("syswarden")))
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if identity, err := readAuthenticatedRPMIdentity(t.Context(), file); err == nil || identity != (nativePackageHeaderIdentity{}) {
		t.Fatal("closed descriptor was accepted")
	}
}
