package journal

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"os"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func testAuthorityELF(arch string, dynamic bool) []byte {
	class, machine := authorityELFMachine(arch)
	data := make([]byte, 1024)
	copy(data, "\x7fELF")
	data[4] = class
	data[5] = 1
	data[6] = 1
	le := binary.LittleEndian
	le.PutUint16(data[16:], 2)
	le.PutUint16(data[18:], machine)
	le.PutUint32(data[20:], 1)
	count := uint16(2)
	if dynamic {
		count = 4
		le.PutUint16(data[16:], 3)
	}
	header, record := 52, 32
	if class == 2 {
		header, record = 64, 56
		le.PutUint64(data[24:], 0x400300)
		le.PutUint64(data[32:], uint64(header))
		le.PutUint16(data[52:], uint16(header))
		le.PutUint16(data[54:], uint16(record))
		le.PutUint16(data[56:], count)
	} else {
		le.PutUint32(data[24:], 0x400300)
		le.PutUint32(data[28:], uint32(header))
		le.PutUint16(data[40:], uint16(header))
		le.PutUint16(data[42:], uint16(record))
		le.PutUint16(data[44:], count)
	}
	segments := []authorityELFSegment{{kind: 1, flags: 5, address: 0x400000, fileBytes: 1024, memoryBytes: 2048, align: 4096}, {kind: 0x6474e551, flags: 6}}
	if dynamic {
		interpreter := "/lib/fixture-loader.so\x00"
		copy(data[384:], interpreter)
		segments = []authorityELFSegment{{kind: 3, flags: 4, offset: 384, address: 0x400180, fileBytes: uint64(len(interpreter)), memoryBytes: uint64(len(interpreter)), align: 1}, segments[0], {kind: 2, flags: 4, offset: 512, address: 0x400200, fileBytes: 16, memoryBytes: 16, align: 8}, segments[1]}
	}
	for i, s := range segments {
		b := data[header+i*record : header+(i+1)*record]
		le.PutUint32(b, s.kind)
		if class == 2 {
			le.PutUint32(b[4:], s.flags)
			le.PutUint64(b[8:], s.offset)
			le.PutUint64(b[16:], s.address)
			le.PutUint64(b[32:], s.fileBytes)
			le.PutUint64(b[40:], s.memoryBytes)
			le.PutUint64(b[48:], s.align)
		} else {
			putAuthorityELF32(b[4:], s.offset)
			putAuthorityELF32(b[8:], s.address)
			putAuthorityELF32(b[16:], s.fileBytes)
			putAuthorityELF32(b[20:], s.memoryBytes)
			le.PutUint32(b[24:], s.flags)
			putAuthorityELF32(b[28:], s.align)
		}
	}
	return data
}

func TestAuthorityELFProfiles(t *testing.T) {
	for _, arch := range []string{"amd64", "arm64", "386"} {
		for _, dynamic := range []bool{false, true} {
			data := testAuthorityELF(arch, dynamic)
			f, err := inspectAuthorityELF(int64(len(data)), arch, bytes.NewReader(data).ReadAt)
			if err != nil || f.Architecture != arch || f.Dynamic != dynamic || f.PositionIndependent != dynamic || (f.Interpreter != "") != dynamic {
				t.Fatal("invalid execution profile", arch, dynamic, f, err)
			}
		}
	}
}

func TestAuthorityELFRefusals(t *testing.T) {
	le := binary.LittleEndian
	cases := map[string]func([]byte){
		"alignment-budget":     func(b []byte) { le.PutUint64(b[64+56+48:], 1<<63) },
		"dynamic-memory-range": func(b []byte) { le.PutUint64(b[64+2*56+40:], 2048) },
		"executable-dynamic":   func(b []byte) { le.PutUint32(b[64+2*56+4:], 5) },
		"unreadable-dynamic":   func(b []byte) { le.PutUint32(b[64+2*56+4:], 2) },

		"script":                func(b []byte) { copy(b, "#!/bin/sh\n") },
		"wrong-class":           func(b []byte) { b[4] = 1 },
		"wrong-endian":          func(b []byte) { b[5] = 2 },
		"wrong-version":         func(b []byte) { b[6] = 0 },
		"wrong-abi":             func(b []byte) { b[7] = 9 },
		"abi-version":           func(b []byte) { b[8] = 1 },
		"padding":               func(b []byte) { b[15] = 1 },
		"relocatable":           func(b []byte) { le.PutUint16(b[16:], 1) },
		"wrong-machine":         func(b []byte) { le.PutUint16(b[18:], 183) },
		"wrong-object-version":  func(b []byte) { le.PutUint32(b[20:], 2) },
		"no-entry":              func(b []byte) { le.PutUint64(b[24:], 0) },
		"bss-entry":             func(b []byte) { le.PutUint64(b[24:], 0x400600) },
		"short-header":          func(b []byte) { le.PutUint16(b[52:], 63) },
		"short-record":          func(b []byte) { le.PutUint16(b[54:], 55) },
		"no-table":              func(b []byte) { le.PutUint16(b[56:], 0) },
		"long-table":            func(b []byte) { le.PutUint16(b[56:], 65) },
		"extended-table":        func(b []byte) { le.PutUint16(b[56:], 0xffff) },
		"table-overlap":         func(b []byte) { le.PutUint64(b[32:], 32) },
		"table-overflow":        func(b []byte) { le.PutUint64(b[32:], ^uint64(0)) },
		"table-truncated":       func(b []byte) { le.PutUint64(b[32:], 1000) },
		"platform-flags":        func(b []byte) { le.PutUint32(b[48:], 1) },
		"unknown-segment":       func(b []byte) { le.PutUint32(b[64:], 5) },
		"writable-code":         func(b []byte) { le.PutUint32(b[64+56+4:], 7) },
		"invalid-flags":         func(b []byte) { le.PutUint32(b[64+56+4:], 13) },
		"non-readable-load":     func(b []byte) { le.PutUint32(b[64+56+4:], 1) },
		"file-overflow":         func(b []byte) { le.PutUint64(b[64+56+8:], ^uint64(0)) },
		"file-truncated":        func(b []byte) { le.PutUint64(b[64+56+32:], 1025) },
		"file-larger-memory":    func(b []byte) { le.PutUint64(b[64+56+40:], 100) },
		"address-overflow":      func(b []byte) { le.PutUint64(b[64+56+16:], ^uint64(0)-1) },
		"memory-budget":         func(b []byte) { le.PutUint64(b[64+56+40:], maxAuthorityELFMemory+1) },
		"alignment":             func(b []byte) { le.PutUint64(b[64+56+48:], 3) },
		"incongruent-load":      func(b []byte) { le.PutUint64(b[64+56+16:], 0x400001) },
		"overlapping-load":      func(b []byte) { copy(b[64+2*56:64+3*56], b[64+56:64+2*56]) },
		"executable-stack":      func(b []byte) { le.PutUint32(b[64+3*56+4:], 7) },
		"missing-stack":         func(b []byte) { le.PutUint32(b[64+3*56:], 0) },
		"duplicate-stack":       func(b []byte) { copy(b[64:64+56], b[64+3*56:64+4*56]) },
		"duplicate-interpreter": func(b []byte) { copy(b[64+2*56:64+3*56], b[64:64+56]) },
		"late-interpreter": func(b []byte) {
			tmp := bytes.Clone(b[64 : 64+56])
			copy(b[64:64+56], b[64+56:64+2*56])
			copy(b[64+56:64+2*56], tmp)
		},
		"long-interpreter":         func(b []byte) { le.PutUint64(b[64+32:], 257) },
		"relative-interpreter":     func(b []byte) { b[384] = 'x' },
		"interpreter-nul":          func(b []byte) { b[386] = 0 },
		"interpreter-control":      func(b []byte) { b[386] = '\n' },
		"interpreter-unterminated": func(b []byte) { b[384+len("/lib/fixture-loader.so")] = 'x' },
		"interpreter-dot-path":     func(b []byte) { copy(b[384:], "/lib/../fixture-ld.so\x00\x00") },
		"missing-dynamic":          func(b []byte) { le.PutUint32(b[64+2*56:], 0) },
		"missing-interpreter":      func(b []byte) { le.PutUint32(b[64:], 0) },
		"unmapped-dynamic":         func(b []byte) { le.PutUint64(b[64+2*56+16:], 0x800000) },
		"empty-dynamic":            func(b []byte) { le.PutUint64(b[64+2*56+32:], 0) },
		"unaligned-dynamic":        func(b []byte) { le.PutUint64(b[64+2*56+32:], 15) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			data := testAuthorityELF("amd64", true)
			mutate(data)
			f, err := inspectAuthorityELF(int64(len(data)), "amd64", bytes.NewReader(data).ReadAt)
			if !errors.Is(err, ErrAuthorityExecutable) || f != (AuthorityExecutableFormat{}) {
				t.Fatal("unsupported image admitted", f, err)
			}
		})
	}
}

func TestAuthorityELFIOBounds(t *testing.T) {
	data := testAuthorityELF("amd64", true)
	for _, size := range []int64{-1, 0, 63, MaxAuthorityExecutableBytes + 1} {
		if _, err := inspectAuthorityELF(size, "amd64", nil); err == nil {
			t.Fatal("invalid size accepted")
		}
	}
	if _, err := inspectAuthorityELF(1024, "unknown", bytes.NewReader(data).ReadAt); err == nil {
		t.Fatal("unknown architecture admitted")
	}
	for _, short := range []bool{false, true} {
		for failure := 1; failure <= 3; failure++ {
			calls := 0
			f, err := inspectAuthorityELF(1024, "amd64", func(b []byte, off int64) (int, error) {
				calls++
				if calls == failure {
					if short {
						return len(b) - 1, nil
					}
					return 0, unix.EIO
				}
				return bytes.NewReader(data).ReadAt(b, off)
			})
			if err == nil || f != (AuthorityExecutableFormat{}) || calls != failure {
				t.Fatal("uncertain read continued")
			}
		}
	}
}

func FuzzAuthorityELF(f *testing.F) {
	for _, arch := range []string{"amd64", "arm64", "386"} {
		for _, dynamic := range []bool{false, true} {
			f.Add(testAuthorityELF(arch, dynamic), arch)
		}
	}
	f.Fuzz(func(t *testing.T, data []byte, arch string) {
		if len(data) > MaxAuthorityExecutableBytes {
			return
		}
		calls, total := 0, 0
		result, err := inspectAuthorityELF(int64(len(data)), arch, func(b []byte, off int64) (int, error) {
			calls++
			total += len(b)
			if calls > 3 || len(b) > maxAuthorityProgramHeaders*56 || total > 64+maxAuthorityProgramHeaders*56+maxAuthorityInterpreterBytes || off < 0 || off > int64(len(data)) || int64(len(b)) > int64(len(data))-off {
				t.Fatal("unbounded ELF inspection")
			}
			return bytes.NewReader(data).ReadAt(b, off)
		})
		if err != nil && result != (AuthorityExecutableFormat{}) {
			t.Fatal("partial format exposed")
		}
	})
}

func testAuthorityELFImage(t *testing.T, data []byte) *os.File {
	t.Helper()
	fd, err := newAuthorityImage(unix.MemfdCreate)
	if err != nil {
		t.Fatal(err)
	}
	image := os.NewFile(uintptr(fd), "synthetic-elf")
	t.Cleanup(func() { _ = image.Close() })
	if _, err := image.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := image.Chmod(0555); err != nil {
		t.Fatal(err)
	}
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_ADD_SEALS, authorityImageSeals); err != nil {
		t.Fatal(err)
	}
	return image
}

func testActualAuthorityELF(t *testing.T, images executableImages) {
	for _, image := range []*os.File{images.authority, images.bootstrap, images.launcher} {
		st, err := image.Stat()
		if err != nil {
			t.Fatal(err)
		}
		data := make([]byte, int(st.Size()))
		if _, err := image.ReadAt(data, 0); err != nil {
			t.Fatal(err)
		}
		if _, err := image.Seek(11, io.SeekStart); err != nil {
			t.Fatal(err)
		}
		format, err := InspectAuthorityExecutableImage(image, recoveryDigest(data))
		if err != nil || format.Architecture != runtime.GOARCH {
			t.Fatal("actual native format rejected", err)
		}
		if off, err := image.Seek(0, io.SeekCurrent); err != nil || off != 11 {
			t.Fatal("format inspection changed offset")
		}
		t.Logf("Authenticated actual program: architecture=%s dynamic=%t position_independent=%t", format.Architecture, format.Dynamic, format.PositionIndependent)
		if _, err := InspectAuthorityExecutableImage(image, strings.Repeat("0", 64)); err == nil {
			t.Fatal("profile exposed before authentication")
		}
	}
	if f, err := InspectAuthorityExecutableImage(nil, strings.Repeat("a", 64)); err == nil || f != (AuthorityExecutableFormat{}) {
		t.Fatal("nil image admitted")
	}
}

func TestAuthorityELF32AddressOverflow(t *testing.T) {
	data := testAuthorityELF("386", false)
	binary.LittleEndian.PutUint32(data[52+8:], 0xfffff800)
	if _, err := inspectAuthorityELF(int64(len(data)), "386", bytes.NewReader(data).ReadAt); err == nil {
		t.Fatal("32-bit address overflow admitted")
	}
}

func putAuthorityELF32(b []byte, value uint64) {
	if value > math.MaxUint32 {
		panic("ELF32 test fixture outside supported range")
	}
	binary.LittleEndian.PutUint32(b, uint32(value))
}

func TestAuthorityELFChunkRejectsInvalidRangesBeforeIO(t *testing.T) {
	for _, c := range []struct {
		size   int64
		offset uint64
		bytes  int
	}{{-1, 0, 1}, {MaxAuthorityExecutableBytes + 1, 0, 1}, {1024, math.MaxUint64, 1}, {1024, 1025, 0}, {1024, 1024, 1}} {
		calls := 0
		ok := readAuthorityELFChunk(c.size, make([]byte, c.bytes), c.offset, func([]byte, int64) (int, error) { calls++; return 0, nil })
		if ok || calls != 0 {
			t.Fatal("invalid read reached descriptor")
		}
	}
}
