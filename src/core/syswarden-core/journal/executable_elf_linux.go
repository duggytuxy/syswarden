package journal

import (
	"encoding/binary"
	"math"
	"os"
	"path"
	"runtime"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	maxAuthorityProgramHeaders   = 64
	maxAuthorityInterpreterBytes = 256
	maxAuthorityELFMemory        = 1 << 30
)

// AuthorityExecutableFormat describes a bounded native ELF execution layout.
// Interpreter is descriptive, not an approved loader path or dependency pin.
// A valid layout and matching image digest do not authenticate external libraries.
type AuthorityExecutableFormat struct {
	Architecture        string
	PositionIndependent bool
	Interpreter         string
	Dynamic             bool
}

// InspectAuthorityExecutableImage authenticates immutable bytes before parsing
// their native ELF layout. It never reads a loader path, changes file offsets,
// executes code or grants deployment approval. Zero data is returned on failure.
func InspectAuthorityExecutableImage(image *os.File, digest string) (AuthorityExecutableFormat, error) {
	if err := VerifyAuthorityExecutableImage(image, digest); err != nil {
		return AuthorityExecutableFormat{}, err
	}
	raw, err := image.SyscallConn()
	if err != nil {
		return AuthorityExecutableFormat{}, ErrAuthorityExecutable
	}
	var result AuthorityExecutableFormat
	operation := ErrAuthorityExecutable
	err = raw.Control(func(fd uintptr) {
		var st unix.Stat_t
		if unix.Fstat(int(fd), &st) != nil {
			return
		}
		result, operation = inspectAuthorityELF(st.Size, runtime.GOARCH, func(b []byte, off int64) (int, error) { return unix.Pread(int(fd), b, off) })
	})
	if err != nil || operation != nil {
		return AuthorityExecutableFormat{}, ErrAuthorityExecutable
	}
	return result, nil
}

type authorityELFSegment struct {
	kind, flags                                    uint32
	offset, address, fileBytes, memoryBytes, align uint64
}

func authorityELFMachine(arch string) (byte, uint16) {
	switch arch {
	case "amd64":
		return 2, 62
	case "arm64":
		return 2, 183
	case "386":
		return 1, 3
	default:
		return 0, 0
	}
}

// Only fixed ELF and program headers are read. Sections, symbols, relocation
// tables and compressed debug data are never traversed or allocated from input.
func inspectAuthorityELF(size int64, arch string, read func([]byte, int64) (int, error)) (AuthorityExecutableFormat, error) {
	reject := func() (AuthorityExecutableFormat, error) { return AuthorityExecutableFormat{}, ErrAuthorityExecutable }
	class, machine := authorityELFMachine(arch)
	if class == 0 || size < 64 || size > MaxAuthorityExecutableBytes || read == nil {
		return reject()
	}
	get := func(b []byte, offset uint64) bool { return readAuthorityELFChunk(size, b, offset, read) }
	var h [64]byte
	if !get(h[:], 0) || string(h[:4]) != "\x7fELF" || h[4] != class || h[5] != 1 || h[6] != 1 || (h[7] != 0 && h[7] != 3) || h[8] != 0 {
		return reject()
	}
	for _, b := range h[9:16] {
		if b != 0 {
			return reject()
		}
	}
	le := binary.LittleEndian
	kind := le.Uint16(h[16:18])
	if (kind != 2 && kind != 3) || le.Uint16(h[18:20]) != machine || le.Uint32(h[20:24]) != 1 {
		return reject()
	}
	var entry, table uint64
	var headerSize, recordSize, count uint16
	var flags uint32
	wantHeader, wantRecord := uint16(64), uint16(56)
	if class == 2 {
		entry, table = le.Uint64(h[24:32]), le.Uint64(h[32:40])
		flags = le.Uint32(h[48:52])
		headerSize, recordSize, count = le.Uint16(h[52:54]), le.Uint16(h[54:56]), le.Uint16(h[56:58])
	} else {
		wantHeader, wantRecord = 52, 32
		entry, table = uint64(le.Uint32(h[24:28])), uint64(le.Uint32(h[28:32]))
		flags = le.Uint32(h[36:40])
		headerSize, recordSize, count = le.Uint16(h[40:42]), le.Uint16(h[42:44]), le.Uint16(h[44:46])
	}
	if entry == 0 || headerSize != wantHeader || recordSize != wantRecord || flags != 0 || count == 0 || count > maxAuthorityProgramHeaders || table < uint64(headerSize) || table > uint64(size) || uint64(count)*uint64(recordSize) > uint64(size)-table {
		return reject()
	}
	var programs [maxAuthorityProgramHeaders * 56]byte
	if !get(programs[:int(count)*int(recordSize)], table) {
		return reject()
	}
	var loads [maxAuthorityProgramHeaders]authorityELFSegment
	var nload int
	var totalMemory, firstAddress, lastEnd uint64
	var entryFound, stack, dynamic bool
	var dynamicSegment authorityELFSegment
	var interpreter string
	maxAddress := ^uint64(0)
	if class == 1 {
		maxAddress = 1<<32 - 1
	}
	for i := 0; i < int(count); i++ {
		b := programs[i*int(recordSize) : (i+1)*int(recordSize)]
		seg := authorityELFSegment{kind: le.Uint32(b[:4])}
		if seg.kind == 0 {
			continue
		}
		if class == 2 {
			seg.flags = le.Uint32(b[4:8])
			seg.offset = le.Uint64(b[8:16])
			seg.address = le.Uint64(b[16:24])
			seg.fileBytes = le.Uint64(b[32:40])
			seg.memoryBytes = le.Uint64(b[40:48])
			seg.align = le.Uint64(b[48:56])
		} else {
			seg.offset = uint64(le.Uint32(b[4:8]))
			seg.address = uint64(le.Uint32(b[8:12]))
			seg.fileBytes = uint64(le.Uint32(b[16:20]))
			seg.memoryBytes = uint64(le.Uint32(b[20:24]))
			seg.flags = le.Uint32(b[24:28])
			seg.align = uint64(le.Uint32(b[28:32]))
		}
		if seg.flags & ^uint32(7) != 0 || seg.flags&3 == 3 || seg.offset > uint64(size) || seg.fileBytes > uint64(size)-seg.offset || seg.memoryBytes > maxAddress-seg.address {
			return reject()
		}
		switch seg.kind {
		case 1: // PT_LOAD
			if seg.flags&4 == 0 || seg.memoryBytes == 0 || seg.fileBytes > seg.memoryBytes || seg.memoryBytes > maxAuthorityELFMemory-totalMemory {
				return reject()
			}
			if seg.align > maxAuthorityELFMemory || (seg.align > 1 && (seg.align&(seg.align-1) != 0 || seg.address%seg.align != seg.offset%seg.align)) {
				return reject()
			}
			end := seg.address + seg.memoryBytes
			if nload == 0 {
				firstAddress = seg.address
			} else if seg.address < lastEnd {
				return reject()
			}
			if end-firstAddress > maxAuthorityELFMemory {
				return reject()
			}
			if seg.flags&1 != 0 && entry >= seg.address && entry-seg.address < seg.fileBytes {
				entryFound = true
			}
			loads[nload] = seg
			nload++
			totalMemory += seg.memoryBytes
			lastEnd = end
		case 2: // PT_DYNAMIC, interpreted but not recursively resolved here
			word := uint64(16)
			if class == 1 {
				word = 8
			}
			if dynamic || seg.flags&4 == 0 || seg.flags&1 != 0 || seg.fileBytes == 0 || seg.fileBytes%word != 0 || seg.fileBytes > seg.memoryBytes {
				return reject()
			}
			dynamic = true
			dynamicSegment = seg
		case 3: // PT_INTERP must precede the first load and be uniquely terminated.
			if interpreter != "" || nload != 0 || seg.fileBytes < 2 || seg.fileBytes > maxAuthorityInterpreterBytes {
				return reject()
			}
			var buf [maxAuthorityInterpreterBytes]byte
			data := buf[:int(seg.fileBytes)]
			if !get(data, seg.offset) || data[len(data)-1] != 0 {
				return reject()
			}
			for _, b := range data[:len(data)-1] {
				if b < 33 || b > 126 {
					return reject()
				}
			}
			interpreter = string(data[:len(data)-1])
			if !strings.HasPrefix(interpreter, "/") || interpreter == "/" || path.Clean(interpreter) != interpreter {
				return reject()
			}
		case 0x6474e551: // PT_GNU_STACK: an explicit non-executable stack is required.
			if stack || seg.flags != 6 {
				return reject()
			}
			stack = true
		case 4, 6, 7, 0x6474e550, 0x6474e552, 0x6474e553: // NOTE, PHDR, TLS, GNU EH_FRAME/RELRO/PROPERTY
		default:
			return reject()
		}
	}
	if nload == 0 || !entryFound || !stack || dynamic != (interpreter != "") || (kind == 3 && !dynamic) {
		return reject()
	}
	if dynamic {
		contained := false
		for _, seg := range loads[:nload] {
			d := dynamicSegment
			if d.offset >= seg.offset && d.address >= seg.address && d.offset-seg.offset == d.address-seg.address && d.offset-seg.offset <= seg.fileBytes && d.fileBytes <= seg.fileBytes-(d.offset-seg.offset) && d.address-seg.address <= seg.memoryBytes && d.memoryBytes <= seg.memoryBytes-(d.address-seg.address) {
				contained = true
			}
		}
		if !contained {
			return reject()
		}
	}
	return AuthorityExecutableFormat{Architecture: arch, PositionIndependent: kind == 3, Interpreter: interpreter, Dynamic: dynamic}, nil
}

func readAuthorityELFChunk(size int64, b []byte, offset uint64, read func([]byte, int64) (int, error)) bool {
	if size < 0 || size > MaxAuthorityExecutableBytes || offset > math.MaxInt64 || read == nil {
		return false
	}
	off := int64(offset)
	if off > size || int64(len(b)) > size-off {
		return false
	}
	n, err := read(b, off)
	return err == nil && n == len(b)
}
