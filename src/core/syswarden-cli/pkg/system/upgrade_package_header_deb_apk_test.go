package system

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
)

// All package contents and signature bytes here are synthetic public test data.
// Native signature verification is a separate mandatory production boundary.
type nativeHeaderTestEntry struct {
	name, link string
	data       []byte
	kind       byte
	pax        map[string]string
}

func nativeHeaderTestTar(t *testing.T, cut bool, entries ...nativeHeaderTestEntry) []byte {
	t.Helper()
	var archive bytes.Buffer
	writer := tar.NewWriter(&archive)
	for _, entry := range entries {
		kind := entry.kind
		if kind == 0 {
			kind = tar.TypeReg
		}
		header := &tar.Header{Name: entry.name, Size: int64(len(entry.data)), Mode: 0644, Typeflag: kind, Linkname: entry.link, PAXRecords: entry.pax}
		if err := writer.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write(entry.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	data := archive.Bytes()
	if cut {
		data = data[:len(data)-1024]
	}
	return data
}

func nativeHeaderTestGzip(t *testing.T, data []byte) []byte {
	t.Helper()
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := writer.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return compressed.Bytes()
}

func nativeHeaderTestDEBControl(name string) []byte {
	return []byte("Package: " + name + "\nVersion: 5.00.0\nArchitecture: amd64\nDescription: Synthetic public fixture\n optional continuation\n .\n final continuation\n")
}

func nativeHeaderTestAPKInfo(name string) []byte {
	return []byte("# Synthetic public fixture\npkgname = " + name + "\npkgver = 5.00.0-r0\narch = x86_64\ndepend = nftables\ndepend = curl\nlicense = GPL-3.0-or-later\n")
}

func nativeHeaderTestDEB(t *testing.T, control []byte) []byte {
	t.Helper()
	var archive bytes.Buffer
	archive.WriteString("!<arch>\n")
	appendQualificationARMember(t, &archive, "debian-binary", []byte("2.0\n"))
	appendQualificationARMember(t, &archive, "control.tar.gz", control)
	appendQualificationARMember(t, &archive, "data.tar.gz", nativeHeaderTestData(t))
	return archive.Bytes()
}

func nativeHeaderTestData(t *testing.T) []byte {
	t.Helper()
	return nativeHeaderTestGzip(t, nativeHeaderTestTar(t, false, nativeHeaderTestEntry{name: "opt/syswarden/bin/syswarden-cli", data: []byte("synthetic payload, never executed\n")}))
}

func TestAuthenticatedDEBHeaderUsesDescriptorAndExactControl(t *testing.T) {
	for _, name := range []string{"syswarden", "syswarden-base"} {
		t.Run(name, func(t *testing.T) {
			control := nativeHeaderTestGzip(t, nativeHeaderTestTar(t, false,
				nativeHeaderTestEntry{name: "./", kind: tar.TypeDir},
				nativeHeaderTestEntry{name: "./control", data: nativeHeaderTestDEBControl(name)},
				nativeHeaderTestEntry{name: "./preinst", data: []byte("#!/bin/sh\nexit 0\n")}))
			file := openQualificationPayloadFixture(t, "untrusted-display-name.apk", nativeHeaderTestDEB(t, control))
			if _, err := file.Seek(3, io.SeekStart); err != nil {
				t.Fatal(err)
			}
			identity, err := readAuthenticatedDEBIdentity(t.Context(), file)
			want := nativePackageHeaderIdentity{name: name, version: "5.00.0", architecture: "amd64"}
			if err != nil || identity != want {
				t.Fatalf("DEB identity = %#v, want %#v: %v", identity, want, err)
			}
			if position, err := file.Seek(0, io.SeekCurrent); err != nil || position != 3 {
				t.Fatalf("descriptor offset changed: %d, %v", position, err)
			}
		})
	}
}

func TestAuthenticatedAPKHeaderReadsSignedAndCutStreams(t *testing.T) {
	for _, name := range []string{"syswarden", "syswarden-base"} {
		for _, signed := range []bool{false, true} {
			for _, cut := range []bool{false, true} {
				var packageBytes []byte
				if signed {
					packageBytes = append(packageBytes, nativeHeaderTestGzip(t, nativeHeaderTestTar(t, cut,
						nativeHeaderTestEntry{name: ".SIGN.RSA.public-test.rsa.pub", data: []byte("synthetic signature"), pax: map[string]string{"atime": "0", "ctime": "0"}}))...)
				}
				packageBytes = append(packageBytes, nativeHeaderTestGzip(t, nativeHeaderTestTar(t, cut,
					nativeHeaderTestEntry{name: ".PKGINFO", data: nativeHeaderTestAPKInfo(name)},
					nativeHeaderTestEntry{name: ".pre-install", data: []byte("#!/bin/sh\nexit 0\n")}))...)
				packageBytes = append(packageBytes, nativeHeaderTestData(t)...)
				file := openQualificationPayloadFixture(t, "untrusted-display-name.deb", packageBytes)
				if _, err := file.Seek(5, io.SeekStart); err != nil {
					t.Fatal(err)
				}
				identity, err := readAuthenticatedAPKIdentity(t.Context(), file)
				want := nativePackageHeaderIdentity{name: name, version: "5.00.0-r0", architecture: "x86_64"}
				if err != nil || identity != want {
					t.Fatalf("APK name=%s signed=%t cut=%t identity=%#v: %v", name, signed, cut, identity, err)
				}
				if position, err := file.Seek(0, io.SeekCurrent); err != nil || position != 5 {
					t.Fatalf("descriptor offset changed: %d, %v", position, err)
				}
			}
		}
	}
}

func TestAuthenticatedHeaderMetadataRejectsAmbiguousFields(t *testing.T) {
	for _, format := range []string{"deb", "apk"} {
		for _, name := range []string{"syswarden", "syswarden-base"} {
			valid := string(nativeHeaderTestDEBControl(name))
			fields := []string{"Package: " + name, "Version: 5.00.0", "Architecture: amd64"}
			parse := parseAuthenticatedDEBControl
			if format == "apk" {
				valid = string(nativeHeaderTestAPKInfo(name))
				fields = []string{"pkgname = " + name, "pkgver = 5.00.0-r0", "arch = x86_64"}
				parse = parseAuthenticatedAPKInfo
			}
			cases := map[string]string{
				"missing final newline": strings.TrimSuffix(valid, "\n"),
				"CRLF":                  strings.ReplaceAll(valid, "\n", "\r\n"),
				"NUL":                   strings.Replace(valid, name, name+"\x00", 1),
				"invalid UTF8":          valid + string([]byte{0xff}) + "\n",
				"excessive":             strings.Repeat("#", maximumNativeHeaderMetadataBytes) + valid,
			}
			for _, field := range fields {
				cases["duplicate "+field] = valid + field + "\n"
				cases["case duplicate "+field] = valid + strings.ToUpper(field) + "\n"
				cases["missing "+field] = strings.Replace(valid, field+"\n", "", 1)
				cases["continued "+field] = strings.Replace(valid, field+"\n", field+"\n additional-identity\n", 1)
			}
			if format == "deb" {
				cases["second paragraph"] = valid + "\nPackage: foreign\n"
			} else {
				cases["foreign delimiter"] = strings.Replace(valid, "pkgname = ", "pkgname=", 1)
				cases["trailing required whitespace"] = strings.Replace(valid, "arch = x86_64\n", "arch = x86_64 \n", 1)
			}
			for label, input := range cases {
				t.Run(format+"/"+name+"/"+label, func(t *testing.T) {
					identity, err := parse([]byte(input))
					if err == nil || identity != (nativePackageHeaderIdentity{}) {
						t.Fatalf("ambiguous metadata accepted: %#v, %v", identity, err)
					}
				})
			}
		}
	}
}

func TestAuthenticatedDEBHeaderRejectsForeignFraming(t *testing.T) {
	validTar := nativeHeaderTestTar(t, false, nativeHeaderTestEntry{name: "control", data: nativeHeaderTestDEBControl("syswarden")})
	validControl := nativeHeaderTestGzip(t, validTar)
	valid := nativeHeaderTestDEB(t, validControl)
	corruptGzip := bytes.Clone(validControl)
	corruptGzip[len(corruptGzip)-8] ^= 1
	var duplicate bytes.Buffer
	duplicate.Write(valid)
	appendQualificationARMember(t, &duplicate, "control.tar.gz", validControl)
	cases := map[string][]byte{
		"foreign magic":              append([]byte("foreign!"), valid[8:]...),
		"truncated ar":               valid[:len(valid)-1],
		"extra ar member":            duplicate.Bytes(),
		"trailing ar bytes":          append(bytes.Clone(valid), 'x'),
		"unsupported format":         bytes.Replace(valid, []byte("2.0\n"), []byte("3.0\n"), 1),
		"unsupported compression":    bytes.Replace(valid, []byte("control.tar.gz"), []byte("control.tar.xz"), 1),
		"gzip checksum":              nativeHeaderTestDEB(t, corruptGzip),
		"extra control gzip":         nativeHeaderTestDEB(t, append(bytes.Clone(validControl), validControl...)),
		"cut control tar":            nativeHeaderTestDEB(t, nativeHeaderTestGzip(t, validTar[:len(validTar)-1024])),
		"foreign trailing tar bytes": nativeHeaderTestDEB(t, nativeHeaderTestGzip(t, append(bytes.Clone(validTar), []byte("hidden")...))),
	}
	for _, tc := range []struct {
		label string
		entry nativeHeaderTestEntry
	}{
		{"missing metadata", nativeHeaderTestEntry{name: "conffiles", data: []byte("/etc/example\n")}},
		{"absolute metadata", nativeHeaderTestEntry{name: "/control", data: nativeHeaderTestDEBControl("syswarden")}},
		{"traversal metadata", nativeHeaderTestEntry{name: "x/../control", data: nativeHeaderTestDEBControl("syswarden")}},
		{"linked metadata", nativeHeaderTestEntry{name: "control", kind: tar.TypeSymlink, link: "other"}},
		{"excessive metadata", nativeHeaderTestEntry{name: "control", data: bytes.Repeat([]byte{'a'}, maximumNativeHeaderMetadataBytes+1)}},
	} {
		cases[tc.label] = nativeHeaderTestDEB(t, nativeHeaderTestGzip(t, nativeHeaderTestTar(t, false, tc.entry)))
	}
	cases["duplicate metadata"] = nativeHeaderTestDEB(t, nativeHeaderTestGzip(t, nativeHeaderTestTar(t, false,
		nativeHeaderTestEntry{name: "control", data: nativeHeaderTestDEBControl("syswarden")},
		nativeHeaderTestEntry{name: "./control", data: nativeHeaderTestDEBControl("syswarden-base")})))
	for label, input := range cases {
		t.Run(label, func(t *testing.T) {
			identity, err := readAuthenticatedDEBIdentity(t.Context(), openQualificationPayloadFixture(t, "candidate", input))
			if err == nil || identity != (nativePackageHeaderIdentity{}) {
				t.Fatalf("foreign DEB framing accepted: %#v, %v", identity, err)
			}
		})
	}
}

func TestAuthenticatedAPKHeaderRejectsForeignFraming(t *testing.T) {
	info := nativeHeaderTestAPKInfo("syswarden")
	control := nativeHeaderTestGzip(t, nativeHeaderTestTar(t, true, nativeHeaderTestEntry{name: ".PKGINFO", data: info}))
	data := nativeHeaderTestData(t)
	valid := append(bytes.Clone(control), data...)
	corrupt := bytes.Clone(valid)
	corrupt[len(corrupt)-8] ^= 1
	cases := map[string][]byte{
		"missing data":          control,
		"missing control":       data,
		"reversed streams":      append(bytes.Clone(data), control...),
		"truncated gzip":        valid[:len(valid)-1],
		"gzip checksum":         corrupt,
		"extra stream":          append(bytes.Clone(valid), data...),
		"foreign trailer":       append(bytes.Clone(valid), []byte("foreign")...),
		"duplicate control":     append(append(bytes.Clone(control), control...), data...),
		"empty leading stream":  append(nativeHeaderTestGzip(t, nil), valid...),
		"missing metadata":      append(nativeHeaderTestGzip(t, nativeHeaderTestTar(t, true, nativeHeaderTestEntry{name: ".pre-install", data: []byte("fixture")})), data...),
		"foreign tar after end": append(nativeHeaderTestGzip(t, append(nativeHeaderTestTar(t, false, nativeHeaderTestEntry{name: ".PKGINFO", data: info}), []byte("hidden")...)), data...),
		"metadata in data":      append(bytes.Clone(control), nativeHeaderTestGzip(t, nativeHeaderTestTar(t, false, nativeHeaderTestEntry{name: ".PKGINFO", data: info}))...),
		"metadata in signature": append(nativeHeaderTestGzip(t, nativeHeaderTestTar(t, true, nativeHeaderTestEntry{name: ".SIGN.RSA.public-test", data: []byte("signature")}, nativeHeaderTestEntry{name: ".PKGINFO", data: info})), valid...),
		"duplicate metadata":    append(nativeHeaderTestGzip(t, nativeHeaderTestTar(t, true, nativeHeaderTestEntry{name: ".PKGINFO", data: info}, nativeHeaderTestEntry{name: "./.PKGINFO", data: info})), data...),
		"linked metadata":       append(nativeHeaderTestGzip(t, nativeHeaderTestTar(t, true, nativeHeaderTestEntry{name: ".PKGINFO", kind: tar.TypeSymlink, link: "other"})), data...),
		"nested metadata":       append(nativeHeaderTestGzip(t, nativeHeaderTestTar(t, true, nativeHeaderTestEntry{name: "nested/.PKGINFO", data: info})), data...),
		"excessive metadata":    append(nativeHeaderTestGzip(t, nativeHeaderTestTar(t, true, nativeHeaderTestEntry{name: ".PKGINFO", data: bytes.Repeat([]byte{'a'}, maximumNativeHeaderMetadataBytes+1)})), data...),
		"cut data tar":          append(bytes.Clone(control), nativeHeaderTestGzip(t, nativeHeaderTestTar(t, true, nativeHeaderTestEntry{name: "opt/fixture", data: []byte("payload")}))...),
	}
	for label, input := range cases {
		t.Run(label, func(t *testing.T) {
			identity, err := readAuthenticatedAPKIdentity(t.Context(), openQualificationPayloadFixture(t, "candidate", input))
			if err == nil || identity != (nativePackageHeaderIdentity{}) {
				t.Fatalf("foreign APK framing accepted: %#v, %v", identity, err)
			}
		})
	}
}

func TestAuthenticatedHeaderControlExpansionIsBounded(t *testing.T) {
	// A small compressed archive declares a control file beyond the expansion
	// budget. The header reader must refuse before copying its expanded contents.
	bomb := nativeHeaderTestTar(t, false,
		nativeHeaderTestEntry{name: "control", data: nativeHeaderTestDEBControl("syswarden")},
		nativeHeaderTestEntry{name: "preinst", data: make([]byte, maximumNativeControlBytes+1)})
	file := openQualificationPayloadFixture(t, "candidate", nativeHeaderTestDEB(t, nativeHeaderTestGzip(t, bomb)))
	if _, err := readAuthenticatedDEBIdentity(t.Context(), file); err == nil || !strings.Contains(err.Error(), "expanded bound") {
		t.Fatalf("control expansion bound error = %v", err)
	}
	apkBomb := nativeHeaderTestTar(t, true,
		nativeHeaderTestEntry{name: ".PKGINFO", data: nativeHeaderTestAPKInfo("syswarden")},
		nativeHeaderTestEntry{name: ".pre-install", data: make([]byte, maximumNativeControlBytes+1)})
	apk := append(nativeHeaderTestGzip(t, apkBomb), nativeHeaderTestData(t)...)
	file = openQualificationPayloadFixture(t, "apk-candidate", apk)
	if _, err := readAuthenticatedAPKIdentity(t.Context(), file); err == nil || !strings.Contains(err.Error(), "expanded bound") {
		t.Fatalf("APK control expansion bound error = %v", err)
	}
}

func nativeHeaderTestSparseTar(t *testing.T, format string) []byte {
	t.Helper()
	entry := nativeHeaderTestEntry{name: "opt/synthetic-sparse"}
	if format == "gnu" {
		data := nativeHeaderTestTar(t, false, entry)
		// Old GNU sparse headers store the logical size separately from the
		// zero-byte physical body. An empty sparse map describes only holes.
		data[156] = tar.TypeGNUSparse
		copy(data[257:265], "ustar  \x00")
		copy(data[483:495], fmt.Sprintf("%011o\x00", 4096))
		copy(data[148:156], "        ")
		checksum := 0
		for _, value := range data[:512] {
			checksum += int(value)
		}
		copy(data[148:156], fmt.Sprintf("%06o\x00 ", checksum))
		return data
	}
	// tar.Writer filters GNU sparse records. Equal-length test placeholders
	// retain valid PAX lengths and are replaced only after serialization.
	entry.pax = map[string]string{"TST.sparse.realsize": "4096"}
	switch format {
	case "pax-0.1":
		entry.pax["TST.sparse.major"] = "0"
		entry.pax["TST.sparse.minor"] = "1"
		entry.pax["TST.sparse.numblocks"] = "1"
		entry.pax["TST.sparse.map"] = "0,0"
	case "pax-1.0":
		entry.pax["TST.sparse.major"] = "1"
		entry.pax["TST.sparse.minor"] = "0"
		entry.data = make([]byte, 512)
		copy(entry.data, "0\n") // Zero data extents, padded to the next tar block.
	case "pax-unknown":
		entry.pax = map[string]string{"TST.sparse.future": "1"}
		entry.data = []byte("ordinary physical body")
	default:
		t.Fatalf("unknown sparse test format %q", format)
	}
	return bytes.ReplaceAll(nativeHeaderTestTar(t, false, entry), []byte("TST.sparse."), []byte("GNU.sparse."))
}

func TestAuthenticatedHeaderRejectsParsedSparseMembersBeforeReadingBodies(t *testing.T) {
	for _, format := range []string{"gnu", "pax-0.1", "pax-1.0", "pax-unknown"} {
		t.Run(format, func(t *testing.T) {
			data := nativeHeaderTestSparseTar(t, format)
			source := bytes.NewReader(data)
			archive := tar.NewReader(source)
			header, err := archive.Next()
			if err != nil {
				t.Fatalf("sparse fixture must be accepted by archive/tar: %v", err)
			}
			headerBytes := int64(len(data) - source.Len())
			if format == "gnu" && header.Typeflag != tar.TypeGNUSparse {
				t.Fatalf("GNU sparse fixture was parsed as type %q", header.Typeflag)
			}
			if format != "gnu" && len(header.PAXRecords) == 0 {
				t.Fatal("sparse PAX fixture lost its extension records")
			}
			if format != "pax-unknown" {
				var holes [32]byte
				before := source.Len()
				if header.Size != 4096 {
					t.Fatalf("sparse fixture logical size = %d", header.Size)
				}
				if _, err := io.ReadFull(archive, holes[:]); err != nil || holes != [32]byte{} || source.Len() != before {
					t.Fatalf("fixture did not synthesize holes without consuming bytes: %v", err)
				}
			}
			for _, kind := range []string{"deb-control", "apk-first", "apk-control", "apk-signature", "apk-data"} {
				t.Run(kind, func(t *testing.T) {
					total := int64(0)
					reader := &nativeHeaderReader{reader: bytes.NewReader(data), ctx: t.Context(), limit: maximumNativeControlBytes, total: &total}
					if _, _, err := readNativeHeaderTar(reader, kind); err == nil || !strings.Contains(err.Error(), "unsupported sparse framing") {
						t.Fatalf("sparse member was not refused before classification: %v", err)
					}
					if reader.count != headerBytes || total != headerBytes {
						t.Fatalf("sparse member body or trailer was consumed: read=%d total=%d headers=%d", reader.count, total, headerBytes)
					}
				})
			}
			for _, name := range []string{"syswarden", "syswarden-base"} {
				control := nativeHeaderTestGzip(t, nativeHeaderTestTar(t, true, nativeHeaderTestEntry{name: ".PKGINFO", data: nativeHeaderTestAPKInfo(name)}))
				packageBytes := append(control, nativeHeaderTestGzip(t, data)...)
				identity, err := readAuthenticatedAPKIdentity(t.Context(), openQualificationPayloadFixture(t, "sparse-apk", packageBytes))
				if err == nil || !strings.Contains(err.Error(), "unsupported sparse framing") || identity != (nativePackageHeaderIdentity{}) {
					t.Fatalf("APK %s sparse data accepted: %#v, %v", name, identity, err)
				}
			}
		})
	}
}

type nativeHeaderTestReader func([]byte) (int, error)

func (read nativeHeaderTestReader) Read(buffer []byte) (int, error) { return read(buffer) }

func TestAuthenticatedHeaderReaderEnforcesCancellationAndAggregateBound(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	total := int64(0)
	reader := nativeHeaderReader{
		ctx: ctx, limit: maximumNativeControlBytes, total: &total,
		reader: nativeHeaderTestReader(func(buffer []byte) (int, error) {
			n := copy(buffer, "synthetic")
			cancel()
			return n, nil
		}),
	}
	var buffer [32]byte
	if _, err := reader.Read(buffer[:]); !errors.Is(err, context.Canceled) {
		t.Fatalf("successful read after cancellation was accepted: %v", err)
	}
	total = maximumQualificationPackageExpandedBytes - 1
	reader = nativeHeaderReader{ctx: t.Context(), reader: strings.NewReader("too much"), limit: maximumNativeControlBytes, total: &total}
	if _, err := reader.Read(buffer[:]); err == nil || !strings.Contains(err.Error(), "expanded bound") {
		t.Fatalf("aggregate expansion budget was bypassed: %v", err)
	}
}

func TestAuthenticatedHeaderContextAndDescriptorFailures(t *testing.T) {
	for _, read := range []func(context.Context, *os.File) (nativePackageHeaderIdentity, error){readAuthenticatedDEBIdentity, readAuthenticatedAPKIdentity} {
		if _, err := read(nil, nil); err == nil {
			t.Fatal("nil context accepted")
		}
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		if _, err := read(ctx, nil); !errors.Is(err, context.Canceled) {
			t.Fatalf("cancellation did not precede descriptor access: %v", err)
		}
		if _, err := read(t.Context(), nil); err == nil {
			t.Fatal("nil descriptor accepted")
		}
		file := openQualificationPayloadFixture(t, "closed", []byte("synthetic"))
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := read(t.Context(), file); err == nil {
			t.Fatal("closed descriptor accepted")
		}
	}
}
