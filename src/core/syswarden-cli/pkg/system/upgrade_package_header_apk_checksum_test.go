package system

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
)

// Independent fixed vectors were generated with Python's tarfile USTAR_FORMAT,
// gzip.compress(mtime=0) and hashlib.sha1, not the production reader or Go gzip.
// Each control contains modern .PKGINFO including the actual compressed datahash,
// mode 0600 and zero uid, gid and mtime. Cut control is 1024 bytes; full control
// adds two zero blocks and is rejected by this bridge. The cut vector's C was
// independently matched by rootless APK2 2.14.12 and APK3 3.0.8 index operations.
// The second positive vector changes only gzip mtime to 1. These synthetic bytes
// are not signed release artifacts, and neither oracle installs any package.
const apkRegistrationCutControl = "H4sIAAAAAAAC/+2NzU7DMBCEc/ZT+AVIJ4ntpEhcQRXiR4I72tgbEjVNK9sFytPjgAQHJG5wKd9ldkezO/nt5cXq+vwm+0WQMMC74ruiUl/zh1+jQiaR/QH7EMmnyuw42a0fJ9qwPJPhEJ7JO55E8p7YJ0vnQI4TD0He9sl4acyDUSIMr/OFwtLMYcfBpvXuMMWe42DlMLGP0vZs12G/kVtPdmSx92NK9THuwuli8VmXD1sxDpanMP+8Wt0LR5F6CnMht0qjgGnLrkGZ+rol6bYwZBpC6SoQN7Uu6tJZ3YFUVcJ1ip1rNWpbKJH98yNvIIz7dQAEAAA="
const apkRegistrationFullControl = "H4sIAAAAAAAC/+3Nz07EIBAG8J55Cl7A7rQF2jXxqtkY/yR6N1OYSrNddgNUXZ9eqoke9KoX+V0Gvgx85e3lxeb6/Kb4RZAogPcJ3yc04uv8kbfQQMGh+ANziOhTZfE/HbaPDnfEz3g4hmf0hhxL2RP5FMkSoIQTDwy9til46dSDEiyMr8sLAWu1LBsKOl3vji5aiqPmoyMfubakt2He8b1HPRGb/ZS2bIyHcLpafdaV455NoyYXlj+vNvfMYESLYSmkXkioQPX10EGd+oY1yr5SqDqE2jSA1LWyamuj5QAomhrMIMiYXkKrK8GKLMuy7EdvVvZHBgAIAAA="
const apkRegistrationData = "H4sIAAAAAAAC/+3SQQrCQAyF4aw9xRxAJS1VD+IJhjbQwjDCGIXe3rEbF64tQv9v88LbBEJuJfbJDlO24vIjWp1Vl9TvVO0un/ndN9p2JwkqK3jcPZa6XrbpOmcfzac+LC8QhuhxH7I9rdSm3iYlG447AQAAAAAAAAAAAAAAAAD8lxdWEFpEACgAAA=="
const apkRegistrationDataSHA256 = "eb450106b2f802096f9a5b16a68a02d30ae875172dc5f0a4320df4eddb507c14"

func apkRegistrationTestVector(t *testing.T, encoded string) []byte {
	t.Helper()
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func apkRegistrationTestSignature(t *testing.T, value string) []byte {
	t.Helper()
	return nativeHeaderTestGzip(t, nativeHeaderTestTar(t, true,
		nativeHeaderTestEntry{name: ".SIGN.RSA.public-test.rsa.pub", data: []byte(value)}))
}

func TestAuthenticatedAPKRegistrationChecksumFixedVectors(t *testing.T) {
	for _, vector := range []struct {
		name  string
		mtime byte
		want  string
	}{
		{"cut", 0, "Q1rHoRxJ3fSZ12zpR+TbuWUfXpV8Q="},
		{"cut with gzip mtime", 1, "Q1Jp2diBYciWLGXJfIiyaWSv4asjM="},
	} {
		for _, signed := range []bool{false, true} {
			name := vector.name + "/unsigned"
			var signature []byte
			if signed {
				name = vector.name + "/signed"
				signature = apkRegistrationTestSignature(t, "synthetic signature")
			}
			t.Run(name, func(t *testing.T) {
				control := apkRegistrationTestVector(t, apkRegistrationCutControl)
				control[4] = vector.mtime
				contents := bytes.Join([][]byte{signature, control, apkRegistrationTestVector(t, apkRegistrationData)}, nil)
				file := openQualificationPayloadFixture(t, "candidate.apk", contents)
				if _, err := file.Seek(7, io.SeekStart); err != nil {
					t.Fatal(err)
				}
				got, err := readAuthenticatedAPKRegistrationChecksum(t.Context(), file)
				if err != nil || got != vector.want {
					t.Fatalf("registration checksum = %q, want %q: %v", got, vector.want, err)
				}
				if offset, err := file.Seek(0, io.SeekCurrent); err != nil || offset != 7 {
					t.Fatalf("descriptor offset changed: %d, %v", offset, err)
				}
				identity, err := readAuthenticatedAPKIdentity(t.Context(), file)
				want := nativePackageHeaderIdentity{name: "syswarden", version: "5.00.0-r0", architecture: "x86_64"}
				if err != nil || identity != want {
					t.Fatalf("identity = %#v, want %#v: %v", identity, want, err)
				}
			})
		}
	}
}

func apkRegistrationTestInfo(data []byte) []byte {
	digest := sha256.Sum256(data)
	return append(nativeHeaderTestAPKInfo("syswarden"), []byte("datahash = "+hex.EncodeToString(digest[:])+"\n")...)
}

func TestAuthenticatedAPKRegistrationChecksumBindsExactControlAndData(t *testing.T) {
	control := apkRegistrationTestVector(t, apkRegistrationCutControl)
	signature := apkRegistrationTestSignature(t, "first synthetic signature")
	data := apkRegistrationTestVector(t, apkRegistrationData)
	changedHeader := bytes.Clone(control)
	changedHeader[4] = 1 // Valid gzip mtime change, identical uncompressed control.
	changedBody := nativeHeaderTestGzip(t, nativeHeaderTestTar(t, true,
		nativeHeaderTestEntry{name: ".PKGINFO", data: append(apkRegistrationTestInfo(data), []byte("# Changed control comment\n")...)}))
	changedData := nativeHeaderTestGzip(t, nativeHeaderTestTar(t, false,
		nativeHeaderTestEntry{name: "opt/syswarden/bin/syswarden-cli", data: []byte("different inert payload\n")}))
	changedDataHeader := bytes.Clone(data)
	changedDataHeader[4] = 1 // Datahash binds compression framing as well as contents.
	for _, test := range []struct {
		name                     string
		signature, control, data []byte
		wantSame, wantError      bool
	}{
		{"unchanged", signature, control, data, true, false},
		{"different signature", apkRegistrationTestSignature(t, "different synthetic signature"), control, data, true, false},
		{"different compressed control header", signature, changedHeader, data, false, false},
		{"different control content", signature, changedBody, data, false, false},
		{"different data", signature, control, changedData, false, true},
		{"different compressed data header", signature, control, changedDataHeader, false, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			contents := bytes.Join([][]byte{test.signature, test.control, test.data}, nil)
			got, err := readAuthenticatedAPKRegistrationChecksum(t.Context(), openQualificationPayloadFixture(t, "candidate.apk", contents))
			if test.wantError {
				if err == nil || got != "" {
					t.Fatalf("unbound data produced checksum %q: %v", got, err)
				}
				return
			}
			if err != nil || got == "" || (got == "Q1rHoRxJ3fSZ12zpR+TbuWUfXpV8Q=") != test.wantSame {
				t.Fatalf("checksum = %q, want same=%t: %v", got, test.wantSame, err)
			}
		})
	}
}

func TestAuthenticatedAPKRegistrationChecksumRequiresCanonicalDatahash(t *testing.T) {
	data := apkRegistrationTestVector(t, apkRegistrationData)
	for name, fields := range map[string]string{
		"absent":                 "",
		"comment only":           "# datahash = " + apkRegistrationDataSHA256 + "\n",
		"duplicate":              "datahash = " + apkRegistrationDataSHA256 + "\ndatahash = " + apkRegistrationDataSHA256 + "\n",
		"uppercase key":          "DataHash = " + apkRegistrationDataSHA256 + "\n",
		"duplicate case variant": "datahash = " + apkRegistrationDataSHA256 + "\nDataHash = " + apkRegistrationDataSHA256 + "\n",
		"uppercase digest":       "datahash = " + strings.ToUpper(apkRegistrationDataSHA256) + "\n",
		"empty digest":           "datahash = \n",
		"short digest":           "datahash = " + apkRegistrationDataSHA256[:62] + "\n",
		"long digest":            "datahash = " + apkRegistrationDataSHA256 + "00\n",
		"nonhex digest":          "datahash = " + strings.Repeat("z", 64) + "\n",
		"trailing space":         "datahash = " + apkRegistrationDataSHA256 + " \n",
		"mismatched digest":      "datahash = " + strings.Repeat("0", 64) + "\n",
	} {
		t.Run(name, func(t *testing.T) {
			info := append(nativeHeaderTestAPKInfo("syswarden"), []byte(fields)...)
			control := nativeHeaderTestGzip(t, nativeHeaderTestTar(t, true, nativeHeaderTestEntry{name: ".PKGINFO", data: info}))
			contents := bytes.Join([][]byte{control, data}, nil)
			file := openQualificationPayloadFixture(t, "candidate.apk", contents)
			if _, err := readAuthenticatedAPKIdentity(t.Context(), file); err != nil {
				t.Fatalf("generic identity semantics changed: %v", err)
			}
			if got, err := readAuthenticatedAPKRegistrationChecksum(t.Context(), file); err == nil || got != "" {
				t.Fatalf("noncanonical datahash produced checksum %q: %v", got, err)
			}
		})
	}
}

func TestAuthenticatedAPKRegistrationChecksumRequiresCutControlAndSignature(t *testing.T) {
	control := apkRegistrationTestVector(t, apkRegistrationCutControl)
	data := apkRegistrationTestVector(t, apkRegistrationData)
	for name, contents := range map[string][]byte{
		"padded control": bytes.Join([][]byte{apkRegistrationTestVector(t, apkRegistrationFullControl), data}, nil),
		"padded signature": bytes.Join([][]byte{nativeHeaderTestGzip(t, nativeHeaderTestTar(t, false,
			nativeHeaderTestEntry{name: ".SIGN.RSA.public-test.rsa.pub", data: []byte("synthetic signature")})), control, data}, nil),
	} {
		t.Run(name, func(t *testing.T) {
			file := openQualificationPayloadFixture(t, "candidate.apk", contents)
			if _, err := readAuthenticatedAPKIdentity(t.Context(), file); err != nil {
				t.Fatalf("generic identity semantics changed: %v", err)
			}
			if got, err := readAuthenticatedAPKRegistrationChecksum(t.Context(), file); err == nil || got != "" {
				t.Fatalf("uncut segment produced checksum %q: %v", got, err)
			}
		})
	}
}

func TestAuthenticatedAPKRegistrationChecksumRejectsIncompleteOrForeignStreams(t *testing.T) {
	control := apkRegistrationTestVector(t, apkRegistrationCutControl)
	signature := apkRegistrationTestSignature(t, "synthetic signature")
	data := apkRegistrationTestVector(t, apkRegistrationData)
	valid := bytes.Join([][]byte{signature, control, data}, nil)
	corruptControl := bytes.Clone(control)
	corruptControl[len(corruptControl)-8] ^= 1
	corruptData := bytes.Clone(data)
	corruptData[len(corruptData)-8] ^= 1
	for name, contents := range map[string][]byte{
		"missing control":         bytes.Join([][]byte{signature, data}, nil),
		"missing data":            bytes.Join([][]byte{signature, control}, nil),
		"data before control":     bytes.Join([][]byte{signature, data, control}, nil),
		"signature after control": bytes.Join([][]byte{control, signature, data}, nil),
		"duplicate signature":     bytes.Join([][]byte{signature, signature, control, data}, nil),
		"duplicate control":       bytes.Join([][]byte{signature, control, control, data}, nil),
		"extra data":              bytes.Join([][]byte{valid, data}, nil),
		"extra empty gzip":        bytes.Join([][]byte{valid, nativeHeaderTestGzip(t, nil)}, nil),
		"truncated signature":     signature[:len(signature)-1],
		"truncated control":       bytes.Join([][]byte{signature, control[:len(control)-1]}, nil),
		"truncated data":          valid[:len(valid)-1],
		"corrupt control CRC":     bytes.Join([][]byte{signature, corruptControl, data}, nil),
		"corrupt data CRC":        bytes.Join([][]byte{signature, control, corruptData}, nil),
		"foreign trailing bytes":  bytes.Join([][]byte{valid, []byte("foreign")}, nil),
		"APK v3":                  []byte("ADB.\x01synthetic unsupported APKv3 data"),
		"malformed final control metadata": bytes.Join([][]byte{signature, nativeHeaderTestGzip(t, nativeHeaderTestTar(t, true,
			nativeHeaderTestEntry{name: ".PKGINFO", data: []byte("pkgname = syswarden\n")})), data}, nil),
	} {
		t.Run(name, func(t *testing.T) {
			got, err := readAuthenticatedAPKRegistrationChecksum(t.Context(), openQualificationPayloadFixture(t, "candidate.apk", contents))
			if err == nil || got != "" {
				t.Fatalf("invalid package produced registration checksum %q: %v", got, err)
			}
		})
	}
}

func TestAuthenticatedAPKRegistrationChecksumBoundsAndContext(t *testing.T) {
	t.Run("expanded control bound", func(t *testing.T) {
		control := nativeHeaderTestGzip(t, nativeHeaderTestTar(t, true,
			nativeHeaderTestEntry{name: ".PKGINFO", data: nativeHeaderTestAPKInfo("syswarden")},
			nativeHeaderTestEntry{name: ".pre-install", data: make([]byte, maximumNativeControlBytes+1)}))
		contents := bytes.Join([][]byte{control, nativeHeaderTestData(t)}, nil)
		got, err := readAuthenticatedAPKRegistrationChecksum(t.Context(), openQualificationPayloadFixture(t, "candidate.apk", contents))
		if err == nil || got != "" || !strings.Contains(err.Error(), "expanded bound") {
			t.Fatalf("expanded control bound: %q, %v", got, err)
		}
	})
	t.Run("nil context", func(t *testing.T) {
		if got, err := readAuthenticatedAPKRegistrationChecksum(nil, nil); err == nil || got != "" { //nolint:staticcheck // SA1012: Deliberate invalid context verifies rejection before reading candidate bytes or returning identity.
			t.Fatalf("nil context: %q, %v", got, err)
		}
	})
	t.Run("cancelled context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		if got, err := readAuthenticatedAPKRegistrationChecksum(ctx, nil); !errors.Is(err, context.Canceled) || got != "" {
			t.Fatalf("cancelled context: %q, %v", got, err)
		}
	})
	t.Run("nil descriptor", func(t *testing.T) {
		if got, err := readAuthenticatedAPKRegistrationChecksum(t.Context(), nil); err == nil || got != "" {
			t.Fatalf("nil descriptor: %q, %v", got, err)
		}
	})
	t.Run("closed descriptor", func(t *testing.T) {
		file := openQualificationPayloadFixture(t, "candidate.apk", []byte("closed synthetic fixture"))
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		if got, err := readAuthenticatedAPKRegistrationChecksum(t.Context(), file); !errors.Is(err, os.ErrClosed) || got != "" {
			t.Fatalf("closed descriptor: %q, %v", got, err)
		}
	})
}
