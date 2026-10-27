package system

import (
	"archive/tar"
	"context"
	"crypto/sha1" // #nosec G505 -- verifies the native APK member checksum, not release authenticity
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"sort"
	"strings"
)

type apkTransitionMember struct {
	Stream    string `json:"stream"`
	Path      string `json:"path"`
	Mode      int64  `json:"mode"`
	Size      int64  `json:"size"`
	Directory bool   `json:"directory"`
	SHA256    string `json:"sha256"`
}

// This inventory describes the candidate, not ownership of existing host files.
// In particular, neither a native registration nor a canonical-looking alias
// grants permission to replace an administrator's file.
func readAPKTransitionInventory(ctx context.Context, file *os.File) ([]apkTransitionMember, nativePackageHeaderIdentity, error) {
	required := map[string]int64{
		"opt": 0755, "opt/syswarden": 0755, "opt/syswarden/bin": 0755,
		"usr": 0755, "usr/share": 0755, "usr/share/bash-completion": 0755,
		"usr/share/bash-completion/completions": 0755, "usr/share/doc": 0755, "usr/share/doc/syswarden": 0755,
		"etc": 0755, "etc/apk": 0755, "etc/apk/commit_hooks.d": 0755,
	}
	files := map[string]int64{
		"opt/syswarden/bin/syswarden-cli": 0750, "opt/syswarden/bin/syswarden-core": 0750,
		"opt/syswarden/bin/syswarden-tui": 0750, "opt/syswarden/signatures.json": 0640,
		"usr/share/bash-completion/completions/syswarden": 0644,
		"usr/share/doc/syswarden/GEOIP-DATA-LICENSE.txt":  0644,
		"usr/share/doc/syswarden/LICENSE.txt":             0644,
		"etc/apk/commit_hooks.d/syswarden-recovery":       0755,
	}
	controls := map[string]int64{".PKGINFO": 0644, ".pre-install": 0755, ".post-install": 0755,
		".pre-upgrade": 0755, ".post-upgrade": 0755, ".pre-deinstall": 0755, ".post-deinstall": 0755}
	seen := make(map[string]bool)
	var members []apkTransitionMember
	var digests []hash.Hash
	var nativeDigests []hash.Hash
	var expectedNativeDigests []string
	signatures := 0
	identity, err := readAuthenticatedAPKObserved(ctx, file, func(stream, name string, header *tar.Header) (io.Writer, error) {
		key := stream + ":" + name
		if seen[key] || len(seen) >= 64 || header.Name != name && header.Name != name+"/" || header.Uid != 0 || header.Gid != 0 || header.Linkname != "" || header.Format == tar.FormatGNU {
			return nil, errors.New("APK transition inventory has duplicate, aliased or foreign-owned members")
		}
		seen[key] = true
		for key := range header.PAXRecords {
			if key != "APK-TOOLS.checksum.SHA1" {
				return nil, fmt.Errorf("APK transition inventory uses unsupported extended metadata %q", key)
			}
		}
		nativeDigest := header.PAXRecords["APK-TOOLS.checksum.SHA1"]
		if nativeDigest != "" {
			decoded, err := hex.DecodeString(nativeDigest)
			if err != nil || len(decoded) != sha1.Size || hex.EncodeToString(decoded) != nativeDigest {
				return nil, errors.New("APK transition native member checksum is noncanonical")
			}
		}
		directory := header.Typeflag == tar.TypeDir
		if !directory && !qualificationTarHeaderIsRegular(header.Typeflag) || directory && header.Size != 0 || !directory && header.Size <= 0 {
			return nil, errors.New("APK transition inventory requires nonempty regular files and plain directories")
		}
		switch stream {
		case "apk-signature":
			if directory || !strings.HasPrefix(name, ".SIGN.RSA.") || header.Size > maximumNativeHeaderMetadataBytes || header.Mode != 0644 {
				return nil, errors.New("APK transition requires bounded native RSA signature framing")
			}
			signatures++
		case "apk-control":
			mode, known := controls[name]
			if directory || !known || header.Mode != mode || header.Size > maximumNativeHeaderMetadataBytes {
				return nil, fmt.Errorf("APK transition has an unsupported control member, mode or size %q", name)
			}
		case "apk-data":
			want, known := files[name]
			if directory {
				want, known = required[name]
			}
			if !known || header.Mode != want {
				return nil, fmt.Errorf("APK transition refuses unexpected payload path, type or mode %q", name)
			}
		default:
			return nil, errors.New("APK transition inventory has an unknown archive stream")
		}
		digest := sha256.New()
		nativeHash := sha1.New() // #nosec G401 -- native format consistency, independent of signed SHA-256 binding
		digests = append(digests, digest)
		nativeDigests = append(nativeDigests, nativeHash)
		expectedNativeDigests = append(expectedNativeDigests, nativeDigest)
		members = append(members, apkTransitionMember{Stream: stream, Path: name, Mode: header.Mode, Size: header.Size, Directory: directory})
		return io.MultiWriter(digest, nativeHash), nil
	})
	if err != nil {
		return nil, nativePackageHeaderIdentity{}, err
	}
	if signatures != 1 {
		return nil, nativePackageHeaderIdentity{}, errors.New("APK transition requires exactly one native signature member")
	}
	for name := range controls {
		if !seen["apk-control:"+name] {
			return nil, nativePackageHeaderIdentity{}, fmt.Errorf("APK transition lacks required lifecycle control %q", name)
		}
	}
	for name := range required {
		if !seen["apk-data:"+name] {
			return nil, nativePackageHeaderIdentity{}, fmt.Errorf("APK transition lacks payload directory %q", name)
		}
	}
	for name := range files {
		if !seen["apk-data:"+name] {
			return nil, nativePackageHeaderIdentity{}, fmt.Errorf("APK transition lacks payload file %q", name)
		}
	}
	for index := range members {
		if expectedNativeDigests[index] != "" && hex.EncodeToString(nativeDigests[index].Sum(nil)) != expectedNativeDigests[index] {
			return nil, nativePackageHeaderIdentity{}, errors.New("APK transition native member checksum disagrees with its bytes")
		}
		members[index].SHA256 = hex.EncodeToString(digests[index].Sum(nil))
	}
	sort.Slice(members, func(i, j int) bool {
		return members[i].Stream+":"+members[i].Path < members[j].Stream+":"+members[j].Path
	})
	return members, identity, ctx.Err()
}
