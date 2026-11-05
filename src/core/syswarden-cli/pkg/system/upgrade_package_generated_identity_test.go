package system

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// This opt-in producer/consumer check reads generated artifacts without native
// installation, scripts, extraction or trust in their filenames as metadata.
// It checks identity and read-only behavior, not signatures or release acceptance.
func TestGeneratedNativePackageIdentity(t *testing.T) {
	directory, hasDirectory := os.LookupEnv("SYSWARDEN_GENERATED_PACKAGE_DIRECTORY")
	version, hasVersion := os.LookupEnv("SYSWARDEN_GENERATED_PACKAGE_VERSION")
	if !hasDirectory && !hasVersion {
		t.Skip("generated package artifacts are supplied by the package build gate")
	}
	if !hasDirectory || !hasVersion || !filepath.IsAbs(directory) {
		t.Fatal("generated package directory and exact release are required")
	}
	if _, err := parseReleaseVersion(version); err != nil {
		t.Fatal("generated package release is invalid")
	}
	names := []string{compatibilityNativePackageName}
	if strings.HasPrefix(version, "v5.") {
		names = append(names, baseNativePackageName)
	} else if !strings.HasPrefix(version, "v4.") {
		t.Fatal("generated package release is unsupported")
	}
	beforeRoot, err := os.Lstat(directory)
	if err != nil || !beforeRoot.IsDir() || beforeRoot.Mode()&os.ModeSymlink != 0 {
		t.Fatal("generated package directory must be a real directory")
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	openedRoot, err := root.Stat(".")
	if err != nil || !os.SameFile(beforeRoot, openedRoot) {
		t.Fatal("generated package directory changed while opening")
	}
	for _, name := range names {
		for _, format := range []string{packageFormatDEB, packageFormatRPM, packageFormatAPK} {
			t.Run(name+"/"+format, func(t *testing.T) {
				target := packageHeaderBoundaryTarget(t, name, format, version)
				before, err := root.Lstat(target.filename)
				if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 {
					t.Fatal("generated package must be a regular file")
				}
				file, err := root.Open(target.filename)
				if err != nil {
					t.Fatal(err)
				}
				defer file.Close()
				opened, err := file.Stat()
				if err != nil || !os.SameFile(before, opened) {
					t.Fatal("generated package changed while opening")
				}
				size, err := qualificationPackageDescriptorSize(file, format)
				if err != nil {
					t.Fatal(err)
				}
				digest := func() string {
					hash := sha256.New()
					n, err := io.Copy(hash, io.NewSectionReader(file, 0, size))
					if err != nil || n != size {
						t.Fatal("cannot hash complete generated package")
					}
					return fmt.Sprintf("%x", hash.Sum(nil))
				}
				originalDigest := digest()
				if _, err := file.Seek(7, io.SeekStart); err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
				defer cancel()
				if err := attestNativePackageHeader(ctx, target, version, file); err != nil {
					t.Fatalf("generated %s package identity refused: %v", format, err)
				}
				other := compatibilityNativePackageName
				if name == other {
					other = baseNativePackageName
				}
				if strings.HasPrefix(version, "v5.") || name == baseNativePackageName {
					wrong := packageHeaderBoundaryTarget(t, other, format, version)
					if err := attestNativePackageHeader(ctx, wrong, version, file); err == nil {
						t.Fatal("generated package accepted as the other identity")
					}
				}
				wrongVersion := "v5.00.1"
				if version == wrongVersion {
					wrongVersion = "v5.00.2"
				}
				wrong := packageHeaderBoundaryTarget(t, name, format, wrongVersion)
				if err := attestNativePackageHeader(ctx, wrong, wrongVersion, file); err == nil {
					t.Fatal("generated package accepted as another release")
				}
				offset, err := file.Seek(0, io.SeekCurrent)
				if err != nil || offset != 7 {
					t.Fatal("identity inspection changed caller descriptor offset")
				}
				after, err := file.Stat()
				current, pathErr := root.Lstat(target.filename)
				if err != nil || pathErr != nil || !os.SameFile(opened, after) || !os.SameFile(after, current) ||
					opened.Mode() != after.Mode() || after.Mode() != current.Mode() || opened.Size() != after.Size() || after.Size() != current.Size() ||
					!opened.ModTime().Equal(after.ModTime()) || !after.ModTime().Equal(current.ModTime()) || digest() != originalDigest {
					t.Fatal("generated package changed during read-only inspection")
				}
				t.Logf("verified generated header: package=%s format=%s release=%s sha256=%s", name, format, version, originalDigest)
			})
		}
	}
	afterRoot, err := os.Lstat(directory)
	if err != nil || afterRoot.Mode()&os.ModeSymlink != 0 || !os.SameFile(openedRoot, afterRoot) {
		t.Fatal("generated package directory changed during inspection")
	}
}
