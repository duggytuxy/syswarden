package system

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

type httpStatusError struct {
	statusCode int
	status     string
}

func (statusError *httpStatusError) Error() string {
	return fmt.Sprintf("HTTP response status is %s", statusError.status)
}

func downloadBoundedBytes(ctx context.Context, client *http.Client, rawURL string, limit int64) ([]byte, error) {
	if client == nil || limit <= 0 {
		return nil, errors.New("invalid bounded download configuration")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create HTTP request: %w", err)
	}
	request.Header.Set("Accept", "application/octet-stream, application/json")
	request.Header.Set("User-Agent", "syswarden-signed-updater/1")
	response, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("execute HTTP request: %w", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return nil, &httpStatusError{statusCode: response.StatusCode, status: response.Status}
	}
	if response.ContentLength > limit {
		return nil, fmt.Errorf("HTTP response declares %d bytes, limit is %d", response.ContentLength, limit)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read HTTP response: %w", err)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("HTTP response exceeds %d-byte limit", limit)
	}
	return data, nil
}

func downloadVerifiedPackage(
	ctx context.Context,
	client *http.Client,
	rawURL string,
	destination *os.File,
	artifact updateArtifact,
	expectedUID int,
) error {
	if client == nil || destination == nil {
		return errors.New("package download dependencies are incomplete")
	}
	if artifact.Size <= 0 || artifact.Size > maxPackageBytes || !validSHA256(artifact.SHA256) {
		return errors.New("package manifest metadata is invalid")
	}
	if err := validateSecureOpenFile(destination, destination.Name(), expectedUID); err != nil {
		return fmt.Errorf("validate package destination: %w", err)
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return fmt.Errorf("create package request: %w", err)
	}
	request.Header.Set("Accept", "application/octet-stream")
	request.Header.Set("User-Agent", "syswarden-signed-updater/1")
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("execute package request: %w", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("package HTTP response status is %s", response.Status)
	}
	if response.ContentLength >= 0 && response.ContentLength != artifact.Size {
		return fmt.Errorf("package Content-Length is %d, manifest size is %d", response.ContentLength, artifact.Size)
	}

	digest := sha256.New()
	written, err := io.Copy(io.MultiWriter(destination, digest), io.LimitReader(response.Body, artifact.Size+1))
	if err != nil {
		return fmt.Errorf("write package: %w", err)
	}
	if written != artifact.Size {
		return fmt.Errorf("downloaded package size is %d, manifest size is %d", written, artifact.Size)
	}
	actualDigest := hex.EncodeToString(digest.Sum(nil))
	if actualDigest != artifact.SHA256 {
		return fmt.Errorf("downloaded package SHA-256 is %s, manifest requires %s", actualDigest, artifact.SHA256)
	}
	if err := destination.Sync(); err != nil {
		return fmt.Errorf("sync package: %w", err)
	}
	if err := validateSecureOpenFile(destination, destination.Name(), expectedUID); err != nil {
		return fmt.Errorf("revalidate downloaded package: %w", err)
	}
	return nil
}

// verifySecurePackageForInstallation repeats the complete content binding at
// the last possible point before the package manager is invoked. The initial
// download verification is not sufficient on its own because a same-inode,
// same-size write after that check would otherwise survive the metadata-only
// pre-install validation.
func verifySecurePackageForInstallation(
	destination *os.File,
	path string,
	artifact updateArtifact,
	expectedUID int,
) error {
	if destination == nil {
		return errors.New("package verification requires an open file")
	}
	if artifact.Size <= 0 || artifact.Size > maxPackageBytes || !validSHA256(artifact.SHA256) {
		return errors.New("package manifest metadata is invalid")
	}
	if err := validateSecureOpenFile(destination, path, expectedUID); err != nil {
		return fmt.Errorf("validate package before final hash: %w", err)
	}

	var before unix.Stat_t
	if err := unix.Fstat(int(destination.Fd()), &before); err != nil {
		return fmt.Errorf("inspect package before final hash: %w", err)
	}
	if before.Size != artifact.Size {
		return fmt.Errorf("package size before installation is %d, manifest requires %d", before.Size, artifact.Size)
	}

	digest := sha256.New()
	read, err := io.Copy(digest, io.NewSectionReader(destination, 0, artifact.Size+1))
	if err != nil {
		return fmt.Errorf("rehash package before installation: %w", err)
	}
	if read != artifact.Size {
		return fmt.Errorf("package size during final verification is %d, manifest requires %d", read, artifact.Size)
	}
	actualDigest := hex.EncodeToString(digest.Sum(nil))
	if actualDigest != artifact.SHA256 {
		return fmt.Errorf("package SHA-256 before installation is %s, manifest requires %s", actualDigest, artifact.SHA256)
	}

	var after unix.Stat_t
	if err := unix.Fstat(int(destination.Fd()), &after); err != nil {
		return fmt.Errorf("inspect package after final hash: %w", err)
	}
	if before.Dev != after.Dev || before.Ino != after.Ino || before.Size != after.Size ||
		before.Mode != after.Mode || before.Uid != after.Uid || before.Nlink != after.Nlink {
		return errors.New("package metadata changed during final verification")
	}
	if err := validateSecureOpenFile(destination, path, expectedUID); err != nil {
		return fmt.Errorf("revalidate package after final hash: %w", err)
	}
	return nil
}

func createSecureWorkspace(base string, expectedUID int) (string, error) {
	if err := validateSecureTempBase(base, expectedUID); err != nil {
		return "", err
	}
	workspace, err := os.MkdirTemp(base, "syswarden-update-")
	if err != nil {
		return "", fmt.Errorf("create private temporary directory: %w", err)
	}
	if err := validateSecureWorkspace(workspace, expectedUID); err != nil {
		_ = os.RemoveAll(workspace)
		return "", err
	}
	return workspace, nil
}

func validateSecureTempBase(base string, expectedUID int) error {
	if base == "" || !filepath.IsAbs(base) {
		return errors.New("temporary base must be an absolute path")
	}
	var status unix.Stat_t
	if err := unix.Lstat(base, &status); err != nil {
		return fmt.Errorf("inspect temporary base: %w", err)
	}
	if status.Mode&unix.S_IFMT != unix.S_IFDIR {
		return errors.New("temporary base is not a real directory")
	}
	if int(status.Uid) != expectedUID {
		return fmt.Errorf("temporary base owner is UID %d, want %d", status.Uid, expectedUID)
	}
	permissions := status.Mode & 0777
	if permissions&0022 != 0 && status.Mode&unix.S_ISVTX == 0 {
		return fmt.Errorf("writable temporary base mode %#o lacks the sticky bit", permissions)
	}
	return nil
}

func validateSecureWorkspace(workspace string, expectedUID int) error {
	if workspace == "" || !filepath.IsAbs(workspace) {
		return errors.New("update workspace must be an absolute path")
	}
	var status unix.Stat_t
	if err := unix.Lstat(workspace, &status); err != nil {
		return fmt.Errorf("inspect update workspace: %w", err)
	}
	if status.Mode&unix.S_IFMT != unix.S_IFDIR {
		return errors.New("update workspace is not a real directory")
	}
	if int(status.Uid) != expectedUID {
		return fmt.Errorf("update workspace owner is UID %d, want %d", status.Uid, expectedUID)
	}
	if status.Mode&07777 != 0700 {
		return fmt.Errorf("update workspace mode is %#o, want 0700", status.Mode&07777)
	}
	return nil
}

func createSecureExclusiveFile(workspace, name string, expectedUID int) (*os.File, string, error) {
	if err := validateSecureWorkspace(workspace, expectedUID); err != nil {
		return nil, "", err
	}
	if !safeAssetName(name) {
		return nil, "", fmt.Errorf("unsafe package filename %q", name)
	}
	path := filepath.Join(workspace, name)
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return nil, "", fmt.Errorf("open package with O_EXCL/O_NOFOLLOW: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		_ = os.Remove(path)
		return nil, "", errors.New("create Go package file handle")
	}
	if err := validateSecureOpenFile(file, path, expectedUID); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return nil, "", err
	}
	return file, path, nil
}

func validateSecureOpenFile(file *os.File, path string, expectedUID int) error {
	if file == nil || path == "" || !filepath.IsAbs(path) {
		return errors.New("secure file validation requires an open file and absolute path")
	}
	var descriptorStatus unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &descriptorStatus); err != nil {
		return fmt.Errorf("inspect package descriptor: %w", err)
	}
	if descriptorStatus.Mode&unix.S_IFMT != unix.S_IFREG {
		return errors.New("package descriptor is not a regular file")
	}
	if descriptorStatus.Nlink != 1 {
		return fmt.Errorf("package descriptor link count is %d, want 1", descriptorStatus.Nlink)
	}
	if int(descriptorStatus.Uid) != expectedUID {
		return fmt.Errorf("package descriptor owner is UID %d, want %d", descriptorStatus.Uid, expectedUID)
	}
	if descriptorStatus.Mode&07777 != 0600 {
		return fmt.Errorf("package descriptor mode is %#o, want 0600", descriptorStatus.Mode&07777)
	}

	var pathStatus unix.Stat_t
	if err := unix.Lstat(path, &pathStatus); err != nil {
		return fmt.Errorf("inspect package path: %w", err)
	}
	if pathStatus.Mode&unix.S_IFMT != unix.S_IFREG {
		return errors.New("package path is not a regular non-symlink file")
	}
	if pathStatus.Dev != descriptorStatus.Dev || pathStatus.Ino != descriptorStatus.Ino {
		return errors.New("package path no longer names the open package descriptor")
	}
	return nil
}

func removeSecureWorkspace(workspace string) error {
	if workspace == "" || !filepath.IsAbs(workspace) || !strings.HasPrefix(filepath.Base(workspace), "syswarden-update-") {
		return errors.New("refusing to clean an invalid update workspace path")
	}
	if err := os.RemoveAll(workspace); err != nil {
		return err
	}
	if _, err := os.Lstat(workspace); !errors.Is(err, os.ErrNotExist) {
		if err == nil {
			return errors.New("update workspace still exists after cleanup")
		}
		return fmt.Errorf("verify update workspace cleanup: %w", err)
	}
	return nil
}
