//go:build linux

package system

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const removalMountInfoLimit = 4 * 1024 * 1024

var hostRemovalMountRoots = []string{
	"/opt/syswarden",
	"/etc/syswarden",
	"/var/log/syswarden",
	"/var/lib/syswarden",
}

type removalMountInfoReader func() ([]byte, error)

func readProcRemovalMountInfo() ([]byte, error) {
	file, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return nil, fmt.Errorf("open removal mount topology: %w", err)
	}
	content, readErr := io.ReadAll(io.LimitReader(file, removalMountInfoLimit+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil {
		return nil, errors.Join(fmt.Errorf("read removal mount topology"), readErr, closeErr)
	}
	if len(content) > removalMountInfoLimit {
		return nil, fmt.Errorf("removal mount topology exceeds %d bytes", removalMountInfoLimit)
	}
	return content, nil
}

func decodeMountInfoPath(field string) (string, error) {
	var decoded strings.Builder
	decoded.Grow(len(field))
	for index := 0; index < len(field); index++ {
		if field[index] != '\\' {
			decoded.WriteByte(field[index])
			continue
		}
		if index+3 >= len(field) {
			return "", fmt.Errorf("truncated mountinfo path escape")
		}
		escape := field[index+1 : index+4]
		switch escape {
		case "040":
			decoded.WriteByte(' ')
		case "011":
			decoded.WriteByte('\t')
		case "012":
			decoded.WriteByte('\n')
		case "134":
			decoded.WriteByte('\\')
		default:
			return "", fmt.Errorf("unsupported mountinfo path escape \\%s", escape)
		}
		index += 3
	}
	path := decoded.String()
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", fmt.Errorf("mountinfo path %q is not clean and absolute", path)
	}
	return path, nil
}

func parseRemovalMountPoints(content []byte) ([]string, error) {
	if len(content) == 0 || len(content) > removalMountInfoLimit {
		return nil, fmt.Errorf("removal mount topology is empty or oversized")
	}
	lines := strings.Split(strings.TrimSuffix(string(content), "\n"), "\n")
	mounts := make([]string, 0, len(lines))
	for lineNumber, line := range lines {
		fields := strings.Fields(line)
		separator := -1
		for index, field := range fields {
			if field == "-" {
				separator = index
				break
			}
		}
		if len(fields) < 10 || separator < 6 || separator+3 >= len(fields) {
			return nil, fmt.Errorf("malformed mountinfo line %d", lineNumber+1)
		}
		mountPoint, err := decodeMountInfoPath(fields[4])
		if err != nil {
			return nil, fmt.Errorf("decode mountinfo line %d: %w", lineNumber+1, err)
		}
		mounts = append(mounts, mountPoint)
	}
	return mounts, nil
}

func preflightRemovalMountBoundariesAt(
	roots []string,
	readMountInfo removalMountInfoReader,
) error {
	if len(roots) == 0 || readMountInfo == nil {
		return fmt.Errorf("removal mount-boundary preflight is unavailable")
	}
	cleanRoots := make([]string, len(roots))
	for index, root := range roots {
		if root == "" || root == "/" || !filepath.IsAbs(root) || filepath.Clean(root) != root {
			return fmt.Errorf("unsafe removal mount root %q", root)
		}
		cleanRoots[index] = root
	}
	content, err := readMountInfo()
	if err != nil {
		return err
	}
	mounts, err := parseRemovalMountPoints(content)
	if err != nil {
		return err
	}
	for _, root := range cleanRoots {
		prefix := root + string(filepath.Separator)
		for _, mountPoint := range mounts {
			if mountPoint == root || strings.HasPrefix(mountPoint, prefix) {
				return fmt.Errorf(
					"refusing recursive removal of %s across mount boundary %s",
					root,
					mountPoint,
				)
			}
		}
	}
	return nil
}

func preflightHostRemovalMountBoundaries() error {
	return preflightRemovalMountBoundariesAt(hostRemovalMountRoots, readProcRemovalMountInfo)
}
