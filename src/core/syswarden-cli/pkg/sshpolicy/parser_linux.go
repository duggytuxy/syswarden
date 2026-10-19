//go:build linux

package sshpolicy

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path"
	"reflect"
	"sort"
	"strings"

	"golang.org/x/sys/unix"
)

// parserImage keeps each Include as a separate sealed file. Flattening Includes
// can change Match scope; the daemon must see the same file boundaries. The
// child reads the retained parent descriptors through procfs. OpenSSH closes
// inherited nonstandard descriptors at startup, so /proc/self/fd is unsuitable
// for configuration inputs. The parent keeps all files alive until exit.
type parserImage struct {
	files []*os.File
	main  string
}

func (image *parserImage) Close() error {
	var failures []error
	for _, file := range image.files {
		failures = append(failures, file.Close())
	}
	image.files = nil
	return errors.Join(failures...)
}

func newParserImage(files map[string][]byte) (*parserImage, error) {
	if len(files) == 0 || len(files) > MaxFiles {
		return nil, ErrInventoryBounds
	}
	if _, ok := files[MainPath]; !ok {
		return nil, ErrInventoryUnsafe
	}
	names := sortedKeys(files)
	aliases := make(map[string]string, len(names))
	total := 0
	for _, name := range names {
		if !safePath(name) || len(files[name]) > MaxBytes-total || bytes.IndexByte(files[name], 0) >= 0 {
			return nil, ErrInventoryBounds
		}
		total += len(files[name])
	}
	image := &parserImage{}
	ok := false
	defer func() {
		if !ok {
			_ = image.Close()
		}
	}()
	for _, name := range names {
		fd, err := unix.MemfdCreate("syswarden-ssh-parser", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
		if err != nil {
			return nil, err
		}
		file := os.NewFile(uintptr(fd), "ssh-parser-configuration")
		image.files = append(image.files, file)
		aliases[name] = fmt.Sprintf("/proc/%d/fd/%d", os.Getpid(), fd)
	}
	image.main = aliases[MainPath]
	rewritten := 0
	for index, name := range names {
		content, err := parserIncludeAliases(files[name], names, aliases)
		if err != nil || len(content) > 4*MaxBytes-rewritten {
			return nil, errors.Join(ErrInventoryBounds, err)
		}
		rewritten += len(content)
		file := image.files[index]
		if n, err := file.Write(content); err != nil || n != len(content) {
			return nil, errors.Join(fmt.Errorf("incomplete SSH parser image"), err)
		}
		if _, err := file.Seek(0, 0); err != nil {
			return nil, err
		}
		seals := unix.F_SEAL_WRITE | unix.F_SEAL_GROW | unix.F_SEAL_SHRINK | unix.F_SEAL_SEAL
		if _, err := unix.FcntlInt(file.Fd(), unix.F_ADD_SEALS, seals); err != nil {
			return nil, err
		}
	}
	ok = true
	return image, nil
}

func parserIncludeAliases(content []byte, names []string, aliases map[string]string) ([]byte, error) {
	var output strings.Builder
	patterns := 0
	for _, line := range strings.SplitAfter(string(content), "\n") {
		if len(strings.TrimSuffix(line, "\n")) > MaxLineBytes {
			return nil, ErrInventoryBounds
		}
		key, value := splitDirective(strings.TrimSuffix(line, "\n"))
		if key != "include" {
			output.WriteString(line)
			continue
		}
		inputs, err := arguments(value)
		if err != nil || len(inputs) == 0 {
			return nil, errors.Join(ErrInventoryUnsafe, err)
		}
		var matches []string
		for _, input := range inputs {
			patterns++
			if patterns > MaxExpansions {
				return nil, ErrInventoryBounds
			}
			pattern, err := includePattern(input)
			if err != nil {
				return nil, err
			}
			for _, name := range names {
				matched, err := path.Match(pattern, name)
				if err != nil {
					return nil, err
				}
				if matched {
					matches = append(matches, aliases[name])
				}
			}
		}
		if len(matches) == 0 {
			output.WriteString("# Empty attested Include expansion\n")
		} else {
			output.WriteString("Include " + strings.Join(matches, " ") + "\n")
		}
		if output.Len() > 4*MaxBytes {
			return nil, ErrInventoryBounds
		}
	}
	return []byte(output.String()), nil
}

type sshEffective map[string][]string

func parseEffective(output []byte) (sshEffective, error) {
	if len(output) == 0 || len(output) > MaxBytes || bytes.IndexByte(output, 0) >= 0 {
		return nil, ErrInventoryBounds
	}
	result := make(sshEffective)
	for _, line := range strings.Split(string(output), "\n") {
		if len(line) > MaxLineBytes {
			return nil, ErrInventoryBounds
		}
		if line == "" {
			continue
		}
		key, value, ok := strings.Cut(line, " ")
		if !ok || key == "" {
			return nil, fmt.Errorf("malformed SSH effective directive")
		}
		for index, character := range key {
			if (character < 'a' || character > 'z') && (index == 0 || character < '0' || character > '9') {
				return nil, fmt.Errorf("noncanonical SSH effective directive")
			}
		}
		result[key] = append(result[key], value)
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("empty SSH effective configuration")
	}
	return result, nil
}

// compareEffective reports only directive names, never private values. Repeated
// directives and their ordering remain significant. The allowed keys come only
// from a reviewed fixed policy, never from daemon output or environment hints.
func compareEffective(before, after sshEffective, allowed map[string]bool) error {
	keys := make(map[string]bool, len(before)+len(after))
	for key := range before {
		keys[key] = true
	}
	for key := range after {
		keys[key] = true
	}
	var changed []string
	for key := range keys {
		if !allowed[key] && !reflect.DeepEqual(before[key], after[key]) {
			changed = append(changed, key)
		}
	}
	if len(changed) != 0 {
		sort.Strings(changed)
		return fmt.Errorf("SSH effective administrator settings changed: %s", strings.Join(changed, ", "))
	}
	return nil
}
