//go:build linux

package sshpolicy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const maxSSHDBytes = 64 << 20

// VerificationSummary is a parser result, not migration approval, proof of a
// successful login, daemon activation, or ownership of a configuration file.
type VerificationSummary struct {
	Plan             PlanSummary `json:"plan"`
	ParserSHA256     string      `json:"parser_sha256"`
	ContextsVerified int         `json:"contexts_verified"`
	ParserVerified   bool        `json:"parser_verified"`
	RuntimeActivated bool        `json:"runtime_activated"`
}

// VerifyPlan examines fixed protected paths and invokes only the installed
// daemon's syntax/effective-configuration modes. Candidate files exist only as
// sealed memory descriptors. It never starts a listener or a service manager.
func VerifyPlan() (VerificationSummary, error) {
	if os.Geteuid() != 0 {
		return VerificationSummary{}, fmt.Errorf("SSH policy verification requires root")
	}
	root, err := os.Open("/")
	if err != nil {
		return VerificationSummary{}, err
	}
	defer root.Close()
	plan, err := inspectPlan(root, 0)
	if err != nil {
		return VerificationSummary{}, err
	}
	daemon, err := openSSHD(root, 0)
	if err != nil {
		return VerificationSummary{}, err
	}
	defer daemon.file.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	recheck := func() error {
		current, err := collectPlanInventory(root, 0)
		if err != nil || !reflect.DeepEqual(current, plan.inventory) {
			return errors.Join(ErrInventoryChanged, err)
		}
		return daemon.recheck(root, 0)
	}
	return verifyPlan(ctx, plan, daemon.digest, daemon.run, recheck)
}

type sshParserRun func(context.Context, *parserImage, string, string) ([]byte, error)

func verifyPlan(ctx context.Context, plan migrationPlan, digest string, run sshParserRun, recheck func() error) (VerificationSummary, error) {
	if run == nil || recheck == nil || !lowerDigest.MatchString(digest) {
		return VerificationSummary{}, ErrInventoryUnsafe
	}
	files := make(map[string][]byte, len(plan.inventory.files))
	for name, content := range plan.inventory.files {
		if name != IntentPath {
			files[name] = content
		}
	}
	before, err := newParserImage(files)
	if err != nil {
		return VerificationSummary{}, err
	}
	defer before.Close()
	images := []*parserImage{nil, before}
	if plan.intent.Owner == "syswarden" {
		// The drop-in is published before the legacy main-file exchange. Check
		// that exact intermediate graph too, with the original main bytes.
		files[DropInPath] = plan.candidate.Bytes()
		intermediate, err := newParserImage(files)
		if err != nil {
			return VerificationSummary{}, err
		}
		defer intermediate.Close()
		images = append(images, intermediate)
	}
	files[MainPath] = plan.main
	after, err := newParserImage(files)
	if err != nil {
		return VerificationSummary{}, err
	}
	defer after.Close()
	images = append(images, after)
	invoke := func(image *parserImage, mode, access string) ([]byte, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if err := recheck(); err != nil {
			return nil, err
		}
		output, err := run(ctx, image, mode, access)
		// Recheck on failure too; a parser error must not hide changed inputs.
		if checkErr := recheck(); checkErr != nil {
			return nil, errors.Join(ErrInventoryChanged, checkErr)
		}
		return output, err
	}
	for _, image := range images {
		if _, err := invoke(image, "syntax", ""); err != nil {
			return VerificationSummary{}, fmt.Errorf("SSH syntax verification failed: %w", err)
		}
	}
	contexts := []string{""} // The global defaults also need independent checking.
	for _, access := range plan.intent.Contexts {
		contexts = append(contexts, access.sshdArgument())
	}
	allowed := make(map[string]bool)
	if plan.intent.Owner == "syswarden" {
		policy, err := directives(plan.candidate.profile)
		if err != nil {
			return VerificationSummary{}, err
		}
		for _, item := range policy {
			allowed[strings.ToLower(item.key)] = true
		}
	}
	for index, access := range contexts {
		effective := make([]sshEffective, len(images))
		for position, image := range images {
			output, err := invoke(image, "effective", access)
			if err == nil {
				effective[position], err = parseEffective(output)
			}
			if err == nil && position == len(images)-1 && plan.intent.Owner == "syswarden" {
				err = plan.candidate.CheckEffective(output)
			}
			if err != nil {
				return VerificationSummary{}, fmt.Errorf("SSH parser verification failed for context %d: %w", index, err)
			}
		}
		if err := compareEffective(effective[0], effective[1], nil); err != nil {
			return VerificationSummary{}, fmt.Errorf("SSH sealed baseline differs from installed configuration for context %d: %w", index, err)
		}
		if err := compareEffective(effective[1], effective[len(images)-1], allowed); err != nil {
			return VerificationSummary{}, fmt.Errorf("SSH candidate changed unrelated settings for context %d: %w", index, err)
		}
		if plan.intent.Owner == "syswarden" {
			if err := compareSSHIntermediate(effective[1], effective[2], effective[3], allowed); err != nil {
				return VerificationSummary{}, fmt.Errorf("SSH publication intermediate state is unsafe for context %d: %w", index, err)
			}
		}
	}
	if err := recheck(); err != nil {
		return VerificationSummary{}, err
	}
	return VerificationSummary{Plan: plan.summary, ParserSHA256: digest,
		ContextsVerified: len(plan.intent.Contexts), ParserVerified: true}, nil
}

type pinnedSSHD struct {
	file   *os.File
	parent string
	state  inventoryStamp
	digest string
}

func openSSHD(root *os.File, uid int) (*pinnedSSHD, error) {
	// Fedora's merged /usr layout uses /usr/bin. Debian and RHEL also support
	// the separate /usr/sbin layout. Never follow a directory alias or PATH.
	for _, parent := range []string{"/usr/bin", "/usr/sbin"} {
		reader := inventoryReader{root: root, uid: uid, state: inventorySnapshot{nodes: make(map[string]inventoryStamp)}}
		directory, err := reader.openDirectory(parent)
		if err != nil {
			return nil, fmt.Errorf("inspect trusted SSH daemon directory: %w", err)
		}
		if directory == nil {
			continue
		}
		file, state, digest, err := readSSHD(directory, uid)
		closeErr := directory.Close()
		if errors.Is(err, os.ErrNotExist) && closeErr == nil {
			continue
		}
		if err != nil || closeErr != nil {
			if file != nil {
				_ = file.Close()
			}
			return nil, errors.Join(err, closeErr)
		}
		return &pinnedSSHD{file: file, parent: parent, state: state, digest: digest}, nil
	}
	return nil, fmt.Errorf("trusted installed SSH daemon is unavailable")
}

func readSSHD(directory *os.File, uid int) (*os.File, inventoryStamp, string, error) {
	var before, opened, after unix.Stat_t
	if err := unix.Fstatat(int(directory.Fd()), "sshd", &before, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return nil, inventoryStamp{}, "", err
	}
	if int64(before.Uid) != int64(uid) || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Mode&07022 != 0 ||
		before.Mode&0100 == 0 || before.Nlink != 1 || before.Size < 1 || before.Size > maxSSHDBytes {
		return nil, inventoryStamp{}, "", ErrInventoryUnsafe
	}
	fd, err := unix.Openat(int(directory.Fd()), "sshd", unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_NOCTTY, 0)
	if err != nil {
		return nil, inventoryStamp{}, "", err
	}
	file := os.NewFile(uintptr(fd), "trusted-ssh-parser")
	ok := false
	defer func() {
		if !ok {
			_ = file.Close()
		}
	}()
	if err := unix.Fstat(fd, &opened); err != nil || stamp(before) != stamp(opened) {
		return nil, inventoryStamp{}, "", errors.Join(ErrInventoryChanged, err)
	}
	var header [20]byte
	if _, err := file.ReadAt(header[:], 0); err != nil || !bytes.Equal(header[:7], []byte{0x7f, 'E', 'L', 'F', 2, 1, 1}) || header[18] != 62 || header[19] != 0 {
		return nil, inventoryStamp{}, "", fmt.Errorf("SSH parser must be a Linux AMD64 ELF executable")
	}
	hash := sha256.New()
	n, err := io.Copy(hash, io.LimitReader(file, maxSSHDBytes+1))
	if err != nil || n != before.Size {
		return nil, inventoryStamp{}, "", errors.Join(ErrInventoryChanged, err)
	}
	err = errors.Join(unix.Fstat(fd, &after), unix.Fstatat(int(directory.Fd()), "sshd", &before, unix.AT_SYMLINK_NOFOLLOW))
	if err != nil || stamp(opened) != stamp(after) || stamp(after) != stamp(before) {
		return nil, inventoryStamp{}, "", errors.Join(ErrInventoryChanged, err)
	}
	ok = true
	return file, stamp(after), fmt.Sprintf("%x", hash.Sum(nil)), nil
}

func (daemon *pinnedSSHD) recheck(root *os.File, uid int) error {
	current, err := openSSHD(root, uid)
	if err != nil {
		return err
	}
	defer current.file.Close()
	if current.parent != daemon.parent || current.state != daemon.state || current.digest != daemon.digest {
		return ErrInventoryChanged
	}
	return nil
}

type parserOutput struct{ buffer bytes.Buffer }

func (output *parserOutput) Len() int      { return output.buffer.Len() }
func (output *parserOutput) Bytes() []byte { return output.buffer.Bytes() }

func (output *parserOutput) Write(data []byte) (int, error) {
	if len(data) > MaxBytes-output.Len() {
		return 0, ErrInventoryBounds
	}
	return output.buffer.Write(data)
}

func (daemon *pinnedSSHD) run(parent context.Context, image *parserImage, mode, access string) ([]byte, error) {
	configuration := MainPath
	files := []*os.File{daemon.file}
	if image != nil {
		configuration = image.main
	}
	var flag string
	switch mode {
	case "syntax":
		if access != "" {
			return nil, ErrInventoryUnsafe
		}
		flag = "-t"
	case "effective":
		flag = "-T"
	default:
		return nil, ErrInventoryUnsafe
	}
	args := []string{flag, "-f", configuration}
	if access != "" {
		args = append(args, "-C", access)
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	// Descriptor 3 is the attested ELF executable. No shell, PATH lookup,
	// executable pathname race, environment-provided options or listener mode.
	command := exec.CommandContext(ctx, "/proc/self/fd/3", args...) // #nosec G204 -- FD 3 pins the attested AMD64 daemon; only fixed parser modes, protected configuration and validated context fields are passed without a shell.
	command.ExtraFiles = files
	command.Env = []string{"LC_ALL=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	command.Dir = "/"
	command.WaitDelay = time.Second
	var stdout, stderr parserOutput
	command.Stdout, command.Stderr = &stdout, &stderr
	if err := command.Run(); err != nil {
		// Do not expose raw stderr, which may contain private configuration.
		return nil, fmt.Errorf("installed SSH parser refused the configuration or exceeded execution bounds")
	}
	if mode == "syntax" && stdout.Len() != 0 {
		return nil, fmt.Errorf("unexpected SSH syntax output")
	}
	return stdout.Bytes(), nil
}
