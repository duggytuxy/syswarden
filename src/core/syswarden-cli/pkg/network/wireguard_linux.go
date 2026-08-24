//go:build linux

package network

import (
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"syswarden-cli/config"
	"syswarden-cli/pkg/system"
	"syswarden-cli/pkg/wireguardstate"
	"time"
)

var wireGuardInterfaceName = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,15}$`)
var wireGuardNFTExecutableName = regexp.MustCompile(`^/(?:usr/)?(?:s?bin)/nft$`)
var wireGuardTrueExecutableName = regexp.MustCompile(`^/(?:usr/)?bin/true$`)
var wireGuardOwnershipTokenName = regexp.MustCompile(`^[0-9a-f]{64}$`)
var wireGuardManagerRuntimeState = system.ServiceManagerRuntimeState
var wireGuardIsAlpine = system.IsAlpine
var wireGuardFirewallBackendPreflight = system.PreflightHostFirewallBackend
var wireGuardServicePrepare = prepareConfiguredWireGuardService
var wireGuardServiceActivator = activateConfiguredWireGuardServiceCommand
var wireGuardServiceInspector = inspectConfiguredWireGuardServiceState
var wireGuardAbsentOpenRCServiceInspector = inspectAbsentOpenRCWireGuardServiceState
var wireGuardServiceRollback = restoreConfiguredWireGuardServiceState
var attestWireGuardServiceDefinition = system.AttestWireGuardServiceDefinition
var wireGuardReservedNFTCleanup = cleanupWireGuardReservedNFTTable
var wireGuardNFTActivationGuard = acquireWireGuardNFTActivationGuard
var wireGuardNFTActivationPreflight = attestWireGuardNFTActivationState
var wireGuardNFTExecutablePath = func() (string, error) { return resolveWireGuardExecutable("nft") }
var wireGuardTrueExecutablePath = func() (string, error) { return resolveWireGuardExecutable("true") }
var wireGuardOwnershipToken = func() (string, error) {
	var value [32]byte
	if _, err := io.ReadFull(cryptorand.Reader, value[:]); err != nil {
		return "", fmt.Errorf("generate WireGuard ownership token: %w", err)
	}
	return hex.EncodeToString(value[:]), nil
}
var wireGuardServerIdentityInspector = readConfiguredWireGuardServerIdentity
var wireGuardServerHookExecutableAttestor = wireguardstate.AttestServerHookExecutables
var wireGuardAfterOwnershipCommit = func() {}
var wireGuardExecutableResolver = resolveWireGuardExecutable
var wireGuardExecutableIdentityCapture = captureWireGuardExecutableIdentity
var wireGuardExecutablePreStartAttestor = reattestWireGuardExecutableIdentity
var wireGuardFilesystemRoot = "/"
var wireGuardExpectedOwnerUID uint32
var wireGuardExpectedOwnerGID uint32
var wireGuardCommandOutput = func(name string, args ...string) ([]byte, error) {
	return runBoundedWireGuardCommand(name, args, "", maximumWireGuardCommandOutput, wireGuardCommandTimeout)
}
var wireGuardCommandInputOutput = func(input string, name string, args ...string) ([]byte, error) {
	return runBoundedWireGuardCommand(name, args, input, maximumWireGuardCommandOutput, wireGuardCommandTimeout)
}
var wireGuardForwardingTransactionFactory = newPinnedWireGuardForwardingTransaction
var wireGuardQRCodeRender = func(configuration string) error {
	return runWireGuardStreamingCommand(
		"qrencode", []string{"-t", "ansiutf8"}, configuration, os.Stdout, wireGuardCommandTimeout,
	)
}

type wireGuardRenderInput struct {
	Subnet         string
	Port           string
	Backend        string
	NFTPath        string
	TruePath       string
	OwnershipToken string
	ActiveIf       string
	EndpointIP     string
	ServerPriv     string
	ServerPub      string
	ClientPriv     string
	ClientPub      string
	PresharedKey   string
}

type wireGuardNFTExpectation struct {
	AllowExisting  bool
	RequirePresent bool
	Identity       wireguardstate.ServerConfigurationIdentity
}

type wireGuardServiceState struct {
	Alpine    bool
	Active    bool
	Enabled   bool
	Interface bool
}

func (state wireGuardServiceState) ready() bool {
	return state.Active && state.Enabled && state.Interface
}

type wireGuardServiceRunner func(name string, args ...string) error
type wireGuardServiceOutputRunner func(name string, args ...string) ([]byte, error)

type wireGuardForwardingTransaction interface {
	Apply() error
	Restore() error
	Close() error
}

type wireGuardNFTCommandRunner interface {
	Run(ctx context.Context, args ...string) ([]byte, error)
}

type execWireGuardNFTCommandRunner struct{}

type wireGuardExecutableIdentity struct {
	Path   string
	SHA256 [sha256.Size]byte
	Mode   os.FileMode
	UID    uint32
	GID    uint32
	NLink  uint64
	Device uint64
	Inode  uint64
	Size   int64
}

const (
	maximumWireGuardCommandOutput  = 1 << 20
	wireGuardCommandTimeout        = 15 * time.Second
	wireGuardCommandWaitDelay      = 2 * time.Second
	wireGuardNFTLockPath           = "/run/syswarden-firewall.lock"
	maximumWireGuardExecutableSize = 128 << 20
)

var wireGuardExecutableCandidates = map[string][]string{
	"wg":         {"/usr/bin/wg", "/usr/sbin/wg", "/bin/wg", "/sbin/wg"},
	"ip":         {"/usr/bin/ip", "/usr/sbin/ip", "/bin/ip", "/sbin/ip"},
	"curl":       {"/usr/bin/curl", "/bin/curl"},
	"systemctl":  {"/usr/bin/systemctl", "/bin/systemctl"},
	"rc-service": {"/sbin/rc-service", "/usr/sbin/rc-service"},
	"rc-update":  {"/sbin/rc-update", "/usr/sbin/rc-update"},
	"nft":        {"/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft"},
	"true":       {"/usr/bin/true", "/bin/true"},
	"qrencode":   {"/usr/bin/qrencode", "/bin/qrencode"},
}

var wireGuardFixedCommandEnvironment = []string{
	"LANG=C",
	"LC_ALL=C",
	"PATH=/usr/sbin:/usr/bin:/sbin:/bin",
}

func attestWireGuardExecutable(path string) (string, error) {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", err
	}
	if !filepath.IsAbs(resolved) || filepath.Clean(resolved) != resolved {
		return "", fmt.Errorf("resolved executable path is not canonical")
	}
	trustedRoot := false
	for _, root := range []string{"/usr/bin", "/usr/sbin", "/bin", "/sbin"} {
		if filepath.Dir(resolved) == root {
			trustedRoot = true
			break
		}
	}
	if !trustedRoot {
		return "", fmt.Errorf("resolved executable %s is outside trusted system directories", resolved)
	}
	for current := filepath.Dir(resolved); ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 {
			return "", fmt.Errorf("executable parent %s is not attestable", current)
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 {
			return "", fmt.Errorf("executable parent %s is not root-owned", current)
		}
		if current == "/" {
			break
		}
	}
	info, err := os.Lstat(resolved)
	if err != nil {
		return "", err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 || info.Mode().Perm()&0022 != 0 ||
		stat.Uid != 0 || stat.Nlink == 0 {
		return "", fmt.Errorf("executable %s is not a trusted root-owned regular file", resolved)
	}
	return resolved, nil
}

func resolveWireGuardExecutable(name string) (string, error) {
	candidates, ok := wireGuardExecutableCandidates[name]
	if !ok {
		return "", fmt.Errorf("unsupported WireGuard command %q", name)
	}
	for _, candidate := range candidates {
		resolved, err := attestWireGuardExecutable(candidate)
		if err == nil {
			return resolved, nil
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return "", fmt.Errorf("attest WireGuard command %s: %w", candidate, err)
		}
	}
	return "", fmt.Errorf("no trusted executable found for WireGuard command %q", name)
}

func captureWireGuardExecutableIdentityForOwner(
	path string,
	expectedUID uint32,
	requireProtectedRootParents bool,
) (wireGuardExecutableIdentity, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return wireGuardExecutableIdentity{}, fmt.Errorf("WireGuard executable path is not canonical and absolute")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return wireGuardExecutableIdentity{}, fmt.Errorf("WireGuard executable %s is not an exact resolved path", path)
	}
	if requireProtectedRootParents {
		for current := filepath.Dir(path); ; current = filepath.Dir(current) {
			info, err := os.Lstat(current)
			if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 {
				return wireGuardExecutableIdentity{}, fmt.Errorf("WireGuard executable parent %s is not protected", current)
			}
			stat, ok := info.Sys().(*syscall.Stat_t)
			if !ok || stat.Uid != 0 {
				return wireGuardExecutableIdentity{}, fmt.Errorf("WireGuard executable parent %s is not root-owned", current)
			}
			if current == "/" {
				break
			}
		}
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return wireGuardExecutableIdentity{}, fmt.Errorf("pin WireGuard executable %s: %w", path, err)
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = syscall.Close(fd)
		return wireGuardExecutableIdentity{}, fmt.Errorf("pin WireGuard executable %s", path)
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return wireGuardExecutableIdentity{}, fmt.Errorf("stat pinned WireGuard executable %s: %w", path, err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 ||
		info.Mode().Perm()&0022 != 0 || stat.Uid != expectedUID || stat.Nlink == 0 || info.Size() < 1 ||
		info.Size() > maximumWireGuardExecutableSize {
		return wireGuardExecutableIdentity{}, fmt.Errorf("WireGuard executable %s has an unsafe identity", path)
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, io.LimitReader(file, maximumWireGuardExecutableSize+1)); err != nil {
		return wireGuardExecutableIdentity{}, fmt.Errorf("hash pinned WireGuard executable %s: %w", path, err)
	}
	var digest [sha256.Size]byte
	copy(digest[:], hash.Sum(nil))
	pathInfo, err := os.Lstat(path)
	if err != nil || !samePinnedWireGuardIdentity(info, pathInfo) {
		return wireGuardExecutableIdentity{}, fmt.Errorf("WireGuard executable path %s changed while pinning", path)
	}
	return wireGuardExecutableIdentity{
		Path: path, SHA256: digest, Mode: info.Mode(), UID: stat.Uid, GID: stat.Gid,
		NLink: uint64(stat.Nlink), Device: uint64(stat.Dev), Inode: stat.Ino, Size: info.Size(),
	}, nil
}

func captureWireGuardExecutableIdentity(path string) (wireGuardExecutableIdentity, error) {
	return captureWireGuardExecutableIdentityForOwner(path, 0, true)
}

func reattestWireGuardExecutableIdentity(expected wireGuardExecutableIdentity) error {
	actual, err := wireGuardExecutableIdentityCapture(expected.Path)
	if err != nil {
		return err
	}
	if actual != expected {
		return fmt.Errorf("WireGuard executable %s changed identity before start", expected.Path)
	}
	return nil
}

func runBoundedWireGuardCommandContext(
	ctx context.Context,
	name string,
	args []string,
	input string,
	limit int,
) ([]byte, error) {
	if limit < 1 || limit > maximumWireGuardCommandOutput {
		return nil, fmt.Errorf("invalid WireGuard command output limit %d", limit)
	}
	path, err := wireGuardExecutableResolver(name)
	if err != nil {
		return nil, err
	}
	executableIdentity, err := wireGuardExecutableIdentityCapture(path)
	if err != nil {
		return nil, err
	}
	var output boundedWireGuardCommandBuffer
	output.limit = limit
	command := exec.CommandContext(ctx, path, args...) // #nosec G204 -- executable is root/ancestry attested and arguments are fixed or previously validated
	configureWireGuardCommandLifecycle(command)
	command.Env = append([]string(nil), wireGuardFixedCommandEnvironment...)
	if input != "" {
		if len(input) > maximumWireGuardCommandOutput {
			return nil, fmt.Errorf("WireGuard command input exceeds %d bytes", maximumWireGuardCommandOutput)
		}
		command.Stdin = strings.NewReader(input)
	}
	command.Stdout = &output
	command.Stderr = &output
	if err := wireGuardExecutablePreStartAttestor(executableIdentity); err != nil {
		return nil, fmt.Errorf("reattest WireGuard command %s immediately before start: %w", name, err)
	}
	err = command.Start()
	if err == nil {
		err = command.Wait()
	}
	if errors.Is(err, exec.ErrWaitDelay) && command.Process != nil {
		_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
	}
	output.mu.Lock()
	wire := append([]byte(nil), output.buffer.Bytes()...)
	output.mu.Unlock()
	if err != nil {
		return wire, fmt.Errorf("WireGuard command %s failed: %w: %s", name, err, strings.TrimSpace(string(wire)))
	}
	return wire, nil
}

func configureWireGuardCommandLifecycle(command *exec.Cmd) {
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.WaitDelay = wireGuardCommandWaitDelay
	command.Cancel = func() error {
		if command.Process == nil {
			return os.ErrProcessDone
		}
		err := syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
}

func runBoundedWireGuardCommand(name string, args []string, input string, limit int, timeout time.Duration) ([]byte, error) {
	if timeout <= 0 || timeout > time.Minute {
		return nil, fmt.Errorf("invalid WireGuard command timeout %s", timeout)
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	wire, err := runBoundedWireGuardCommandContext(ctx, name, args, input, limit)
	if ctx.Err() != nil {
		return wire, fmt.Errorf("WireGuard command %s exceeded %s: %w", name, timeout, ctx.Err())
	}
	return wire, err
}

func runWireGuardStreamingCommand(name string, args []string, input string, stdout *os.File, timeout time.Duration) error {
	if stdout == nil || len(input) > maximumWireGuardCommandOutput || timeout <= 0 || timeout > time.Minute {
		return fmt.Errorf("invalid streaming WireGuard command parameters")
	}
	path, err := wireGuardExecutableResolver(name)
	if err != nil {
		return err
	}
	executableIdentity, err := wireGuardExecutableIdentityCapture(path)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	var stderr boundedWireGuardCommandBuffer
	stderr.limit = maximumWireGuardCommandOutput
	command := exec.CommandContext(ctx, path, args...) // #nosec G204 -- executable is root/ancestry attested and arguments are fixed
	configureWireGuardCommandLifecycle(command)
	command.Env = append([]string(nil), wireGuardFixedCommandEnvironment...)
	command.Stdin = strings.NewReader(input)
	command.Stdout = stdout
	command.Stderr = &stderr
	if err := wireGuardExecutablePreStartAttestor(executableIdentity); err != nil {
		return fmt.Errorf("reattest streaming WireGuard command %s immediately before start: %w", name, err)
	}
	err = command.Start()
	if err == nil {
		err = command.Wait()
	}
	if errors.Is(err, exec.ErrWaitDelay) && command.Process != nil {
		_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
	}
	if ctx.Err() != nil {
		return fmt.Errorf("WireGuard command %s exceeded %s: %w", name, timeout, ctx.Err())
	}
	if err != nil {
		stderr.mu.Lock()
		message := strings.TrimSpace(stderr.buffer.String())
		stderr.mu.Unlock()
		return fmt.Errorf("WireGuard command %s failed: %w: %s", name, err, message)
	}
	return nil
}

type pinnedWireGuardForwardingTransaction struct {
	file     *os.File
	path     string
	identity os.FileInfo
	original string
	applied  bool
	closed   bool
}

func samePinnedWireGuardIdentity(expected, actual os.FileInfo) bool {
	if expected == nil || actual == nil || !os.SameFile(expected, actual) || expected.Mode() != actual.Mode() {
		return false
	}
	left, leftOK := expected.Sys().(*syscall.Stat_t)
	right, rightOK := actual.Sys().(*syscall.Stat_t)
	return leftOK && rightOK && left.Uid == right.Uid && left.Gid == right.Gid &&
		left.Nlink == right.Nlink && left.Dev == right.Dev && left.Ino == right.Ino
}

func openPinnedWireGuardForwardingTransaction(path string, expectedUID uint32) (*pinnedWireGuardForwardingTransaction, error) {
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("pin net.ipv4.ip_forward: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("pin net.ipv4.ip_forward")
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || stat.Uid != expectedUID || stat.Nlink != 1 {
		_ = file.Close()
		return nil, fmt.Errorf("net.ipv4.ip_forward is not an exact owned regular file")
	}
	pathInfo, err := os.Lstat(path)
	if err != nil || !samePinnedWireGuardIdentity(info, pathInfo) {
		_ = file.Close()
		return nil, fmt.Errorf("net.ipv4.ip_forward path changed while pinning")
	}
	transaction := &pinnedWireGuardForwardingTransaction{file: file, path: path, identity: info}
	original, err := transaction.read()
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	transaction.original = original
	return transaction, nil
}

func newPinnedWireGuardForwardingTransaction() (wireGuardForwardingTransaction, error) {
	if wireGuardFilesystemRoot != "/" {
		return nil, fmt.Errorf("runtime forwarding mutation requires the live filesystem root")
	}
	return openPinnedWireGuardForwardingTransaction("/proc/sys/net/ipv4/ip_forward", 0)
}

func (transaction *pinnedWireGuardForwardingTransaction) attest() error {
	if transaction == nil || transaction.closed || transaction.file == nil {
		return fmt.Errorf("net.ipv4.ip_forward transaction is not active")
	}
	info, err := transaction.file.Stat()
	if err != nil || !samePinnedWireGuardIdentity(transaction.identity, info) {
		return fmt.Errorf("pinned net.ipv4.ip_forward identity changed")
	}
	pathInfo, err := os.Lstat(transaction.path)
	if err != nil || !samePinnedWireGuardIdentity(transaction.identity, pathInfo) {
		return fmt.Errorf("net.ipv4.ip_forward path identity changed")
	}
	return nil
}

func (transaction *pinnedWireGuardForwardingTransaction) read() (string, error) {
	if err := transaction.attest(); err != nil {
		return "", err
	}
	if _, err := transaction.file.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	wire, err := io.ReadAll(io.LimitReader(transaction.file, 16))
	if err != nil {
		return "", err
	}
	value := strings.TrimSpace(string(wire))
	if value != "0" && value != "1" {
		return "", fmt.Errorf("unexpected net.ipv4.ip_forward value %q", value)
	}
	if err := transaction.attest(); err != nil {
		return "", err
	}
	return value, nil
}

func (transaction *pinnedWireGuardForwardingTransaction) write(value string) error {
	if value != "0" && value != "1" {
		return fmt.Errorf("refusing invalid net.ipv4.ip_forward value %q", value)
	}
	if err := transaction.attest(); err != nil {
		return err
	}
	if _, err := transaction.file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if _, err := io.WriteString(transaction.file, value+"\n"); err != nil {
		return err
	}
	actual, err := transaction.read()
	if err != nil {
		return err
	}
	if actual != value {
		return fmt.Errorf("net.ipv4.ip_forward write did not converge to %s", value)
	}
	return nil
}

func (transaction *pinnedWireGuardForwardingTransaction) Apply() error {
	transaction.applied = true
	return transaction.write("1")
}

func (transaction *pinnedWireGuardForwardingTransaction) Restore() error {
	if transaction == nil || !transaction.applied {
		return nil
	}
	err := transaction.write(transaction.original)
	if err == nil {
		transaction.applied = false
	}
	return err
}

func (transaction *pinnedWireGuardForwardingTransaction) Close() error {
	if transaction == nil || transaction.closed {
		return nil
	}
	transaction.closed = true
	return transaction.file.Close()
}

func acquireWireGuardNFTActivationGuard() (func() error, error) {
	fd, err := syscall.Open(
		wireGuardNFTLockPath,
		syscall.O_CREAT|syscall.O_RDWR|syscall.O_NOFOLLOW|syscall.O_CLOEXEC,
		0600,
	)
	if err != nil {
		return nil, fmt.Errorf("open WireGuard nftables activation lock: %w", err)
	}
	file := os.NewFile(uintptr(fd), wireGuardNFTLockPath)
	if file == nil {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("open WireGuard nftables activation lock")
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || int64(stat.Uid) != int64(os.Geteuid()) || stat.Nlink != 1 {
		_ = file.Close()
		return nil, fmt.Errorf("WireGuard nftables activation lock is not an exact owned 0600 regular file")
	}
	pathInfo, err := os.Lstat(wireGuardNFTLockPath)
	if err != nil || !os.SameFile(info, pathInfo) || pathInfo.Mode() != info.Mode() {
		_ = file.Close()
		return nil, fmt.Errorf("WireGuard nftables activation lock path changed while opening")
	}
	deadline := time.Now().Add(wireGuardCommandTimeout)
	for {
		err = syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			break
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
			_ = file.Close()
			return nil, fmt.Errorf("lock WireGuard nftables activation: %w", err)
		}
		if time.Now().After(deadline) {
			_ = file.Close()
			return nil, fmt.Errorf("lock WireGuard nftables activation: timeout after %s", wireGuardCommandTimeout)
		}
		time.Sleep(50 * time.Millisecond)
	}
	lockedInfo, err := file.Stat()
	if err != nil {
		_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
		_ = file.Close()
		return nil, fmt.Errorf("reattest locked WireGuard nftables activation lock: %w", err)
	}
	lockedPathInfo, err := os.Lstat(wireGuardNFTLockPath)
	if err != nil || !samePinnedWireGuardIdentity(info, lockedInfo) ||
		!samePinnedWireGuardIdentity(info, lockedPathInfo) {
		_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
		_ = file.Close()
		return nil, fmt.Errorf("WireGuard nftables activation lock changed while acquiring it")
	}
	return func() error {
		unlockErr := syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
		closeErr := file.Close()
		return errors.Join(unlockErr, closeErr)
	}, nil
}

func runWireGuardServiceCommand(name string, args ...string) error {
	_, err := runBoundedWireGuardCommand(name, args, "", maximumWireGuardCommandOutput, wireGuardCommandTimeout)
	return err
}

func ensureExactSymlink(target, link string) error {
	info, err := os.Lstat(link)
	switch {
	case err == nil:
		if info.Mode()&os.ModeSymlink == 0 {
			return fmt.Errorf("refusing to replace non-symlink %s", link)
		}
		currentTarget, err := os.Readlink(link)
		if err != nil {
			return fmt.Errorf("read existing symlink %s: %w", link, err)
		}
		if currentTarget != target {
			return fmt.Errorf("refusing to replace symlink %s targeting %s", link, currentTarget)
		}
		return nil
	case !os.IsNotExist(err):
		return fmt.Errorf("inspect symlink %s: %w", link, err)
	}

	if err := os.Symlink(target, link); err != nil {
		return fmt.Errorf("create symlink %s: %w", link, err)
	}
	return nil
}

func prepareConfiguredWireGuardService() error {
	if wireGuardIsAlpine() {
		_, present, err := wireguardstate.InspectOpenRCServiceLink(
			wireGuardFilesystemRoot, wireGuardExpectedOwnerUID, wireGuardExpectedOwnerGID,
		)
		if err != nil || !present {
			if err == nil {
				err = fs.ErrNotExist
			}
			return fmt.Errorf("verify exact preexisting OpenRC WireGuard service link: %w", err)
		}
		return attestWireGuardServiceDefinition()
	}
	if err := attestWireGuardServiceDefinition(); err != nil {
		return fmt.Errorf("attest systemd WireGuard service definition before daemon reload: %w", err)
	}
	return runWireGuardServiceCommand("systemctl", "daemon-reload")
}

func activateWireGuardServiceFromExactState(
	baseline wireGuardServiceState,
	alpine bool,
	run wireGuardServiceRunner,
	output wireGuardServiceOutputRunner,
	attestDefinition func() error,
	attestHooks func() error,
) error {
	if baseline.Alpine != alpine {
		return fmt.Errorf("WireGuard service-manager identity changed before activation")
	}
	attestBeforeCommand := func(expected wireGuardServiceState, command string) error {
		current, err := inspectWireGuardServiceState(alpine, output)
		if err != nil || current != expected {
			if err == nil {
				err = fmt.Errorf("state changed: got %#v want %#v", current, expected)
			}
			return fmt.Errorf("reattest exact WireGuard service state before %s: %w", command, err)
		}
		if err := attestDefinition(); err != nil {
			return fmt.Errorf("reattest exact WireGuard service definition before %s: %w", command, err)
		}
		if err := attestHooks(); err != nil {
			return fmt.Errorf("reattest exact WireGuard configuration before %s: %w", command, err)
		}
		return nil
	}
	if alpine {
		if err := attestBeforeCommand(baseline, "OpenRC enablement"); err != nil {
			return err
		}
		if err := run("rc-update", "add", "wg-quick.wg-syswarden", "default"); err != nil {
			return fmt.Errorf("enable OpenRC WireGuard service: %w", err)
		}
		enabled := baseline
		enabled.Enabled = true
		if err := attestBeforeCommand(enabled, "OpenRC start"); err != nil {
			return err
		}
		if err := run("rc-service", "wg-quick.wg-syswarden", "start"); err != nil {
			return fmt.Errorf("start OpenRC WireGuard service: %w", err)
		}
		return nil
	}
	if err := attestBeforeCommand(baseline, "systemd activation"); err != nil {
		return err
	}
	if err := run("systemctl", "enable", "--now", "wg-quick@wg-syswarden.service"); err != nil {
		return fmt.Errorf("enable and start systemd WireGuard service: %w", err)
	}
	return nil
}

func activateConfiguredWireGuardServiceCommand(baseline wireGuardServiceState) error {
	return activateWireGuardServiceFromExactState(
		baseline, wireGuardIsAlpine(), runWireGuardServiceCommand,
		runWireGuardServiceOutput, attestWireGuardServiceDefinition,
		attestConfiguredWireGuardServerHooks,
	)
}

func attestConfiguredWireGuardServiceCommandInputs() error {
	if err := attestWireGuardServiceDefinition(); err != nil {
		return fmt.Errorf("attest exact WireGuard service definition: %w", err)
	}
	return attestConfiguredWireGuardServerHooks()
}

func attestConfiguredWireGuardServerHooks() error {
	identity, err := wireGuardServerIdentityInspector()
	if err != nil {
		return err
	}
	return wireGuardServerHookExecutableAttestor(identity)
}

func readConfiguredWireGuardServerIdentity() (wireguardstate.ServerConfigurationIdentity, error) {
	manifest, err := wireguardstate.ReadAndVerify(
		wireGuardFilesystemRoot, wireGuardExpectedOwnerUID, wireGuardExpectedOwnerGID,
	)
	if err != nil {
		return wireguardstate.ServerConfigurationIdentity{}, err
	}
	server, err := wireguardstate.ReadVerifiedArtifact(
		wireGuardFilesystemRoot, manifest, wireguardstate.ServerConfigurationPath,
		wireGuardExpectedOwnerUID, wireGuardExpectedOwnerGID,
	)
	if err != nil {
		return wireguardstate.ServerConfigurationIdentity{}, err
	}
	return wireguardstate.ParseServerConfiguration(server)
}

func runWireGuardServiceOutput(name string, args ...string) ([]byte, error) {
	return runBoundedWireGuardCommand(name, args, "", maximumWireGuardCommandOutput, wireGuardCommandTimeout)
}

func exactServiceBoolean(output []byte, outputErr error, positive, negative string) (bool, error) {
	value := strings.TrimSpace(string(output))
	switch value {
	case positive:
		if outputErr != nil {
			return false, fmt.Errorf("positive service state %q returned an error: %w", value, outputErr)
		}
		return true, nil
	case negative:
		return false, nil
	default:
		return false, errors.Join(fmt.Errorf("ambiguous service state %q", value), outputErr)
	}
}

func inspectWireGuardServiceState(
	alpine bool,
	output wireGuardServiceOutputRunner,
) (wireGuardServiceState, error) {
	state := wireGuardServiceState{Alpine: alpine}
	if alpine {
		status, statusErr := output("rc-service", "wg-quick.wg-syswarden", "status")
		trimmed := strings.TrimSpace(string(status))
		switch {
		case trimmed == "* status: started" && statusErr == nil:
			state.Active = true
		case trimmed == "* status: stopped":
			state.Active = false
		default:
			return wireGuardServiceState{}, errors.Join(fmt.Errorf("ambiguous OpenRC WireGuard status %q", trimmed), statusErr)
		}
		runlevels, err := output("rc-update", "show")
		if err != nil {
			return wireGuardServiceState{}, fmt.Errorf("inspect OpenRC WireGuard enablement: %w", err)
		}
		matches := 0
		for _, line := range strings.Split(string(runlevels), "\n") {
			fields := strings.Fields(line)
			if len(fields) > 0 && fields[0] == "wg-quick.wg-syswarden" {
				matches++
				if len(fields) != 3 || fields[1] != "|" || fields[2] != "default" {
					return wireGuardServiceState{}, fmt.Errorf("OpenRC WireGuard service has unexpected runlevel %q", strings.TrimSpace(line))
				}
			}
		}
		if matches > 1 {
			return wireGuardServiceState{}, fmt.Errorf("OpenRC WireGuard service has duplicate enablement")
		}
		state.Enabled = matches == 1
	} else {
		const unit = "wg-quick@wg-syswarden.service"
		active, activeErr := output("systemctl", "is-active", unit)
		value, err := exactServiceBoolean(active, activeErr, "active", "inactive")
		if err != nil {
			return wireGuardServiceState{}, fmt.Errorf("inspect systemd WireGuard active state: %w", err)
		}
		state.Active = value
		enabled, enabledErr := output("systemctl", "is-enabled", unit)
		value, err = exactServiceBoolean(enabled, enabledErr, "enabled", "disabled")
		if err != nil {
			return wireGuardServiceState{}, fmt.Errorf("inspect systemd WireGuard enablement: %w", err)
		}
		state.Enabled = value
	}
	interfaces, err := output("wg", "show", "interfaces")
	if err != nil {
		return wireGuardServiceState{}, fmt.Errorf("inspect WireGuard runtime interfaces: %w", err)
	}
	matches := 0
	for _, name := range strings.Fields(string(interfaces)) {
		if name == "wg-syswarden" {
			matches++
		}
	}
	if matches > 1 {
		return wireGuardServiceState{}, fmt.Errorf("WireGuard runtime reports duplicate wg-syswarden interfaces")
	}
	state.Interface = matches == 1
	if state.Interface != state.Active {
		return wireGuardServiceState{}, fmt.Errorf("WireGuard service/interface state is incoherent: %#v", state)
	}
	return state, nil
}

func inspectConfiguredWireGuardServiceState() (wireGuardServiceState, error) {
	return inspectWireGuardServiceState(wireGuardIsAlpine(), runWireGuardServiceOutput)
}

func inspectAbsentOpenRCWireGuardServiceState() (wireGuardServiceState, error) {
	runlevels, err := runWireGuardServiceOutput("rc-update", "show")
	if err != nil {
		return wireGuardServiceState{}, fmt.Errorf("inspect absent OpenRC WireGuard enablement: %w", err)
	}
	for _, line := range strings.Split(string(runlevels), "\n") {
		fields := strings.Fields(line)
		if len(fields) > 0 && fields[0] == "wg-quick.wg-syswarden" {
			return wireGuardServiceState{}, fmt.Errorf("OpenRC WireGuard instance is enabled while its exact service link is absent")
		}
	}
	interfaces, err := runWireGuardServiceOutput("wg", "show", "interfaces")
	if err != nil {
		return wireGuardServiceState{}, fmt.Errorf("inspect absent OpenRC WireGuard runtime interface: %w", err)
	}
	for _, name := range strings.Fields(string(interfaces)) {
		if name == "wg-syswarden" {
			return wireGuardServiceState{}, fmt.Errorf("WireGuard interface exists while its exact OpenRC service link is absent")
		}
	}
	return wireGuardServiceState{Alpine: true}, nil
}

func restoreWireGuardServiceState(
	target wireGuardServiceState,
	run wireGuardServiceRunner,
	output wireGuardServiceOutputRunner,
) error {
	current, inspectErr := inspectWireGuardServiceState(target.Alpine, output)
	known := inspectErr == nil
	var result error
	if inspectErr != nil {
		result = errors.Join(result, fmt.Errorf("inspect WireGuard service before restoration: %w", inspectErr))
	}
	runAttested := func(name string, args ...string) {
		if err := attestConfiguredWireGuardServiceCommandInputs(); err != nil {
			result = errors.Join(result, fmt.Errorf("reattest WireGuard hooks before %s: %w", name, err))
			return
		}
		if err := run(name, args...); err != nil {
			result = errors.Join(result, fmt.Errorf("restore WireGuard service with %s: %w", name, err))
		}
	}
	if target.Alpine {
		if target.Enabled && (!known || !current.Enabled) {
			runAttested("rc-update", "add", "wg-quick.wg-syswarden", "default")
		}
		if target.Active && (!known || !current.Active) {
			runAttested("rc-service", "wg-quick.wg-syswarden", "start")
		}
		if !target.Active && (!known || current.Active) {
			runAttested("rc-service", "wg-quick.wg-syswarden", "stop")
		}
		if !target.Enabled && (!known || current.Enabled) {
			runAttested("rc-update", "del", "wg-quick.wg-syswarden", "default")
		}
	} else {
		const unit = "wg-quick@wg-syswarden.service"
		if target.Enabled && (!known || !current.Enabled) {
			runAttested("systemctl", "enable", unit)
		}
		if target.Active && (!known || !current.Active) {
			runAttested("systemctl", "start", unit)
		}
		if !target.Active && (!known || current.Active) {
			runAttested("systemctl", "stop", unit)
		}
		if !target.Enabled && (!known || current.Enabled) {
			runAttested("systemctl", "disable", unit)
		}
	}
	final, finalErr := inspectWireGuardServiceState(target.Alpine, output)
	if finalErr != nil || final != target {
		if finalErr == nil {
			finalErr = fmt.Errorf("state mismatch: got %#v want %#v", final, target)
		}
		result = errors.Join(result, fmt.Errorf("reattest restored WireGuard service state: %w", finalErr))
	}
	return result
}

func restoreConfiguredWireGuardServiceState(target wireGuardServiceState) error {
	return restoreWireGuardServiceState(target, runWireGuardServiceCommand, runWireGuardServiceOutput)
}

type boundedWireGuardCommandBuffer struct {
	mu     sync.Mutex
	buffer bytes.Buffer
	limit  int
}

func (buffer *boundedWireGuardCommandBuffer) Write(value []byte) (int, error) {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	if len(value) > buffer.limit-buffer.buffer.Len() {
		return 0, fmt.Errorf("WireGuard command output exceeds %d bytes", buffer.limit)
	}
	return buffer.buffer.Write(value)
}

func (execWireGuardNFTCommandRunner) Run(ctx context.Context, args ...string) ([]byte, error) {
	return runBoundedWireGuardCommandContext(ctx, "nft", args, "", maximumWireGuardCommandOutput)
}

func wireGuardReservedNFTTableIdentity(ctx context.Context, runner wireGuardNFTCommandRunner) (bool, uint64, error) {
	wire, err := runner.Run(ctx, "-a", "-j", "list", "tables")
	if err != nil {
		return false, 0, fmt.Errorf("inventory nftables before WireGuard cleanup: %w: %s", err, strings.TrimSpace(string(wire)))
	}
	var envelope struct {
		NFTables []struct {
			Table *struct {
				Family string `json:"family"`
				Name   string `json:"name"`
				Handle uint64 `json:"handle"`
			} `json:"table,omitempty"`
		} `json:"nftables"`
	}
	decoder := json.NewDecoder(bytes.NewReader(wire))
	if err := decoder.Decode(&envelope); err != nil {
		return false, 0, fmt.Errorf("decode nftables table inventory: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return false, 0, fmt.Errorf("nftables table inventory has trailing data")
	}
	found := 0
	handle := uint64(0)
	for _, element := range envelope.NFTables {
		if element.Table != nil && element.Table.Family == "inet" && element.Table.Name == "syswarden_wg" {
			found++
			handle = element.Table.Handle
		}
	}
	if found > 1 {
		return false, 0, fmt.Errorf("nftables inventory contains duplicate inet syswarden_wg identities")
	}
	if found == 1 && handle == 0 {
		return false, 0, fmt.Errorf("reserved inet syswarden_wg table has no stable nftables handle")
	}
	return found == 1, handle, nil
}

func wireGuardNFTExpressionSignature(expressions []map[string]json.RawMessage) (string, error) {
	if len(expressions) != 2 || len(expressions[0]) != 1 || len(expressions[1]) != 1 {
		return "", fmt.Errorf("WireGuard nftables rule has an unexpected expression count")
	}
	matchWire, ok := expressions[0]["match"]
	if !ok {
		return "", fmt.Errorf("WireGuard nftables rule does not start with a match")
	}
	var match struct {
		Op   string `json:"op"`
		Left struct {
			Meta *struct {
				Key string `json:"key"`
			} `json:"meta"`
		} `json:"left"`
		Right string `json:"right"`
	}
	decoder := json.NewDecoder(bytes.NewReader(matchWire))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&match); err != nil || match.Op != "==" || match.Left.Meta == nil ||
		(match.Left.Meta.Key != "iifname" && match.Left.Meta.Key != "oifname") || match.Right == "" {
		return "", fmt.Errorf("WireGuard nftables rule has an unexpected match expression")
	}
	action := ""
	for _, candidate := range []string{"accept", "masquerade"} {
		if raw, exists := expressions[1][candidate]; exists &&
			(bytes.Equal(bytes.TrimSpace(raw), []byte("null")) || bytes.Equal(bytes.TrimSpace(raw), []byte("{}"))) {
			action = candidate
		}
	}
	if action == "" {
		return "", fmt.Errorf("WireGuard nftables rule has an unexpected terminal expression")
	}
	return match.Left.Meta.Key + "=" + match.Right + ":" + action, nil
}

func decodeStrictWireGuardNFTObject(raw json.RawMessage, target any, label string) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("decode exact WireGuard nftables %s: %w", label, err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return fmt.Errorf("WireGuard nftables %s has trailing data", label)
	}
	return nil
}

func validateExistingWireGuardNFTTable(wire []byte, identity wireguardstate.ServerConfigurationIdentity) (uint64, error) {
	if !wireGuardInterfaceName.MatchString(identity.ActiveInterface) ||
		!wireGuardOwnershipTokenName.MatchString(identity.OwnershipToken) {
		return 0, fmt.Errorf("invalid expected WireGuard nftables ownership identity")
	}
	var envelope struct {
		NFTables []map[string]json.RawMessage `json:"nftables"`
	}
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil {
		return 0, fmt.Errorf("decode existing WireGuard nftables table: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return 0, fmt.Errorf("existing WireGuard nftables table has trailing data")
	}
	tableCount := 0
	tableHandle := uint64(0)
	chains := make(map[string]string)
	rules := make(map[string]int)
	chainHandles := make(map[uint64]struct{})
	ruleHandles := make(map[string]map[uint64]struct{})
	for _, element := range envelope.NFTables {
		if len(element) != 1 {
			return 0, fmt.Errorf("existing WireGuard nftables table contains an ambiguous element")
		}
		for kind, raw := range element {
			switch kind {
			case "metainfo":
				continue
			case "table":
				var table struct {
					Family  string `json:"family"`
					Name    string `json:"name"`
					Comment string `json:"comment"`
					Handle  uint64 `json:"handle"`
				}
				if err := decodeStrictWireGuardNFTObject(raw, &table, "table"); err != nil ||
					table.Family != "inet" || table.Name != "syswarden_wg" ||
					table.Comment != "syswarden-wg-v1:"+identity.OwnershipToken || table.Handle == 0 {
					return 0, fmt.Errorf("existing WireGuard nftables table provenance mismatch")
				}
				tableCount++
				tableHandle = table.Handle
			case "chain":
				var chain struct {
					Family string `json:"family"`
					Table  string `json:"table"`
					Name   string `json:"name"`
					Type   string `json:"type"`
					Hook   string `json:"hook"`
					Prio   int    `json:"prio"`
					Policy string `json:"policy"`
					Handle uint64 `json:"handle"`
				}
				if err := decodeStrictWireGuardNFTObject(raw, &chain, "chain"); err != nil ||
					chain.Family != "inet" || chain.Table != "syswarden_wg" || chain.Handle == 0 {
					return 0, fmt.Errorf("existing WireGuard nftables chain identity mismatch")
				}
				if _, duplicate := chainHandles[chain.Handle]; duplicate {
					return 0, fmt.Errorf("existing WireGuard nftables chain handle is duplicated")
				}
				chainHandles[chain.Handle] = struct{}{}
				if _, duplicate := chains[chain.Name]; duplicate {
					return 0, fmt.Errorf("existing WireGuard nftables table has duplicate chain %s", chain.Name)
				}
				chains[chain.Name] = fmt.Sprintf("%s:%s:%d:%s", chain.Type, chain.Hook, chain.Prio, chain.Policy)
			case "rule":
				var rule struct {
					Family string                       `json:"family"`
					Table  string                       `json:"table"`
					Chain  string                       `json:"chain"`
					Expr   []map[string]json.RawMessage `json:"expr"`
					Handle uint64                       `json:"handle"`
				}
				if err := decodeStrictWireGuardNFTObject(raw, &rule, "rule"); err != nil ||
					rule.Family != "inet" || rule.Table != "syswarden_wg" || rule.Handle == 0 {
					return 0, fmt.Errorf("existing WireGuard nftables rule identity mismatch")
				}
				if ruleHandles[rule.Chain] == nil {
					ruleHandles[rule.Chain] = make(map[uint64]struct{})
				}
				if _, duplicate := ruleHandles[rule.Chain][rule.Handle]; duplicate {
					return 0, fmt.Errorf("existing WireGuard nftables rule handle is duplicated within chain %s", rule.Chain)
				}
				ruleHandles[rule.Chain][rule.Handle] = struct{}{}
				signature, err := wireGuardNFTExpressionSignature(rule.Expr)
				if err != nil {
					return 0, err
				}
				rules[rule.Chain+":"+signature]++
			default:
				return 0, fmt.Errorf("existing WireGuard nftables table contains unexpected %s state", kind)
			}
		}
	}
	if tableCount != 1 {
		return 0, fmt.Errorf("existing WireGuard nftables table count is %d", tableCount)
	}
	expectedChains := map[string]string{
		"prerouting":  "nat:prerouting:-100:accept",
		"postrouting": "nat:postrouting:100:accept",
		"forward":     "filter:forward:0:accept",
	}
	if !reflectStringMap(chains, expectedChains) {
		return 0, fmt.Errorf("existing WireGuard nftables chain structure is not owned")
	}
	expectedRules := map[string]int{
		"postrouting:oifname=" + identity.ActiveInterface + ":masquerade": 1,
		"forward:iifname=wg-syswarden:accept":                             1,
		"forward:oifname=wg-syswarden:accept":                             1,
	}
	if len(rules) != len(expectedRules) {
		return 0, fmt.Errorf("existing WireGuard nftables rule inventory is not owned")
	}
	for signature, count := range expectedRules {
		if rules[signature] != count {
			return 0, fmt.Errorf("existing WireGuard nftables rule %s is missing or duplicated", signature)
		}
	}
	return tableHandle, nil
}

func reflectStringMap(actual, expected map[string]string) bool {
	if len(actual) != len(expected) {
		return false
	}
	for key, expectedValue := range expected {
		if actual[key] != expectedValue {
			return false
		}
	}
	return true
}

func attestWireGuardNFTActivationState(expectation wireGuardNFTExpectation) error {
	ctx, cancel := context.WithTimeout(context.Background(), wireGuardCommandTimeout)
	defer cancel()
	runner := execWireGuardNFTCommandRunner{}
	present, inventoryHandle, err := wireGuardReservedNFTTableIdentity(ctx, runner)
	if err != nil {
		return err
	}
	if !present {
		if expectation.RequirePresent {
			return fmt.Errorf("owned inet syswarden_wg table is absent")
		}
		return nil
	}
	if !expectation.AllowExisting {
		return fmt.Errorf("reserved inet syswarden_wg table existed before WireGuard activation")
	}
	wire, err := runner.Run(ctx, "-a", "-j", "list", "table", "inet", "syswarden_wg")
	if err != nil {
		return fmt.Errorf("inspect existing reserved WireGuard table: %w: %s", err, strings.TrimSpace(string(wire)))
	}
	handle, err := validateExistingWireGuardNFTTable(wire, expectation.Identity)
	if err != nil {
		return err
	}
	if handle != inventoryHandle {
		return fmt.Errorf("reserved WireGuard table handle changed during provenance attestation")
	}
	return nil
}

func cleanupWireGuardReservedNFTTableWithRunner(
	runner wireGuardNFTCommandRunner,
	expected wireguardstate.ServerConfigurationIdentity,
) error {
	actual, err := wireGuardServerIdentityInspector()
	if err != nil {
		return fmt.Errorf("verify exact ownership manifest before nftables cleanup: %w", err)
	}
	if actual != expected {
		return fmt.Errorf("WireGuard nftables cleanup identity no longer matches its exact ownership manifest")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	present, inventoryHandle, err := wireGuardReservedNFTTableIdentity(ctx, runner)
	if err != nil || !present {
		return err
	}
	wire, err := runner.Run(ctx, "-a", "-j", "list", "table", "inet", "syswarden_wg")
	if err != nil {
		return fmt.Errorf("read owned WireGuard table before cleanup: %w: %s", err, strings.TrimSpace(string(wire)))
	}
	handle, err := validateExistingWireGuardNFTTable(wire, actual)
	if err != nil || handle != inventoryHandle {
		if err == nil {
			err = fmt.Errorf("table handle changed during cleanup attestation")
		}
		return fmt.Errorf("refuse unproven WireGuard nftables cleanup: %w", err)
	}
	output, err := runner.Run(ctx, "delete", "table", "inet", "handle", strconv.FormatUint(handle, 10))
	if err != nil {
		return fmt.Errorf("delete exact WireGuard table handle %d: %w: %s", handle, err, strings.TrimSpace(string(output)))
	}
	remaining, remainingHandle, err := wireGuardReservedNFTTableIdentity(ctx, runner)
	if err != nil {
		return fmt.Errorf("verify reserved WireGuard table cleanup: %w", err)
	}
	if remaining && remainingHandle == handle {
		return fmt.Errorf("exact WireGuard table handle %d remains after cleanup", handle)
	}
	return nil
}

func cleanupWireGuardReservedNFTTable(identity wireguardstate.ServerConfigurationIdentity) error {
	return cleanupWireGuardReservedNFTTableWithRunner(execWireGuardNFTCommandRunner{}, identity)
}

// CleanupOwnedWireGuardNFTState removes only the table handle proven by the
// exact ownership manifest and server-configuration token while holding the
// shared firewall lock. A same-name replacement is preserved.
func CleanupOwnedWireGuardNFTState() (resultErr error) {
	release, err := wireGuardNFTActivationGuard()
	if err != nil {
		return fmt.Errorf("acquire WireGuard nftables cleanup guard: %w", err)
	}
	defer func() {
		if err := release(); err != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("release WireGuard nftables cleanup guard: %w", err))
		}
	}()
	identity, err := wireGuardServerIdentityInspector()
	if err != nil {
		return fmt.Errorf("read manifest-bound WireGuard nftables identity: %w", err)
	}
	return wireGuardReservedNFTCleanup(identity)
}

func configuredWireGuardFirewallBackend() string {
	if config.GlobalConfig == nil || config.GlobalConfig.FirewallBackend == "" {
		return "keep"
	}
	return config.GlobalConfig.FirewallBackend
}

func compensateWireGuardActivation(
	baseline wireGuardServiceState,
	expectation wireGuardNFTExpectation,
) (bool, error) {
	var result error
	if rollbackErr := wireGuardServiceRollback(baseline); rollbackErr != nil {
		result = errors.Join(result, fmt.Errorf("rollback WireGuard service: %w", rollbackErr))
	}
	if expectation.RequirePresent {
		preserved := expectation
		preserved.RequirePresent = true
		if err := wireGuardNFTActivationPreflight(preserved); err != nil {
			result = errors.Join(result, fmt.Errorf("verify preexisting WireGuard nftables state was preserved: %w", err))
		}
		return result == nil, result
	}
	if cleanupErr := wireGuardReservedNFTCleanup(expectation.Identity); cleanupErr != nil {
		result = errors.Join(result, fmt.Errorf("cleanup manifest-bound WireGuard nftables state: %w", cleanupErr))
	}
	return result == nil, result
}

func rollbackWireGuardActivation(
	cause error,
	baseline wireGuardServiceState,
	expectation wireGuardNFTExpectation,
) error {
	_, compensationErr := compensateWireGuardActivation(baseline, expectation)
	return errors.Join(cause, compensationErr)
}

func rollbackWireGuardActivationGuarded(
	cause error,
	baseline wireGuardServiceState,
	expectation wireGuardNFTExpectation,
) (resultErr error) {
	_, compensationErr := compensateWireGuardActivationGuarded(baseline, expectation)
	return errors.Join(cause, compensationErr)
}

func compensateWireGuardActivationGuarded(
	baseline wireGuardServiceState,
	expectation wireGuardNFTExpectation,
) (converged bool, resultErr error) {
	release, err := wireGuardNFTActivationGuard()
	if err != nil {
		return false, fmt.Errorf("acquire WireGuard nftables rollback guard: %w", err)
	}
	defer func() {
		if err := release(); err != nil {
			converged = false
			resultErr = errors.Join(resultErr, fmt.Errorf("release WireGuard nftables rollback guard: %w", err))
		}
	}()
	return compensateWireGuardActivation(baseline, expectation)
}

func attestCommittedWireGuardRuntime(
	backend string,
	expectation wireGuardNFTExpectation,
	baseline wireGuardServiceState,
) (resultErr error) {
	release, err := wireGuardNFTActivationGuard()
	if err != nil {
		return fmt.Errorf("acquire WireGuard nftables post-commit attestation guard: %w", err)
	}
	defer func() {
		if err := release(); err != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("release WireGuard nftables post-commit attestation guard: %w", err))
		}
	}()
	if err := wireGuardFirewallBackendPreflight(backend); err != nil {
		return fmt.Errorf("firewall backend changed after WireGuard ownership commit: %w", err)
	}
	if err := attestWireGuardServiceDefinition(); err != nil {
		return fmt.Errorf("reattest exact WireGuard service definition after ownership commit: %w", err)
	}
	identity, err := wireGuardServerIdentityInspector()
	if err != nil || identity != expectation.Identity {
		if err == nil {
			err = fmt.Errorf("configuration ownership identity changed")
		}
		return fmt.Errorf("reattest exact WireGuard configuration after ownership commit: %w", err)
	}
	if err := wireGuardServerHookExecutableAttestor(identity); err != nil {
		return fmt.Errorf("reattest exact WireGuard hook executables after ownership commit: %w", err)
	}
	activeState, err := wireGuardServiceInspector()
	if err != nil || !activeState.ready() || activeState.Alpine != baseline.Alpine {
		if err == nil {
			err = fmt.Errorf("service is not exactly enabled, active, and interface-bound: %#v", activeState)
		}
		return fmt.Errorf("reattest exact WireGuard service state after ownership commit: %w", err)
	}
	postExpectation := expectation
	postExpectation.AllowExisting = true
	postExpectation.RequirePresent = true
	if err := wireGuardNFTActivationPreflight(postExpectation); err != nil {
		return fmt.Errorf("reattest manifest-bound WireGuard nftables state after ownership commit: %w", err)
	}
	return nil
}

func activateWireGuardAfterBackendPreflight(
	backend string,
	expectation wireGuardNFTExpectation,
	baseline wireGuardServiceState,
	forwarding wireGuardForwardingTransaction,
) (resultErr error) {
	release, err := wireGuardNFTActivationGuard()
	if err != nil {
		return fmt.Errorf("acquire WireGuard nftables activation guard: %w", err)
	}
	needsRollback := false
	defer func() {
		if err := release(); err != nil {
			releaseErr := fmt.Errorf("release WireGuard nftables activation guard: %w", err)
			if needsRollback {
				needsRollback = false
				resultErr = rollbackWireGuardActivationGuarded(errors.Join(resultErr, releaseErr), baseline, expectation)
			} else {
				resultErr = errors.Join(resultErr, releaseErr)
			}
		}
	}()
	if err := wireGuardNFTActivationPreflight(expectation); err != nil {
		return fmt.Errorf("attest reserved WireGuard nftables state before activation: %w", err)
	}
	if expectation.AllowExisting && !expectation.RequirePresent {
		if err := wireGuardReservedNFTCleanup(expectation.Identity); err != nil {
			return fmt.Errorf("retire manifest-bound inactive WireGuard nftables state before activation: %w", err)
		}
		expectation.AllowExisting = false
		if err := wireGuardNFTActivationPreflight(expectation); err != nil {
			return fmt.Errorf("verify reserved WireGuard nftables state is absent before activation: %w", err)
		}
	}
	if forwarding == nil {
		return fmt.Errorf("WireGuard forwarding transaction is unavailable")
	}
	if err := wireGuardFirewallBackendPreflight(backend); err != nil {
		return fmt.Errorf("firewall backend changed before WireGuard forwarding mutation: %w", err)
	}
	if err := forwarding.Apply(); err != nil {
		return fmt.Errorf("apply pinned net.ipv4.ip_forward mutation: %w", err)
	}
	if err := wireGuardServicePrepare(); err != nil {
		return fmt.Errorf("prepare WireGuard service activation: %w", err)
	}
	current, err := wireGuardServiceInspector()
	if err != nil || current != baseline {
		if err == nil {
			err = fmt.Errorf("state changed: got %#v want %#v", current, baseline)
		}
		return fmt.Errorf("reattest exact WireGuard service state immediately before activation: %w", err)
	}
	identity, err := wireGuardServerIdentityInspector()
	if err != nil || identity != expectation.Identity {
		if err == nil {
			err = fmt.Errorf("configuration ownership identity changed")
		}
		return fmt.Errorf("reattest exact WireGuard configuration immediately before activation: %w", err)
	}
	if err := wireGuardFirewallBackendPreflight(backend); err != nil {
		return fmt.Errorf("firewall backend changed before WireGuard activation: %w", err)
	}
	if err := wireGuardServiceActivator(baseline); err != nil {
		postBackendErr := wireGuardFirewallBackendPreflight(backend)
		return rollbackWireGuardActivation(errors.Join(
			fmt.Errorf("activate WireGuard service: %w", err), postBackendErr,
		), baseline, expectation)
	}
	needsRollback = true
	if err := wireGuardFirewallBackendPreflight(backend); err != nil {
		needsRollback = false
		return rollbackWireGuardActivation(fmt.Errorf("firewall backend changed after WireGuard activation: %w", err), baseline, expectation)
	}
	activeState, err := wireGuardServiceInspector()
	if err != nil || !activeState.ready() || activeState.Alpine != baseline.Alpine {
		if err == nil {
			err = fmt.Errorf("service is not exactly enabled, active, and interface-bound: %#v", activeState)
		}
		needsRollback = false
		return rollbackWireGuardActivation(fmt.Errorf("post-activation WireGuard service attestation failed: %w", err), baseline, expectation)
	}
	postExpectation := expectation
	postExpectation.AllowExisting = true
	postExpectation.RequirePresent = true
	if err := wireGuardNFTActivationPreflight(postExpectation); err != nil {
		needsRollback = false
		return rollbackWireGuardActivation(fmt.Errorf("post-activation WireGuard nftables provenance attestation failed: %w", err), baseline, expectation)
	}
	return nil
}

func attestWireGuardDirectory(info os.FileInfo, label string) error {
	if info == nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 {
		return fmt.Errorf("WireGuard directory %s is not a protected real directory", label)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != wireGuardExpectedOwnerUID || stat.Gid != wireGuardExpectedOwnerGID {
		return fmt.Errorf("WireGuard directory %s has unexpected ownership", label)
	}
	return nil
}

func ensureWireGuardDirectory(relative string, createMode os.FileMode, exactFinalMode bool) error {
	if !fs.ValidPath(relative) || relative == "." {
		return fmt.Errorf("invalid WireGuard directory path %q", relative)
	}
	currentRoot, err := os.OpenRoot(wireGuardFilesystemRoot)
	if err != nil {
		return fmt.Errorf("open WireGuard filesystem root: %w", err)
	}
	components := strings.Split(relative, "/")
	for index, component := range components {
		final := index == len(components)-1
		mode := os.FileMode(0755)
		if final {
			mode = createMode
		}
		info, statErr := currentRoot.Lstat(component)
		if errors.Is(statErr, fs.ErrNotExist) {
			if err := currentRoot.Mkdir(component, mode); err != nil {
				_ = currentRoot.Close()
				return fmt.Errorf("create WireGuard directory %s: %w", relative, err)
			}
			info, statErr = currentRoot.Lstat(component)
		}
		if statErr != nil {
			_ = currentRoot.Close()
			return fmt.Errorf("inspect WireGuard directory %s: %w", relative, statErr)
		}
		if err := attestWireGuardDirectory(info, filepath.Join("/", strings.Join(components[:index+1], "/"))); err != nil {
			_ = currentRoot.Close()
			return err
		}
		if final && exactFinalMode && info.Mode().Perm() != createMode.Perm() {
			_ = currentRoot.Close()
			return fmt.Errorf("WireGuard directory /%s must have mode %#o", relative, createMode.Perm())
		}
		next, err := currentRoot.OpenRoot(component)
		if err != nil {
			_ = currentRoot.Close()
			return fmt.Errorf("pin WireGuard directory %s: %w", relative, err)
		}
		opened, err := next.Stat(".")
		if err != nil || !os.SameFile(info, opened) {
			_ = next.Close()
			_ = currentRoot.Close()
			return fmt.Errorf("WireGuard directory /%s changed while opening", relative)
		}
		_ = currentRoot.Close()
		currentRoot = next
	}
	return currentRoot.Close()
}

func prepareWireGuardStateDirectories() error {
	if err := ensureWireGuardDirectory("etc/wireguard", 0700, true); err != nil {
		return fmt.Errorf("prepare WireGuard directory: %w", err)
	}
	if err := ensureWireGuardDirectory("etc/wireguard/clients", 0700, true); err != nil {
		return fmt.Errorf("prepare WireGuard clients directory: %w", err)
	}
	return ensureWireGuardDirectory("etc/sysctl.d", 0755, false)
}

func reusableWireGuardState() (wireguardstate.Manifest, []byte, bool, error) {
	inventory, err := wireguardstate.Inspect(wireGuardFilesystemRoot)
	if err != nil {
		return wireguardstate.Manifest{}, nil, false, err
	}
	if inventory.Empty() {
		return wireguardstate.Manifest{}, nil, false, nil
	}
	if inventory.Transaction {
		if _, err := wireguardstate.Recover(
			wireGuardFilesystemRoot, wireGuardExpectedOwnerUID, wireGuardExpectedOwnerGID,
		); err != nil {
			return wireguardstate.Manifest{}, nil, false, fmt.Errorf("recover interrupted WireGuard state transaction: %w", err)
		}
		inventory, err = wireguardstate.Inspect(wireGuardFilesystemRoot)
		if err != nil {
			return wireguardstate.Manifest{}, nil, false, err
		}
		if inventory.Empty() {
			return wireguardstate.Manifest{}, nil, false, nil
		}
	}
	manifest, err := wireguardstate.ReadAndVerify(
		wireGuardFilesystemRoot, wireGuardExpectedOwnerUID, wireGuardExpectedOwnerGID,
	)
	if err == nil {
		client, err := wireguardstate.ReadVerifiedArtifact(
			wireGuardFilesystemRoot, manifest, wireguardstate.ClientConfigurationPath,
			wireGuardExpectedOwnerUID, wireGuardExpectedOwnerGID,
		)
		if err != nil {
			return wireguardstate.Manifest{}, nil, false, err
		}
		return manifest, client, true, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return wireguardstate.Manifest{}, nil, false, fmt.Errorf("verify existing WireGuard ownership state: %w", err)
	}
	if !inventory.Empty() {
		return wireguardstate.Manifest{}, nil, false, fmt.Errorf("refusing unmanifested or partial WireGuard generated state: %#v", inventory)
	}
	return wireguardstate.Manifest{}, nil, false, nil
}

func canonicalWireGuardKey(value string) (string, error) {
	if value == "" || strings.TrimSpace(value) != value || strings.ContainsAny(value, "\r\n") {
		return "", fmt.Errorf("WireGuard key is empty or contains surrounding/control whitespace")
	}
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(decoded) != 32 || base64.StdEncoding.EncodeToString(decoded) != value {
		return "", fmt.Errorf("WireGuard key is not canonical base64 for 32 bytes")
	}
	return value, nil
}

func wireGuardHostAddresses(rawSubnet string) (netip.Prefix, netip.Addr, netip.Addr, error) {
	prefix, err := netip.ParsePrefix(rawSubnet)
	if err != nil || !prefix.Addr().Is4() || prefix.Addr().Is4In6() || prefix != prefix.Masked() || prefix.Bits() > 30 {
		return netip.Prefix{}, netip.Addr{}, netip.Addr{}, fmt.Errorf("WireGuard subnet must be a canonical IPv4 prefix with at least two host addresses")
	}
	server := prefix.Addr().Next()
	client := server.Next()
	if !server.IsValid() || !client.IsValid() || !prefix.Contains(server) || !prefix.Contains(client) {
		return netip.Prefix{}, netip.Addr{}, netip.Addr{}, fmt.Errorf("WireGuard subnet has no usable server/client address pair")
	}
	return prefix, server, client, nil
}

func renderWireGuardConfigurations(input wireGuardRenderInput) (string, string, error) {
	prefix, serverVPNIP, clientVPNIP, err := wireGuardHostAddresses(input.Subnet)
	if err != nil {
		return "", "", err
	}
	portNumber, err := strconv.Atoi(input.Port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return "", "", fmt.Errorf("invalid WireGuard port %q", input.Port)
	}
	port := strconv.Itoa(portNumber)
	if !wireGuardInterfaceName.MatchString(input.ActiveIf) {
		return "", "", fmt.Errorf("invalid WireGuard egress interface %q", input.ActiveIf)
	}
	if !wireGuardNFTExecutableName.MatchString(input.NFTPath) {
		return "", "", fmt.Errorf("invalid nft executable path %q", input.NFTPath)
	}
	if !wireGuardTrueExecutableName.MatchString(input.TruePath) {
		return "", "", fmt.Errorf("invalid true executable path %q", input.TruePath)
	}
	if !wireGuardOwnershipTokenName.MatchString(input.OwnershipToken) {
		return "", "", fmt.Errorf("invalid WireGuard ownership token")
	}
	endpoint, err := netip.ParseAddr(input.EndpointIP)
	if err != nil || endpoint.Zone() != "" || endpoint.Is4In6() {
		return "", "", fmt.Errorf("invalid WireGuard endpoint IP %q", input.EndpointIP)
	}
	keys := []*string{&input.ServerPriv, &input.ServerPub, &input.ClientPriv, &input.ClientPub, &input.PresharedKey}
	for _, key := range keys {
		canonical, err := canonicalWireGuardKey(*key)
		if err != nil {
			return "", "", err
		}
		*key = canonical
	}

	var postUp, postDown string
	switch input.Backend {
	case "nftables":
		postUp = fmt.Sprintf(`%s 'create table inet syswarden_wg { comment "syswarden-wg-v1:%s"; }; add chain inet syswarden_wg prerouting { type nat hook prerouting priority dstnat; }; add chain inet syswarden_wg postrouting { type nat hook postrouting priority srcnat; }; add chain inet syswarden_wg forward { type filter hook forward priority 0; policy accept; }; add rule inet syswarden_wg postrouting oifname "%s" masquerade; add rule inet syswarden_wg forward iifname "wg-syswarden" accept; add rule inet syswarden_wg forward oifname "wg-syswarden" accept'`, input.NFTPath, input.OwnershipToken, input.ActiveIf)
		// A raw wg-quick deletion hook cannot prove manifest ownership or hold
		// the shared firewall lock. Lifecycle code uses CleanupOwnedWireGuardNFTState.
		postDown = input.TruePath
	case "keep":
		return "", "", fmt.Errorf("WireGuard requires the explicit nftables backend; keep does not mutate operator-managed firewalld or UFW forwarding policy")
	case "iptables":
		return "", "", fmt.Errorf("iptables is not an operational WireGuard firewall mode in v4.03.2")
	default:
		return "", "", fmt.Errorf("unsupported WireGuard firewall backend %q", input.Backend)
	}

	serverConf := fmt.Sprintf(`[Interface]
Address = %s/%d
ListenPort = %s
PrivateKey = %s
PostUp = %s
PostDown = %s

[Peer]
PublicKey = %s
PresharedKey = %s
AllowedIPs = %s/32
`, serverVPNIP, prefix.Bits(), port, input.ServerPriv, postUp, postDown, input.ClientPub, input.PresharedKey, clientVPNIP)

	clientConf := fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = %s/%d
MTU = 1360
DNS = 1.1.1.1, 1.0.0.1

[Peer]
PublicKey = %s
PresharedKey = %s
Endpoint = %s
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
`, input.ClientPriv, clientVPNIP, prefix.Bits(), input.ServerPub, input.PresharedKey, net.JoinHostPort(endpoint.String(), port))
	return serverConf, clientConf, nil
}

func generateWireGuardConfigurations(backend string) (string, string, error) {
	fixedOutput := func(limit int, operation, name string, args ...string) ([]byte, error) {
		output, err := wireGuardCommandOutput(name, args...)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", operation, err)
		}
		if len(output) > limit {
			return nil, fmt.Errorf("%s output exceeds %d bytes", operation, limit)
		}
		return output, nil
	}

	nftPath, err := wireGuardNFTExecutablePath()
	if err != nil {
		return "", "", fmt.Errorf("resolve trusted nft executable for WireGuard hooks: %w", err)
	}
	truePath, err := wireGuardTrueExecutablePath()
	if err != nil {
		return "", "", fmt.Errorf("resolve trusted no-op executable for WireGuard hooks: %w", err)
	}
	ownershipToken, err := wireGuardOwnershipToken()
	if err != nil {
		return "", "", err
	}
	fmt.Println(" -> Generating cryptographic keys (incl. Post-Quantum PSK)")
	serverPriv, err := fixedOutput(256, "generate WireGuard server key", "wg", "genkey")
	if err != nil {
		return "", "", err
	}
	serverPrivStr := strings.TrimSpace(string(serverPriv))
	serverPub, err := wireGuardCommandInputOutput(serverPrivStr, "wg", "pubkey")
	if err != nil {
		return "", "", fmt.Errorf("derive WireGuard server public key: %w", err)
	}
	if len(serverPub) > 256 {
		return "", "", fmt.Errorf("derive WireGuard server public key output exceeds 256 bytes")
	}

	clientPriv, err := fixedOutput(256, "generate WireGuard client key", "wg", "genkey")
	if err != nil {
		return "", "", err
	}
	clientPrivStr := strings.TrimSpace(string(clientPriv))
	clientPub, err := wireGuardCommandInputOutput(clientPrivStr, "wg", "pubkey")
	if err != nil {
		return "", "", fmt.Errorf("derive WireGuard client public key: %w", err)
	}
	if len(clientPub) > 256 {
		return "", "", fmt.Errorf("derive WireGuard client public key output exceeds 256 bytes")
	}
	presharedKey, err := fixedOutput(256, "generate WireGuard preshared key", "wg", "genpsk")
	if err != nil {
		return "", "", err
	}
	fmt.Println(" -> Injecting Quantum-Resistant PresharedKey (PSK)")

	activeIfOut, err := fixedOutput(4096, "discover WireGuard egress interface", "ip", "route", "get", "8.8.8.8")
	if err != nil {
		return "", "", err
	}
	activeIf := ""
	fields := strings.Fields(string(activeIfOut))
	for index, value := range fields {
		if value == "dev" && index+1 < len(fields) {
			activeIf = fields[index+1]
			break
		}
	}
	if activeIf == "" {
		return "", "", fmt.Errorf("WireGuard egress route has no interface")
	}

	serverIPOut, err := fixedOutput(
		256,
		"discover WireGuard endpoint IP",
		"curl",
		"--proto", "=https",
		"--tlsv1.3",
		"--fail",
		"--silent",
		"--show-error",
		"--connect-timeout", "3",
		"--max-time", "5",
		"-4",
		"https://api.ipify.org",
	)
	if err != nil {
		return "", "", err
	}

	serverConf, clientConf, err := renderWireGuardConfigurations(wireGuardRenderInput{
		Subnet:         config.GlobalConfig.WGSubnet,
		Port:           config.GlobalConfig.WGPort,
		Backend:        backend,
		NFTPath:        nftPath,
		TruePath:       truePath,
		OwnershipToken: ownershipToken,
		ActiveIf:       activeIf,
		EndpointIP:     strings.TrimSpace(string(serverIPOut)),
		ServerPriv:     serverPrivStr,
		ServerPub:      strings.TrimSpace(string(serverPub)),
		ClientPriv:     clientPrivStr,
		ClientPub:      strings.TrimSpace(string(clientPub)),
		PresharedKey:   strings.TrimSpace(string(presharedKey)),
	})
	if err != nil {
		return "", "", fmt.Errorf("render WireGuard configuration: %w", err)
	}
	if err := wireguardstate.VerifyServerConfiguration([]byte(serverConf)); err != nil {
		return "", "", fmt.Errorf("verify generated WireGuard server hooks: %w", err)
	}
	return serverConf, clientConf, nil
}

func stageAndPublishWireGuardState(
	backend, serverConf, clientConf string,
	ownOpenRCServiceLink bool,
) (result *wireguardstate.StagedPublication, resultErr error) {
	contents := map[string][]byte{
		wireguardstate.ServerConfigurationPath:     []byte(serverConf),
		wireguardstate.ClientConfigurationPath:     []byte(clientConf),
		wireguardstate.ForwardingConfigurationPath: []byte("net.ipv4.ip_forward = 1\n"),
	}
	publication, err := wireguardstate.StageOwnedArtifacts(
		wireGuardFilesystemRoot, contents, wireGuardExpectedOwnerUID, wireGuardExpectedOwnerGID,
	)
	if err != nil {
		return nil, fmt.Errorf("stage WireGuard generated state: %w", err)
	}
	keepPublication := false
	defer func() {
		if !keepPublication {
			if err := publication.Rollback(); err != nil {
				resultErr = errors.Join(resultErr, fmt.Errorf("rollback WireGuard artifact publication: %w", err))
			}
		}
	}()
	if err := wireGuardFirewallBackendPreflight(backend); err != nil {
		return nil, fmt.Errorf("firewall backend changed before WireGuard artifact publication: %w", err)
	}
	if ownOpenRCServiceLink {
		if err := publication.PlanOpenRCServiceLink(); err != nil {
			return nil, fmt.Errorf("plan durable OpenRC WireGuard service-link ownership: %w", err)
		}
	}
	if err := publication.Publish(); err != nil {
		return nil, fmt.Errorf("publish WireGuard generated artifacts: %w", err)
	}
	var openRCServiceLink *wireguardstate.SymlinkArtifact
	if ownOpenRCServiceLink {
		identity, err := publication.CreateOpenRCServiceLink()
		if err != nil {
			return nil, err
		}
		openRCServiceLink = &identity
	}
	manifest, err := wireguardstate.CaptureManifest(
		wireGuardFilesystemRoot, wireGuardExpectedOwnerUID, wireGuardExpectedOwnerGID,
	)
	if err != nil {
		return nil, err
	}
	manifest.OpenRCServiceLink = openRCServiceLink
	stagedManifest, err := publication.StageManifest(manifest)
	if err != nil {
		return nil, fmt.Errorf("stage WireGuard ownership manifest: %w", err)
	}
	if err := wireGuardFirewallBackendPreflight(backend); err != nil {
		return nil, fmt.Errorf("firewall backend changed before WireGuard manifest publication: %w", err)
	}
	if err := stagedManifest.Publish(); err != nil {
		return nil, fmt.Errorf("publish WireGuard ownership manifest: %w", err)
	}
	keepPublication = true
	return publication, nil
}

func SetupWireguard() (resultErr error) {
	if config.GlobalConfig == nil {
		return fmt.Errorf("WireGuard setup requires a loaded configuration")
	}
	if !config.GlobalConfig.EnableWG {
		fmt.Println("[INFO] WireGuard is disabled in SYSWARDEN configuration. Skipping WireGuard setup.")
		return nil
	}
	backend := configuredWireGuardFirewallBackend()
	if backend != "nftables" {
		return fmt.Errorf("WireGuard setup requires core.firewall_backend=nftables; configured backend is %q", backend)
	}
	if err := wireGuardFirewallBackendPreflight(backend); err != nil {
		return fmt.Errorf("firewall backend preflight failed before WireGuard mutation: %w", err)
	}
	managerState, err := wireGuardManagerRuntimeState()
	if err != nil {
		return fmt.Errorf("classify service-manager runtime before WireGuard setup: %w", err)
	}
	if managerState != "ACTIVE" {
		return fmt.Errorf("WireGuard setup requires an attestable active service manager; state is %s", managerState)
	}
	alpine := wireGuardIsAlpine()
	var baselineOpenRCLinkPresent bool
	if alpine {
		_, baselineOpenRCLinkPresent, err = wireguardstate.InspectOpenRCServiceLink(
			wireGuardFilesystemRoot, wireGuardExpectedOwnerUID, wireGuardExpectedOwnerGID,
		)
		if err != nil {
			return fmt.Errorf("inspect OpenRC WireGuard service-link baseline: %w", err)
		}
	}
	var baseline wireGuardServiceState
	if alpine && !baselineOpenRCLinkPresent {
		baseline, err = wireGuardAbsentOpenRCServiceInspector()
	} else {
		baseline, err = wireGuardServiceInspector()
	}
	if err != nil {
		return fmt.Errorf("capture exact WireGuard service state before generated-state preparation: %w", err)
	}
	if baseline.Alpine != alpine {
		return fmt.Errorf("service-manager identity changed during WireGuard baseline capture")
	}

	fmt.Println("[INFO] Configuring WireGuard VPN...")
	manifest, clientBytes, reused, err := reusableWireGuardState()
	if err != nil {
		return err
	}
	if !reused && baseline.Active {
		return fmt.Errorf("refusing to adopt an active preexisting WireGuard service without an ownership manifest")
	}
	ownOpenRCServiceLink := false
	if baseline.Alpine {
		if reused {
			if manifest.OpenRCServiceLink == nil && !baselineOpenRCLinkPresent {
				return fmt.Errorf("reusable WireGuard state has no OpenRC service link and no ownership proof; refusing an unjournaled creation")
			}
		} else {
			ownOpenRCServiceLink = !baselineOpenRCLinkPresent
		}
	}
	var publication *wireguardstate.StagedPublication
	var serverConfiguration string
	if !reused {
		if err := prepareWireGuardStateDirectories(); err != nil {
			return err
		}
		serverConf, clientConf, err := generateWireGuardConfigurations(backend)
		if err != nil {
			return err
		}
		serverConfiguration = serverConf
		clientBytes = []byte(clientConf)
		publication, err = stageAndPublishWireGuardState(
			backend, serverConf, clientConf, ownOpenRCServiceLink,
		)
		if err != nil {
			return err
		}
		defer func() {
			if err := publication.Rollback(); err != nil {
				resultErr = errors.Join(resultErr, fmt.Errorf("recover WireGuard publication after setup: %w", err))
			}
		}()
	} else {
		serverBytes, err := wireguardstate.ReadVerifiedArtifact(
			wireGuardFilesystemRoot, manifest, wireguardstate.ServerConfigurationPath,
			wireGuardExpectedOwnerUID, wireGuardExpectedOwnerGID,
		)
		if err != nil {
			return err
		}
		if err := wireguardstate.VerifyServerConfiguration(serverBytes); err != nil {
			return fmt.Errorf("verify reusable WireGuard server hooks: %w", err)
		}
		serverConfiguration = string(serverBytes)
	}

	identity, err := wireguardstate.ParseServerConfiguration([]byte(serverConfiguration))
	if err != nil {
		return fmt.Errorf("parse exact WireGuard runtime ownership identity: %w", err)
	}
	expectation := wireGuardNFTExpectation{
		AllowExisting:  reused,
		RequirePresent: reused && baseline.Active,
		Identity:       identity,
	}
	forwarding, err := wireGuardForwardingTransactionFactory()
	if err != nil {
		return fmt.Errorf("pin net.ipv4.ip_forward before WireGuard activation: %w", err)
	}
	keepForwarding := false
	removalReloadDebtPending := false
	defer func() {
		restored := keepForwarding
		if !keepForwarding {
			if err := forwarding.Restore(); err != nil {
				resultErr = errors.Join(resultErr, fmt.Errorf("restore net.ipv4.ip_forward after failed WireGuard setup: %w", err))
			} else {
				restored = true
			}
		}
		closeErr := forwarding.Close()
		if closeErr != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("close pinned net.ipv4.ip_forward transaction: %w", closeErr))
		}
		if removalReloadDebtPending && !keepForwarding && restored && closeErr == nil {
			finalized, err := wireguardstate.FinalizeRemoval(
				wireGuardFilesystemRoot, wireGuardExpectedOwnerUID, wireGuardExpectedOwnerGID,
			)
			if err != nil {
				resultErr = errors.Join(resultErr, fmt.Errorf("finalize WireGuard removal after forwarding restoration: %w", err))
			} else if !finalized {
				resultErr = errors.Join(resultErr, fmt.Errorf("WireGuard removal reload debt disappeared before finalization"))
			}
		}
	}()

	fmt.Println(" -> Starting WireGuard Interface")
	if err := activateWireGuardAfterBackendPreflight(backend, expectation, baseline, forwarding); err != nil {
		return err
	}
	activationRollbackRequired := publication != nil
	ownershipCommitted := false
	defer func() {
		if activationRollbackRequired && resultErr != nil {
			cause := errors.Join(
				resultErr, errors.New("WireGuard activation rolled back because final committed runtime attestation did not complete"),
			)
			converged, rollbackErr := compensateWireGuardActivationGuarded(baseline, expectation)
			resultErr = errors.Join(cause, rollbackErr)
			if ownershipCommitted {
				current, err := wireGuardServiceInspector()
				if !converged || err != nil || current != baseline {
					if err == nil {
						if !converged {
							err = fmt.Errorf("service/nftables compensation did not converge")
						} else {
							err = fmt.Errorf("state mismatch: got %#v want %#v", current, baseline)
						}
					}
					resultErr = errors.Join(resultErr, fmt.Errorf("retain committed ownership evidence because service rollback is unproven: %w", err))
				} else if changed, err := wireguardstate.PrepareRemoval(
					wireGuardFilesystemRoot, wireGuardExpectedOwnerUID, wireGuardExpectedOwnerGID,
				); err != nil {
					resultErr = errors.Join(resultErr, fmt.Errorf("prepare committed WireGuard state removal after failed final runtime attestation: %w", err))
				} else if !changed {
					resultErr = errors.Join(resultErr, fmt.Errorf("committed WireGuard state disappeared before durable removal preparation"))
				} else {
					removalReloadDebtPending = true
				}
			}
		}
	}()
	if publication != nil {
		if err := publication.Commit(); err != nil {
			return fmt.Errorf("commit WireGuard ownership transaction: %w", err)
		}
		ownershipCommitted = true
		wireGuardAfterOwnershipCommit()
		if err := attestCommittedWireGuardRuntime(backend, expectation, baseline); err != nil {
			return fmt.Errorf("final WireGuard runtime attestation after ownership commit: %w", err)
		}
	}
	activationRollbackRequired = false
	keepForwarding = true
	if reused {
		fmt.Println("[INFO] Existing fully attested WireGuard keys preserved and service activation verified.")
	}

	fmt.Println("\n=======================================================")
	fmt.Println("             WIREGUARD CLIENT CONFIGURATION            ")
	fmt.Println("=======================================================")
	fmt.Println("Scan the QR Code below with your WireGuard mobile app:")

	_ = wireGuardQRCodeRender(string(clientBytes))

	fmt.Println("=======================================================")
	fmt.Println("Client config saved at: " + wireguardstate.ClientConfigurationPath)

	return nil
}
