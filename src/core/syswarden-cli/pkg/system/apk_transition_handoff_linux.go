//go:build linux

package system

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const apkNativeHandoffSchema = "syswarden-apk-native-handoff/v1"
const apkNativeSocketName = "native-handoff.sock"
const apkNativeHookTimeout = 30 * time.Second

type apkNativeHandoffRecord struct {
	Schema         string                      `json:"schema"`
	PlanSHA256     string                      `json:"plan_sha256"`
	ApprovalSHA256 string                      `json:"approval_sha256"`
	Helper         nativeActivationRuntimeFile `json:"helper"`
	Coordinator    apkNativeProcess            `json:"coordinator"`
	Hook           apkTransitionHostEntry      `json:"hook"`
	Active         apkTransitionHostEntry      `json:"active_dispatcher"`
}
type apkNativeHookPacket struct {
	Schema        string `json:"schema"`
	PlanSHA256    string `json:"plan_sha256"`
	HandoffSHA256 string `json:"handoff_sha256"`
	Phase         string `json:"phase"`
	Status        string `json:"status"`
}
type apkNativeHookAcknowledgment struct {
	DatabaseSHA256 string              `json:"database_sha256,omitempty"`
	Request        apkNativeHookPacket `json:"request"`
	Native         apkNativeProcess    `json:"native"`
	Helper         apkNativeProcess    `json:"helper"`
}

type apkTransitionHandoff struct {
	expectedRecoverySHA256 string
	host                   string
	directory              *pinnedServiceDirectory
	hookDirectory          *pinnedServiceDirectory
	parent                 *pinnedServiceDirectory
	postVerify             func(context.Context) error
	listener               *net.UnixListener
	record                 apkNativeHandoffRecord
	digest                 string
	hooks                  *apkNativeHookProposal
	revalidate             func() error
	phases                 int
}

func apkTransitionGateBytes(digest string) ([]byte, error) {
	if !validSHA256(digest) {
		return nil, errors.New("APK gate requires an exact execution digest")
	}
	path := apkTransitionRoot + "/execution-" + digest + "/" + apkExecutionHelper
	return []byte("#!/bin/sh\nset -eu\ncase \"${1:-}\" in\npre-commit|pre-upgrade|post-commit) helper=" + path + " ;;\npost-upgrade) helper=/opt/syswarden/bin/syswarden-cli ;;\n*) exit 1 ;;\nesac\nexec \"$helper\" internal-apk-transition-hook --execution-plan " + digest + " --phase \"$1\"\n"), nil
}

func prepareAPKTransitionHandoff(ctx context.Context, prepared *verifiedPreparedAPKTransition, directory *pinnedServiceDirectory, plan apkExecutionPlan, approval string, revalidate func() error) (_ *apkTransitionHandoff, result error) {
	if ctx == nil || prepared == nil || directory == nil || revalidate == nil || plan.NativeHooks == nil || !validSHA256(approval) {
		return nil, errors.New("APK native handoff lacks exact approved custody")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	expectedHooks := map[string]string{".pre-upgrade": APKTransitionUpgradeHookSHA256("pre-upgrade"), ".post-upgrade": APKTransitionUpgradeHookSHA256("post-upgrade"), "etc/apk/commit_hooks.d/syswarden-recovery": APKRecoveryHookSHA256()}
	for _, member := range prepared.plan.Inventory {
		if expected, ok := expectedHooks[member.Path]; ok {
			if member.SHA256 != expected {
				return nil, errors.New("APK candidate hook is not the compiled bounded transition implementation")
			}
			delete(expectedHooks, member.Path)
		}
	}
	if len(expectedHooks) != 0 {
		return nil, errors.New("APK candidate omits a required bounded transition hook")
	}
	data, err := apkExecutionJSON(plan)
	if err != nil {
		return nil, err
	}
	digest := apkTransitionDigest(data)
	if err := verifyAPKNativeHandoffAuthority(directory, digest, approval, false); err != nil {
		return nil, err
	}
	if err := revalidateAPKNativeHookProposal(ctx, prepared.services.hostRoot, plan.NativeHooks); err != nil {
		return nil, err
	}
	for _, entry := range plan.NativeHooks.Entries {
		if entry.Path == apkTransitionGateDirectory && entry.Absent {
			return nil, errors.New("APK native handoff requires the reviewed existing protected commit hook directory")
		}
	}
	helper, err := openAPKExecutionHelper(directory, plan.CandidateCLISHA256)
	if err != nil {
		return nil, err
	}
	info, statErr := helper.Stat()
	closeErr := helper.Close()
	if err := errors.Join(statErr, closeErr); err != nil {
		return nil, err
	}
	coordinator, err := observeAPKNativeProcess(ctx, os.Getpid())
	if err != nil {
		return nil, err
	}
	h := &apkTransitionHandoff{host: prepared.services.hostRoot, directory: directory, revalidate: revalidate, parent: prepared.parent, postVerify: prepared.activation.VerifyInstalledCandidate, expectedRecoverySHA256: APKRecoveryHookSHA256()}
	defer func() {
		if result != nil {
			result = errors.Join(result, h.Close())
		}
	}()
	h.record = apkNativeHandoffRecord{Schema: apkNativeHandoffSchema, PlanSHA256: digest, ApprovalSHA256: approval, Helper: nativeActivationRuntimeFile{apkTransitionStat(info.Sys().(*syscall.Stat_t)), plan.CandidateCLISHA256}, Coordinator: coordinator}
	// The bounded transport requires existing protected ancestry. It never
	// repairs a missing directory or revises the original host snapshot.
	h.hookDirectory, err = openExistingPinnedServiceDirectory(filepath.Join(h.host, apkTransitionGateDirectory))
	if err != nil {
		return nil, err
	}
	body, err := apkTransitionGateBytes(digest)
	if err != nil {
		return nil, err
	}
	intent, err := apkExecutionJSON(struct {
		PlanSHA256 string `json:"plan_sha256"`
		BodySHA256 string `json:"body_sha256"`
	}{digest, apkTransitionDigest(body)})
	if err != nil {
		return nil, err
	}
	if err := writeAPKTransitionBytes(directory, "native-gate-intent.json", intent); err != nil {
		return nil, err
	}
	active, err := prepared.parent.root.OpenFile("active-hook", os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0700)
	if err != nil {
		return nil, err
	}
	_, activeWrite := active.Write(body)
	if err := errors.Join(activeWrite, active.Sync(), active.Close(), prepared.parent.sync()); err != nil {
		return nil, err
	}
	h.record.Active, err = readAPKNativeHookMode(prepared.parent.root, "active-hook", 0700)
	if err != nil {
		return nil, err
	}
	file, err := h.hookDirectory.root.OpenFile(apkTransitionGateName, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0755)
	if err != nil {
		return nil, err
	}
	_, writeErr := file.Write(body)
	err = errors.Join(writeErr, file.Sync(), file.Close(), h.hookDirectory.sync())
	if err != nil {
		return nil, err
	}
	h.record.Hook, err = readAPKNativeHook(h.hookDirectory.root, apkTransitionGateName)
	if err != nil {
		return nil, err
	}
	h.hooks, err = captureAPKNativeHooksWithGate(ctx, h.host, &h.record.Hook)
	if err != nil {
		return nil, err
	}
	record, err := apkExecutionJSON(h.record)
	if err != nil {
		return nil, err
	}
	h.digest = apkTransitionDigest(record)
	if err := writeAPKTransitionBytes(directory, "native-handoff.json", record); err != nil {
		return nil, err
	}
	socket := fmt.Sprintf("/proc/self/fd/%d/%s", directory.fd, apkNativeSocketName)
	h.listener, err = net.ListenUnix("unixpacket", &net.UnixAddr{Name: socket, Net: "unixpacket"})
	if err != nil {
		return nil, err
	}
	h.listener.SetUnlinkOnClose(false)
	if err := directory.root.Chmod(apkNativeSocketName, 0600); err != nil {
		return nil, err
	}
	raw, err := h.listener.SyscallConn()
	if err != nil {
		return nil, err
	}
	var optionErr error
	if err := raw.Control(func(fd uintptr) { optionErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_PASSCRED, 1) }); err != nil {
		return nil, err
	}
	if optionErr != nil {
		return nil, optionErr
	}
	if err := directory.sync(); err != nil {
		return nil, err
	}
	return h, h.Revalidate(ctx)
}

func (h *apkTransitionHandoff) Revalidate(ctx context.Context) error {
	if h == nil || ctx == nil {
		return errors.New("APK native handoff is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	got, err := captureAPKNativeHooksWithGate(ctx, h.host, &h.record.Hook)
	if err != nil {
		return err
	}
	active, err := readAPKNativeHookMode(h.parent.root, "active-hook", 0700)
	if err != nil || !reflect.DeepEqual(active, h.record.Active) {
		return errors.New("APK active dispatcher changed")
	}
	if !reflect.DeepEqual(got, h.hooks) {
		return errors.New("APK native gate or hook inventory changed before dispatch")
	}
	return verifyAPKNativeHandoffAuthority(h.directory, h.record.PlanSHA256, h.record.ApprovalSHA256, false)
}

// Closing transport retains the hook and all records. Without the original live
// coordinator that hook refuses future commits. Only independently inspected
// terminal recovery may retire the exact owned gate; completion JSON alone may
// never perform that cleanup.
func (h *apkTransitionHandoff) Close() error {
	if h == nil {
		return nil
	}
	var result error
	if h.listener != nil {
		result = errors.Join(result, h.listener.Close())
		h.listener = nil
	}
	if h.hookDirectory != nil {
		result = errors.Join(result, closeAPKExecutionDirectory(h.hookDirectory))
		h.hookDirectory = nil
	}
	return result
}

func configureAPKHookConnection(conn *net.UnixConn) error {
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var result error
	err = raw.Control(func(fd uintptr) { result = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_PASSCRED, 1) })
	return errors.Join(err, result, conn.SetDeadline(time.Now().Add(apkNativeHookTimeout)))
}

// Per-message SCM_CREDENTIALS identifies the actual sender. SO_PEERCRED alone
// identifies the socket creator and would not reject a transferred descriptor.
func readAPKHookPacket(conn *net.UnixConn) (apkNativeHookPacket, *unix.Ucred, error) {
	var empty apkNativeHookPacket
	data := make([]byte, 4096)
	control := make([]byte, unix.CmsgSpace(unix.SizeofUcred))
	n, oob, flags, _, err := conn.ReadMsgUnix(data, control)
	if err != nil {
		return empty, nil, err
	}
	if n == 0 || flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 {
		return empty, nil, errors.New("APK hook packet is incomplete or excessive")
	}
	messages, err := unix.ParseSocketControlMessage(control[:oob])
	if err != nil || len(messages) != 1 {
		return empty, nil, errors.New("APK hook packet lacks exact kernel credentials")
	}
	credentials, err := unix.ParseUnixCredentials(&messages[0])
	if err != nil {
		return empty, nil, err
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		return empty, nil, err
	}
	var peer *unix.Ucred
	var peerErr error
	err = raw.Control(func(fd uintptr) { peer, peerErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) })
	if err != nil || peerErr != nil || peer == nil || *peer != *credentials {
		return empty, nil, errors.New("APK hook sender differs from socket creator")
	}
	if err := decodeAPKTransitionJSON(data[:n], &empty); err != nil {
		return empty, nil, err
	}
	return empty, credentials, nil
}

func writeAPKHookPacket(conn *net.UnixConn, packet apkNativeHookPacket) error {
	data, err := apkExecutionJSON(packet)
	if err != nil {
		return err
	}
	n, err := conn.Write(data)
	if err != nil {
		return err
	}
	if n != len(data) {
		return io.ErrShortWrite
	}
	return nil
}

func (h *apkTransitionHandoff) serve(ctx context.Context, child apkNativeProcess) error {
	for _, phase := range []string{"pre-commit", "pre-upgrade", "post-upgrade", "post-commit"} {
		conn, err := h.listener.AcceptUnix()
		if err != nil {
			return err
		}
		err = configureAPKHookConnection(conn)
		if err == nil {
			err = h.authorize(ctx, conn, child, phase)
		}
		if err != nil {
			// A package hook failure does not veto APK unpacking. Stop our
			// unreaped native child before releasing the rejected helper.
			err = errors.Join(err, stopAPKNativeChild(child.PID))
		}
		err = errors.Join(err, conn.Close())
		if err != nil {
			return err
		}
		h.phases++
	}
	return nil
}

func (h *apkTransitionHandoff) authorize(ctx context.Context, conn *net.UnixConn, child apkNativeProcess, phase string) error {
	stop := context.AfterFunc(ctx, func() {
		// Cancellation must not release a failed package hook before APK stops.
		_ = stopAPKNativeChild(child.PID)
		_ = conn.Close()
	})
	defer stop()
	request, credentials, err := readAPKHookPacket(conn)
	if err != nil {
		return err
	}
	if request.Schema != apkNativeHandoffSchema || request.PlanSHA256 != h.record.PlanSHA256 || request.HandoffSHA256 != h.digest || request.Phase != phase || request.Status != "request" || int64(credentials.Uid) != int64(os.Geteuid()) || int64(credentials.Gid) != int64(os.Getegid()) {
		return errors.New("APK native hook request differs from approved handoff")
	}
	helper, err := observeAPKNativeProcess(ctx, int(credentials.Pid))
	if err != nil {
		return err
	}
	native, err := observeAPKNativeProcess(ctx, child.PID)
	if err != nil {
		return err
	}
	if native != child || helper.ParentPID != child.PID {
		return errors.New("APK hook ancestry differs from the live native child")
	}
	if phase == "post-upgrade" {
		if helper.Executable.SHA256 != h.record.Helper.SHA256 {
			return errors.New("APK post-upgrade executing candidate bytes differ")
		}
		source, err := os.Lstat(filepath.Join(h.host, "opt/syswarden/bin/syswarden-cli"))
		if err != nil || !source.Mode().IsRegular() || apkTransitionStat(source.Sys().(*syscall.Stat_t)) != helper.Executable.Identity {
			return errors.New("APK post-upgrade process is not the installed candidate inode")
		}
		if err := h.postVerify(ctx); err != nil {
			return err
		}
	} else if helper.Executable != h.record.Helper {
		return errors.New("APK hook is not the retained authenticated helper")
	}
	if err := verifyAPKNativeHandoffAuthority(h.directory, h.record.PlanSHA256, h.record.ApprovalSHA256, true); err != nil {
		return err
	}
	if phase == "pre-commit" || phase == "pre-upgrade" {
		if err := h.Revalidate(ctx); err != nil {
			return err
		}
		if err := h.revalidate(); err != nil {
			return err
		}
	} else {
		// Native replacement may replace the known recovery script, but cannot
		// substitute this gate or introduce an unknown commit hook.
		currentHooks, err := captureAPKNativeHooksWithGate(ctx, h.host, &h.record.Hook)
		if err != nil {
			return err
		}
		// Production always binds this digest from authenticated candidate inventory.
		// Only the private transport oracle deliberately omits a product hook.
		if h.expectedRecoverySHA256 != "" {
			if err := verifyAPKPostHookInventory(currentHooks, h.expectedRecoverySHA256); err != nil {
				return err
			}
		}
	}
	again, err := observeAPKNativeProcess(ctx, helper.PID)
	if err != nil || again != helper {
		return errors.New("APK helper changed during native authorization")
	}
	databaseSHA := ""
	if phase == "post-commit" {
		database, err := captureAPKHookDatabase(ctx, h.host)
		if err != nil {
			return err
		}
		databaseSHA = apkTransitionDigest(database)
		if err := writeAPKTransitionBytes(h.directory, "native-post-commit-database.txt", database); err != nil {
			return err
		}
	}
	ack, err := apkExecutionJSON(apkNativeHookAcknowledgment{Request: request, Native: native, Helper: helper, DatabaseSHA256: databaseSHA})
	if err != nil {
		return err
	}
	if err := writeAPKTransitionBytes(h.directory, "native-hook-"+phase+".json", ack); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	request.Status = "continue"
	return writeAPKHookPacket(conn, request)
}

func (h *apkTransitionHandoff) run(ctx context.Context, command *exec.Cmd, output io.Writer) error {
	if h == nil || ctx == nil || command == nil {
		return errors.New("APK native transport is unavailable")
	}
	bounded, cancel := context.WithTimeout(ctx, packageInstallationTimeout)
	defer cancel()
	if err := h.Revalidate(bounded); err != nil {
		return err
	}
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	capture, err := prepareAPKNativeOutput(command, output)
	if err != nil {
		return err
	}
	defer func() { _ = capture.close() }()
	if err := command.Start(); err != nil {
		_ = capture.close()
		<-capture.done
		return err
	}
	if err := capture.write.Close(); err != nil {
		return finishAPKNativeProcess(bounded, command, capture, err)
	}
	waited := make(chan error, 1)
	// Keep the original leader unreaped until handoff processing has stopped.
	// This prevents process identity checks from accepting a reused numeric PID.
	child, observeErr := observeAPKNativeProcess(bounded, command.Process.Pid)
	if observeErr == nil {
		info, err := os.Stat(command.Path)
		if err != nil || apkTransitionStat(info.Sys().(*syscall.Stat_t)) != child.Executable.Identity {
			observeErr = errors.New("APK child differs from the selected native executable")
		}
	}
	if observeErr == nil {
		raw, err := apkExecutionJSON(child)
		observeErr = err
		if err == nil {
			observeErr = writeAPKTransitionBytes(h.directory, "native-child.json", raw)
		}
	}
	served := make(chan error, 1)
	if observeErr == nil {
		go func() { served <- h.serve(bounded, child) }()
	} else {
		served <- observeErr
	}
	go func() {
		for {
			var status unix.Siginfo
			err := unix.Waitid(unix.P_PID, command.Process.Pid, &status, unix.WEXITED|unix.WNOWAIT, nil)
			if errors.Is(err, syscall.EINTR) {
				continue
			}
			waited <- err
			return
		}
	}()
	var runErr error
	var serviceErr error
	serviceDone := false
	select {
	case runErr = <-waited:
	case serviceErr = <-served:
		serviceDone = true
		if serviceErr != nil {
			cancel()
		}
		select {
		case runErr = <-waited:
		case <-bounded.Done():
			runErr = bounded.Err()
		}
	case <-bounded.Done():
		runErr = bounded.Err()
	}
	closeErr := h.listener.Close()
	if !serviceDone {
		grace := time.NewTimer(qualificationCommandTerminationGrace)
		select {
		case serviceErr = <-served:
		case <-bounded.Done():
			cancel()
			serviceErr = <-served
		case <-grace.C:
			cancel()
			serviceErr = <-served
		}
		if !grace.Stop() {
			select {
			case <-grace.C:
			default:
			}
		}
	}
	waitErr := finishAPKNativeProcess(bounded, command, capture, errors.Join(runErr, serviceErr))
	// No authority is inferred from a null/no-change transaction or exit zero.
	if h.phases != 4 {
		serviceErr = errors.Join(serviceErr, errors.New("APK did not complete all four exact native hook acknowledgments"))
	}
	if errors.Is(closeErr, net.ErrClosed) {
		closeErr = nil
	}
	h.listener = nil
	return errors.Join(runErr, serviceErr, waitErr, closeErr, bounded.Err())
}

func apkHandoffDigest(h *apkTransitionHandoff) string {
	if h == nil {
		return ""
	}
	return h.digest
}

// This is an observation under APK's commit lock, not acceptance of its content.
// The engine independently checks exact registration and unrelated package state.
func captureAPKHookDatabase(ctx context.Context, host string) (_ []byte, result error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(host)
	if err != nil {
		return nil, err
	}
	defer func() { result = errors.Join(result, root.Close()) }()
	file, err := root.OpenFile("lib/apk/db/installed", os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer func() { result = errors.Join(result, file.Close()) }()
	before, err := file.Stat()
	if err != nil {
		return nil, err
	}
	st, ok := before.Sys().(*syscall.Stat_t)
	if !ok || !before.Mode().IsRegular() || before.Mode().Perm()&0022 != 0 || st.Nlink != 1 || before.Size() <= 0 || before.Size() > maximumAPKInstalledDatabaseSize || int64(st.Uid) != int64(os.Geteuid()) || int64(st.Gid) != int64(os.Getegid()) {
		return nil, errors.New("APK post-commit database metadata is unsafe")
	}
	data, err := io.ReadAll(io.LimitReader(file, maximumAPKInstalledDatabaseSize+1))
	if err != nil || int64(len(data)) != before.Size() {
		return nil, errors.New("APK post-commit database observation was incomplete")
	}
	after, err := root.Lstat("lib/apk/db/installed")
	if err != nil || apkTransitionStat(after.Sys().(*syscall.Stat_t)) != apkTransitionStat(st) {
		return nil, errors.New("APK post-commit database changed during observation")
	}
	return data, ctx.Err()
}

func verifyAPKPostHookInventory(hooks *apkNativeHookProposal, expected string) error {
	if hooks == nil || !validSHA256(expected) {
		return errors.New("APK selected recovery hook binding is unavailable")
	}
	found := 0
	for _, entry := range hooks.Entries {
		if entry.Path == apkTransitionGateDirectory+"/syswarden-recovery" {
			found++
			if entry.Absent || apkTransitionDigest(entry.Content) != expected {
				return errors.New("APK recovery hook differs from the authenticated selected candidate")
			}
		}
	}
	if found != 1 {
		return errors.New("APK selected recovery hook is missing or duplicated")
	}
	return nil
}
