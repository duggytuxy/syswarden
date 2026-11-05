//go:build linux

package system

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
)

func verifyAPKNativeHandoffAuthority(directory *pinnedServiceDirectory, digest, approvalSHA string, started bool) error {
	if directory == nil || !validSHA256(digest) || !validSHA256(approvalSHA) {
		return errors.New("APK native authority is unavailable")
	}
	raw, err := readAPKTransitionBytes(directory, "execution-plan.json", 1<<20)
	if err != nil {
		return err
	}
	var plan apkExecutionPlan
	if err := decodeAPKTransitionJSON(raw, &plan); err != nil {
		return err
	}
	if apkTransitionDigest(raw) != digest || plan.Schema != apkExecutionSchema || plan.ProductAccepted {
		return errors.New("APK execution plan binding changed")
	}
	raw, err = readAPKTransitionBytes(directory, "execution-approval.json", 4096)
	if err != nil {
		return err
	}
	var approval apkExecutionApproval
	if err := decodeAPKTransitionJSON(raw, &approval); err != nil {
		return err
	}
	if apkTransitionDigest(raw) != approvalSHA || approval.Schema != apkExecutionSchema || approval.Purpose != "explicit-native-execution" || approval.ExecutionPlanSHA256 != digest || approval.EffectPlanSHA256 != plan.EffectPlanSHA256 {
		return errors.New("APK exact execution approval changed")
	}
	for _, name := range []string{"unresolved.json", "pre-dispatch-refused.json", "completed.json"} {
		if _, err := directory.root.Lstat(name); err == nil || !errors.Is(err, os.ErrNotExist) {
			return errors.New("APK native hook refuses terminal or unresolved execution debt")
		}
	}
	if started {
		raw, err = readAPKTransitionBytes(directory, "native-started.json", 4096)
		if err != nil {
			return err
		}
		var event apkExecutionEvent
		if err := decodeAPKTransitionJSON(raw, &event); err != nil {
			return err
		}
		if event.Schema != apkExecutionSchema || event.State != "native-started" || event.PlanSHA256 != digest || event.ApprovalSHA256 != approvalSHA || event.ProductAccepted {
			return errors.New("APK native start intent differs from approval")
		}
	}
	return nil
}

func validAPKHookPhase(phase string) bool {
	switch phase {
	case "pre-commit", "pre-upgrade", "post-upgrade", "post-commit":
		return true
	}
	return false
}

// RunAPKTransitionHook is restricted transport ingress. A matching receipt or
// root caller alone cannot release a transaction: the live coordinator checks
// kernel message credentials, exact executing bytes and native parent identity.
// This operation never invokes install, reload, discovery or a package manager.
func RunAPKTransitionHook(ctx context.Context, executionPlanSHA256, phase string) error {
	if os.Geteuid() != 0 || os.Getegid() != 0 {
		return errors.New("APK native hook requires root custody")
	}
	return runAPKTransitionHookAt(ctx, "/", executionPlanSHA256, phase)
}

func runAPKTransitionHookAt(ctx context.Context, host, digest, phase string) (result error) {
	if ctx == nil || !validSHA256(digest) || !validAPKHookPhase(phase) {
		return errors.New("APK native hook requires an exact execution digest and compiled phase")
	}
	bounded, cancel := context.WithTimeout(ctx, apkNativeHookTimeout)
	defer cancel()
	if err := bounded.Err(); err != nil {
		return err
	}
	parent, err := openAPKTransitionRoot(filepath.Join(host, apkTransitionRoot), false)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, closeAPKExecutionDirectory(parent)) }()
	path := filepath.Join(host, apkTransitionRoot, "execution-"+digest)
	directory, err := openExistingPinnedServiceDirectory(path)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, closeAPKExecutionDirectory(directory)) }()
	info, err := directory.file.Stat()
	if err != nil || info.Mode() != os.ModeDir|0700 {
		return errors.New("APK native hook custody is not private")
	}
	raw, err := readAPKTransitionBytes(directory, "native-handoff.json", 16384)
	if err != nil {
		return err
	}
	var record apkNativeHandoffRecord
	if err := decodeAPKTransitionJSON(raw, &record); err != nil {
		return err
	}
	if record.Schema != apkNativeHandoffSchema || record.PlanSHA256 != digest || !validSHA256(record.ApprovalSHA256) || !validSHA256(record.Helper.SHA256) {
		return errors.New("APK retained handoff record is malformed")
	}
	if err := verifyAPKNativeHandoffAuthority(directory, digest, record.ApprovalSHA256, true); err != nil {
		return err
	}
	current, err := observeAPKNativeProcess(bounded, os.Getpid())
	if err != nil {
		return err
	}
	if phase != "post-upgrade" && current.Executable != record.Helper {
		return errors.New("APK hook is not the exact retained candidate helper")
	}
	if phase == "post-upgrade" && current.Executable.SHA256 != record.Helper.SHA256 {
		return errors.New("APK post-upgrade hook is not the authenticated candidate")
	}
	server, err := observeAPKNativeProcess(bounded, record.Coordinator.PID)
	if err != nil || !sameAPKCoordinatorProcess(server, record.Coordinator, phase) {
		return errors.New("APK hook coordinator is no longer the original live process")
	}
	socket := fmt.Sprintf("/proc/self/fd/%d/%s", directory.fd, apkNativeSocketName)
	dialer := net.Dialer{Timeout: apkNativeHookTimeout}
	connected, err := dialer.DialContext(bounded, "unixpacket", socket)
	if err != nil {
		return fmt.Errorf("APK commit remains refused without its original coordinator: %w", err)
	}
	conn, ok := connected.(*net.UnixConn)
	if !ok {
		_ = connected.Close()
		return errors.New("APK transport is not a local credential socket")
	}
	defer func() { result = errors.Join(result, conn.Close()) }()
	stop := context.AfterFunc(bounded, func() { _ = conn.Close() })
	defer stop()
	if err := configureAPKHookConnection(conn); err != nil {
		return err
	}
	request := apkNativeHookPacket{apkNativeHandoffSchema, digest, apkTransitionDigest(raw), phase, "request"}
	if err := writeAPKHookPacket(conn, request); err != nil {
		return err
	}
	response, credentials, err := readAPKHookPacket(conn)
	if err != nil {
		return err
	}
	request.Status = "continue"
	if response != request || int(credentials.Pid) != record.Coordinator.PID || int64(credentials.Uid) != int64(os.Geteuid()) || int64(credentials.Gid) != int64(os.Getegid()) {
		return errors.New("APK hook response is not from the exact coordinator")
	}
	server, err = observeAPKNativeProcess(bounded, record.Coordinator.PID)
	if err != nil || !sameAPKCoordinatorProcess(server, record.Coordinator, phase) {
		return errors.New("APK coordinator changed during authorization")
	}
	return bounded.Err()
}
