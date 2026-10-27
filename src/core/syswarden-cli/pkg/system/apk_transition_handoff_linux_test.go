//go:build linux

package system

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func apkHookInventoryFixture(t *testing.T) string {
	t.Helper()
	host := t.TempDir()
	for _, path := range []string{"etc/apk/commit_hooks.d", "lib/apk"} {
		if err := os.MkdirAll(filepath.Join(host, path), 0700); err != nil {
			t.Fatal(err)
		}
	}
	return host
}

func TestAPKNativeHooksRejectUnreviewedInventory(t *testing.T) {
	for _, kind := range []string{"unknown", "known-name-wrong-bytes", "symlink", "writable-directory", "directory-drift", "cancelled"} {
		t.Run(kind, func(t *testing.T) {
			host := apkHookInventoryFixture(t)
			proposal, err := captureAPKNativeHooks(t.Context(), host)
			if err != nil {
				t.Fatal(err)
			}
			dir := filepath.Join(host, apkTransitionGateDirectory)
			switch kind {
			case "unknown":
				err = os.WriteFile(filepath.Join(dir, "administrator-hook"), []byte("#!/bin/sh\nexit 0\n"), 0755) // #nosec G306 -- private temporary unknown-hook fixture intentionally models executable0755 metadata
			case "known-name-wrong-bytes":
				err = os.WriteFile(filepath.Join(dir, "syswarden-recovery"), []byte("#!/bin/sh\nexit 0\n"), 0755) // #nosec G306 -- private temporary wrong-byte hook fixture intentionally models executable0755 metadata
			case "symlink":
				err = os.Symlink("/dev/null", filepath.Join(dir, "syswarden-recovery"))
			case "writable-directory":
				err = os.Chmod(dir, 0777) // #nosec G302 -- private temporary directory is deliberately writable to verify refusal
			case "directory-drift":
				err = os.Chmod(dir, 0755) // #nosec G302 -- private temporary directory mode deliberately drifts after capture
			}
			if err != nil {
				t.Fatal(err)
			}
			ctx := t.Context()
			if kind == "cancelled" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if err := revalidateAPKNativeHookProposal(ctx, host, proposal); err == nil {
				t.Fatal("unapproved hook inventory or cancelled review was adopted")
			}
		})
	}
}

func TestAPKNativeProcessStatRejectsAmbiguity(t *testing.T) {
	fields := append([]string{"R", "17"}, make([]string, 18)...)
	for i := 2; i < len(fields); i++ {
		fields[i] = "0"
	}
	fields[19] = "1234"
	valid := []byte("42 (name with ) parentheses) " + strings.Join(fields, " ") + "\n")
	parent, start, err := parseAPKNativeProcessStat(valid, 42)
	if err != nil || parent != 17 || start != 1234 {
		t.Fatal(parent, start, err)
	}
	for _, raw := range []string{string(valid[:8]), strings.Replace(string(valid), "42 (", "43 (", 1), strings.Replace(string(valid), ") R ", ") Z ", 1), strings.Replace(string(valid), "1234", "0", 1), strings.Repeat("x", 8193)} {
		if _, _, err := parseAPKNativeProcessStat([]byte(raw), 42); err == nil {
			t.Fatal("invalid process identity accepted")
		}
	}
}

func TestAPKNativeProcessObservesActualExecutable(t *testing.T) {
	first, err := observeAPKNativeProcess(t.Context(), os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	second, err := observeAPKNativeProcess(t.Context(), os.Getpid())
	if err != nil || first != second || first.ParentPID <= 0 || !validSHA256(first.Executable.SHA256) {
		t.Fatal("live executable identity was not stable", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := observeAPKNativeProcess(ctx, os.Getpid()); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled process observation accepted", err)
	}
}

func TestAPKNativeHookPacketsRequireActualKernelCredentials(t *testing.T) {
	for _, kind := range []string{"valid", "oversized", "noncanonical", "file-descriptor-control"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			root, err := openExistingPinnedServiceDirectory(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer root.close()
			socket := fmt.Sprintf("/proc/self/fd/%d/sock", root.fd)
			listener, err := net.ListenUnix("unixpacket", &net.UnixAddr{Name: socket, Net: "unixpacket"})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			conn, err := net.DialUnix("unixpacket", nil, &net.UnixAddr{Name: socket, Net: "unixpacket"})
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			accepted, err := listener.AcceptUnix()
			if err != nil {
				t.Fatal(err)
			}
			defer accepted.Close()
			if err := configureAPKHookConnection(accepted); err != nil {
				t.Fatal(err)
			}
			request := apkNativeHookPacket{apkNativeHandoffSchema, strings.Repeat("a", 64), strings.Repeat("b", 64), "pre-commit", "request"}
			data, err := apkExecutionJSON(request)
			if err != nil {
				t.Fatal(err)
			}
			var control []byte
			switch kind {
			case "oversized":
				data = make([]byte, 8192)
			case "noncanonical":
				data = append(data, ' ')
			case "file-descriptor-control":
				control = unix.UnixRights(root.fd)
			}
			if _, _, err := conn.WriteMsgUnix(data, control, nil); err != nil {
				t.Fatal(err)
			}
			got, credentials, err := readAPKHookPacket(accepted)
			if kind == "valid" {
				if err != nil || got != request || int64(credentials.Pid) != int64(os.Getpid()) {
					t.Fatal("valid kernel-bound packet rejected", err)
				}
			} else if err == nil {
				t.Fatal("ambiguous packet accepted")
			}
		})
	}
}

func apkHookAuthorityFixture(t *testing.T) (*pinnedServiceDirectory, string, string) {
	t.Helper()
	directory, err := openExistingPinnedServiceDirectory(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(directory.close)
	plan := apkExecutionPlan{Schema: apkExecutionSchema, EffectPlanSHA256: strings.Repeat("a", 64)}
	raw, err := apkExecutionJSON(plan)
	if err != nil {
		t.Fatal(err)
	}
	digest := apkTransitionDigest(raw)
	if err := writeAPKTransitionBytes(directory, "execution-plan.json", raw); err != nil {
		t.Fatal(err)
	}
	approval := apkExecutionApproval{apkExecutionSchema, "explicit-native-execution", digest, plan.EffectPlanSHA256}
	raw, err = apkExecutionJSON(approval)
	if err != nil {
		t.Fatal(err)
	}
	approved := apkTransitionDigest(raw)
	if err := writeAPKTransitionBytes(directory, "execution-approval.json", raw); err != nil {
		t.Fatal(err)
	}
	return directory, digest, approved
}

func TestAPKNativeHookRequiresExactApprovalAndStartedState(t *testing.T) {
	for _, kind := range []string{"valid", "missing-start", "wrong-plan", "wrong-approval", "wrong-start", "unresolved", "completed", "refused"} {
		t.Run(kind, func(t *testing.T) {
			directory, digest, approved := apkHookAuthorityFixture(t)
			event := apkExecutionEvent{Schema: apkExecutionSchema, State: "native-started", PlanSHA256: digest, ApprovalSHA256: approved}
			if kind == "wrong-start" {
				event.ApprovalSHA256 = strings.Repeat("f", 64)
			}
			if kind != "missing-start" {
				raw, _ := apkExecutionJSON(event)
				if err := writeAPKTransitionBytes(directory, "native-started.json", raw); err != nil {
					t.Fatal(err)
				}
			}
			switch kind {
			case "wrong-plan":
				digest = strings.Repeat("e", 64)
			case "wrong-approval":
				approved = strings.Repeat("e", 64)
			case "unresolved", "completed", "refused":
				name := kind
				if kind == "refused" {
					name = "pre-dispatch-refused"
				}
				if err := writeAPKTransitionBytes(directory, name+".json", []byte("{}\n")); err != nil {
					t.Fatal(err)
				}
			}
			err := verifyAPKNativeHandoffAuthority(directory, digest, approved, true)
			if (err == nil) != (kind == "valid") {
				t.Fatal("wrong native authority outcome", err)
			}
		})
	}
}

func TestAPKNativeGateIsLiteralAndNeverUsesEnvironmentAuthority(t *testing.T) {
	digest := strings.Repeat("a", 64)
	body, err := apkTransitionGateBytes(digest)
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"execution-" + digest + "/candidate-helper", "post-upgrade) helper=/opt/syswarden/bin/syswarden-cli", "--execution-plan " + digest} {
		if !strings.Contains(string(body), required) {
			t.Fatal("fixed dispatch binding missing", required)
		}
	}
	for _, bad := range []string{"", strings.Repeat("A", 64), "$(touch /tmp/unapproved)"} {
		if _, err := apkTransitionGateBytes(bad); err == nil {
			t.Fatal("noncanonical execution digest accepted")
		}
	}
	for _, phase := range []string{"install", "reload", "fresh", "", "pre-commit post-commit"} {
		if validAPKHookPhase(phase) {
			t.Fatal("unbounded phase accepted", phase)
		}
	}
}

func TestAPKNativePostHookRequiresExactSelectedCandidate(t *testing.T) {
	selected := []byte("selected bounded recovery script\n")
	for _, kind := range []string{"exact", "historical", "missing", "duplicate", "absent"} {
		t.Run(kind, func(t *testing.T) {
			entry := apkTransitionHostEntry{Path: apkTransitionGateDirectory + "/syswarden-recovery", Content: selected}
			proposal := &apkNativeHookProposal{Entries: []apkTransitionHostEntry{entry}}
			switch kind {
			case "historical":
				proposal.Entries[0].Content = []byte("recognized historical script\n")
			case "missing":
				proposal.Entries = nil
			case "duplicate":
				proposal.Entries = append(proposal.Entries, entry)
			case "absent":
				proposal.Entries[0].Absent = true
			}
			if err := verifyAPKPostHookInventory(proposal, apkTransitionDigest(selected)); (err == nil) != (kind == "exact") {
				t.Fatal("wrong selected-hook disposition", err)
			}
		})
	}
}

func TestAPKNativeCoordinatorAllowsOnlyPostReplacementUnlink(t *testing.T) {
	original := apkNativeProcess{PID: 41, ParentPID: 17, Start: 1234, Executable: nativeActivationRuntimeFile{SHA256: strings.Repeat("a", 64), Identity: apkTransitionIdentity{Device: 1, Inode: 2, Links: 1, Mode: 0100750, Size: 42, ModifiedSec: 5, ChangedSec: 6}}}
	for _, kind := range []string{"same", "unlink-after", "unlink-before", "inode", "pid", "start", "parent", "bytes", "uid", "mode", "size", "mtime", "ctime-only"} {
		t.Run(kind, func(t *testing.T) {
			current := original
			phase := "post-upgrade"
			if kind != "same" {
				current.Executable.Identity.Links = 0
				current.Executable.Identity.ChangedSec = 9
			}
			switch kind {
			case "unlink-before":
				phase = "pre-upgrade"
			case "inode":
				current.Executable.Identity.Inode++
			case "pid":
				current.PID++
			case "start":
				current.Start++
			case "parent":
				current.ParentPID++
			case "bytes":
				current.Executable.SHA256 = strings.Repeat("b", 64)
			case "uid":
				current.Executable.Identity.UID++
			case "mode":
				current.Executable.Identity.Mode = 0100700
			case "size":
				current.Executable.Identity.Size++
			case "mtime":
				current.Executable.Identity.ModifiedSec++
			case "ctime-only":
				current.Executable.Identity.Links = 1
			}
			if got := sameAPKCoordinatorProcess(current, original, phase); got != (kind == "same" || kind == "unlink-after") {
				t.Fatal("incorrect coordinator identity acceptance", kind, got)
			}
		})
	}
}
