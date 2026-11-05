//go:build linux

package system

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// This opt-in test is a transport oracle only. The inert fixture archives are
// deliberately not a product release, and the manual custody below does not
// qualify candidate authentication, lifecycle effects or complete removal.
func TestAPKNativeTransportOracle(t *testing.T) {
	if os.Getenv("SYSWARDEN_APK_HANDOFF_NATIVE_ORACLE") != "1" {
		t.Skip("requires an explicitly isolated inert native APK transport fixture")
	}
	if runtime.GOARCH != "amd64" || os.Geteuid() != 0 || os.Getegid() != 0 || os.Getpid() <= 1 {
		t.Fatal("native transport oracle requires a rootless-container AMD64 child process")
	}
	marker, err := os.ReadFile("/tmp/sw-apk-native-oracle/ALLOW-INERT-APK-HANDOFF")
	if err != nil || string(marker) != "syswarden-apk-transport-oracle-v1\n" {
		t.Fatal("native transport fixture marker absent")
	}
	if info, err := os.Lstat("/run/.containerenv"); err != nil || !info.Mode().IsRegular() {
		t.Fatal("native transport oracle must run in its disposable container")
	}
	kind := os.Getenv("SYSWARDEN_APK_HANDOFF_NATIVE_CASE")
	if kind != "success" && kind != "no-change" && kind != "orphaned" && kind != "wrong-ancestry" {
		t.Fatal("unknown native transport oracle case")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 75*time.Second)
	defer cancel()
	runSetup := func(arguments ...string) {
		t.Helper()
		command := exec.CommandContext(ctx, "/sbin/apk", arguments...) // #nosec G204 -- opt-in disposable-container oracle uses only fixed offline APK setup arguments and inert fixture archives
		command.Env = nativeRetentionEnvironment()
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("inert APK setup failed: %v\n%s", err, output)
		}
	}
	runSetup("--no-network", "--allow-untrusted", "add", "/tmp/sw-apk-native-oracle/old.apk")
	if kind == "no-change" {
		runSetup("--no-network", "--allow-untrusted", "--no-scripts", "add", "/tmp/sw-apk-native-oracle/candidate.apk")
	}
	if err := os.MkdirAll("/etc/apk/commit_hooks.d", 0755); err != nil { // #nosec G301 -- opt-in disposable-container oracle models the fixed native public hook directory
		t.Fatal(err)
	}
	if err := os.MkdirAll(apkTransitionRoot, 0700); err != nil {
		t.Fatal(err)
	}
	helperBytes, err := os.ReadFile("/tmp/sw-apk-native-oracle/helper")
	if err != nil {
		t.Fatal(err)
	}
	helperSHA := apkTransitionDigest(helperBytes)
	proposal, err := captureAPKNativeHooks(ctx, "/")
	if err != nil {
		t.Fatal(err)
	}
	hooksRaw, _ := apkExecutionJSON(proposal)
	plan := apkExecutionPlan{Schema: apkExecutionSchema, EffectPlanSHA256: strings.Repeat("e", 64), CandidateCLISHA256: helperSHA, NativeHooks: proposal, NativeHooksSHA256: apkTransitionDigest(hooksRaw)}
	raw, err := apkExecutionJSON(plan)
	if err != nil {
		t.Fatal(err)
	}
	digest := apkTransitionDigest(raw)
	path := filepath.Join(apkTransitionRoot, "execution-"+digest)
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	directory, err := openExistingPinnedServiceDirectory(path)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.close()
	if err := writeAPKTransitionBytes(directory, "execution-plan.json", raw); err != nil {
		t.Fatal(err)
	}
	approval := apkExecutionApproval{apkExecutionSchema, "explicit-native-execution", digest, plan.EffectPlanSHA256}
	raw, _ = apkExecutionJSON(approval)
	approved := apkTransitionDigest(raw)
	if err := writeAPKTransitionBytes(directory, "execution-approval.json", raw); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, apkExecutionHelper), helperBytes, 0700); err != nil { // #nosec G306 G703 -- opt-in disposable-container custody uses a digest-derived directory and fixed helper basename with executable0700 metadata
		t.Fatal(err)
	}
	helper, err := openAPKExecutionHelper(directory, helperSHA)
	if err != nil {
		t.Fatal(err)
	}
	info, err := helper.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if err := helper.Close(); err != nil {
		t.Fatal(err)
	}
	coordinator, err := observeAPKNativeProcess(ctx, os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	parent, err := openAPKTransitionRoot(apkTransitionRoot, false)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.close()
	hookDirectory, err := openExistingPinnedServiceDirectory("/etc/apk/commit_hooks.d")
	if err != nil {
		t.Fatal(err)
	}
	h := &apkTransitionHandoff{host: "/", directory: directory, parent: parent, hookDirectory: hookDirectory, revalidate: func() error { return ctx.Err() }, postVerify: func(check context.Context) error {
		data, err := os.ReadFile("/opt/syswarden/bin/syswarden-cli")
		if err != nil {
			return err
		}
		if apkTransitionDigest(data) != helperSHA {
			return fmt.Errorf("installed helper differs")
		}
		return check.Err()
	}}
	defer h.Close()
	h.record = apkNativeHandoffRecord{Schema: apkNativeHandoffSchema, PlanSHA256: digest, ApprovalSHA256: approved, Helper: nativeActivationRuntimeFile{apkTransitionStat(info.Sys().(*syscall.Stat_t)), helperSHA}, Coordinator: coordinator}
	body, err := apkTransitionGateBytes(digest)
	if err != nil {
		t.Fatal(err)
	}
	activeBody := body
	if kind == "wrong-ancestry" {
		// Keep an intervening shell alive so kernel credentials and helper
		// bytes match, but the helper is not the actual APK child's direct child.
		activeBody = bytes.Replace(body, []byte("exec \"$helper\""), []byte("\"$helper\""), 1)
		activeBody = append(activeBody, []byte("status=$?\nexit \"$status\"\n")...)
	}
	if err := os.WriteFile(filepath.Join(apkTransitionRoot, "active-hook"), activeBody, 0700); err != nil { // #nosec G306 -- opt-in disposable-container oracle creates only the fixed private executable dispatcher
		t.Fatal(err)
	}
	if err := os.WriteFile("/etc/apk/commit_hooks.d/"+apkTransitionGateName, body, 0755); err != nil { // #nosec G306 -- opt-in disposable-container oracle models the exact native executable0755 commit gate
		t.Fatal(err)
	}
	h.record.Active, err = readAPKNativeHookMode(parent.root, "active-hook", 0700)
	if err != nil {
		t.Fatal(err)
	}
	h.record.Hook, err = readAPKNativeHook(hookDirectory.root, apkTransitionGateName)
	if err != nil {
		t.Fatal(err)
	}
	h.hooks, err = captureAPKNativeHooksWithGate(ctx, "/", &h.record.Hook)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ = apkExecutionJSON(h.record)
	h.digest = apkTransitionDigest(raw)
	if err := writeAPKTransitionBytes(directory, "native-handoff.json", raw); err != nil {
		t.Fatal(err)
	}
	raw, _ = apkExecutionJSON(apkExecutionEvent{Schema: apkExecutionSchema, State: "native-started", PlanSHA256: digest, ApprovalSHA256: approved})
	if err := writeAPKTransitionBytes(directory, "native-started.json", raw); err != nil {
		t.Fatal(err)
	}
	socket := fmt.Sprintf("/proc/self/fd/%d/%s", directory.fd, apkNativeSocketName)
	h.listener, err = net.ListenUnix("unixpacket", &net.UnixAddr{Name: socket, Net: "unixpacket"})
	if err != nil {
		t.Fatal(err)
	}
	h.listener.SetUnlinkOnClose(false)
	control, err := h.listener.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var optionErr error
	if err := control.Control(func(fd uintptr) { optionErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_PASSCRED, 1) }); err != nil || optionErr != nil {
		t.Fatal(err, optionErr)
	}
	if err := directory.root.Chmod(apkNativeSocketName, 0600); err != nil {
		t.Fatal(err)
	}
	overlay, err := openAPKExecutionOverlay()
	if err != nil {
		t.Fatal(err)
	}
	defer overlay.Close()
	command := exec.Command("/sbin/apk", "--no-network", "--allow-untrusted", "--overlay-from-stdin", "add", "/tmp/sw-apk-native-oracle/candidate.apk")
	command.Env = nativeRetentionEnvironment()
	command.Stdin = overlay
	var output bytes.Buffer
	command.Stdout = &output
	command.Stderr = &output
	if kind == "orphaned" {
		if err := h.Close(); err != nil {
			t.Fatal(err)
		}
		err = runQualificationProcessGroup(ctx, command)
		if err == nil {
			t.Fatal("orphaned fixed gate allowed a native upgrade")
		}
		database, readErr := os.ReadFile("/lib/apk/db/installed")
		if readErr != nil || !bytes.Contains(database, []byte("P:syswarden-apk-transport-oracle\nV:1.0.0-r0\n")) {
			t.Fatal("orphaned gate failed to preserve old registration", readErr)
		}
	} else {
		err = h.run(ctx, command, &output)
		if kind == "success" && err != nil {
			currentHooks, captureErr := captureAPKNativeHooksWithGate(context.Background(), "/", &h.record.Hook)
			t.Logf("failed native inventory capture: %v", captureErr)
			if captureErr == nil {
				for _, original := range h.hooks.Entries {
					for _, current := range currentHooks.Entries {
						if current.Path == original.Path && !reflect.DeepEqual(current, original) {
							t.Logf("native inventory delta path=%s original=%+v current=%+v", original.Path, original.Identity, current.Identity)
						}
					}
				}
			}
			t.Fatalf("native handoff failed: %v\n%s", err, output.Bytes())
		}
		if kind == "no-change" && err == nil {
			t.Fatal("null/no-change native transaction accepted without every required phase")
		}
		if kind == "wrong-ancestry" {
			if err == nil || !strings.Contains(err.Error(), "APK hook ancestry differs") || h.phases != 1 {
				t.Fatalf("wrong helper ancestry was not rejected before package replacement: phases=%d err=%v\n%s", h.phases, err, output.Bytes())
			}
			database, readErr := os.ReadFile("/lib/apk/db/installed")
			if readErr != nil || !bytes.Contains(database, []byte("P:syswarden-apk-transport-oracle\nV:1.0.0-r0\n")) {
				t.Fatal("wrong-ancestry refusal failed to preserve old registration", readErr)
			}
			current, readErr := os.ReadFile("/opt/syswarden/bin/syswarden-cli")
			if readErr != nil || apkTransitionDigest(current) != coordinator.Executable.SHA256 {
				t.Fatal("wrong-ancestry refusal replaced the original runtime", readErr)
			}
		}
		if kind == "success" {
			for _, phase := range []string{"pre-commit", "pre-upgrade", "post-upgrade", "post-commit"} {
				data, err := readAPKTransitionBytes(directory, "native-hook-"+phase+".json", 16384)
				if err != nil {
					t.Fatal(err)
				}
				var ack apkNativeHookAcknowledgment
				if err := decodeAPKTransitionJSON(data, &ack); err != nil {
					t.Fatal(err)
				}
				if phase == "post-commit" {
					visible, err := readAPKTransitionBytes(directory, "native-post-commit-database.txt", maximumAPKInstalledDatabaseSize)
					if err != nil || apkTransitionDigest(visible) != ack.DatabaseSHA256 || !bytes.Contains(visible, []byte("P:syswarden-apk-transport-oracle\nV:2.0.0-r0\n")) {
						t.Fatal("candidate registration was not visible inside post-commit hook", err)
					}
				}
				if ack.Request.Phase != phase || ack.Helper.ParentPID != ack.Native.PID || ack.Helper.Executable.SHA256 != helperSHA {
					t.Fatal("native phase lacks exact helper ancestry and bytes")
				}
			}
			database, err := os.ReadFile("/lib/apk/db/installed")
			if err != nil || !bytes.Contains(database, []byte("P:syswarden-apk-transport-oracle\nV:2.0.0-r0\n")) {
				t.Fatal("native committed candidate registration missing", err)
			}
		}
	}
	if _, err := os.Lstat("/etc/apk/commit_hooks.d/" + apkTransitionGateName); err != nil {
		t.Fatal("transport discarded persistent gate", err)
	}
	t.Logf("native_transport_case=%s acknowledged_phases=%d product_accepted=false", kind, h.phases)
	t.Log(output.String())
}
