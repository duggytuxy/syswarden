//go:build linux

package integration

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

type selinuxLifecycleRunnerCall struct {
	directory  string
	executable string
	arguments  []string
}

type fakeSELinuxLifecycleRunner struct {
	candidatePackage         []byte
	candidateIdentity        selinuxModuleIdentity
	baselinePackage          []byte
	baselineIdentity         selinuxModuleIdentity
	currentIdentity          selinuxModuleIdentity
	currentPackage           []byte
	currentExists            bool
	otherModules             []selinuxModuleIdentity
	calls                    []selinuxLifecycleRunnerCall
	listCalls                int
	failListAt               map[int]error
	failInstall              error
	failInstallAfterMutation error
	failRestoreAfterMutation error
	failRemove               error
	failRemoveAfterMutation  error
	ignoreRemove             bool
}

func selinuxLifecycleChecksum(character byte) string {
	return "sha256:" + strings.Repeat(string(character), 64)
}

func selinuxLifecycleIdentity(priority uint16, name string, checksumCharacter byte) selinuxModuleIdentity {
	return selinuxModuleIdentity{
		priority: priority,
		name:     name,
		language: "pp",
		enabled:  true,
		checksum: selinuxLifecycleChecksum(checksumCharacter),
	}
}

func renderFakeSELinuxModuleListing(identity selinuxModuleIdentity) string {
	state := ""
	if !identity.enabled {
		state = " disabled"
	}
	return fmt.Sprintf(
		"%d %s %s%s %s\n",
		identity.priority,
		identity.name,
		identity.language,
		state,
		identity.checksum,
	)
}

func (fake *fakeSELinuxLifecycleRunner) listing() []byte {
	var output strings.Builder
	for _, identity := range fake.otherModules {
		output.WriteString(renderFakeSELinuxModuleListing(identity))
	}
	if fake.currentExists {
		output.WriteString(renderFakeSELinuxModuleListing(fake.currentIdentity))
	}
	if output.Len() == 0 {
		output.WriteString("No modules.\n")
	}
	return []byte(output.String())
}

func fakeSELinuxArgumentValue(arguments []string, flag string) (string, bool) {
	for index := 0; index+1 < len(arguments); index++ {
		if arguments[index] == flag {
			return arguments[index+1], true
		}
	}
	return "", false
}

func (fake *fakeSELinuxLifecycleRunner) run(
	directory, executable string,
	arguments ...string,
) ([]byte, error) {
	fake.calls = append(fake.calls, selinuxLifecycleRunnerCall{
		directory:  directory,
		executable: executable,
		arguments:  append([]string(nil), arguments...),
	})
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory || !filepath.IsAbs(executable) {
		return nil, fmt.Errorf("test runner rejected non-absolute command input")
	}
	switch executable {
	case trustedCheckmodulePath:
		output, exists := fakeSELinuxArgumentValue(arguments, "-o")
		if !exists || !filepath.IsAbs(output) {
			return nil, fmt.Errorf("test checkmodule output path is not absolute")
		}
		if err := os.WriteFile(output, []byte("compiled test module\n"), 0600); err != nil {
			return nil, err
		}
		return nil, nil
	case trustedSemodulePackagePath:
		output, exists := fakeSELinuxArgumentValue(arguments, "-o")
		if !exists || !filepath.IsAbs(output) {
			return nil, fmt.Errorf("test semodule_package output path is not absolute")
		}
		if err := os.WriteFile(output, fake.candidatePackage, 0600); err != nil {
			return nil, err
		}
		return nil, nil
	case trustedSemodulePath:
	default:
		return nil, fmt.Errorf("unexpected executable %s", executable)
	}

	if slices.Equal(arguments, []string{"-lfull", "-m"}) {
		fake.listCalls++
		if failure := fake.failListAt[fake.listCalls]; failure != nil {
			return nil, failure
		}
		return fake.listing(), nil
	}
	if slices.Equal(arguments, []string{
		"-X", strconv.Itoa(rsyslogSELinuxModulePriority), "-H", "-E", rsyslogSELinuxModuleName,
	}) {
		if !fake.currentExists || len(fake.currentPackage) == 0 {
			return nil, fmt.Errorf("test extraction has no installed package")
		}
		path := filepath.Join(directory, rsyslogSELinuxModuleName+".pp")
		if err := os.WriteFile(path, fake.currentPackage, 0600); err != nil {
			return nil, err
		}
		return nil, nil
	}
	if len(arguments) == 4 && arguments[0] == "-X" &&
		arguments[1] == strconv.Itoa(rsyslogSELinuxModulePriority) && arguments[2] == "-i" {
		if fake.failInstall != nil {
			return nil, fake.failInstall
		}
		packagePath := arguments[3]
		if !filepath.IsAbs(packagePath) {
			return nil, fmt.Errorf("test install package path is not absolute")
		}
		content, err := os.ReadFile(packagePath) // #nosec G304 -- the production code supplied an attested private absolute path
		if err != nil {
			return nil, err
		}
		restoredBaseline := false
		switch {
		case bytes.Equal(content, fake.candidatePackage):
			fake.currentIdentity = fake.candidateIdentity
			fake.currentPackage = append([]byte(nil), fake.candidatePackage...)
		case bytes.Equal(content, fake.baselinePackage):
			restoredBaseline = true
			fake.currentIdentity = fake.baselineIdentity
			fake.currentPackage = append([]byte(nil), fake.baselinePackage...)
		default:
			return nil, fmt.Errorf("test install received an unknown package")
		}
		fake.currentExists = true
		if fake.failInstallAfterMutation != nil {
			return nil, fake.failInstallAfterMutation
		}
		if restoredBaseline && fake.failRestoreAfterMutation != nil {
			return nil, fake.failRestoreAfterMutation
		}
		return nil, nil
	}
	if slices.Equal(arguments, []string{
		"-X", strconv.Itoa(rsyslogSELinuxModulePriority), "-r", rsyslogSELinuxModuleName,
	}) {
		if fake.failRemove != nil {
			return nil, fake.failRemove
		}
		if !fake.ignoreRemove {
			fake.currentExists = false
			fake.currentIdentity = selinuxModuleIdentity{}
			fake.currentPackage = nil
		}
		if fake.failRemoveAfterMutation != nil {
			return nil, fake.failRemoveAfterMutation
		}
		return nil, nil
	}
	return nil, fmt.Errorf("unexpected semodule arguments %q", arguments)
}

func newSELinuxLifecycleFixture(
	t *testing.T,
	candidatePackage []byte,
) (string, string, uint32, uint32) {
	t.Helper()
	root := t.TempDir()
	parent := filepath.Join(root, "etc")
	workspace := filepath.Join(root, "workspace")
	if err := os.Mkdir(parent, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(workspace, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(workspace, rsyslogSELinuxModuleName+".te"),
		[]byte(rsyslogSELinuxPolicy),
		0600,
	); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(parent)
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("SELinux lifecycle fixture parent has no Linux stat metadata")
	}
	return workspace, parent, stat.Uid, stat.Gid
}

func syncSELinuxLifecycleDirectory(directory *os.File) error {
	return directory.Sync()
}

func allowSELinuxLifecycleMutation() error { return nil }

func recordSELinuxLifecycleProvenance(
	t *testing.T,
	parent string,
	uid, gid uint32,
	identity selinuxModuleIdentity,
) {
	t.Helper()
	directory, err := openWAFRsyslogDirectoryAt(parent, uid, gid)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	if err := recordSELinuxModuleProvenanceInDirectoryUsing(
		directory,
		uid,
		gid,
		identity,
		syncSELinuxLifecycleDirectory,
	); err != nil {
		t.Fatal(err)
	}
}

func readSELinuxLifecycleProvenance(
	t *testing.T,
	parent string,
	uid, gid uint32,
) selinuxModuleProvenance {
	t.Helper()
	directory, exists, err := openExistingOwnedArtifactDirectoryAt(
		parent,
		wafRsyslogDirectoryName,
		uid,
		gid,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !exists {
		return selinuxModuleProvenance{}
	}
	defer directory.Close()
	provenance, err := readSELinuxModuleProvenanceInDirectory(directory, uid, gid)
	if err != nil {
		t.Fatal(err)
	}
	return provenance
}

func countSELinuxLifecycleOperation(
	calls []selinuxLifecycleRunnerCall,
	want []string,
) int {
	count := 0
	for _, call := range calls {
		if call.executable == trustedSemodulePath && slices.Equal(call.arguments, want) {
			count++
		}
	}
	return count
}

func TestSELinuxModuleListingParsesCanonicalPrioritiesAndStates_SW2_PKG_001(t *testing.T) {
	operatorChecksum := selinuxLifecycleChecksum('a')
	targetChecksum := selinuxLifecycleChecksum('b')
	modules, err := parseSELinuxModuleListing([]byte(
		"1 operator_local pp " + operatorChecksum + "\n" +
			"001 operator_padded pp " + operatorChecksum + "\n" +
			"400 syswarden_rsyslog pp disabled " + targetChecksum + "\n",
	))
	if err != nil {
		t.Fatalf("parse real semodule full listing: %v", err)
	}
	if len(modules) != 3 || modules[0] != selinuxLifecycleIdentity(1, "operator_local", 'a') ||
		modules[1] != selinuxLifecycleIdentity(1, "operator_padded", 'a') {
		t.Fatalf("non-target priority 1 identity = %#v", modules)
	}
	wantTarget := selinuxLifecycleIdentity(400, rsyslogSELinuxModuleName, 'b')
	wantTarget.enabled = false
	if modules[2] != wantTarget {
		t.Fatalf("disabled target identity = %#v, want %#v", modules[2], wantTarget)
	}

	empty, err := parseSELinuxModuleListing([]byte("No modules.\n"))
	if err != nil || len(empty) != 0 {
		t.Fatalf("parse empty module store = %#v, %v", empty, err)
	}
}

func TestSELinuxModuleListingRejectsMalformedAndAmbiguousTarget_SW2_PKG_001(t *testing.T) {
	checksum := selinuxLifecycleChecksum('c')
	for name, listing := range map[string][]byte{
		"empty":               nil,
		"overpadded priority": []byte("0001 operator pp " + checksum + "\n"),
		"invalid state":       []byte("400 syswarden_rsyslog pp enabled " + checksum + "\n"),
		"invalid checksum":    []byte("400 syswarden_rsyslog pp sha256:abcd\n"),
		"contradictory empty": []byte("No modules.\n400 syswarden_rsyslog pp " + checksum + "\n"),
		"NUL":                 []byte("400 syswarden_rsyslog pp " + checksum + "\x00\n"),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseSELinuxModuleListing(listing); err == nil {
				t.Fatalf("malformed listing %q was accepted", listing)
			}
		})
	}
	identity := selinuxLifecycleIdentity(400, rsyslogSELinuxModuleName, 'c')
	if _, _, err := exactRsyslogSELinuxModule([]selinuxModuleIdentity{identity, identity}); err == nil {
		t.Fatal("duplicate exact target identities were accepted")
	}
}

func TestSELinuxModuleProvenanceIsCanonicalPrivateAndRejectsSymlink_SW2_PKG_001(t *testing.T) {
	identity := selinuxLifecycleIdentity(400, rsyslogSELinuxModuleName, 'd')
	want := []byte(
		rsyslogSELinuxProvenanceSchema + "\n" +
			"400\tsyswarden_rsyslog\tpp\tenabled\t" + identity.checksum + "\n",
	)
	rendered, err := renderSELinuxModuleProvenance(identity)
	if err != nil || !bytes.Equal(rendered, want) {
		t.Fatalf("canonical provenance = %q, %v", rendered, err)
	}
	parsed, err := parseSELinuxModuleProvenance(rendered)
	if err != nil || parsed != identity {
		t.Fatalf("parse canonical provenance = %#v, %v", parsed, err)
	}
	for name, content := range map[string][]byte{
		"unterminated": bytes.TrimSuffix(rendered, []byte("\n")),
		"extra line":   append(append([]byte(nil), rendered...), []byte("extra\n")...),
		"noncanonical": bytes.Replace(rendered, []byte("400\t"), []byte("0400\t"), 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseSELinuxModuleProvenance(content); err == nil {
				t.Fatalf("non-canonical provenance %q was accepted", content)
			}
		})
	}

	_, parent, uid, gid := newSELinuxLifecycleFixture(t, []byte("candidate"))
	recordSELinuxLifecycleProvenance(t, parent, uid, gid, identity)
	path := filepath.Join(parent, wafRsyslogDirectoryName, rsyslogSELinuxProvenanceName)
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	stat := info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 ||
		stat.Uid != uid || stat.Gid != gid || stat.Nlink != 1 {
		t.Fatalf("provenance metadata = mode %v uid:gid %d:%d nlink %d", info.Mode(), stat.Uid, stat.Gid, stat.Nlink)
	}
	if got, err := os.ReadFile(path); err != nil || !bytes.Equal(got, want) { // #nosec G304 -- fixture path is private and test-owned
		t.Fatalf("published provenance = %q, %v", got, err)
	}

	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(parent, "operator-target")
	operatorBytes := []byte("operator-owned bytes\n")
	if err := os.WriteFile(target, operatorBytes, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	directory, err := os.Open(filepath.Join(parent, wafRsyslogDirectoryName))
	if err != nil {
		t.Fatal(err)
	}
	_, readErr := readSELinuxModuleProvenanceInDirectory(directory, uid, gid)
	closeErr := directory.Close()
	if readErr == nil || closeErr != nil {
		t.Fatalf("symlinked provenance read = %v, close = %v", readErr, closeErr)
	}
	if got, err := os.ReadFile(target); err != nil || !bytes.Equal(got, operatorBytes) { // #nosec G304 -- fixture target is test-owned
		t.Fatalf("operator target changed = %q, %v", got, err)
	}
}

func publishSELinuxLifecycleWAFBridge(
	t *testing.T,
	parent string,
	uid, gid uint32,
	content []byte,
) {
	t.Helper()
	if _, err := reconcileRsyslogArtifactAtUsing(
		parent,
		wafRsyslogConfigName,
		uid,
		gid,
		content,
		nil,
		syncSELinuxLifecycleDirectory,
	); err != nil {
		t.Fatal(err)
	}
	if err := recordRsyslogArtifactProvenanceAtUsing(
		parent,
		uid,
		gid,
		wafRsyslogConfigName,
		content,
		syncSELinuxLifecycleDirectory,
	); err != nil {
		t.Fatal(err)
	}
}

func TestRsyslogBridgeRollbackRestoresExactExternalBaseline_SW2_PKG_001(t *testing.T) {
	for _, baselineContent := range [][]byte{nil, []byte("operator baseline bridge\n")} {
		name := "absent baseline"
		if baselineContent != nil {
			name = "existing baseline"
		}
		t.Run(name, func(t *testing.T) {
			_, parent, uid, gid := newSELinuxLifecycleFixture(t, []byte("candidate"))
			if baselineContent != nil {
				publishSELinuxLifecycleWAFBridge(t, parent, uid, gid, baselineContent)
			}
			desired := []byte("candidate WAF bridge\n")
			baseline, err := captureRsyslogBridgeRollbackBaselineAt(parent, uid, gid, desired)
			if err != nil {
				t.Fatalf("capture bridge rollback baseline: %v", err)
			}
			publishSELinuxLifecycleWAFBridge(t, parent, uid, gid, desired)
			activations := 0
			if err := baseline.Rollback(func(changed bool) error {
				if !changed {
					t.Fatal("bridge rollback activation was not marked changed")
				}
				activations++
				return nil
			}); err != nil {
				t.Fatalf("rollback coordinated bridge: %v", err)
			}
			if activations != 1 {
				t.Fatalf("bridge rollback activations = %d, want 1", activations)
			}
			directory, err := os.Open(filepath.Join(parent, wafRsyslogDirectoryName))
			if err != nil {
				t.Fatal(err)
			}
			state, content, inspectErr := inspectRsyslogArtifact(
				directory, wafRsyslogConfigName, uid, gid,
			)
			registryState, _, registryErr := inspectRsyslogArtifact(
				directory, rsyslogProvenanceName, uid, gid,
			)
			closeErr := directory.Close()
			if inspectErr != nil || registryErr != nil || closeErr != nil {
				t.Fatalf("inspect coordinated rollback = %v / %v / %v", inspectErr, registryErr, closeErr)
			}
			if baselineContent == nil {
				if state.exists || registryState.exists {
					t.Fatalf("absent bridge baseline was not restored: config=%t registry=%t", state.exists, registryState.exists)
				}
			} else if !state.exists || !registryState.exists || !bytes.Equal(content, baselineContent) {
				t.Fatalf("existing bridge baseline was not restored: state=%#v content=%q registry=%t", state, content, registryState.exists)
			}
		})
	}
}

func TestRsyslogBridgeRollbackPreservesConcurrentOperatorChange_SW2_PKG_001(t *testing.T) {
	_, parent, uid, gid := newSELinuxLifecycleFixture(t, []byte("candidate"))
	desired := []byte("candidate WAF bridge\n")
	baseline, err := captureRsyslogBridgeRollbackBaselineAt(parent, uid, gid, desired)
	if err != nil {
		t.Fatal(err)
	}
	publishSELinuxLifecycleWAFBridge(t, parent, uid, gid, desired)
	operatorContent := []byte("operator replacement bridge\n")
	if _, err := reconcileRsyslogArtifactAtUsing(
		parent, wafRsyslogConfigName, uid, gid, operatorContent, nil,
		syncSELinuxLifecycleDirectory,
	); err != nil {
		t.Fatal(err)
	}
	activated := false
	if err := baseline.Rollback(func(bool) error { activated = true; return nil }); err == nil {
		t.Fatal("coordinated rollback accepted a concurrent operator bridge")
	}
	if activated {
		t.Fatal("coordinated rollback activated rsyslog after refusing an operator bridge")
	}
	directory, err := os.Open(filepath.Join(parent, wafRsyslogDirectoryName))
	if err != nil {
		t.Fatal(err)
	}
	_, content, inspectErr := inspectRsyslogArtifact(directory, wafRsyslogConfigName, uid, gid)
	closeErr := directory.Close()
	if inspectErr != nil || closeErr != nil || !bytes.Equal(content, operatorContent) {
		t.Fatalf("operator bridge after refused rollback = %q, %v, %v", content, inspectErr, closeErr)
	}
}

func TestSELinuxPolicyInstallRecordsExactIdentityAndUsesAbsolutePaths_SW2_PKG_001(t *testing.T) {
	candidate := []byte("candidate policy package\n")
	workspace, parent, uid, gid := newSELinuxLifecycleFixture(t, candidate)
	fake := &fakeSELinuxLifecycleRunner{
		candidatePackage:  candidate,
		candidateIdentity: selinuxLifecycleIdentity(400, rsyslogSELinuxModuleName, 'e'),
		otherModules: []selinuxModuleIdentity{
			selinuxLifecycleIdentity(1, "operator_local", '1'),
		},
	}
	transaction, err := installRsyslogSELinuxPolicyWithProvenanceAtUsing(
		workspace,
		parent,
		uid,
		gid,
		fake.run,
		allowSELinuxLifecycleMutation,
		syncSELinuxLifecycleDirectory,
	)
	if err != nil {
		t.Fatalf("install exact priority 400 module: %v", err)
	}
	if transaction == nil || !fake.currentExists || fake.currentIdentity != fake.candidateIdentity {
		t.Fatalf("installed transaction/current = %#v / %#v", transaction, fake.currentIdentity)
	}
	provenance := readSELinuxLifecycleProvenance(t, parent, uid, gid)
	if !provenance.exists || provenance.identity != fake.candidateIdentity {
		t.Fatalf("installed provenance = %#v", provenance)
	}
	if err := transaction.Commit(); err != nil {
		t.Fatalf("commit install: %v", err)
	}
	for _, call := range fake.calls {
		if !filepath.IsAbs(call.directory) || !filepath.IsAbs(call.executable) {
			t.Fatalf("non-absolute command call = %#v", call)
		}
		for _, argument := range call.arguments {
			if strings.HasSuffix(argument, ".te") || strings.HasSuffix(argument, ".mod") || strings.HasSuffix(argument, ".pp") {
				if !filepath.IsAbs(argument) {
					t.Fatalf("non-absolute SELinux artifact argument %q in %#v", argument, call)
				}
			}
		}
	}
}

func TestSELinuxPolicyAdoptsOnlyByteExactUnprovenancedModule_SW2_PKG_001(t *testing.T) {
	for _, test := range []struct {
		name            string
		installed       []byte
		wantErr         bool
		wantProvenance  bool
		rollbackAdopted bool
	}{
		{
			name:            "byte exact adoption",
			installed:       []byte("candidate policy package\n"),
			wantProvenance:  true,
			rollbackAdopted: true,
		},
		{
			name:      "different extracted package",
			installed: []byte("operator policy package\n"),
			wantErr:   true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := []byte("candidate policy package\n")
			workspace, parent, uid, gid := newSELinuxLifecycleFixture(t, candidate)
			identity := selinuxLifecycleIdentity(400, rsyslogSELinuxModuleName, 'f')
			fake := &fakeSELinuxLifecycleRunner{
				candidatePackage:  candidate,
				candidateIdentity: identity,
				currentExists:     true,
				currentIdentity:   identity,
				currentPackage:    append([]byte(nil), test.installed...),
				baselineIdentity:  identity,
				baselinePackage:   append([]byte(nil), test.installed...),
			}
			transaction, err := installRsyslogSELinuxPolicyWithProvenanceAtUsing(
				workspace,
				parent,
				uid,
				gid,
				fake.run,
				allowSELinuxLifecycleMutation,
				syncSELinuxLifecycleDirectory,
			)
			if (err != nil) != test.wantErr {
				t.Fatalf("unprovenanced reconciliation error = %v, wantErr %t", err, test.wantErr)
			}
			if count := countSELinuxLifecycleOperation(fake.calls, []string{
				"-X", strconv.Itoa(rsyslogSELinuxModulePriority), "-i", filepath.Join(workspace, rsyslogSELinuxModuleName+".pp"),
			}); count != 0 {
				t.Fatalf("unprovenanced module was overwritten %d times", count)
			}
			provenance := readSELinuxLifecycleProvenance(t, parent, uid, gid)
			if provenance.exists != test.wantProvenance {
				t.Fatalf("unprovenanced reconciliation provenance = %#v", provenance)
			}
			if test.rollbackAdopted {
				if transaction == nil {
					t.Fatal("byte-exact adoption returned no transaction")
				}
				if err := transaction.Rollback(); err != nil {
					t.Fatalf("rollback byte-exact adoption: %v", err)
				}
				if !fake.currentExists || fake.currentIdentity != identity {
					t.Fatalf("adoption rollback changed installed module = %#v", fake.currentIdentity)
				}
				if provenance := readSELinuxLifecycleProvenance(t, parent, uid, gid); provenance.exists {
					t.Fatalf("adoption rollback retained new provenance = %#v", provenance)
				}
			}
		})
	}
}

func TestSELinuxPolicyDoesNotRecreateTrackedModuleRemovedByOperator_SW2_PKG_001(t *testing.T) {
	candidate := []byte("candidate policy package\n")
	workspace, parent, uid, gid := newSELinuxLifecycleFixture(t, candidate)
	trackedIdentity := selinuxLifecycleIdentity(400, rsyslogSELinuxModuleName, '6')
	recordSELinuxLifecycleProvenance(t, parent, uid, gid, trackedIdentity)
	fake := &fakeSELinuxLifecycleRunner{
		candidatePackage:  candidate,
		candidateIdentity: trackedIdentity,
	}

	transaction, err := installRsyslogSELinuxPolicyWithProvenanceAtUsing(
		workspace,
		parent,
		uid,
		gid,
		fake.run,
		allowSELinuxLifecycleMutation,
		syncSELinuxLifecycleDirectory,
	)
	if err == nil || transaction != nil {
		t.Fatalf("absent tracked module reconciliation = %#v, %v", transaction, err)
	}
	if fake.currentExists {
		t.Fatalf("absent tracked module was recreated as %#v", fake.currentIdentity)
	}
	if count := countSELinuxLifecycleOperation(fake.calls, []string{
		"-X", strconv.Itoa(rsyslogSELinuxModulePriority), "-i", filepath.Join(workspace, rsyslogSELinuxModuleName+".pp"),
	}); count != 0 {
		t.Fatalf("absent tracked module install calls = %d, want 0", count)
	}
	provenance := readSELinuxLifecycleProvenance(t, parent, uid, gid)
	if !provenance.exists || provenance.identity != trackedIdentity {
		t.Fatalf("absent tracked module provenance changed = %#v", provenance)
	}
}

func TestSELinuxPolicyDoesNotShadowHomonymousOperatorPriority_SW2_PKG_001(t *testing.T) {
	candidate := []byte("candidate policy package\n")
	workspace, parent, uid, gid := newSELinuxLifecycleFixture(t, candidate)
	operatorIdentity := selinuxLifecycleIdentity(100, rsyslogSELinuxModuleName, '4')
	fake := &fakeSELinuxLifecycleRunner{
		candidatePackage: candidate,
		candidateIdentity: selinuxLifecycleIdentity(
			400,
			rsyslogSELinuxModuleName,
			'5',
		),
		otherModules: []selinuxModuleIdentity{operatorIdentity},
	}

	transaction, err := installRsyslogSELinuxPolicyWithProvenanceAtUsing(
		workspace,
		parent,
		uid,
		gid,
		fake.run,
		allowSELinuxLifecycleMutation,
		syncSELinuxLifecycleDirectory,
	)
	if err == nil || transaction != nil {
		t.Fatalf("homonymous operator priority reconciliation = %#v, %v", transaction, err)
	}
	if fake.currentExists || len(fake.otherModules) != 1 || fake.otherModules[0] != operatorIdentity {
		t.Fatalf("homonymous operator priority was changed: current=%t others=%#v", fake.currentExists, fake.otherModules)
	}
	if count := countSELinuxLifecycleOperation(fake.calls, []string{
		"-X", strconv.Itoa(rsyslogSELinuxModulePriority), "-i", filepath.Join(workspace, rsyslogSELinuxModuleName+".pp"),
	}); count != 0 {
		t.Fatalf("homonymous operator priority caused %d priority-400 install calls", count)
	}
	if provenance := readSELinuxLifecycleProvenance(t, parent, uid, gid); provenance.exists {
		t.Fatalf("homonymous operator priority created provenance = %#v", provenance)
	}
}

func TestSELinuxPolicyRollbackRemovesNewModuleWhenProvenancePublicationFails_SW2_PKG_001(t *testing.T) {
	candidate := []byte("candidate policy package\n")
	workspace, parent, uid, gid := newSELinuxLifecycleFixture(t, candidate)
	fake := &fakeSELinuxLifecycleRunner{
		candidatePackage:  candidate,
		candidateIdentity: selinuxLifecycleIdentity(400, rsyslogSELinuxModuleName, '7'),
	}
	syncFailure := errors.New("injected provenance directory sync failure")
	transaction, err := installRsyslogSELinuxPolicyWithProvenanceAtUsing(
		workspace,
		parent,
		uid,
		gid,
		fake.run,
		allowSELinuxLifecycleMutation,
		func(*os.File) error { return syncFailure },
	)
	if err == nil || !errors.Is(err, syncFailure) || transaction != nil {
		t.Fatalf("publication failure transaction/error = %#v, %v", transaction, err)
	}
	if fake.currentExists {
		t.Fatalf("publication failure orphaned module %#v", fake.currentIdentity)
	}
	if provenance := readSELinuxLifecycleProvenance(t, parent, uid, gid); provenance.exists {
		t.Fatalf("publication failure retained provenance %#v", provenance)
	}
	if count := countSELinuxLifecycleOperation(fake.calls, []string{
		"-X", strconv.Itoa(rsyslogSELinuxModulePriority), "-r", rsyslogSELinuxModuleName,
	}); count != 1 {
		t.Fatalf("publication failure rollback removals = %d, want 1", count)
	}
}

func TestSELinuxPolicyRollbackCoversPostInstallFailures_SW2_PKG_001(t *testing.T) {
	for _, test := range []struct {
		name      string
		configure func(*fakeSELinuxLifecycleRunner)
	}{
		{
			name: "semodule reports failure after mutation",
			configure: func(fake *fakeSELinuxLifecycleRunner) {
				fake.failInstallAfterMutation = errors.New("injected late semodule install failure")
			},
		},
		{
			name: "first post-install listing fails",
			configure: func(fake *fakeSELinuxLifecycleRunner) {
				fake.failListAt = map[int]error{3: errors.New("injected first post-install listing failure")}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := []byte("candidate policy package\n")
			workspace, parent, uid, gid := newSELinuxLifecycleFixture(t, candidate)
			fake := &fakeSELinuxLifecycleRunner{
				candidatePackage:  candidate,
				candidateIdentity: selinuxLifecycleIdentity(400, rsyslogSELinuxModuleName, '3'),
			}
			test.configure(fake)

			transaction, err := installRsyslogSELinuxPolicyWithProvenanceAtUsing(
				workspace,
				parent,
				uid,
				gid,
				fake.run,
				allowSELinuxLifecycleMutation,
				syncSELinuxLifecycleDirectory,
			)
			if err == nil || transaction != nil {
				t.Fatalf("post-install failure transaction/error = %#v, %v", transaction, err)
			}
			if fake.currentExists {
				t.Fatalf("post-install failure orphaned module = %#v", fake.currentIdentity)
			}
			if provenance := readSELinuxLifecycleProvenance(t, parent, uid, gid); provenance.exists {
				t.Fatalf("post-install failure retained provenance = %#v", provenance)
			}
			if count := countSELinuxLifecycleOperation(fake.calls, []string{
				"-X", strconv.Itoa(rsyslogSELinuxModulePriority), "-r", rsyslogSELinuxModuleName,
			}); count != 1 {
				t.Fatalf("post-install failure rollback removals = %d, want 1", count)
			}
		})
	}
}

func TestSELinuxPolicyRollbackAfterLaterFailureAndFailedCommit_SW2_PKG_001(t *testing.T) {
	for _, failCommit := range []bool{false, true} {
		name := "later caller failure"
		if failCommit {
			name = "commit attestation failure"
		}
		t.Run(name, func(t *testing.T) {
			candidate := []byte("candidate policy package\n")
			workspace, parent, uid, gid := newSELinuxLifecycleFixture(t, candidate)
			fake := &fakeSELinuxLifecycleRunner{
				candidatePackage:  candidate,
				candidateIdentity: selinuxLifecycleIdentity(400, rsyslogSELinuxModuleName, '2'),
			}
			if failCommit {
				fake.failListAt = map[int]error{5: errors.New("injected commit attestation failure")}
			}
			transaction, err := installRsyslogSELinuxPolicyWithProvenanceAtUsing(
				workspace,
				parent,
				uid,
				gid,
				fake.run,
				allowSELinuxLifecycleMutation,
				syncSELinuxLifecycleDirectory,
			)
			if err != nil || transaction == nil {
				t.Fatalf("prepare transaction for later failure = %#v, %v", transaction, err)
			}
			if failCommit {
				err = transaction.Commit()
				if err == nil {
					t.Fatal("commit attestation failure was accepted")
				}
			} else if err := transaction.Rollback(); err != nil {
				t.Fatalf("rollback later caller failure: %v", err)
			}
			if fake.currentExists {
				t.Fatalf("later failure orphaned module = %#v", fake.currentIdentity)
			}
			if provenance := readSELinuxLifecycleProvenance(t, parent, uid, gid); provenance.exists {
				t.Fatalf("later failure retained provenance = %#v", provenance)
			}
		})
	}
}

func TestSELinuxPolicyRollbackCompletesAfterLateSemoduleError_SW2_PKG_001(t *testing.T) {
	t.Run("new module removal reports error after mutation", func(t *testing.T) {
		candidate := []byte("candidate policy package\n")
		workspace, parent, uid, gid := newSELinuxLifecycleFixture(t, candidate)
		fake := &fakeSELinuxLifecycleRunner{
			candidatePackage:  candidate,
			candidateIdentity: selinuxLifecycleIdentity(400, rsyslogSELinuxModuleName, '1'),
		}
		transaction, err := installRsyslogSELinuxPolicyWithProvenanceAtUsing(
			workspace, parent, uid, gid, fake.run,
			allowSELinuxLifecycleMutation, syncSELinuxLifecycleDirectory,
		)
		if err != nil {
			t.Fatalf("prepare new-module rollback: %v", err)
		}
		lateFailure := errors.New("injected late rollback removal failure")
		fake.failRemoveAfterMutation = lateFailure
		err = transaction.Rollback()
		if !errors.Is(err, lateFailure) {
			t.Fatalf("late rollback removal error = %v", err)
		}
		if fake.currentExists {
			t.Fatalf("late removal error left module = %#v", fake.currentIdentity)
		}
		if provenance := readSELinuxLifecycleProvenance(t, parent, uid, gid); provenance.exists {
			t.Fatalf("late removal error left provenance = %#v", provenance)
		}
	})

	t.Run("baseline restore reports error after mutation", func(t *testing.T) {
		candidate := []byte("new candidate policy package\n")
		baseline := []byte("owned baseline policy package\n")
		workspace, parent, uid, gid := newSELinuxLifecycleFixture(t, candidate)
		baselineIdentity := selinuxLifecycleIdentity(400, rsyslogSELinuxModuleName, 'a')
		candidateIdentity := selinuxLifecycleIdentity(400, rsyslogSELinuxModuleName, 'b')
		recordSELinuxLifecycleProvenance(t, parent, uid, gid, baselineIdentity)
		fake := &fakeSELinuxLifecycleRunner{
			candidatePackage:  candidate,
			candidateIdentity: candidateIdentity,
			baselinePackage:   baseline,
			baselineIdentity:  baselineIdentity,
			currentExists:     true,
			currentIdentity:   baselineIdentity,
			currentPackage:    append([]byte(nil), baseline...),
		}
		transaction, err := installRsyslogSELinuxPolicyWithProvenanceAtUsing(
			workspace, parent, uid, gid, fake.run,
			allowSELinuxLifecycleMutation, syncSELinuxLifecycleDirectory,
		)
		if err != nil {
			t.Fatalf("prepare baseline rollback: %v", err)
		}
		lateFailure := errors.New("injected late baseline restore failure")
		fake.failRestoreAfterMutation = lateFailure
		err = transaction.Rollback()
		if !errors.Is(err, lateFailure) {
			t.Fatalf("late baseline restore error = %v", err)
		}
		if !fake.currentExists || fake.currentIdentity != baselineIdentity || !bytes.Equal(fake.currentPackage, baseline) {
			t.Fatalf("late restore error failed baseline restoration = %#v, %q", fake.currentIdentity, fake.currentPackage)
		}
		provenance := readSELinuxLifecycleProvenance(t, parent, uid, gid)
		if !provenance.exists || provenance.identity != baselineIdentity {
			t.Fatalf("late restore error failed provenance restoration = %#v", provenance)
		}
	})
}

func TestSELinuxPolicyRollbackPreservesConcurrentProvenanceOwner_SW2_PKG_001(t *testing.T) {
	candidate := []byte("candidate policy package\n")
	workspace, parent, uid, gid := newSELinuxLifecycleFixture(t, candidate)
	candidateIdentity := selinuxLifecycleIdentity(400, rsyslogSELinuxModuleName, 'd')
	fake := &fakeSELinuxLifecycleRunner{
		candidatePackage:  candidate,
		candidateIdentity: candidateIdentity,
	}
	transaction, err := installRsyslogSELinuxPolicyWithProvenanceAtUsing(
		workspace, parent, uid, gid, fake.run,
		allowSELinuxLifecycleMutation, syncSELinuxLifecycleDirectory,
	)
	if err != nil {
		t.Fatalf("prepare concurrent-provenance rollback: %v", err)
	}
	operatorIdentity := selinuxLifecycleIdentity(400, rsyslogSELinuxModuleName, 'e')
	recordSELinuxLifecycleProvenance(t, parent, uid, gid, operatorIdentity)
	if err := transaction.Rollback(); err == nil {
		t.Fatal("rollback accepted concurrently replaced SELinux provenance")
	}
	if !fake.currentExists || fake.currentIdentity != candidateIdentity {
		t.Fatalf("rollback changed module after concurrent provenance ownership = %#v", fake.currentIdentity)
	}
	provenance := readSELinuxLifecycleProvenance(t, parent, uid, gid)
	if !provenance.exists || provenance.identity != operatorIdentity {
		t.Fatalf("rollback changed concurrent provenance = %#v", provenance)
	}
	if count := countSELinuxLifecycleOperation(fake.calls, []string{
		"-X", strconv.Itoa(rsyslogSELinuxModulePriority), "-r", rsyslogSELinuxModuleName,
	}); count != 0 {
		t.Fatalf("rollback issued %d removals after concurrent provenance ownership", count)
	}
}

func TestSELinuxPolicyRollbackRestoresExactOwnedBaseline_SW2_PKG_001(t *testing.T) {
	candidate := []byte("new candidate policy package\n")
	baseline := []byte("owned baseline policy package\n")
	workspace, parent, uid, gid := newSELinuxLifecycleFixture(t, candidate)
	baselineIdentity := selinuxLifecycleIdentity(400, rsyslogSELinuxModuleName, '8')
	candidateIdentity := selinuxLifecycleIdentity(400, rsyslogSELinuxModuleName, '9')
	recordSELinuxLifecycleProvenance(t, parent, uid, gid, baselineIdentity)
	fake := &fakeSELinuxLifecycleRunner{
		candidatePackage:  candidate,
		candidateIdentity: candidateIdentity,
		baselinePackage:   baseline,
		baselineIdentity:  baselineIdentity,
		currentExists:     true,
		currentIdentity:   baselineIdentity,
		currentPackage:    append([]byte(nil), baseline...),
	}
	transaction, err := installRsyslogSELinuxPolicyWithProvenanceAtUsing(
		workspace,
		parent,
		uid,
		gid,
		fake.run,
		allowSELinuxLifecycleMutation,
		syncSELinuxLifecycleDirectory,
	)
	if err != nil {
		t.Fatalf("replace owned baseline: %v", err)
	}
	if !fake.currentExists || fake.currentIdentity != candidateIdentity {
		t.Fatalf("candidate not installed = %#v", fake.currentIdentity)
	}
	if err := transaction.Rollback(); err != nil {
		t.Fatalf("rollback owned baseline: %v", err)
	}
	if !fake.currentExists || fake.currentIdentity != baselineIdentity || !bytes.Equal(fake.currentPackage, baseline) {
		t.Fatalf("baseline not restored exactly = %#v, %q", fake.currentIdentity, fake.currentPackage)
	}
	provenance := readSELinuxLifecycleProvenance(t, parent, uid, gid)
	if !provenance.exists || provenance.identity != baselineIdentity {
		t.Fatalf("baseline provenance not restored = %#v", provenance)
	}
	baselinePath := filepath.Join(workspace, "baseline", rsyslogSELinuxModuleName+".pp")
	if count := countSELinuxLifecycleOperation(fake.calls, []string{
		"-X", strconv.Itoa(rsyslogSELinuxModulePriority), "-i", baselinePath,
	}); count != 1 {
		t.Fatalf("baseline restore installations = %d, want 1", count)
	}
}

func TestSELinuxPolicyRemovalIsExactAndPreservesOtherPriorities_SW2_PKG_001(t *testing.T) {
	identity := selinuxLifecycleIdentity(400, rsyslogSELinuxModuleName, 'a')
	_, parent, uid, gid := newSELinuxLifecycleFixture(t, []byte("candidate"))
	recordSELinuxLifecycleProvenance(t, parent, uid, gid, identity)
	otherModules := []selinuxModuleIdentity{
		selinuxLifecycleIdentity(1, rsyslogSELinuxModuleName, '1'),
		selinuxLifecycleIdentity(500, rsyslogSELinuxModuleName, '5'),
		selinuxLifecycleIdentity(400, "operator_local", 'd'),
	}
	fake := &fakeSELinuxLifecycleRunner{
		currentExists:   true,
		currentIdentity: identity,
		currentPackage:  []byte("candidate"),
		otherModules:    append([]selinuxModuleIdentity(nil), otherModules...),
	}
	warnings := []string{}
	options := defaultExactOwnedArtifactRemovalOptions()
	options.warn = func(message string) { warnings = append(warnings, message) }
	if err := removeOwnedRsyslogSELinuxPolicyForPackageRemovalAtUsing(
		parent,
		uid,
		gid,
		options,
		fake.run,
	); err != nil {
		t.Fatalf("remove exact priority 400 module: %v", err)
	}
	if fake.currentExists || !slices.Equal(fake.otherModules, otherModules) {
		t.Fatalf("exact removal current/other modules = %t / %#v", fake.currentExists, fake.otherModules)
	}
	if len(warnings) != 0 {
		t.Fatalf("exact removal warnings = %v", warnings)
	}
	if provenance := readSELinuxLifecycleProvenance(t, parent, uid, gid); provenance.exists {
		t.Fatalf("exact removal retained provenance = %#v", provenance)
	}
	if count := countSELinuxLifecycleOperation(fake.calls, []string{
		"-X", strconv.Itoa(rsyslogSELinuxModulePriority), "-r", rsyslogSELinuxModuleName,
	}); count != 1 {
		t.Fatalf("exact priority 400 removal calls = %d, want 1", count)
	}
}

func TestSELinuxPolicyRemovalPreservesChangedOrUnverifiedModuleAndProvenance_SW2_PKG_001(t *testing.T) {
	for _, test := range []struct {
		name          string
		configureFake func(*fakeSELinuxLifecycleRunner)
		wantErr       bool
	}{
		{
			name: "checksum changed",
			configureFake: func(fake *fakeSELinuxLifecycleRunner) {
				fake.currentIdentity = selinuxLifecycleIdentity(400, rsyslogSELinuxModuleName, 'c')
			},
		},
		{
			name: "remove command failed",
			configureFake: func(fake *fakeSELinuxLifecycleRunner) {
				fake.failRemove = errors.New("injected semodule removal failure")
			},
			wantErr: true,
		},
		{
			name: "post-remove module remains",
			configureFake: func(fake *fakeSELinuxLifecycleRunner) {
				fake.ignoreRemove = true
			},
			wantErr: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			identity := selinuxLifecycleIdentity(400, rsyslogSELinuxModuleName, 'b')
			_, parent, uid, gid := newSELinuxLifecycleFixture(t, []byte("candidate"))
			recordSELinuxLifecycleProvenance(t, parent, uid, gid, identity)
			fake := &fakeSELinuxLifecycleRunner{
				currentExists:   true,
				currentIdentity: identity,
				currentPackage:  []byte("candidate"),
			}
			test.configureFake(fake)
			warnings := []string{}
			options := defaultExactOwnedArtifactRemovalOptions()
			options.warn = func(message string) { warnings = append(warnings, message) }
			err := removeOwnedRsyslogSELinuxPolicyForPackageRemovalAtUsing(
				parent,
				uid,
				gid,
				options,
				fake.run,
			)
			if (err != nil) != test.wantErr {
				t.Fatalf("preserving removal error = %v, wantErr %t", err, test.wantErr)
			}
			if !fake.currentExists {
				t.Fatal("unsafe removal did not preserve the target module")
			}
			provenance := readSELinuxLifecycleProvenance(t, parent, uid, gid)
			if !provenance.exists || provenance.identity != identity {
				t.Fatalf("unsafe removal did not preserve provenance = %#v", provenance)
			}
			if test.name == "checksum changed" && len(warnings) == 0 {
				t.Fatal("changed module preservation emitted no warning")
			}
		})
	}
}
