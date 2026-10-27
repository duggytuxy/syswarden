//go:build linux

package config

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func activationApprovalFixture(t *testing.T) (*ActivationPolicy, activationApprovalStore, ActivationApprovalRequest) {
	t.Helper()
	root, _ := initializedUserModule(t)
	policy, err := CaptureActivationPolicy(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	store := activationApprovalStore{path: filepath.Join(t.TempDir(), "activation"), uid: activationFixtureOwnerUID(t)}
	request := ActivationApprovalRequest{PlanSHA256: strings.Repeat("a", 64), ApprovedPlanSHA256: strings.Repeat("a", 64), Operation: "install"}
	return policy, store, request
}

func approveActivationFixture(t *testing.T, policy *ActivationPolicy, store activationApprovalStore, request ActivationApprovalRequest) *ActivationApproval {
	t.Helper()
	approval, err := policy.approveAt(t.Context(), store, request, func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	return approval
}

func TestActivationApprovalRejectsUnreviewedOrStaleInputsWithoutWrites(t *testing.T) {
	for _, change := range []string{"missing-approval", "different-approval", "bad-plan", "bad-operation", "bad-predecessor", "nil-host", "host-drift", "source-drift", "cancelled"} {
		t.Run(change, func(t *testing.T) {
			policy, store, request := activationApprovalFixture(t)
			global, load := GlobalConfig, CurrentLoadState()
			ctx := t.Context()
			guard := func() error { return nil }
			switch change {
			case "missing-approval":
				request.ApprovedPlanSHA256 = ""
			case "different-approval":
				request.ApprovedPlanSHA256 = strings.Repeat("b", 64)
			case "bad-plan":
				request.PlanSHA256 = "invalid"
				request.ApprovedPlanSHA256 = "invalid"
			case "bad-operation":
				request.Operation = "boot"
			case "bad-predecessor":
				request.PreviousApprovalSHA256 = strings.Repeat("b", 64)
			case "nil-host":
				guard = nil
			case "host-drift":
				guard = func() error { return errors.New("changed live state") }
			case "source-drift":
				guard = func() error {
					return os.WriteFile(filepath.Join(policy.root, "modules", "99-user.toml"), []byte("# changed by independent administrator\n"), 0600)
				}
			case "cancelled":
				cancelled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = cancelled
			}
			if _, err := policy.approveAt(ctx, store, request, guard); err == nil {
				t.Fatal("unreviewed activation accepted")
			}
			if _, err := os.Lstat(store.path); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("refusal created activation storage", err)
			}
			if GlobalConfig != global || !reflect.DeepEqual(load, CurrentLoadState()) {
				t.Fatal("approval refusal changed global config")
			}
		})
	}
}

func TestActivationApprovalConsumptionAndAppliedAreDistinct(t *testing.T) {
	preserveOperatorPolicyGlobals(t)
	policy, store, request := activationApprovalFixture(t)
	before := intentFixtureFiles(t, policy.root)
	global, load := GlobalConfig, CurrentLoadState()
	approval := approveActivationFixture(t, policy, store, request)
	if approval.Review().Applied {
		t.Fatal("approval claimed successful application")
	}
	if GlobalConfig != global || !reflect.DeepEqual(load, CurrentLoadState()) {
		t.Fatal("approval published global config")
	}
	if !reflect.DeepEqual(before, intentFixtureFiles(t, policy.root)) {
		t.Fatal("approval rewrote TOML")
	}
	host, err := policy.HostSHA256()
	if err != nil || host != approval.Review().HostSHA256 || approval.Review().PolicySHA256 != policy.Review().Digest {
		t.Fatal("approval did not bind exact source", err)
	}
	if _, err := policy.verifyApprovedAt(t.Context(), store); err != nil {
		t.Fatal(err)
	}
	// A nested verifier obtains no publication lock and can execute before
	// successful parent application has been recorded.
	if err := approval.Revalidate(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := policy.useApprovedAt(t.Context(), store); err != nil {
		t.Fatal(err)
	}
	if CurrentLoadState().Degraded || GlobalConfig.InstallProfile != UnconfiguredInstallProfile || GlobalConfig.ListChoice != "4" {
		t.Fatal("approved capture was not installed")
	}
	GlobalConfig.ListChoice = "1"
	candidate, err := policy.Configuration(t.Context())
	if err != nil || candidate.ListChoice != "4" {
		t.Fatal("global config aliases immutable capture", err)
	}
	if err := approval.MarkApplied(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := approval.MarkApplied(t.Context()); err != nil {
		t.Fatal("idempotent application recording failed", err)
	}
	current, err := policy.currentApprovalAt(t.Context(), store)
	if err != nil || !current.Review().Applied || current.Review().SHA256 != approval.Review().SHA256 {
		t.Fatal("applied state is not tied to exact approval", err)
	}
	for _, name := range []string{activationApprovedName, activationAppliedName, activationLockName} {
		info, err := os.Lstat(filepath.Join(store.path, name))
		if err != nil || info.Mode() != 0600 {
			t.Fatal("approval artifact is not private", name, err)
		}
	}
}

func TestActivationApprovalCASAndChangedPolicyRequireNewConsent(t *testing.T) {
	policy, store, request := activationApprovalFixture(t)
	first := approveActivationFixture(t, policy, store, request)
	if err := first.MarkApplied(t.Context()); err != nil {
		t.Fatal(err)
	}
	firstBytes, err := os.ReadFile(filepath.Join(store.path, activationApprovedName))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := policy.approveAt(t.Context(), store, request, func() error { return nil }); err == nil {
		t.Fatal("stale absent predecessor replaced approval")
	}
	actual, _ := os.ReadFile(filepath.Join(store.path, activationApprovedName))
	if !bytes.Equal(firstBytes, actual) {
		t.Fatal("failed CAS changed approval")
	}
	if err := os.WriteFile(filepath.Join(policy.root, "modules", "99-user.toml"), []byte("[user]\nprofile_name='reviewed'\n"), 0600); err != nil {
		t.Fatal(err)
	}
	secondPolicy, err := CaptureActivationPolicy(t.Context(), policy.root)
	if err != nil {
		t.Fatal(err)
	}
	previous, err := secondPolicy.currentApprovalAt(t.Context(), store)
	if err != nil || previous.Review().SHA256 != first.Review().SHA256 {
		t.Fatal("cannot review changed policy against predecessor", err)
	}
	if _, err := secondPolicy.verifyApprovedAt(t.Context(), store); err == nil {
		t.Fatal("changed policy inherited approval")
	}
	request.PreviousApprovalSHA256 = first.Review().SHA256
	request.PlanSHA256 = strings.Repeat("b", 64)
	request.ApprovedPlanSHA256 = request.PlanSHA256
	request.Operation = "reload"
	second := approveActivationFixture(t, secondPolicy, store, request)
	if second.Review().Applied || second.Review().Operation != "reload" {
		t.Fatal("older successful install was promoted to new approval")
	}
	if err := first.MarkApplied(t.Context()); err == nil {
		t.Fatal("old approval marked replacement applied")
	}
	if _, err := secondPolicy.verifyApprovedAt(t.Context(), store); err != nil {
		t.Fatal(err)
	}
	// Reapproval before applying retains the exact older application marker,
	// without treating it as success of either newer operation.
	request.PreviousApprovalSHA256 = second.Review().SHA256
	request.PlanSHA256 = strings.Repeat("c", 64)
	request.ApprovedPlanSHA256 = request.PlanSHA256
	third := approveActivationFixture(t, secondPolicy, store, request)
	if third.Review().Applied {
		t.Fatal("stale application marker granted new success")
	}
	if err := third.MarkApplied(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func TestActivationApprovalRefusesInputAndReceiptDrift(t *testing.T) {
	for _, change := range []string{"bytes", "inode", "missing", "extra", "mode", "symlink", "hardlink", "environment", "receipt-symlink", "receipt-mode", "receipt-hardlink", "receipt-unknown", "receipt-duplicate", "state-unknown", "retirement"} {
		t.Run(change, func(t *testing.T) {
			policy, store, request := activationApprovalFixture(t)
			approval := approveActivationFixture(t, policy, store, request)
			path := filepath.Join(policy.root, "modules", "99-user.toml")
			receipt := filepath.Join(store.path, activationApprovedName)
			switch change {
			case "bytes":
				if err := os.WriteFile(path, []byte("# changed\n"), 0600); err != nil {
					t.Fatal(err)
				}
			case "inode":
				// #nosec G304 -- path is the fixed user module in this test's private configuration fixture.
				raw, _ := os.ReadFile(path)
				if err := os.Rename(path, path+".saved"); err != nil {
					t.Fatal(err)
				}
				// #nosec G703 -- this exact fixture path is recreated to test same-byte inode replacement.
				if err := os.WriteFile(path, raw, 0600); err != nil {
					t.Fatal(err)
				}
			case "missing":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			case "extra":
				if err := os.WriteFile(filepath.Join(policy.root, "modules", "zz-local.toml"), []byte("# additional\n"), 0600); err != nil {
					t.Fatal(err)
				}
			case "mode":
				// #nosec G302 -- deliberate fixture permission drift must invalidate previously captured policy.
				if err := os.Chmod(path, 0640); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Join(policy.root, "config.toml"), path); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(path, filepath.Join(t.TempDir(), "copy")); err != nil {
					t.Fatal(err)
				}
			case "environment":
				t.Setenv("SYSWARDEN_CORE_LOG_LEVEL", "")
			case "receipt-symlink":
				if err := os.Rename(receipt, receipt+".saved"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(receipt+".saved", receipt); err != nil {
					t.Fatal(err)
				}
			case "receipt-mode":
				// #nosec G302 -- deliberate nonprivate receipt mode verifies fail-closed consumption.
				if err := os.Chmod(receipt, 0640); err != nil {
					t.Fatal(err)
				}
			case "receipt-hardlink":
				if err := os.Link(receipt, filepath.Join(t.TempDir(), "copy")); err != nil {
					t.Fatal(err)
				}
			case "receipt-unknown":
				// #nosec G304 -- receipt is the fixed approval file in this test's private temporary store.
				raw, _ := os.ReadFile(receipt)
				raw = bytes.Replace(raw, []byte("{"), []byte("{\"unknown\":true,"), 1)
				// #nosec G703 -- only this test-owned receipt is corrupted to exercise unknown-field rejection.
				if err := os.WriteFile(receipt, raw, 0600); err != nil {
					t.Fatal(err)
				}
			case "receipt-duplicate":
				// #nosec G304 -- receipt is the fixed approval file in this test's private temporary store.
				raw, _ := os.ReadFile(receipt)
				raw = bytes.Replace(raw, []byte("{"), []byte("{\"operation\":\"install\","), 1)
				// #nosec G703 -- only this test-owned receipt is corrupted to exercise duplicate-field rejection.
				if err := os.WriteFile(receipt, raw, 0600); err != nil {
					t.Fatal(err)
				}
			case "state-unknown":
				if err := os.WriteFile(filepath.Join(store.path, "administrator-note"), []byte("keep"), 0600); err != nil {
					t.Fatal(err)
				}
			case "retirement":
				if err := os.WriteFile(filepath.Join(filepath.Dir(store.path), activationRetirementName), []byte("retain"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := approval.Revalidate(t.Context()); err == nil {
				t.Fatal("changed authority remained valid")
			}
			if _, err := policy.verifyApprovedAt(t.Context(), store); err == nil {
				t.Fatal("changed source or approval accepted")
			}
		})
	}
}

func TestActivationApprovalStrictContractRefusesMalformedWitnesses(t *testing.T) {
	policy, store, request := activationApprovalFixture(t)
	record, err := policy.approvalRecord(request, store.uid)
	if err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []string{"schema", "source", "environment", "operation", "root", "host", "missing", "duplicate", "order", "path", "links", "oversize", "owner", "mode"} {
		t.Run(mutation, func(t *testing.T) {
			raw, err := activationCanonical(record)
			if err != nil {
				t.Fatal(err)
			}
			copy, err := decodeActivationApproval(raw, store.uid)
			if err != nil {
				t.Fatal(err)
			}
			switch mutation {
			case "schema":
				copy.Schema = "other"
			case "source":
				copy.SourceContract = "other"
			case "environment":
				copy.Environment = "allow-environment"
			case "operation":
				copy.Operation = "upgrade"
			case "root":
				copy.Root = "/etc/syswarden/../config"
			case "host":
				copy.HostSHA256 = strings.Repeat("0", 64)
			case "missing":
				copy.Inputs = copy.Inputs[:len(copy.Inputs)-1]
			case "duplicate":
				copy.Inputs[1] = copy.Inputs[0]
			case "order":
				copy.Inputs[1], copy.Inputs[2] = copy.Inputs[2], copy.Inputs[1]
			case "path":
				copy.Inputs[1].Path = "modules/../outside.toml"
			case "links":
				copy.Inputs[1].File.Links = 2
			case "oversize":
				copy.Inputs[1].File.Size = maximumActivationInputBytes + 1
			case "owner":
				copy.Inputs[1].File.UID++
			case "mode":
				copy.Inputs[1].File.Mode = 0644
			}
			raw, err = activationCanonical(copy)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := decodeActivationApproval(raw, store.uid); err == nil {
				t.Fatal("malformed approval accepted")
			}
		})
	}
}

func TestActivationContractConsumersRemainIdentical(t *testing.T) {
	local, err := os.ReadFile("activation_contract_linux.go")
	if err != nil {
		t.Fatal(err)
	}
	core, err := os.ReadFile("../../syswarden-core/config/activation_contract_linux.go")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(local, core) {
		t.Fatal("CLI and core wire contract readers diverged")
	}
	sections := map[string]bool{}
	typ := reflect.TypeOf(ModularConfig{})
	for index := 0; index < typ.NumField(); index++ {
		sections[strings.ToUpper(typ.Field(index).Tag.Get("mapstructure"))] = true
	}
	for _, name := range activationNamespaces {
		if !sections[name] {
			t.Fatal("shared environment namespace lacks CLI schema source", name)
		}
		delete(sections, name)
	}
	if len(sections) != 0 {
		t.Fatal("shared environment contract omits CLI schema namespace", sections)
	}
}
