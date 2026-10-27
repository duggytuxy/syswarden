//go:build linux

package config

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/viper"
)

func coreApprovedFixture(t *testing.T) (string, string, *activationApprovalRecord) {
	t.Helper()
	root := unconfiguredRuntimeFixture(t)
	store := filepath.Join(t.TempDir(), "activation")
	if err := os.Mkdir(store, 0700); err != nil {
		t.Fatal(err)
	}
	uid := activationFixtureOwnerUID(t)
	opened, rootIdentity, err := openActivationDirectory(root, uid)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	modules, moduleIdentity, err := openActivationDirectory(filepath.Join(root, "modules"), uid)
	if err != nil {
		t.Fatal(err)
	}
	defer modules.Close()
	host, err := activationHostDigest(root, rootIdentity, moduleIdentity)
	if err != nil {
		t.Fatal(err)
	}
	record := &activationApprovalRecord{Schema: activationApprovalSchema, SourceContract: activationSourceContract, Environment: activationEnvironmentContract,
		Root: root, RootIdentity: rootIdentity, ModulesIdentity: moduleIdentity, HostSHA256: host, PolicySHA256: strings.Repeat("a", 64), PlanSHA256: strings.Repeat("b", 64), Operation: "install"}
	names, err := activationModuleNames(modules)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range names {
		dir := modules
		if name == "config.toml" {
			dir = opened
		}
		_, file, err := readActivationFile(dir, filepath.Base(name), uid, maximumActivationInputBytes)
		if err != nil {
			t.Fatal(err)
		}
		record.Inputs = append(record.Inputs, activationInput{Path: name, File: file})
	}
	raw, err := activationCanonical(record)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(store, activationApprovedName), raw, 0600); err != nil {
		t.Fatal(err)
	}
	return root, store, record
}

func TestCoreApprovedStartupConsumesExactBytesBeforeApplied(t *testing.T) {
	t.Cleanup(viper.Reset)
	root, store, _ := coreApprovedFixture(t)
	if _, err := loadApprovedConfigDirectory(t.Context(), root, store, activationFixtureOwnerUID(t)); err != nil {
		t.Fatal(err)
	}
	if viper.GetString("network.blocklists.list_choice") != "2" || !viper.GetBool("waap.enabled") {
		t.Fatal("approved core selection lost")
	}
	if _, err := os.Lstat(filepath.Join(store, activationAppliedName)); !os.IsNotExist(err) {
		t.Fatal("startup created application state", err)
	}
	t.Setenv("SYSWARDEN_CORE_LOG_LEVEL", "DEBUG")
	t.Setenv("SYSWARDEN_NETWORK_BLOCKLISTS_LIST_CHOICE", "1")
	if viper.GetString("core.log_level") != "INFO" || viper.GetString("network.blocklists.list_choice") != "2" {
		t.Fatal("runtime reread modular environment after approved publication")
	}
}

func TestCoreApprovedStartupRefusesDriftWithoutPublishing(t *testing.T) {
	for _, change := range []string{"absent", "unsupported", "duplicate", "unknown", "source-bytes", "source-replaced", "source-missing", "source-extra", "source-mode", "source-link", "source-hardlink", "source-oversize", "directory-replaced", "receipt-mode", "receipt-link", "receipt-hardlink", "state-extra", "environment", "retirement"} {
		t.Run(change, func(t *testing.T) {
			t.Cleanup(viper.Reset)
			root, store, _ := coreApprovedFixture(t)
			viper.Reset()
			viper.Set("core.log_level", "LAST_VALID")
			path := filepath.Join(root, "modules", "10-network.toml")
			receipt := filepath.Join(store, activationApprovedName)
			switch change {
			case "absent":
				if err := os.Remove(receipt); err != nil {
					t.Fatal(err)
				}
			case "unsupported", "duplicate", "unknown":
				// #nosec G304 -- receipt is the fixed approval file in this test's private temporary store.
				raw, _ := os.ReadFile(receipt)
				switch change {
				case "unsupported":
					raw = bytes.Replace(raw, []byte(activationSourceContract), []byte("unknown-contract"), 1)
				case "duplicate":
					raw = bytes.Replace(raw, []byte("{"), []byte("{\"operation\":\"install\","), 1)
				case "unknown":
					raw = bytes.Replace(raw, []byte("{"), []byte("{\"unknown\":true,"), 1)
				}
				// #nosec G703 -- only this fixture receipt is corrupted to test strict contract decoding.
				if err := os.WriteFile(receipt, raw, 0600); err != nil {
					t.Fatal(err)
				}
			case "source-bytes":
				if err := os.WriteFile(path, []byte("[network.blocklists]\nlist_choice='1'\n"), 0600); err != nil {
					t.Fatal(err)
				}
			case "source-replaced":
				// #nosec G304 -- path is the fixed network module in this test's private configuration fixture.
				raw, _ := os.ReadFile(path)
				if err := os.Rename(path, path+".saved"); err != nil {
					t.Fatal(err)
				}
				// #nosec G703 -- recreating this exact fixture module tests same-byte inode replacement.
				if err := os.WriteFile(path, raw, 0600); err != nil {
					t.Fatal(err)
				}
			case "source-missing":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			case "source-extra":
				if err := os.WriteFile(filepath.Join(root, "modules", "zz-local.toml"), []byte("# extra\n"), 0600); err != nil {
					t.Fatal(err)
				}
			case "source-mode":
				// #nosec G302 -- deliberate source permission drift must invalidate previously captured policy.
				if err := os.Chmod(path, 0640); err != nil {
					t.Fatal(err)
				}
			case "source-link":
				if err := os.Rename(path, path+".saved"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(path+".saved", path); err != nil {
					t.Fatal(err)
				}
			case "source-hardlink":
				if err := os.Link(path, filepath.Join(t.TempDir(), "linked")); err != nil {
					t.Fatal(err)
				}
			case "source-oversize":
				if err := os.WriteFile(path, bytes.Repeat([]byte("x"), maximumActivationInputBytes+1), 0600); err != nil {
					t.Fatal(err)
				}
			case "directory-replaced":
				if err := os.Rename(filepath.Join(root, "modules"), filepath.Join(root, "saved")); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(filepath.Join(root, "modules"), 0700); err != nil {
					t.Fatal(err)
				}
			case "receipt-mode":
				// #nosec G302 -- deliberate nonprivate receipt mode verifies fail-closed startup.
				if err := os.Chmod(receipt, 0640); err != nil {
					t.Fatal(err)
				}
			case "receipt-link":
				if err := os.Rename(receipt, receipt+".saved"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(receipt+".saved", receipt); err != nil {
					t.Fatal(err)
				}
			case "receipt-hardlink":
				if err := os.Link(receipt, filepath.Join(t.TempDir(), "linked")); err != nil {
					t.Fatal(err)
				}
			case "state-extra":
				if err := os.WriteFile(filepath.Join(store, "unrecognized"), []byte("keep"), 0600); err != nil {
					t.Fatal(err)
				}
			case "environment":
				t.Setenv("SYSWARDEN_INTEGRATIONS_SAAS_ENABLED", "")
			case "retirement":
				if err := os.WriteFile(filepath.Join(filepath.Dir(store), activationRetirementName), []byte("retain"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := loadApprovedConfigDirectory(t.Context(), root, store, activationFixtureOwnerUID(t)); err == nil {
				t.Fatal("unapproved core startup accepted")
			}
			if viper.GetString("core.log_level") != "LAST_VALID" {
				t.Fatal("refusal published partial runtime config")
			}
		})
	}
}

func TestCoreActivationStartupCannotUseInspectionLoader(t *testing.T) {
	files := token.NewFileSet()
	current, err := parser.ParseFile(files, "config.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, decl := range current.Decls {
		function, ok := decl.(*ast.FuncDecl)
		if !ok || function.Name.Name != "LoadConfig" {
			continue
		}
		ast.Inspect(function.Body, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			name, ok := call.Fun.(*ast.Ident)
			if !ok {
				return true
			}
			if name.Name == "LoadConfigDirectory" || name.Name == "loadConfigDirectory" {
				t.Fatal("production startup bypasses approval with inspection loader")
			}
			if name.Name == "loadApprovedConfigDirectory" {
				found = true
			}
			return true
		})
	}
	if !found {
		t.Fatal("production LoadConfig does not consume approval")
	}
	mainFile, err := parser.ParseFile(files, "../main.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	loadPosition := token.NoPos
	firstMutation := token.NoPos
	ast.Inspect(mainFile, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if selector.Sel.Name == "LoadConfig" {
			loadPosition = call.Pos()
		}
		switch selector.Sel.Name {
		case "ReserveHAStartupLease", "MkdirAll", "NewManager":
			if firstMutation == token.NoPos || call.Pos() < firstMutation {
				firstMutation = call.Pos()
			}
		case "LoadConfigDirectory":
			t.Fatal("core main calls unapproved inspection loader")
		}
		return true
	})
	if loadPosition == token.NoPos || firstMutation == token.NoPos || loadPosition >= firstMutation {
		t.Fatal("core mutation precedes approved configuration")
	}
}

func TestCoreActivationContractReaderMatchesCLI(t *testing.T) {
	core, err := os.ReadFile("activation_contract_linux.go")
	if err != nil {
		t.Fatal(err)
	}
	cli, err := os.ReadFile("../../syswarden-cli/config/activation_contract_linux.go")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(core, cli) {
		t.Fatal("independent consumers disagree on activation wire contract")
	}
}
