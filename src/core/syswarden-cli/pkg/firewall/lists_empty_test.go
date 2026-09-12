package firewall

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestFinalListRemovalPersistsCanonicalEmptyFile_SW_GRC_017(t *testing.T) {
	for _, address := range []string{"192.0.2.10", "2001:db8::10"} {
		for _, operation := range []struct {
			name string
			run  func(approvedListFile, string) error
		}{
			{name: "exact removal", run: removeFromListFileAt},
			{name: "IP removal", run: func(target approvedListFile, address string) error {
				found, changed, err := removeIPFromListFileAt(target, address)
				if err == nil && (!found || !changed) {
					return fmt.Errorf("final address removal did not report the committed change")
				}
				return err
			}},
		} {
			t.Run(operation.name+"/"+address, func(t *testing.T) {
				target := approvedListFile{directory: t.TempDir(), name: "list"}
				if err := writeListFileAt(target, []byte(address+"\n")); err != nil {
					t.Fatal(err)
				}
				if err := operation.run(target, address); err != nil {
					t.Fatal(err)
				}
				assertCanonicalEmptyListFile(t, target)
				if err := addToListFileAt(target, address); err != nil {
					t.Fatal(err)
				}
				content, err := readListFileAt(target)
				if err != nil || string(content) != address+"\n" {
					t.Fatalf("readding an address after emptying the list = %q, error=%v", content, err)
				}
			})
		}
	}
}

func TestEmptyListTransactionsPreserveRollback_SW_GRC_017(t *testing.T) {
	for _, test := range []struct {
		name string
		seed string
		run  func(approvedListFile) (transactionalListMutation, error)
	}{
		{name: "remove final address", seed: "192.0.2.10\n", run: func(target approvedListFile) (transactionalListMutation, error) {
			return removeFromListFileTransactionally(target, "192.0.2.10")
		}},
		{name: "sanitize final unsafe entry", seed: "0.0.0.0/0\n", run: sanitizeLegacyListFileTransactionally},
	} {
		t.Run(test.name, func(t *testing.T) {
			target := approvedListFile{directory: t.TempDir(), name: "list"}
			if err := writeListFileAt(target, []byte(test.seed)); err != nil {
				t.Fatal(err)
			}
			mutation, err := test.run(target)
			if err != nil || !mutation.changed {
				t.Fatalf("list transaction = %#v, error=%v", mutation, err)
			}
			assertCanonicalEmptyListFile(t, target)
			if err := rollbackTransactionalListMutation(mutation); err != nil {
				t.Fatal(err)
			}
			content, err := readListFileAt(target)
			if err != nil || string(content) != test.seed {
				t.Fatalf("rollback did not restore the exact preimage: %q, error=%v", content, err)
			}
		})
	}
}

func TestSanitizingFinalUnsafeEntryPersistsEmptyFile_SW_GRC_017(t *testing.T) {
	target := approvedListFile{directory: t.TempDir(), name: "list"}
	if err := writeListFileAt(target, []byte("0.0.0.0/0\n")); err != nil {
		t.Fatal(err)
	}
	changed, err := sanitizeLegacyListFileAt(target)
	if err != nil || !changed {
		t.Fatalf("sanitize final entry changed=%t, error=%v", changed, err)
	}
	assertCanonicalEmptyListFile(t, target)
}

func assertCanonicalEmptyListFile(t *testing.T, target approvedListFile) {
	t.Helper()
	content, err := readListFileAt(target)
	if err != nil || len(content) != 0 {
		t.Fatalf("last-entry removal must leave an existing zero-byte list for strict GRC reads: content=%q, error=%v", content, err)
	}
	info, err := os.Stat(filepath.Join(target.directory, target.name))
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		t.Fatalf("empty list metadata is not protected: mode=%v", info.Mode())
	}
}
