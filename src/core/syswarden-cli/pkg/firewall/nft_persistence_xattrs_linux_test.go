//go:build linux

package firewall

import (
	"bytes"
	"os"
	"reflect"
	"testing"

	"golang.org/x/sys/unix"
)

func TestNFTPersistenceXattrsPreserveExactAdministratorMetadata(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	files := make(map[string]*os.File)
	for _, name := range []string{"original", "candidate"} {
		file, err := root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = file.Close() })
		files[name] = file
	}
	original, candidate := files["original"], files["candidate"]
	for _, attr := range []nftPersistenceXattr{{"user.administrator", []byte("preserved")}, {"user.binary", []byte{0, 1, 2, 255}}, {"user.empty", []byte{}}} {
		if err := unix.Fsetxattr(int(original.Fd()), attr.Name, attr.Value, 0); err != nil {
			t.Fatal("fixture filesystem must support user extended attributes", err)
		}
	}
	if err := unix.Fsetxattr(int(candidate.Fd()), "user.inherited", []byte("candidate only"), 0); err != nil {
		t.Fatal(err)
	}
	expected, err := readNFTPersistenceXattrs(original)
	if err != nil || len(expected) < 3 {
		t.Fatal(err)
	}
	for _, name := range []string{"user.administrator", "user.binary", "user.empty"} {
		found := false
		for _, attr := range expected {
			found = found || attr.Name == name
		}
		if !found {
			t.Fatal("fixture attribute was not inspected", name)
		}
	}
	before := nftPersistenceXattrDigest(expected)
	if err := copyNFTPersistenceXattrs(candidate, expected); err != nil {
		t.Fatal(err)
	}
	actual, err := readNFTPersistenceXattrs(candidate)
	if err != nil || !reflect.DeepEqual(expected, actual) || nftPersistenceXattrDigest(actual) != before {
		t.Fatal("extended attributes were dropped or changed", err)
	}
	retained, err := readNFTPersistenceXattrs(original)
	if err != nil || !reflect.DeepEqual(retained, expected) {
		t.Fatal("copy changed the active original's metadata", err)
	}
	if err := unix.Fsetxattr(int(candidate.Fd()), "user.administrator", bytes.Repeat([]byte{1}, 17), 0); err != nil {
		t.Fatal(err)
	}
	changed, err := readNFTPersistenceXattrs(candidate)
	if err != nil || nftPersistenceXattrDigest(changed) == before {
		t.Fatal("changed metadata retained its attested digest", err)
	}
	if attrs, err := readNFTPersistenceXattrs(nil); err == nil || attrs != nil {
		t.Fatal("missing file was treated as metadata absence")
	}
}
