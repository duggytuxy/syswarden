package journal

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func provisionedFixture(t *testing.T) (authorityFixtureState, AuthorityServerConfig, *os.File, string, string) {
	t.Helper()
	f, c, endpoint := serverFixture(t)
	root, path := testDirectory(t)
	old := []string{f.policyPath, f.custodyPath, f.files.anchorPath, f.files.journalPath, filepath.Clean(c.PinDirectory.Name())}
	for i, name := range authorityLayoutNames() {
		if err := os.Rename(old[i], filepath.Join(path, name)); err != nil {
			t.Fatal(err)
		}
	}
	f.policyPath, f.custodyPath = filepath.Join(path, "policy"), filepath.Join(path, "custody")
	f.files.anchorPath, f.files.journalPath = filepath.Join(path, "anchors"), filepath.Join(path, "journal")
	c.Authority.PolicyDirectory, c.Authority.CustodyDirectory = nil, nil
	c.Authority.AnchorDirectory, c.Authority.JournalDirectory, c.PinDirectory = nil, nil, nil
	return f, c, root, path, endpoint
}

func provisionedServer(t *testing.T, root *os.File, c AuthorityServerConfig) *LocalAuthorityServer {
	t.Helper()
	s, err := OpenProvisionedAuthorityServer(root, c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func layoutSnapshot(t *testing.T, roots ...string) map[string]adversarialFileState {
	t.Helper()
	var paths []string
	for _, root := range roots {
		if err := filepath.WalkDir(root, func(path string, _ fs.DirEntry, err error) error {
			paths = append(paths, path)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	return endpointRecoverySnapshot(t, paths)
}

func TestProvisionedAuthorityOwnsDirectoriesAndReopens(t *testing.T) {
	f, c, root, path, endpoint := provisionedFixture(t)
	canary := filepath.Join(path, "administrator-note")
	if err := os.WriteFile(canary, []byte("preserve unrelated data"), 0600); err != nil {
		t.Fatal(err)
	}
	s := provisionedServer(t, root, c)
	if second, err := OpenProvisionedAuthorityServer(root, c); second != nil || !errors.Is(err, ErrLocked) {
		t.Fatal("provisioned root lease was not exclusive", err)
	}
	if err := errors.Join(root.Close(), c.Directory.Close()); err != nil {
		t.Fatal(err)
	}
	done := runServer(s)
	authorityAnchor(t, serverRequest(t, endpoint, authorityRequest{Operation: "resume"}), f.files.expected)
	authorityAnchor(t, serverRequest(t, endpoint, authorityRequest{Operation: "commit", Segment: testName}), f.files.next)
	stopServer(t, s, done)
	if string(readFile(t, canary)) != "preserve unrelated data" {
		t.Fatal("startup or shutdown changed unrelated content")
	}
	root, err := openFixtureDirectory(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	c.Directory, err = openFixtureDirectory(filepath.Dir(endpoint))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Directory.Close() }()
	s = provisionedServer(t, root, c)
	done = runServer(s)
	authorityAnchor(t, serverRequest(t, endpoint, authorityRequest{Operation: "resume"}), f.files.next)
	stopServer(t, s, done)
	for _, name := range authorityLayoutNames() {
		if st, err := os.Stat(filepath.Join(path, name)); err != nil || !st.IsDir() {
			t.Fatal("shutdown removed provisioned directory", name, err)
		}
	}
}

func TestProvisionedAuthorityRejectsUnsafeStartupWithoutChanges(t *testing.T) {
	for _, kind := range []string{"nil-root", "closed-root", "root-mode", "root-sticky", "root-acl", "root-default-acl", "missing-child", "file-child", "fifo-child", "symlink-child", "alias-child", "child-mode", "child-acl", "child-default-acl", "conflicting-policy", "conflicting-custody", "conflicting-anchor", "conflicting-journal", "conflicting-pin", "wrong-policy-root", "stale-pin", "stale-endpoint"} {
		t.Run(kind, func(t *testing.T) {
			f, c, root, path, endpoint := provisionedFixture(t)
			input := root
			child := filepath.Join(path, "journal")
			var err error
			switch kind {
			case "nil-root":
				input = nil
			case "closed-root":
				err = root.Close()
			case "root-mode":
				err = chmodFixture(path, 0750)
			case "root-sticky":
				err = chmodFixture(path, 0700|os.ModeSticky)
			case "root-acl", "root-default-acl":
				name := "system.posix_acl_access"
				if kind == "root-default-acl" {
					name = "system.posix_acl_default"
				}
				authorityTestACL(t, path, name)
			case "missing-child", "file-child", "fifo-child", "symlink-child", "alias-child":
				if err = os.Rename(child, child+".preserved"); err != nil {
					t.Fatal(err)
				}
				switch kind {
				case "file-child":
					err = os.WriteFile(child, []byte("preserve"), 0600)
				case "fifo-child":
					err = unix.Mkfifo(child, 0600)
				case "symlink-child":
					err = os.Symlink(child+".preserved", child)
				case "alias-child":
					err = os.Symlink("anchors", child)
				}
			case "child-mode":
				err = chmodFixture(child, 0750)
			case "child-acl", "child-default-acl":
				name := "system.posix_acl_access"
				if kind == "child-default-acl" {
					name = "system.posix_acl_default"
				}
				authorityTestACL(t, child, name)
			case "conflicting-policy":
				c.Authority.PolicyDirectory = f.config.PolicyDirectory
			case "conflicting-custody":
				c.Authority.CustodyDirectory = f.config.CustodyDirectory
			case "conflicting-anchor":
				c.Authority.AnchorDirectory = f.config.AnchorDirectory
			case "conflicting-journal":
				c.Authority.JournalDirectory = f.config.JournalDirectory
			case "conflicting-pin":
				c.PinDirectory = root
			case "wrong-policy-root":
				c.Authority.PolicyRoot = clonePolicyTrust(c.Authority.PolicyRoot)
				c.Authority.PolicyRoot.IssuerPublicKey[0] ^= 1
			case "stale-pin":
				err = os.WriteFile(filepath.Join(path, "endpoint-pin", AuthorityEndpointPinName), []byte("preserve"), 0600)
			case "stale-endpoint":
				err = os.WriteFile(endpoint, []byte("preserve"), 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			before := layoutSnapshot(t, path, filepath.Dir(endpoint))
			fds, err := os.ReadDir("/proc/self/fd")
			if err != nil {
				t.Fatal(err)
			}
			if server, err := OpenProvisionedAuthorityServer(input, c); server != nil || err == nil {
				t.Fatal("unsafe provisioned startup admitted", err)
			}
			if after := layoutSnapshot(t, path, filepath.Dir(endpoint)); !reflect.DeepEqual(before, after) {
				t.Fatal("failed startup changed bytes, metadata or inventory")
			}
			afterFDs, err := os.ReadDir("/proc/self/fd")
			if err != nil || len(afterFDs) != len(fds) {
				t.Fatal("failed startup retained descriptors", err)
			}
			probe, err := openFixtureDirectory(path)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = probe.Close() }()
			if err := unix.Flock(int(probe.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
				t.Fatal("failed startup retained root lease", err)
			}
		})
	}
}

func TestProvisionedAuthorityRejectsChildReplacementBeforeServing(t *testing.T) {
	f, c, root, path, endpoint := provisionedFixture(t)
	s := provisionedServer(t, root, c)
	before := f.bytes(t)
	original := filepath.Join(path, "anchors.preserved")
	if err := os.Rename(f.files.anchorPath, original); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(f.files.anchorPath, 0700); err != nil {
		t.Fatal(err)
	}
	f.files.anchorPath = original
	if err := s.Serve(); !errors.Is(err, ErrUnsafeStorage) {
		t.Fatal("replaced child admitted a worker", err)
	}
	if !reflect.DeepEqual(before, f.bytes(t)) || s.Status().Accepted != 0 {
		t.Fatal("replaced child changed authority state")
	}
	entries, err := os.ReadDir(filepath.Join(path, "anchors"))
	if err != nil || len(entries) != 0 {
		t.Fatal("replacement directory was adopted", err)
	}
	if _, err := os.Lstat(endpoint); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("failed server retained its owned endpoint", err)
	}
}

func TestProvisionedAuthorityRetainsRootLeaseThroughDrain(t *testing.T) {
	f, c, root, _, endpoint := provisionedFixture(t)
	s := provisionedServer(t, root, c)
	request := authorityRequest{Operation: "inspect-policy", Change: &authorityChange{Operation: "disable"}}
	plan := authorityReply(t, s.transport.authority, f.peer, request)
	f.administrator.approved = plan.PlanSHA256
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	f.administrator.hook = func(_ PolicyAdministrationRequest, _ *PolicyAdministrationDecision) error {
		close(entered)
		<-release
		return nil
	}
	done := runServer(s)
	peer := serverClient(t, endpoint)
	request.Operation, request.PlanSHA256 = "apply-policy", plan.PlanSHA256
	transportSend(t, peer, transportFrame(authorityMessage(t, request)))
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("approved operation did not enter")
	}
	if !errors.Is(s.Close(), ErrAuthorityServerBusy) {
		t.Fatal("drain did not remain busy")
	}
	if next, err := openAuthorityLayout(root); next != nil || !errors.Is(err, ErrLocked) {
		t.Fatal("drain released the provisioning root lease", err)
	}
	once.Do(func() { close(release) })
	if err := transportResult(t, done); err != nil {
		t.Fatal(err)
	}
	l, err := openAuthorityLayout(root)
	if err != nil {
		t.Fatal("completed drain retained root lease", err)
	}
	if err := l.close(); err != nil {
		t.Fatal(err)
	}
	policy, err := OpenLocalCustodyPolicy(f.config.PolicyDirectory, f.root.Trust)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = policy.Close() }()
	if policyCurrent(t, policy).Trust.Enabled {
		t.Fatal("drain cancelled the approved operation")
	}
}
