package journal

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func testAuthorityLaunch(t testing.TB) AuthorityLaunch {
	t.Helper()
	_, _, root := signTestPolicy(t, testCustodyPolicy())
	return AuthorityLaunch{ServiceUID: processServiceID, ServiceGID: processServiceID, EndpointGID: processClientID, PolicyRoot: root, Enrollment: testEnrollment(), Limits: testLimits(), Transport: testTransportLimits(), AcceptInterval: MinAuthorityAcceptInterval}
}
func launchBytes(t testing.TB, c AuthorityLaunch) []byte {
	t.Helper()
	data, err := EncodeAuthorityLaunch(c)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
func denyLaunch(t testing.TB, data []byte) {
	t.Helper()
	got, err := DecodeAuthorityLaunch(data)
	if !errors.Is(err, ErrAuthorityLaunch) || !reflect.DeepEqual(got, AuthorityLaunch{}) {
		t.Fatal("invalid launch exposed configuration", err)
	}
}
func TestAuthorityLaunchCanonicalTrustAndOwnership(t *testing.T) {
	c := testAuthorityLaunch(t)
	data := launchBytes(t, c)
	got, err := DecodeAuthorityLaunch(data)
	if err != nil || !reflect.DeepEqual(got, c) {
		t.Fatal("launch round trip", err)
	}
	got.PolicyRoot.IssuerPublicKey[0] ^= 1
	got.Enrollment.Authority.PublicKey[0] ^= 1
	if !bytes.Equal(launchBytes(t, c), data) {
		t.Fatal("decoded values alias input trust")
	}
	for _, enabled := range []bool{false, true} {
		c.PolicyRoot.Enabled = enabled
		data = launchBytes(t, c)
		got, err = DecodeAuthorityLaunch(data)
		if err != nil || got.PolicyRoot.Enabled != enabled {
			t.Fatal("explicit enabled state", err)
		}
	}
}
func TestAuthorityLaunchRejectsUnsafeConfiguration(t *testing.T) {
	cases := map[string]func(*AuthorityLaunch){
		"root-service":         func(c *AuthorityLaunch) { c.ServiceUID = 0 },
		"root-group":           func(c *AuthorityLaunch) { c.ServiceGID = 0 },
		"root-endpoint-group":  func(c *AuthorityLaunch) { c.EndpointGID = 0 },
		"invalid-uid":          func(c *AuthorityLaunch) { c.ServiceUID = 1 << 31 },
		"invalid-gid":          func(c *AuthorityLaunch) { c.ServiceGID = 1 << 31 },
		"invalid-endpoint-gid": func(c *AuthorityLaunch) { c.EndpointGID = 1 << 31 },
		"changed-root":         func(c *AuthorityLaunch) { c.PolicyRoot.Initial.NextSequence++ },
		"same-key":             func(c *AuthorityLaunch) { c.PolicyRoot.IssuerPublicKey = c.Enrollment.Authority.PublicKey },
		"empty-key":            func(c *AuthorityLaunch) { c.PolicyRoot.IssuerPublicKey = nil },
		"invalid-digest":       func(c *AuthorityLaunch) { c.PolicyRoot.PolicySHA256 = "x" },
		"invalid-enrollment":   func(c *AuthorityLaunch) { c.Enrollment.Authority.LastSequence = 0 },
		"zero-bytes":           func(c *AuthorityLaunch) { c.Limits.MaxBytes = 0 },
		"negative-frames":      func(c *AuthorityLaunch) { c.Limits.MaxFrames = -1 },
		"zero-peers":           func(c *AuthorityLaunch) { c.Transport.MaxPeers = 0 },
		"uid-capacity":         func(c *AuthorityLaunch) { c.Transport.MaxPeersPerUID = c.Transport.MaxPeers + 1 },
		"read-timeout":         func(c *AuthorityLaunch) { c.Transport.ReadTimeout = 0 },
		"write-timeout":        func(c *AuthorityLaunch) { c.Transport.WriteTimeout = MaxAuthorityIOTimeout + 1 },
		"request-budget":       func(c *AuthorityLaunch) { c.Transport.RequestsPerUID = MaxAuthorityRequestsPerWindow + 1 },
		"history-budget":       func(c *AuthorityLaunch) { c.Transport.MaxRateUIDs = 0 },
		"rate-window":          func(c *AuthorityLaunch) { c.Transport.RateWindow = time.Nanosecond },
		"accept-interval":      func(c *AuthorityLaunch) { c.AcceptInterval = 0 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			c := testAuthorityLaunch(t)
			mutate(&c)
			if b, err := EncodeAuthorityLaunch(c); b != nil || !errors.Is(err, ErrAuthorityLaunch) {
				t.Fatal("unsafe launch encoded", err)
			}
		})
	}
}
func TestAuthorityLaunchRejectsAmbiguousEncoding(t *testing.T) {
	data := launchBytes(t, testAuthorityLaunch(t))
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(data, &obj); err != nil {
		t.Fatal(err)
	}
	for name := range obj {
		t.Run("missing-"+name, func(t *testing.T) {
			var w map[string]json.RawMessage
			_ = json.Unmarshal(data, &w)
			delete(w, name)
			b, err := json.Marshal(w)
			if err != nil {
				t.Fatal(err)
			}
			denyLaunch(t, b)
		})
	}
	for name, b := range map[string][]byte{
		"nil": nil, "empty": {}, "oversized": bytes.Repeat([]byte{' '}, MaxAuthorityLaunchBytes+1),
		"trailing": append(bytes.Clone(data), '\n'), "unknown": bytes.Replace(data, []byte(`{"schema"`), []byte(`{"unknown":true,"schema"`), 1),
		"duplicate":    bytes.Replace(data, []byte(`"service_uid":"65533"`), []byte(`"service_uid":"65533","service_uid":"65533"`), 1),
		"null":         bytes.Replace(data, []byte(`"enabled":true`), []byte(`"enabled":null`), 1),
		"leading-zero": bytes.Replace(data, []byte(`"service_uid":"65533"`), []byte(`"service_uid":"065533"`), 1),
		"number":       bytes.Replace(data, []byte(`"service_uid":"65533"`), []byte(`"service_uid":65533`), 1),
		"overflow":     bytes.Replace(data, []byte(`"service_uid":"65533"`), []byte(`"service_uid":"18446744073709551616"`), 1),
		"schema":       bytes.Replace(data, []byte(AuthorityLaunchSchema), []byte("syswarden.authority-launch.v2"), 1),
	} {
		t.Run(name, func(t *testing.T) { denyLaunch(t, b) })
	}
	var w authorityLaunchWire
	var err error
	if err := json.Unmarshal(data, &w); err != nil {
		t.Fatal(err)
	}
	w.Enrollment.Head, err = encodeAnchor(syntheticIntent().After)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(w)
	if err != nil {
		t.Fatal(err)
	}
	denyLaunch(t, b)
}

func testAuthorityLaunchProtectedFile(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatal("requires isolated root for root-owned launch-file assertions")
	}
	data := launchBytes(t, testAuthorityLaunch(t))
	digest := recoveryDigest(data)
	for _, kind := range []string{"valid", "nil", "closed", "writable-fd", "wrong-owner", "wrong-group", "mode", "special-mode", "hardlink", "acl", "directory", "fifo", "empty", "oversized", "corrupt", "wrong-digest", "uppercase-digest", "service-identity"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "launch.json")
			contents := bytes.Clone(data)
			if kind == "empty" {
				contents = nil
			}
			if kind == "oversized" {
				contents = bytes.Repeat([]byte{'a'}, MaxAuthorityLaunchBytes+1)
			}
			if kind == "corrupt" {
				contents[0] = 'x'
			}
			if err := os.WriteFile(path, contents, 0400); err != nil {
				t.Fatal(err)
			}
			flags := os.O_RDONLY
			var err error
			switch kind {
			case "writable-fd":
				flags = os.O_RDWR
			case "wrong-owner":
				err = os.Chown(path, 1, 0)
			case "wrong-group":
				err = os.Chown(path, 0, 1)
			case "mode":
				err = os.Chmod(path, 0600)
			case "special-mode":
				err = os.Chmod(path, 0400|os.ModeSetuid)
			case "hardlink":
				err = os.Link(path, filepath.Join(dir, "alias"))
			case "acl":
				authorityTestACL(t, path, "system.posix_acl_access")
			case "fifo":
				path = filepath.Join(dir, "pipe")
				err = unix.Mkfifo(path, 0400)
				flags |= unix.O_NONBLOCK
			}
			if err != nil {
				t.Fatal(err)
			}
			fixtureRoot, err := os.OpenRoot(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = fixtureRoot.Close() }()
			name := "launch.json"
			if kind == "directory" {
				name = "."
			}
			if kind == "fifo" {
				name = "pipe"
			}
			f, err := fixtureRoot.OpenFile(name, flags, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = f.Close() }()
			input := f
			expected := digest
			if kind == "nil" {
				input = nil
			}
			if kind == "closed" {
				_ = f.Close()
			}
			if kind == "wrong-digest" {
				expected = strings.Repeat("0", 64)
			}
			if kind == "uppercase-digest" {
				expected = strings.ToUpper(digest)
			}
			before := layoutSnapshot(t, dir)
			got, err := LoadAuthorityLaunch(input, expected)
			if kind == "valid" || kind == "service-identity" {
				if err != nil || !reflect.DeepEqual(got, testAuthorityLaunch(t)) {
					t.Fatal("trusted launch rejected", err)
				}
				if pos, err := f.Seek(0, 1); err != nil || pos != 0 {
					t.Fatal("loader changed descriptor offset", pos, err)
				}
				if kind == "service-identity" {
					if s, err := OpenAuthorityFromLaunch(f, digest, nil, nil, time.Now, nil, nil); s != nil || !errors.Is(err, ErrAuthorityLaunch) {
						t.Fatal("wrong service identity admitted", err)
					}
				}
			} else if !errors.Is(err, ErrAuthorityLaunch) || !reflect.DeepEqual(got, AuthorityLaunch{}) {
				t.Fatal("unsafe launch file accepted", err)
			}
			if !reflect.DeepEqual(before, layoutSnapshot(t, dir)) {
				t.Fatal("read-only launch load changed state")
			}
		})
	}
}

func FuzzAuthorityLaunchDecode(f *testing.F) {
	f.Add(launchBytes(f, testAuthorityLaunch(f)))
	f.Add([]byte(`{"schema":"unknown"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		got, err := DecodeAuthorityLaunch(data)
		if err != nil {
			if !reflect.DeepEqual(got, AuthorityLaunch{}) {
				t.Fatal("failure exposed launch")
			}
			return
		}
		encoded, err := EncodeAuthorityLaunch(got)
		if err != nil || !bytes.Equal(data, encoded) {
			t.Fatal("accepted noncanonical launch", err)
		}
	})
}
