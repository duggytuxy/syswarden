//go:build linux

package sshpolicy

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
)

type sshAuthorityFixture struct {
	f    *inventoryFixture
	doc  sshAccessAuthorityDocument
	wire []byte
	now  time.Time
}

func newSSHAuthorityFixture(t *testing.T) *sshAuthorityFixture {
	t.Helper()
	// These deterministic keys are synthetic test data, never credentials.
	controller := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	key, err := ssh.NewPublicKey(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, ed25519.SeedSize)).Public())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1800000000, 0)
	target := sshAccessPin{Address: "127.0.0.1:2222", User: "operator", HostKey: key.Marshal(), ClientKey: key.Marshal()}
	jump := target
	jump.Address = "127.0.0.1:2223"
	x := &sshAuthorityFixture{f: newInventoryFixture(t, "# Synthetic authority fixture.\n"), now: now,
		doc: sshAccessAuthorityDocument{Schema: 1, Domain: sshAccessAuthorityDomain, Scope: "activation-access",
			PlanSHA256: strings.Repeat("a", 64), Controller: controller,
			Routes:    []sshAccessAuthorityRoute{{ContextID: "second", Target: target, Jump: &jump}, {ContextID: "first", Target: target}},
			NotBefore: now.Unix() - 60, ExpiresAt: now.Unix() + 600}}
	x.write(t)
	return x
}

func (x *sshAuthorityFixture) write(t *testing.T) {
	t.Helper()
	var err error
	x.wire, err = json.Marshal(x.doc)
	if err != nil {
		t.Fatal(err)
	}
	x.f.write(sshAccessAuthorityPath, string(x.wire))
}

func (x *sshAuthorityFixture) open(t *testing.T) *sshAccessAuthority {
	t.Helper()
	authority, err := openSSHAccessAuthority(x.f.root, os.Geteuid(), x.doc.PlanSHA256, digestBytes(x.wire), func() time.Time { return x.now })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = authority.Close() })
	return authority
}

func TestSSHAccessAuthorityRetainsApprovedEnrollment(t *testing.T) {
	x := newSSHAuthorityFixture(t)
	authority := x.open(t)
	if authority.plan != x.doc.PlanSHA256 || authority.digest != digestBytes(x.wire) ||
		!bytes.Equal(authority.controller, x.doc.Controller) || !bytes.Equal(authority.image.data, x.wire) ||
		authority.notBefore != x.doc.NotBefore || authority.expiresAt != x.doc.ExpiresAt || len(authority.ancestors) != 3 ||
		len(authority.pins) != 2 || authority.pins[0].ContextID != "second" || authority.pins[0].Jump == nil ||
		authority.pins[1].ContextID != "first" || authority.pins[1].Jump != nil {
		t.Fatal("approved enrollment identity, window or ordered public route pins were not retained")
	}
	before := bytes.Clone(authority.pins[0].Target.HostKey)
	x.doc.Controller[0] ^= 1
	x.doc.Routes[0].Target.HostKey[0] ^= 1
	if bytes.Equal(authority.controller, x.doc.Controller) || !bytes.Equal(authority.pins[0].Target.HostKey, before) {
		t.Fatal("caller-owned public keys alias retained authority")
	}
	if err := x.f.root.Close(); err != nil {
		t.Fatal(err)
	}
	if err := authority.recheck(); err != nil {
		t.Fatal("authority depends on caller's root descriptor", err)
	}
	if err := authority.Close(); err != nil {
		t.Fatal(err)
	}
	if err := authority.Close(); err != nil || !errors.Is(authority.recheck(), ErrInventoryClosed) {
		t.Fatal("closed authority remained usable or close was not idempotent")
	}
	var absent *sshAccessAuthority
	if absent.Close() != nil || !errors.Is(absent.recheck(), ErrInventoryClosed) {
		t.Fatal("nil authority handling is unsafe")
	}
}

func TestSSHAccessAuthorityRefusesInvalidDocument(t *testing.T) {
	cases := map[string]func(*sshAccessAuthorityDocument){
		"schema":                 func(d *sshAccessAuthorityDocument) { d.Schema = 2 },
		"domain":                 func(d *sshAccessAuthorityDocument) { d.Domain += "-other" },
		"scope":                  func(d *sshAccessAuthorityDocument) { d.Scope = "recovery-access" },
		"plan":                   func(d *sshAccessAuthorityDocument) { d.PlanSHA256 = strings.Repeat("b", 64) },
		"controller-private-key": func(d *sshAccessAuthorityDocument) { d.Controller = make([]byte, ed25519.PrivateKeySize) },
		"controller-missing":     func(d *sshAccessAuthorityDocument) { d.Controller = nil },
		"routes-missing":         func(d *sshAccessAuthorityDocument) { d.Routes = nil },
		"routes-empty":           func(d *sshAccessAuthorityDocument) { d.Routes = []sshAccessAuthorityRoute{} },
		"routes-excess":          func(d *sshAccessAuthorityDocument) { d.Routes = make([]sshAccessAuthorityRoute, MaxAccessContexts+1) },
		"duplicate-context":      func(d *sshAccessAuthorityDocument) { d.Routes[1].ContextID = d.Routes[0].ContextID },
		"invalid-context":        func(d *sshAccessAuthorityDocument) { d.Routes[0].ContextID = "Invalid" },
		"target-hostname":        func(d *sshAccessAuthorityDocument) { d.Routes[0].Target.Address = "localhost:22" },
		"target-zero-port":       func(d *sshAccessAuthorityDocument) { d.Routes[0].Target.Address = "127.0.0.1:0" },
		"target-user":            func(d *sshAccessAuthorityDocument) { d.Routes[0].Target.User = "invalid user" },
		"target-host-key":        func(d *sshAccessAuthorityDocument) { d.Routes[0].Target.HostKey = []byte("invalid") },
		"target-client-key":      func(d *sshAccessAuthorityDocument) { d.Routes[0].Target.ClientKey = nil },
		"jump-host-key":          func(d *sshAccessAuthorityDocument) { d.Routes[0].Jump.HostKey = nil },
		"jump-same-address":      func(d *sshAccessAuthorityDocument) { d.Routes[0].Jump.Address = d.Routes[0].Target.Address },
		"zero-not-before":        func(d *sshAccessAuthorityDocument) { d.NotBefore = 0 },
		"negative-not-before":    func(d *sshAccessAuthorityDocument) { d.NotBefore = -1 },
		"empty-window":           func(d *sshAccessAuthorityDocument) { d.ExpiresAt = d.NotBefore },
		"reversed-window":        func(d *sshAccessAuthorityDocument) { d.ExpiresAt = d.NotBefore - 1 },
		"not-yet-valid":          func(d *sshAccessAuthorityDocument) { d.NotBefore += 61 },
		"expired":                func(d *sshAccessAuthorityDocument) { d.ExpiresAt -= 600 },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			x := newSSHAuthorityFixture(t)
			plan := x.doc.PlanSHA256
			change(&x.doc)
			x.write(t)
			authority, err := openSSHAccessAuthority(x.f.root, os.Geteuid(), plan, digestBytes(x.wire), func() time.Time { return x.now })
			if err == nil || authority != nil {
				_ = authority.Close()
				t.Fatal("invalid independently approved enrollment was accepted")
			}
		})
	}
}

func TestSSHAccessAuthorityRequiresExactCanonicalJSON(t *testing.T) {
	cases := map[string]func([]byte) []byte{
		"newline":    func(w []byte) []byte { return append(w, '\n') },
		"whitespace": func(w []byte) []byte { return append([]byte(" "), w...) },
		"unknown": func(w []byte) []byte {
			return bytes.Replace(w, []byte(`"schema":1`), []byte(`"extra":true,"schema":1`), 1)
		},
		"duplicate": func(w []byte) []byte {
			return bytes.Replace(w, []byte(`"schema":1`), []byte(`"schema":1,"schema":1`), 1)
		},
		"case-folded": func(w []byte) []byte { return bytes.Replace(w, []byte(`"schema":1`), []byte(`"Schema":1`), 1) },
		"missing":     func(w []byte) []byte { return bytes.Replace(w, []byte(`"scope":"activation-access",`), nil, 1) },
		"null-jump": func(w []byte) []byte {
			return bytes.Replace(w, []byte(`"context_id":"first",`), []byte(`"context_id":"first","jump":null,`), 1)
		},
		"trailing-value": func(w []byte) []byte { return append(w, []byte(`{}`)...) },
		"empty":          func([]byte) []byte { return nil },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			x := newSSHAuthorityFixture(t)
			wire := change(bytes.Clone(x.wire))
			x.f.write(sshAccessAuthorityPath, string(wire))
			authority, err := openSSHAccessAuthority(x.f.root, os.Geteuid(), x.doc.PlanSHA256, digestBytes(wire), func() time.Time { return x.now })
			if err == nil || authority != nil {
				_ = authority.Close()
				t.Fatal("noncanonical independently approved enrollment was accepted")
			}
		})
	}
}

func TestSSHAccessAuthorityRequiresIndependentApprovalAndInputs(t *testing.T) {
	x := newSSHAuthorityFixture(t)
	clock := func() time.Time { return x.now }
	cases := []struct {
		root           *os.File
		uid            int
		plan, approved string
		clock          func() time.Time
	}{
		{nil, os.Geteuid(), x.doc.PlanSHA256, digestBytes(x.wire), clock},
		{x.f.root, -1, x.doc.PlanSHA256, digestBytes(x.wire), clock},
		{x.f.root, os.Geteuid(), "", digestBytes(x.wire), clock},
		{x.f.root, os.Geteuid(), x.doc.PlanSHA256, "", clock},
		{x.f.root, os.Geteuid(), x.doc.PlanSHA256, strings.Repeat("b", 64), clock},
		{x.f.root, os.Geteuid(), x.doc.PlanSHA256, strings.ToUpper(digestBytes(x.wire)), clock},
		{x.f.root, os.Geteuid(), x.doc.PlanSHA256, digestBytes(x.wire), nil},
		{x.f.root, os.Geteuid() + 1, x.doc.PlanSHA256, digestBytes(x.wire), clock},
	}
	for _, input := range cases {
		authority, err := openSSHAccessAuthority(input.root, input.uid, input.plan, input.approved, input.clock)
		if err == nil || authority != nil {
			_ = authority.Close()
			t.Fatal("invalid authority input was accepted")
		}
	}
}

func TestSSHAccessAuthorityRefusesUnsafeStorage(t *testing.T) {
	cases := map[string]func(*sshAuthorityFixture) error{
		"readable-file":     func(x *sshAuthorityFixture) error { return x.f.chmod(sshAccessAuthorityPath, 0644) },
		"writable-file":     func(x *sshAuthorityFixture) error { return x.f.chmod(sshAccessAuthorityPath, 0620) },
		"executable-file":   func(x *sshAuthorityFixture) error { return x.f.chmod(sshAccessAuthorityPath, 0700) },
		"writable-parent":   func(x *sshAuthorityFixture) error { return x.f.chmod("/etc/syswarden", 0720) },
		"writable-ancestor": func(x *sshAuthorityFixture) error { return x.f.chmod("/etc", 0702) },
		"writable-root":     func(x *sshAuthorityFixture) error { return x.f.chmod("/", 0770) },
		"hardlink": func(x *sshAuthorityFixture) error {
			return os.Link(x.f.path(sshAccessAuthorityPath), x.f.path("/etc/second-link"))
		},
		"symlink-file": func(x *sshAuthorityFixture) error {
			if err := os.Rename(x.f.path(sshAccessAuthorityPath), x.f.path("/etc/authority.json")); err != nil {
				return err
			}
			return os.Symlink("../authority.json", x.f.path(sshAccessAuthorityPath))
		},
		"symlink-parent": func(x *sshAuthorityFixture) error {
			if err := os.Rename(x.f.path("/etc/syswarden"), x.f.path("/etc/saved")); err != nil {
				return err
			}
			return os.Symlink("saved", x.f.path("/etc/syswarden"))
		},
		"directory": func(x *sshAuthorityFixture) error {
			if err := os.Remove(x.f.path(sshAccessAuthorityPath)); err != nil {
				return err
			}
			return os.Mkdir(x.f.path(sshAccessAuthorityPath), 0700)
		},
		"fifo": func(x *sshAuthorityFixture) error {
			if err := os.Remove(x.f.path(sshAccessAuthorityPath)); err != nil {
				return err
			}
			return unix.Mkfifo(x.f.path(sshAccessAuthorityPath), 0600)
		},
		"oversized": func(x *sshAuthorityFixture) error {
			return os.Truncate(x.f.path(sshAccessAuthorityPath), maxSSHAccessAuthorityBytes+1)
		},
		"missing-file": func(x *sshAuthorityFixture) error { return os.Remove(x.f.path(sshAccessAuthorityPath)) },
		"missing-parent": func(x *sshAuthorityFixture) error {
			return os.Rename(x.f.path("/etc/syswarden"), x.f.path("/etc/saved"))
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			x := newSSHAuthorityFixture(t)
			if err := change(x); err != nil {
				t.Fatal(err)
			}
			authority, err := openSSHAccessAuthority(x.f.root, os.Geteuid(), x.doc.PlanSHA256, digestBytes(x.wire), func() time.Time { return x.now })
			if err == nil || authority != nil {
				_ = authority.Close()
				t.Fatal("unsafe enrollment storage was accepted")
			}
		})
	}
}

func TestSSHAccessAuthorityPoisonsAfterRevocationOrReplacement(t *testing.T) {
	cases := map[string]func(*testing.T, *sshAuthorityFixture){
		"changed-bytes": func(t *testing.T, x *sshAuthorityFixture) { x.f.write(sshAccessAuthorityPath, string(x.wire)+"\n") },
		"byte-identical-replacement": func(t *testing.T, x *sshAuthorityFixture) {
			x.f.write("/etc/syswarden/replacement", string(x.wire))
			if err := os.Rename(x.f.path("/etc/syswarden/replacement"), x.f.path(sshAccessAuthorityPath)); err != nil {
				t.Fatal(err)
			}
		},
		"revoked": func(t *testing.T, x *sshAuthorityFixture) {
			if err := os.Remove(x.f.path(sshAccessAuthorityPath)); err != nil {
				t.Fatal(err)
			}
		},
		"permissions": func(t *testing.T, x *sshAuthorityFixture) {
			if err := x.f.chmod(sshAccessAuthorityPath, 0644); err != nil {
				t.Fatal(err)
			}
		},
		"ancestor-permissions": func(t *testing.T, x *sshAuthorityFixture) {
			if err := x.f.chmod("/etc/syswarden", 0750); err != nil {
				t.Fatal(err)
			}
		},
		"ancestor-replacement": func(t *testing.T, x *sshAuthorityFixture) {
			if err := os.Rename(x.f.path("/etc/syswarden"), x.f.path("/etc/saved")); err != nil {
				t.Fatal(err)
			}
			x.f.write(sshAccessAuthorityPath, string(x.wire))
		},
		"expiry":           func(t *testing.T, x *sshAuthorityFixture) { x.now = time.Unix(x.doc.ExpiresAt, 0) },
		"clock-regression": func(t *testing.T, x *sshAuthorityFixture) { x.now = x.now.Add(-time.Nanosecond) },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			x := newSSHAuthorityFixture(t)
			authority := x.open(t)
			original := x.now
			change(t, x)
			if !errors.Is(authority.recheck(), ErrInventoryChanged) {
				t.Fatal("changed or revoked authority remained usable")
			}
			x.now = original
			x.f.write(sshAccessAuthorityPath, string(x.wire))
			if err := x.f.chmod(sshAccessAuthorityPath, 0600); err != nil {
				t.Fatal(err)
			}
			if !errors.Is(authority.recheck(), ErrInventoryChanged) {
				t.Fatal("restoration revived poisoned authority")
			}
		})
	}
}

func TestSSHAccessAuthorityAllowsUnrelatedDirectoryChurn(t *testing.T) {
	x := newSSHAuthorityFixture(t)
	authority := x.open(t)
	for _, name := range []string{"/unrelated", "/etc/unrelated", "/etc/syswarden/unrelated"} {
		if err := os.Mkdir(x.f.path(name), 0700); err != nil {
			t.Fatal(err)
		}
		if err := authority.recheck(); err != nil {
			t.Fatal("unrelated directory membership revoked authority", err)
		}
		if err := os.Remove(x.f.path(name)); err != nil {
			t.Fatal(err)
		}
		if err := authority.recheck(); err != nil {
			t.Fatal("unrelated directory removal revoked authority", err)
		}
	}
}

func TestSSHAccessAuthorityPinsFileAndAncestorAttributes(t *testing.T) {
	for _, name := range []string{sshAccessAuthorityPath, "/etc/syswarden"} {
		t.Run(name, func(t *testing.T) {
			x := newSSHAuthorityFixture(t)
			if err := unix.Setxattr(x.f.path(name), "user.syswarden-test", []byte("before"), 0); err != nil {
				if errors.Is(err, unix.ENOTSUP) {
					t.Skip("temporary filesystem does not support user attributes")
				}
				t.Fatal(err)
			}
			authority := x.open(t)
			if err := unix.Setxattr(x.f.path(name), "user.syswarden-test", []byte("after"), 0); err != nil {
				t.Fatal(err)
			}
			if !errors.Is(authority.recheck(), ErrInventoryChanged) {
				t.Fatal("changed integrity attributes were ignored")
			}
		})
	}
}

func TestSSHAccessAuthorityFinalGuardAndTimeBoundaries(t *testing.T) {
	for _, action := range []string{"replace", "expire", "regress"} {
		t.Run(action, func(t *testing.T) {
			x := newSSHAuthorityFixture(t)
			authority := x.open(t)
			calls := 0
			authority.clock = func() time.Time {
				calls++
				if calls == 2 {
					switch action {
					case "replace":
						x.f.write("/etc/syswarden/replacement", string(x.wire))
						if err := os.Rename(x.f.path("/etc/syswarden/replacement"), x.f.path(sshAccessAuthorityPath)); err != nil {
							t.Fatal(err)
						}
					case "expire":
						x.now = time.Unix(x.doc.ExpiresAt, 0)
					case "regress":
						x.now = x.now.Add(-time.Nanosecond)
					}
				}
				return x.now
			}
			if !errors.Is(authority.recheck(), ErrInventoryChanged) || calls != 2 {
				t.Fatal("final time or storage guard was bypassed")
			}
		})
	}
	t.Run("inclusive-start-exclusive-expiry", func(t *testing.T) {
		x := newSSHAuthorityFixture(t)
		x.now = time.Unix(x.doc.NotBefore, 0)
		authority := x.open(t)
		x.now = time.Unix(x.doc.ExpiresAt, 0).Add(-time.Nanosecond)
		if err := authority.recheck(); err != nil {
			t.Fatal("valid final instant was refused", err)
		}
		x.now = x.now.Add(time.Nanosecond)
		if !errors.Is(authority.recheck(), ErrInventoryChanged) {
			t.Fatal("exclusive expiry boundary was accepted")
		}
	})
}

func TestSSHAccessAuthorityDoesNotProvision(t *testing.T) {
	x := newSSHAuthorityFixture(t)
	if err := os.Remove(x.f.path(sshAccessAuthorityPath)); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(x.f.path("/etc/syswarden")); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadDir(x.f.path("/etc"))
	if err != nil {
		t.Fatal(err)
	}
	authority, err := openSSHAccessAuthority(x.f.root, os.Geteuid(), x.doc.PlanSHA256, digestBytes(x.wire), func() time.Time { return x.now })
	if err == nil || authority != nil {
		_ = authority.Close()
		t.Fatal("missing enrollment was provisioned")
	}
	after, err := os.ReadDir(x.f.path("/etc"))
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("reader changed directory membership")
	}
	if _, err := os.Lstat(x.f.path("/etc/syswarden")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("reader created an enrollment directory")
	}
}

func FuzzSSHAccessAuthorityCanonical(f *testing.F) {
	// Synthetic public material gives the mutator a fully accepted starting point.
	public := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	key, err := ssh.NewPublicKey(public)
	if err != nil {
		f.Fatal(err)
	}
	plan := strings.Repeat("a", 64)
	doc := sshAccessAuthorityDocument{1, sshAccessAuthorityDomain, "activation-access", plan, public,
		[]sshAccessAuthorityRoute{{ContextID: "operator", Target: sshAccessPin{"127.0.0.1:2222", "operator", key.Marshal(), key.Marshal()}}}, 1800000000, 1800000060}
	wire, err := json.Marshal(doc)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(wire)
	f.Add([]byte("{}"))
	f.Add(append(bytes.Clone(wire), '\n'))
	f.Fuzz(func(t *testing.T, input []byte) {
		before := bytes.Clone(input)
		got, pins, err := decodeSSHAccessAuthority(input, plan)
		if !bytes.Equal(input, before) {
			t.Fatal("decoder mutated caller evidence")
		}
		if err != nil {
			if !reflect.DeepEqual(got, sshAccessAuthorityDocument{}) || pins != nil {
				t.Fatal("refused enrollment retained authority")
			}
			return
		}
		canonical, err := json.Marshal(got)
		if err != nil || !bytes.Equal(input, canonical) || len(input) > maxSSHAccessAuthorityBytes || got.PlanSHA256 != plan || len(pins) != len(got.Routes) || len(pins) == 0 {
			t.Fatal("accepted enrollment lost canonical identity")
		}
	})
}
