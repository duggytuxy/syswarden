//go:build linux

package config

import (
	"bytes"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func activationFixtureOwnerUID(t *testing.T) uint32 {
	t.Helper()
	uid, err := activationOwnerUID(int64(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	return uid
}

func TestActivationOwnerUIDBounds(t *testing.T) {
	for _, value := range []int64{-1, 1 << 32} {
		if _, err := activationOwnerUID(value); err == nil {
			t.Fatal("out-of-range activation owner UID accepted")
		}
	}
	for _, value := range []int64{0, 1<<32 - 1} {
		uid, err := activationOwnerUID(value)
		if err != nil || int64(uid) != value {
			t.Fatal("valid activation owner UID changed", err)
		}
	}
}

func TestActivationApprovalCrossConsumerWireVector(t *testing.T) {
	raw, err := os.ReadFile("../../activation-contract-testdata/approved-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	record, err := decodeActivationApproval(raw, 0)
	if err != nil {
		t.Fatal(err)
	}
	if activationDigest(raw) != "983eb957acfc48763434be68e5c98e54067f6283f7d58acb11d9f5ef01be2406" {
		t.Fatal("public activation vector digest changed")
	}
	if record.HostSHA256 != "33df47a8f114bc72d669a743f1a316adbe1b7fe3a2ce1a9daaef0e475dc03747" || len(record.Inputs) != 7 {
		t.Fatal("public activation vector decoded differently")
	}
	encoded, err := activationCanonical(record)
	if err != nil || !bytes.Equal(encoded, raw) {
		t.Fatal("activation wire round trip changed", err)
	}
	for _, changed := range [][]byte{
		append([]byte(" "), raw...),
		bytes.TrimSuffix(raw, []byte("\n")),
		append(bytes.Clone(raw), []byte("{}\n")...),
		bytes.Replace(raw, []byte("{"), []byte("{\"unknown\":true,"), 1),
		bytes.Replace(raw, []byte("{"), []byte("{\"operation\":\"reload\","), 1),
		bytes.Replace(raw, []byte("syswarden-toml-source-v1"), []byte("syswarden-toml-source-v2"), 1),
		bytes.Repeat([]byte("x"), maximumActivationRecordBytes+1),
	} {
		if _, err := decodeActivationApproval(changed, 0); err == nil {
			t.Fatal("ambiguous or unsupported public wire accepted")
		}
	}
}

func TestActivationBoundedOpenRejectsReplacedFIFOAndSymlink(t *testing.T) {
	for _, kind := range []string{"fifo", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			path := t.TempDir()
			name := filepath.Join(path, "input")
			if err := os.WriteFile(name, []byte("approved"), 0600); err != nil {
				t.Fatal(err)
			}
			uid := activationFixtureOwnerUID(t)
			root, _, err := openActivationDirectory(path, uid)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			done := make(chan error, 1)
			go func() {
				_, _, err := readActivationFileUsing(root, "input", uid, 64, func() error {
					if err := os.Rename(name, name+".saved"); err != nil {
						return err
					}
					if kind == "fifo" {
						return syscall.Mkfifo(name, 0600)
					}
					return os.Symlink("input.saved", name)
				})
				done <- err
			}()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("replaced file was consumed")
				}
			case <-time.After(2 * time.Second):
				// Unblock a regressed FIFO opener so the failing test leaves no
				// blocked goroutine or descriptor after reporting the defect.
				if kind == "fifo" {
					// #nosec G304 -- name is the exact FIFO created by this test inside its private temporary directory.
					file, _ := os.OpenFile(name, os.O_RDWR|syscall.O_NONBLOCK, 0)
					if file != nil {
						_ = file.Close()
					}
				}
				t.Fatal("activation input open was not bounded")
			}
		})
	}
}
