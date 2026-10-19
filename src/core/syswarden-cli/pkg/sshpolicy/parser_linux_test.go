//go:build linux

package sshpolicy

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestParserImagesPreserveIncludeOrderAndFileBoundaries(t *testing.T) {
	files := map[string][]byte{
		MainPath:                                []byte("Port 2222\nInclude sshd_config.d/*.conf /etc/ssh/absent*\nMatch User administrator\nInclude /etc/ssh/access.conf\nPermitTTY no\n"),
		"/etc/ssh/sshd_config.d/20-second.conf": []byte("MaxSessions 20\n"),
		"/etc/ssh/sshd_config.d/10-first.conf":  []byte("MaxSessions 10\n"),
		"/etc/ssh/access.conf":                  []byte("AllowTcpForwarding local\n"),
	}
	image, err := newParserImage(files)
	if err != nil {
		t.Fatal(err)
	}
	defer image.Close()
	if len(image.files) != 4 {
		t.Fatal("unexpected descriptor assignment")
	}
	alias := func(index int) string { return fmt.Sprintf("/proc/%d/fd/%d", os.Getpid(), image.files[index].Fd()) }
	if image.main != alias(1) {
		t.Fatal("wrong main descriptor")
	}
	for index, expected := range []string{
		"AllowTcpForwarding local\n",
		"Port 2222\nInclude " + alias(2) + " " + alias(3) + "\nMatch User administrator\nInclude " + alias(0) + "\nPermitTTY no\n",
		"MaxSessions 10\n", "MaxSessions 20\n",
	} {
		content, err := io.ReadAll(image.files[index])
		if err != nil || string(content) != expected {
			t.Fatalf("image %d lost Include boundaries or ordering: %v %q", index, err, content)
		}
		if _, err := image.files[index].WriteAt([]byte("x"), 0); err == nil {
			t.Fatal("sealed input remained writable")
		}
		if err := image.files[index].Truncate(0); err == nil {
			t.Fatal("sealed input remained truncatable")
		}
		seals, err := unix.FcntlInt(image.files[index].Fd(), unix.F_GET_SEALS, 0)
		if err != nil || seals != unix.F_SEAL_WRITE|unix.F_SEAL_GROW|unix.F_SEAL_SHRINK|unix.F_SEAL_SEAL {
			t.Fatal("missing memory seal", err)
		}
	}
	if !bytes.Contains(files[MainPath], []byte("sshd_config.d/*.conf")) {
		t.Fatal("input map changed")
	}
}

func TestParserImagesRejectMalformedAndOversizedInputs(t *testing.T) {
	for _, content := range []string{"Include\n", "Include ../untrusted\n", "Include /etc/ssh/[a-z]*\n", "Include \"unclosed\n", "\x00", strings.Repeat("x", MaxLineBytes+1), strings.Repeat("Include absent\n", MaxExpansions+1)} {
		if image, err := newParserImage(map[string][]byte{MainPath: []byte(content)}); err == nil || image != nil {
			t.Fatal("accepted malformed or oversized input")
		}
	}
	for _, files := range []map[string][]byte{nil, {"/etc/ssh/other.conf": {}}, {MainPath: {}, "/etc/../bad": {}}, {MainPath: bytes.Repeat([]byte("a"), MaxBytes+1)}} {
		if _, err := newParserImage(files); err == nil {
			t.Fatal("accepted invalid inventory")
		}
	}
	content, err := parserIncludeAliases([]byte("Include absent*\n"), []string{MainPath}, map[string]string{})
	if err != nil || string(content) != "# Empty attested Include expansion\n" {
		t.Fatal("negative expansion was not retained", err)
	}
}

func TestEffectiveComparisonPreservesAllUnrelatedValuesAndMultiplicity(t *testing.T) {
	before, err := parseEffective([]byte("port 22\nport 2222\nx11forwarding yes\nauthenticationmethods publickey\nallowtcpforwarding yes\n"))
	if err != nil {
		t.Fatal(err)
	}
	for _, changed := range []string{
		"port 2222\nport 22\nx11forwarding yes\nauthenticationmethods publickey\nallowtcpforwarding no\n",
		"port 22\nx11forwarding yes\nauthenticationmethods publickey\nallowtcpforwarding no\n",
		"port 22\nport 2222\nx11forwarding yes\nauthenticationmethods private-fixture\nallowtcpforwarding no\n",
	} {
		after, err := parseEffective([]byte(changed))
		if err != nil {
			t.Fatal(err)
		}
		if err := compareEffective(before, after, map[string]bool{"allowtcpforwarding": true}); err == nil || strings.Contains(err.Error(), "private-fixture") {
			t.Fatal("missed unrelated change or exposed its value")
		}
	}
	after, err := parseEffective([]byte("port 22\nport 2222\nx11forwarding yes\nauthenticationmethods publickey\nallowtcpforwarding no\n"))
	if err != nil || compareEffective(before, after, map[string]bool{"allowtcpforwarding": true}) != nil {
		t.Fatal("fixed policy change was rejected", err)
	}
	if !reflect.DeepEqual(before["port"], []string{"22", "2222"}) {
		t.Fatal("repeated directives lost ordering")
	}
	for _, bad := range []string{"", "port", " port 22", "Port 22", "1port 22", "port\t22", "port 22\x00", strings.Repeat("x", MaxLineBytes+1) + " v\n"} {
		if _, err := parseEffective([]byte(bad)); err == nil {
			t.Fatal("accepted malformed effective output")
		}
	}
}
