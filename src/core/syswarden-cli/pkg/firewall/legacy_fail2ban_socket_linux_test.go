//go:build linux

package firewall

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func fixtureLegacyFail2banSocket(t *testing.T, response []byte, afterRequest func(nftPersistenceFilesystem), stalled bool) (legacyFail2banReadOnlySocket, *atomic.Int32) {
	t.Helper()
	expected, err := encodeLegacyFail2banQuery([]string{"version"})
	if err != nil {
		t.Fatal(err)
	}
	return fixtureLegacyFail2banSocketRequest(t, expected, response, afterRequest, stalled)
}

func fixtureLegacyFail2banSocketRequest(t *testing.T, expected, response []byte, afterRequest func(nftPersistenceFilesystem), stalled bool) (legacyFail2banReadOnlySocket, *atomic.Int32) {
	t.Helper()
	_, host := fixtureNFTPersistenceFilesystem(t)
	directory, err := host.root.Open(".")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = directory.Close() })
	address := fmt.Sprintf("/proc/self/fd/%d/control.sock", directory.Fd())
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: address, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	if err := host.root.Chmod("control.sock", 0600); err != nil {
		t.Fatal(err)
	}
	var received atomic.Int32
	done := make(chan struct{})
	problems := make(chan error, 1)
	t.Cleanup(func() {
		_ = listener.Close()
		<-done
		select {
		case err := <-problems:
			t.Error(err)
		default:
		}
	})
	go func() {
		defer close(done)
		connection, err := listener.AcceptUnix()
		if err != nil {
			return
		}
		defer func() { _ = connection.Close() }()
		if err := connection.SetDeadline(time.Now().Add(time.Second)); err != nil {
			problems <- err
			return
		}
		var request bytes.Buffer
		var b [1024]byte
		for !bytes.HasSuffix(request.Bytes(), []byte(legacyFail2banEnd)) {
			n, err := connection.Read(b[:])
			if n > 0 {
				_, _ = request.Write(b[:n])
			}
			if err != nil {
				return
			}
		}
		if !bytes.Equal(request.Bytes(), expected) {
			problems <- fmt.Errorf("unexpected query bytes")
			return
		}
		received.Add(1)
		if afterRequest != nil {
			afterRequest(host)
		}
		if stalled {
			_, _ = io.Copy(io.Discard, connection)
			return
		}
		for len(response) > 0 {
			n := min(3, len(response))
			if _, err := connection.Write(response[:n]); err != nil {
				return
			}
			response = response[n:]
		}
	}()
	pid, err := strconv.ParseInt(strconv.Itoa(os.Getpid()), 10, 32)
	if err != nil {
		t.Fatal(err)
	}
	return legacyFail2banReadOnlySocket{host: host, path: "/control.sock", peer: syscall.Ucred{Pid: int32(pid), Uid: host.expectedUID, Gid: host.expectedGID}, guard: func() error { return nil }}, &received
}

func TestLegacyFail2banSocketChecksPeerBeforeSending(t *testing.T) {
	reply := append(fixtureLegacyFail2banWire(t, "8004950d000000000000004b008c05312e312e309486942e"), []byte(legacyFail2banEnd)...)
	for _, kind := range []string{"valid", "wrong-pid", "wrong-uid", "missing-guard", "guard-failure", "unsafe-mode", "link", "unbounded", "unsupported-query"} {
		t.Run(kind, func(t *testing.T) {
			client, received := fixtureLegacyFail2banSocket(t, reply, nil, false)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			query := []string{"version"}
			switch kind {
			case "wrong-pid":
				client.peer.Pid++
			case "wrong-uid":
				client.peer.Uid++
			case "missing-guard":
				client.guard = nil
			case "guard-failure":
				client.guard = func() error { return fmt.Errorf("fixture guard failed") }
			case "unsafe-mode":
				if err := client.host.root.Chmod("control.sock", 0622); err != nil {
					t.Fatal(err)
				}
			case "link":
				if err := client.host.root.Symlink("control.sock", "alias.sock"); err != nil {
					t.Fatal(err)
				}
				client.path = "/alias.sock"
			case "unbounded":
				ctx = context.Background()
			case "unsupported-query":
				query = []string{"stop"}
			}
			value, err := client.query(ctx, query)
			if kind == "valid" {
				if err != nil || value.text != "1.1.0" || received.Load() != 1 {
					t.Fatal("query failed", err)
				}
			} else if err == nil || received.Load() != 0 {
				t.Fatal("unsafe query reached the server", err)
			}
		})
	}
}

func TestLegacyFail2banSocketRejectsIncompleteRepliesAndChangedEvidence(t *testing.T) {
	base := fixtureLegacyFail2banWire(t, "8004950d000000000000004b008c05312e312e309486942e")
	for _, kind := range []string{"truncated", "oversized", "object", "timeout", "changed-guard", "changed-socket"} {
		t.Run(kind, func(t *testing.T) {
			reply := append(bytes.Clone(base), []byte(legacyFail2banEnd)...)
			var after func(nftPersistenceFilesystem)
			switch kind {
			case "truncated":
				reply = base[:len(base)-1]
			case "oversized":
				reply = bytes.Repeat([]byte{'x'}, maximumLegacyFail2banReply+1024)
			case "object":
				reply = append([]byte("\x80\x02K\x00cos\nsystem\n\x86."), []byte(legacyFail2banEnd)...)
			case "changed-socket":
				after = func(host nftPersistenceFilesystem) {
					if err := host.root.Remove("control.sock"); err != nil {
						panic(err)
					}
				}
			}
			client, received := fixtureLegacyFail2banSocket(t, reply, after, kind == "timeout")
			checks := 0
			if kind == "changed-guard" {
				client.guard = func() error {
					checks++
					if checks >= 3 {
						return fmt.Errorf("fixture process changed")
					}
					return nil
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
			defer cancel()
			value, err := client.query(ctx, []string{"version"})
			if err == nil || value.kind != 0 || received.Load() != 1 {
				t.Fatal("invalid observation accepted", err)
			}
			if strings.Contains(err.Error(), "system") {
				t.Fatal("raw server payload leaked into diagnostics")
			}
		})
	}
}
