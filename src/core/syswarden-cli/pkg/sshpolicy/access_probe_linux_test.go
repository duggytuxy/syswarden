//go:build linux

package sshpolicy

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/netip"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

type sshProbeFixture struct {
	binding     sshAccessBinding
	peer        sshAccessPeer
	connections atomic.Int32
	signatures  atomic.Int32
	stalled     chan struct{}
}

func sshProbeIdentity(t *testing.T) ([]byte, ssh.Signer) {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(key, "fixture")
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(block), signer
}
func sshProbeSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, signer := sshProbeIdentity(t)
	return signer
}

func newSSHProbeFixture(t *testing.T, mode string, forwarding ...string) *sshProbeFixture {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	host := sshProbeSigner(t)
	encodedClient, client := sshProbeIdentity(t)
	port := listener.Addr().(*net.TCPAddr).Port
	endpoint, err := netip.ParseAddrPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	f := &sshProbeFixture{
		stalled: make(chan struct{}),
		binding: sshAccessBinding{strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64), strings.Repeat("d", 64),
			accessContext{"administrator", "direct", "administrator", "controller.example", "127.0.0.1", "127.0.0.1", endpoint.Port()}},
		peer: sshAccessPeer{listener.Addr().String(), "administrator", host.PublicKey().Marshal(), encodedClient},
	}
	ctx, cancel := context.WithCancel(context.Background())
	finished := make(chan struct{})
	var workers sync.WaitGroup
	var sockets sync.Map
	go func() {
		defer close(finished)
		for {
			raw, err := listener.Accept()
			if err != nil {
				return
			}
			f.connections.Add(1)
			sockets.Store(raw, true)
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer sockets.Delete(raw)
				defer raw.Close()
				_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
				if mode == "handshake-stall" {
					close(f.stalled)
					<-ctx.Done()
					return
				}
				config := &ssh.ServerConfig{NoClientAuth: strings.HasSuffix(mode, "no-auth"), PublicKeyCallback: func(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
					if meta.User() != "administrator" || !bytes.Equal(key.Marshal(), client.PublicKey().Marshal()) {
						return nil, errors.New("fixture refuses key")
					}
					return nil, nil
				}, VerifiedPublicKeyCallback: func(_ ssh.ConnMetadata, _ ssh.PublicKey, _ *ssh.Permissions, _ string) (*ssh.Permissions, error) {
					f.signatures.Add(1)
					return nil, nil
				}}
				config.AddHostKey(host)
				server, channels, requests, err := ssh.NewServerConn(raw, config)
				if err != nil {
					return
				}
				defer server.Close()
				go ssh.DiscardRequests(requests)
				for incoming := range channels {
					if incoming.ChannelType() == "direct-tcpip" && strings.HasPrefix(mode, "bastion") {
						var destination struct {
							Host       string
							Port       uint32
							Origin     string
							OriginPort uint32
						}
						if ssh.Unmarshal(incoming.ExtraData(), &destination) != nil || len(forwarding) != 1 ||
							net.JoinHostPort(destination.Host, strconv.FormatUint(uint64(destination.Port), 10)) != forwarding[0] || mode == "bastion-forward-denied" {
							_ = incoming.Reject(ssh.Prohibited, "fixture refuses forwarding")
							continue
						}
						backend, err := (&net.Dialer{}).DialContext(ctx, "tcp", forwarding[0])
						if err != nil {
							_ = incoming.Reject(ssh.ConnectionFailed, "fixture backend unavailable")
							continue
						}
						_ = backend.SetDeadline(time.Now().Add(5 * time.Second))
						channel, requests, err := incoming.Accept()
						if err != nil {
							_ = backend.Close()
							return
						}
						go ssh.DiscardRequests(requests)
						copied := make(chan struct{})
						go func() { _, _ = io.Copy(channel, backend); _ = channel.Close(); close(copied) }()
						_, _ = io.Copy(backend, channel)
						_ = backend.Close()
						_ = channel.Close()
						<-copied
						continue
					}
					if incoming.ChannelType() != "session" {
						_ = incoming.Reject(ssh.UnknownChannelType, "fixture only accepts sessions")
						continue
					}
					channel, requests, err := incoming.Accept()
					if err != nil {
						return
					}
					defer channel.Close()
					for request := range requests {
						var execRequest struct{ Command string }
						if request.Type != "exec" || ssh.Unmarshal(request.Payload, &execRequest) != nil || mode == "exec-refused" {
							_ = request.Reply(false, nil)
							continue
						}
						_ = request.Reply(true, nil)
						if mode == "session-stall" {
							close(f.stalled)
							<-ctx.Done()
							return
						}
						prefix := "printf 'SYSWARDEN-SSH-ACCESS-V1\\n"
						suffix := "\\n'; printf '%s\\n' \"$SSH_CONNECTION\""
						if !strings.HasPrefix(execRequest.Command, prefix) || !strings.HasSuffix(execRequest.Command, suffix) {
							return
						}
						challenge := strings.TrimSuffix(strings.TrimPrefix(execRequest.Command, prefix), suffix)
						if !lowerDigest.MatchString(challenge) {
							return
						}
						remoteHost, remotePort, _ := net.SplitHostPort(raw.RemoteAddr().String())
						tuple := remoteHost + " " + remotePort + " 127.0.0.1 " + strconv.Itoa(port)
						if mode == "wrong-tuple" {
							tuple = "192.0.2.1 12345 127.0.0.1 " + strconv.Itoa(port)
						}
						if mode == "replay" {
							challenge = strings.Repeat("e", 64)
						}
						output := "SYSWARDEN-SSH-ACCESS-V1\n" + challenge + "\n" + tuple + "\n"
						if mode == "oversized" {
							output += strings.Repeat("x", 1024)
						}
						if mode == "extra-output" {
							output += "unapproved\n"
						}
						if mode == "stderr" {
							_, _ = io.WriteString(channel.Stderr(), "unexpected output")
						}
						_, _ = io.WriteString(channel, output)
						exit := uint32(0)
						if mode == "exit-failure" {
							exit = 1
						}
						_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{exit}))
						_ = channel.Close()
					}
				}
			}()
		}
	}()
	t.Cleanup(func() {
		cancel()
		_ = listener.Close()
		<-finished
		sockets.Range(func(key, value any) bool { _ = key.(net.Conn).Close(); return true })
		workers.Wait()
	})
	return f
}

// Cancel only after the server reaches the intended blocked phase, so loaded
// runners cannot turn a handshake/session cancellation test into a dial failure.
func cancelSSHProbeOnStall(t *testing.T, ctx context.Context, cancel context.CancelFunc, fixture *sshProbeFixture) {
	t.Helper()
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		select {
		case <-fixture.stalled:
			cancel()
		case <-ctx.Done():
		}
	}()
	t.Cleanup(func() {
		cancel()
		<-finished
		select {
		case <-fixture.stalled:
		default:
			t.Error("fixture did not reach the cancellation phase")
		}
	})
}

func TestSSHFreshAccessNativeProtocol(t *testing.T) {
	for _, mode := range []string{"success", "no-auth", "wrong-host", "wrong-client", "exec-refused", "wrong-tuple", "replay", "oversized", "extra-output", "stderr", "exit-failure", "handshake-stall", "session-stall", "guard-drift"} {
		t.Run(mode, func(t *testing.T) {
			f := newSSHProbeFixture(t, mode)
			if mode == "wrong-host" {
				f.peer.HostKey = sshProbeSigner(t).PublicKey().Marshal()
			}
			if mode == "wrong-client" {
				f.peer.Identity, _ = sshProbeIdentity(t)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if strings.HasSuffix(mode, "-stall") {
				cancelSSHProbeOnStall(t, ctx, cancel, f)
			}
			guard := func() error {
				if mode == "guard-drift" && f.signatures.Load() > 0 {
					return ErrInventoryChanged
				}
				return nil
			}
			got, err := probeSSHFreshAccess(ctx, f.binding, f.peer, nil, guard)
			if mode != "success" {
				if err == nil || got != (sshAccessObservation{}) {
					t.Fatal("invalid access accepted", got, err)
				}
				if f.connections.Load() != 1 {
					t.Fatal("probe retried", f.connections.Load())
				}
				return
			}
			if err != nil || !got.RecoveryRequired || !lowerDigest.MatchString(got.BindingSHA256) || !lowerDigest.MatchString(got.ChallengeSHA256) || !lowerDigest.MatchString(got.SessionSHA256) || got.JumpSessionSHA256 != "" {
				t.Fatal(got, err)
			}
			next, err := probeSSHFreshAccess(ctx, f.binding, f.peer, nil, guard)
			if err != nil || next.BindingSHA256 != got.BindingSHA256 || next.ChallengeSHA256 == got.ChallengeSHA256 || next.SessionSHA256 == got.SessionSHA256 || f.connections.Load() != 2 || f.signatures.Load() != 2 {
				t.Fatal("session or challenge reused", next, err)
			}
		})
	}
}

func TestSSHFreshAccessRejectsUnboundInputBeforeNetwork(t *testing.T) {
	f := newSSHProbeFixture(t, "success")
	for _, scenario := range []string{"transaction", "plan", "intent", "target", "context", "address", "user", "route", "missing-jump", "unexpected-jump", "host-key", "invalid-host-key", "oversized-host-key", "client-key", "invalid-private-key", "oversized-private-key", "nil-context", "nil-guard", "cancelled", "guard"} {
		t.Run(scenario, func(t *testing.T) {
			binding, peer := f.binding, f.peer
			var jump *sshAccessPeer
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			guard := func() error { return nil }
			switch scenario {
			case "transaction":
				binding.Transaction = ""
			case "plan":
				binding.Plan = "bad"
			case "intent":
				binding.Intent = strings.Repeat("A", 64)
			case "target":
				binding.Target = "bad"
			case "context":
				binding.Access.ID = ""
			case "address":
				peer.Address = "example.invalid:22"
			case "user":
				peer.User = "other"
			case "route":
				binding.Access.Route = "ansible"
			case "missing-jump":
				binding.Access.Route = "proxyjump"
			case "unexpected-jump":
				jump = &peer
			case "host-key":
				peer.HostKey = nil
			case "invalid-host-key":
				peer.HostKey = []byte("invalid host key")
			case "oversized-host-key":
				peer.HostKey = bytes.Repeat([]byte("x"), (16<<10)+1)
			case "client-key":
				peer.Identity = nil
			case "invalid-private-key":
				peer.Identity = []byte("not a private key")
			case "oversized-private-key":
				peer.Identity = bytes.Repeat([]byte("x"), (16<<10)+1)
			case "nil-context":
				ctx = nil
			case "nil-guard":
				guard = nil
			case "cancelled":
				cancel()
			case "guard":
				guard = func() error { return ErrInventoryChanged }
			}
			got, err := probeSSHFreshAccess(ctx, binding, peer, jump, guard)
			if err == nil || got != (sshAccessObservation{}) || f.connections.Load() != 0 {
				t.Fatal("invalid input reached network", got, err)
			}
		})
	}
}

func TestSSHAccessResponseBoundedFraming(t *testing.T) {
	access := accessContext{"administrator", "direct", "administrator", "controller.example", "127.0.0.1", "127.0.0.1", 22}
	challenge := strings.Repeat("a", 64)
	response := "SYSWARDEN-SSH-ACCESS-V1\n" + challenge + "\n127.0.0.1 12345 127.0.0.1 22\n"
	local := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}
	if err := verifySSHAccessResponse([]byte(response), challenge, access, local, false); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{response + "\n", strings.Replace(response, "12345", "012345", 1), strings.Replace(response, "12345", "0", 1), strings.Replace(response, "12345", "65536", 1), strings.Replace(response, "12345", "12346", 1), strings.Replace(response, " 22\n", " 23\n", 1), strings.ReplaceAll(response, "\n", "\r\n"), response[:len(response)-1], strings.Repeat("x", 513)} {
		if err := verifySSHAccessResponse([]byte(bad), challenge, access, local, false); err == nil {
			t.Fatal("malformed response accepted")
		}
	}
	for _, port := range []int{0, 12346} {
		changed := *local
		changed.Port = port
		if verifySSHAccessResponse([]byte(response), challenge, access, &changed, false) == nil {
			t.Fatal("foreign local connection accepted")
		}
	}
	output := &sshAccessOutput{limit: 8}
	if _, ok := any(output).(io.ReaderFrom); ok {
		t.Fatal("ReaderFrom bypasses output bound")
	}
	if _, err := io.Copy(output, strings.NewReader("123456789")); err == nil || output.Len() > 8 {
		t.Fatal("oversized output accepted")
	}
	if _, err := output.Write([]byte("12345678")); err != nil {
		t.Fatal(err)
	}
	if _, err := output.Write([]byte("9")); err == nil || !reflect.DeepEqual(output.Bytes(), []byte("12345678")) {
		t.Fatal("bound changed")
	}
}

func TestSSHFreshAccessProxyJump(t *testing.T) {
	for _, scenario := range []string{"success", "bastion-no-auth", "bastion-forward-denied", "wrong-bastion-host", "wrong-bastion-client", "wrong-target-host", "wrong-target-client", "target-stall"} {
		t.Run(scenario, func(t *testing.T) {
			targetMode := "success"
			if scenario == "target-stall" {
				targetMode = "handshake-stall"
			}
			target := newSSHProbeFixture(t, targetMode)
			jumpMode := "bastion"
			if strings.HasPrefix(scenario, "bastion-") {
				jumpMode = scenario
			}
			jump := newSSHProbeFixture(t, jumpMode, target.peer.Address)
			target.binding.Access.Route = "proxyjump"
			switch scenario {
			case "wrong-bastion-host":
				jump.peer.HostKey = sshProbeSigner(t).PublicKey().Marshal()
			case "wrong-bastion-client":
				jump.peer.Identity, _ = sshProbeIdentity(t)
			case "wrong-target-host":
				target.peer.HostKey = sshProbeSigner(t).PublicKey().Marshal()
			case "wrong-target-client":
				target.peer.Identity, _ = sshProbeIdentity(t)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if scenario == "target-stall" {
				cancelSSHProbeOnStall(t, ctx, cancel, target)
			}
			got, err := probeSSHFreshAccess(ctx, target.binding, target.peer, &jump.peer, func() error { return nil })
			if scenario != "success" {
				if err == nil || got != (sshAccessObservation{}) {
					t.Fatal("invalid proxy route accepted", got, err)
				}
				if jump.connections.Load() != 1 || target.connections.Load() > 1 {
					t.Fatal("route retried")
				}
				return
			}
			if err != nil || !got.RecoveryRequired || got.JumpSessionSHA256 == "" || got.JumpSessionSHA256 == got.SessionSHA256 || target.signatures.Load() != 1 || jump.signatures.Load() != 1 {
				t.Fatal(got, err)
			}
		})
	}
}

func TestSSHFreshAccessBindsEveryApprovedIdentity(t *testing.T) {
	f := newSSHProbeFixture(t, "success")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	first, err := probeSSHFreshAccess(ctx, f.binding, f.peer, nil, func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"transaction", "plan", "intent", "target", "context-id", "context-host"} {
		binding := f.binding
		switch field {
		case "transaction":
			binding.Transaction = strings.Repeat("1", 64)
		case "plan":
			binding.Plan = strings.Repeat("2", 64)
		case "intent":
			binding.Intent = strings.Repeat("3", 64)
		case "target":
			binding.Target = strings.Repeat("4", 64)
		case "context-id":
			binding.Access.ID = "another-approved-context"
		case "context-host":
			binding.Access.Host = "another-controller.example"
		}
		got, err := probeSSHFreshAccess(ctx, binding, f.peer, nil, func() error { return nil })
		if err != nil || got.BindingSHA256 == first.BindingSHA256 || got.ChallengeSHA256 == first.ChallengeSHA256 || got.SessionSHA256 == first.SessionSHA256 {
			t.Fatal("identity lost", field, got, err)
		}
	}
}

func TestSSHAccessSoftwareKeyPolicy(t *testing.T) {
	for _, kind := range []string{"ed25519", "rsa", "ecdsa", "weak-rsa", "certificate"} {
		t.Run(kind, func(t *testing.T) {
			var private any
			var err error
			switch kind {
			case "rsa":
				private, err = rsa.GenerateKey(rand.Reader, 2048)
			case "weak-rsa":
				private, err = rsa.GenerateKey(rand.Reader, 1024) // #nosec G403 -- Deliberately weak fixture key proves refusal; it is never a product credential.
			case "ecdsa":
				private, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			default:
				_, private, err = ed25519.GenerateKey(rand.Reader)
			}
			if err != nil {
				t.Fatal(err)
			}
			signer, err := ssh.NewSignerFromKey(private)
			if err != nil {
				t.Fatal(err)
			}
			block, err := ssh.MarshalPrivateKey(private, "fixture")
			if err != nil {
				t.Fatal(err)
			}
			peer := sshAccessPeer{"127.0.0.1:2222", "administrator", signer.PublicKey().Marshal(), pem.EncodeToMemory(block)}
			if kind == "certificate" {
				cert := &ssh.Certificate{Key: signer.PublicKey(), CertType: ssh.HostCert}
				if err := cert.SignCert(rand.Reader, signer); err != nil {
					t.Fatal(err)
				}
				peer.HostKey = cert.Marshal()
			}
			_, _, counted, err := prepareSSHAccessPeer(peer)
			if kind == "weak-rsa" || kind == "certificate" {
				if err == nil {
					t.Fatal("unsupported key accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			message := []byte("fixture authentication")
			signature, err := counted.SignWithAlgorithm(rand.Reader, message, counted.Algorithms()[0])
			if err != nil || signer.PublicKey().Verify(message, signature) != nil {
				t.Fatal("selected algorithm failed", err)
			}
			if _, err := counted.Sign(rand.Reader, message); err == nil {
				t.Fatal("authentication signer replayed")
			}
		})
	}
}

func FuzzSSHAccessResponse(f *testing.F) {
	access := accessContext{"administrator", "direct", "administrator", "controller.example", "127.0.0.1", "127.0.0.1", 22}
	challenge := strings.Repeat("a", 64)
	expected := []byte("SYSWARDEN-SSH-ACCESS-V1\n" + challenge + "\n127.0.0.1 12345 127.0.0.1 22\n")
	f.Add(expected)
	f.Add([]byte(""))
	f.Add([]byte("SYSWARDEN-SSH-ACCESS-V1\n"))
	f.Fuzz(func(t *testing.T, wire []byte) {
		if len(wire) > 1024 {
			return
		}
		err := verifySSHAccessResponse(wire, challenge, access, &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}, false)
		if err == nil && !bytes.Equal(wire, expected) {
			t.Fatal("noncanonical access response accepted")
		}
	})
}
