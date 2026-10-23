//go:build linux

package sshpolicy

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"
)

// This private transport is for a future independently authorized controller.
// Digests supplied here are bindings, not proof of approval or protected state.
// No installer, CLI, activation completion or journal mutation calls it.
type sshAccessBinding struct {
	Transaction string
	Plan        string
	Intent      string
	Target      string
	Access      accessContext
}

type sshAccessPeer struct {
	Address string
	User    string
	HostKey []byte
	// Identity contains an explicitly supplied unencrypted software key, at most 16 KiB.
	// No passphrase callback, agent, file path or arbitrary signer is accepted.
	Identity []byte
}

// Results are observations of this call only, never reusable authorization or
// evidence that the daemon consumed the full policy. No endpoint/key is exposed.
type sshAccessObservation struct {
	BindingSHA256     string
	ChallengeSHA256   string
	SessionSHA256     string
	JumpSessionSHA256 string
	RecoveryRequired  bool
}

type sshAccessIdentity struct {
	Address         string
	User            string
	HostKeySHA256   string
	ClientKeySHA256 string
}

type sshAccessSigner struct {
	ssh.MultiAlgorithmSigner
	signatures atomic.Int32
}

func (s *sshAccessSigner) SignWithAlgorithm(random io.Reader, data []byte, algorithm string) (*ssh.Signature, error) {
	// No retry, fallback identity or second authentication on this connection.
	if s.signatures.Add(1) != 1 {
		return nil, ErrInventoryUnsafe
	}
	return s.MultiAlgorithmSigner.SignWithAlgorithm(random, data, algorithm)
}

func (s *sshAccessSigner) Sign(random io.Reader, data []byte) (*ssh.Signature, error) {
	return s.SignWithAlgorithm(random, data, s.Algorithms()[0])
}

func prepareSSHAccessPeer(peer sshAccessPeer) (sshAccessPeer, sshAccessIdentity, *sshAccessSigner, error) {
	var empty sshAccessIdentity
	endpoint, err := netip.ParseAddrPort(peer.Address)
	if err != nil || endpoint.String() != peer.Address || endpoint.Port() == 0 ||
		!contextAddress(endpoint.Addr().String()) || !sshUser.MatchString(peer.User) || len(peer.HostKey) == 0 || len(peer.HostKey) > 16<<10 || len(peer.Identity) == 0 || len(peer.Identity) > 16<<10 {
		return sshAccessPeer{}, empty, nil, ErrInventoryUnsafe
	}
	hostWire := bytes.Clone(peer.HostKey)
	if len(hostWire) == 0 || len(hostWire) > 16<<10 {
		return sshAccessPeer{}, empty, nil, ErrInventoryUnsafe
	}
	host, err := ssh.ParsePublicKey(hostWire)
	if err != nil {
		return sshAccessPeer{}, empty, nil, ErrInventoryUnsafe
	}
	private := bytes.Clone(peer.Identity)
	parsed, parseErr := ssh.ParsePrivateKey(private)
	clear(private)
	if parseErr != nil {
		return sshAccessPeer{}, empty, nil, ErrInventoryUnsafe
	}
	signer, ok := parsed.(ssh.AlgorithmSigner)
	if !ok || signer.PublicKey() == nil {
		return sshAccessPeer{}, empty, nil, ErrInventoryUnsafe
	}
	// Certificates, security keys requiring interaction and weak algorithms
	// need separate adapters. Never silently substitute another credential.
	algorithms := func(kind string) []string {
		switch kind {
		case ssh.KeyAlgoED25519, ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521:
			return []string{kind}
		case ssh.KeyAlgoRSA:
			return []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256}
		default:
			return nil
		}
	}
	if !safeSSHAccessRSA(host) || !safeSSHAccessRSA(signer.PublicKey()) || len(algorithms(host.Type())) == 0 {
		return sshAccessPeer{}, empty, nil, ErrInventoryUnsafe
	}
	selected, err := ssh.NewSignerWithAlgorithms(signer, algorithms(signer.PublicKey().Type()))
	if err != nil || len(algorithms(signer.PublicKey().Type())) == 0 {
		return sshAccessPeer{}, empty, nil, ErrInventoryUnsafe
	}
	identity := sshAccessIdentity{peer.Address, peer.User, digestBytes(host.Marshal()), digestBytes(signer.PublicKey().Marshal())}
	peer.HostKey = hostWire
	counted := &sshAccessSigner{MultiAlgorithmSigner: selected}
	peer.Identity = nil
	return peer, identity, counted, nil
}

// Require contemporary RSA sizes even when a weak key was explicitly pinned.
func safeSSHAccessRSA(key ssh.PublicKey) bool {
	if key.Type() != ssh.KeyAlgoRSA {
		return true
	}
	value, ok := key.(ssh.CryptoPublicKey)
	if !ok {
		return false
	}
	rsaKey, ok := value.CryptoPublicKey().(*rsa.PublicKey)
	return ok && rsaKey.N != nil && rsaKey.N.BitLen() >= 2048 && rsaKey.N.BitLen() <= 8192 && rsaKey.E >= 65537 && rsaKey.E%2 == 1
}

func probeSSHFreshAccess(parent context.Context, binding sshAccessBinding, target sshAccessPeer, jump *sshAccessPeer, guard func() error) (result sshAccessObservation, err error) {
	if parent == nil || guard == nil {
		return result, ErrInventoryUnsafe
	}
	ctx, cancel := context.WithTimeout(parent, 15*time.Second)
	defer cancel()
	defer func() {
		if err == nil {
			err = errors.Join(ctx.Err(), guard())
		}
		if err != nil {
			result = sshAccessObservation{}
		}
	}()
	if err := errors.Join(ctx.Err(), guard()); err != nil {
		return result, err
	}
	for _, digest := range []string{binding.Transaction, binding.Plan, binding.Intent, binding.Target} {
		if !lowerDigest.MatchString(digest) {
			return result, ErrInventoryUnsafe
		}
	}
	declaration := intent{Schema: 1, Role: "target", Owner: "syswarden", Profile: "forwarding", Contexts: []accessContext{binding.Access}}
	if err := declaration.validate(); err != nil {
		return result, err
	}
	if binding.Access.Route != "direct" && binding.Access.Route != "proxyjump" {
		return result, ErrInventoryUnsafe
	}
	if (binding.Access.Route == "proxyjump") != (jump != nil) {
		return result, ErrInventoryUnsafe
	}
	target, targetID, targetSigner, err := prepareSSHAccessPeer(target)
	if err != nil {
		return result, err
	}
	expected := net.JoinHostPort(binding.Access.LocalAddress, strconv.Itoa(int(binding.Access.LocalPort)))
	if target.Address != expected || target.User != binding.Access.User {
		return result, ErrInventoryUnsafe
	}
	var jumpID *sshAccessIdentity
	var jumpSigner *sshAccessSigner
	if jump != nil {
		copy, identity, signer, err := prepareSSHAccessPeer(*jump)
		if err != nil {
			return result, err
		}
		if copy.Address == target.Address {
			return result, ErrInventoryUnsafe
		}
		jump, jumpID, jumpSigner = &copy, &identity, signer
	}
	bindingDigest, err := sshActivationDigest(struct {
		Domain  string
		Binding sshAccessBinding
		Target  sshAccessIdentity
		Jump    *sshAccessIdentity
	}{"syswarden-fresh-ssh-access-v1", binding, targetID, jumpID})
	if err != nil {
		return result, err
	}
	check := func() error {
		if digestBytes(targetSigner.PublicKey().Marshal()) != targetID.ClientKeySHA256 ||
			(jump != nil && digestBytes(jumpSigner.PublicKey().Marshal()) != jumpID.ClientKeySHA256) {
			return ErrInventoryChanged
		}
		return errors.Join(ctx.Err(), guard())
	}
	if err := check(); err != nil {
		return result, err
	}
	first := target
	if jump != nil {
		first = *jump
	}
	raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", first.Address)
	if err != nil {
		return result, errors.New("fresh SSH transport could not connect")
	}
	defer func() { err = errors.Join(err, closeSSHAccess(raw)) }()
	// Closing the physical connection also interrupts handshakes, jump channel
	// operations and output reads. SSH forwarded channels do not have deadlines.
	stopped := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { _ = raw.Close(); close(stopped) })
	defer func() {
		if !stop() {
			<-stopped
		}
	}()
	deadline, _ := ctx.Deadline()
	if err := raw.SetDeadline(deadline); err != nil {
		return result, err
	}
	if err := check(); err != nil {
		return result, err
	}
	connection := raw
	var jumpSession string
	if jump != nil {
		client, session, err := authenticateSSHAccess(raw, *jump, jumpSigner)
		if err != nil {
			return result, err
		}
		defer func() { err = errors.Join(err, closeSSHAccess(client)) }()
		jumpSession = session
		if err := check(); err != nil {
			return result, err
		}
		connection, err = client.DialContext(ctx, "tcp", target.Address)
		if err != nil {
			return result, errors.New("fresh SSH bastion forwarding was refused")
		}
		defer func() { err = errors.Join(err, closeSSHAccess(connection)) }()
	}
	client, sessionID, err := authenticateSSHAccess(connection, target, targetSigner)
	if err != nil {
		return result, err
	}
	defer func() { err = errors.Join(err, closeSSHAccess(client)) }()
	if err := check(); err != nil {
		return result, err
	}
	// The random challenge is generated after a new authenticated transport.
	// Only fixed framing and lowercase digests enter the remote shell command.
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return result, err
	}
	challenge := digestBytes(append([]byte(bindingDigest), nonce...))
	session, err := client.NewSession()
	if err != nil {
		return result, errors.New("fresh SSH session was refused")
	}
	defer session.Close()
	stdout, stderr := &sshAccessOutput{limit: 512}, &sshAccessOutput{limit: 256}
	session.Stdout, session.Stderr = stdout, stderr
	command := "printf 'SYSWARDEN-SSH-ACCESS-V1\\n" + challenge + "\\n'; printf '%s\\n' \"$SSH_CONNECTION\""
	if err := check(); err != nil {
		return result, err
	}
	runErr := session.Run(command)
	if err := check(); err != nil {
		return result, err
	}
	if runErr != nil || stderr.Len() != 0 {
		return result, errors.New("fresh SSH challenge did not complete cleanly")
	}
	if err := verifySSHAccessResponse(stdout.Bytes(), challenge, binding.Access, raw.LocalAddr(), jump != nil); err != nil {
		return result, err
	}
	if err := check(); err != nil {
		return result, err
	}
	return sshAccessObservation{bindingDigest, challenge, sessionID, jumpSession, true}, nil
}

func authenticateSSHAccess(connection net.Conn, peer sshAccessPeer, signer *sshAccessSigner) (*ssh.Client, string, error) {
	host, err := ssh.ParsePublicKey(peer.HostKey)
	if err != nil {
		return nil, "", ErrInventoryUnsafe
	}
	safe := ssh.SupportedAlgorithms()
	config := &ssh.ClientConfig{User: peer.User, Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.FixedHostKey(host), HostKeyAlgorithms: safe.HostKeys,
		Config: ssh.Config{KeyExchanges: safe.KeyExchanges, Ciphers: safe.Ciphers, MACs: safe.MACs}}
	conn, channels, requests, err := ssh.NewClientConn(connection, peer.Address, config)
	if err != nil {
		return nil, "", errors.New("fresh SSH pinned-key authentication failed")
	}
	if signer.signatures.Load() != 1 || len(conn.SessionID()) == 0 {
		_ = conn.Close()
		return nil, "", errors.New("fresh SSH server did not require the selected public-key signature")
	}
	return ssh.NewClient(conn, channels, requests), digestBytes(conn.SessionID()), nil
}

func closeSSHAccess(closer io.Closer) error {
	err := closer.Close()
	if errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF) {
		return nil
	}
	return err
}

type sshAccessOutput struct {
	buffer bytes.Buffer
	limit  int
}

func (b *sshAccessOutput) Len() int { return b.buffer.Len() }

func (b *sshAccessOutput) Bytes() []byte { return b.buffer.Bytes() }

func (b *sshAccessOutput) Write(p []byte) (int, error) {
	if len(p) > b.limit-b.Len() {
		return 0, errors.New("SSH access output exceeds bounds")
	}
	return b.buffer.Write(p)
}

func verifySSHAccessResponse(output []byte, challenge string, access accessContext, local net.Addr, viaJump bool) error {
	if !lowerDigest.MatchString(challenge) || len(output) > 512 {
		return ErrInventoryUnsafe
	}
	prefix := "SYSWARDEN-SSH-ACCESS-V1\n" + challenge + "\n"
	if !bytes.HasPrefix(output, []byte(prefix)) || !bytes.HasSuffix(output, []byte("\n")) {
		return ErrInventoryChanged
	}
	tuple := strings.TrimSuffix(string(output[len(prefix):]), "\n")
	parts := strings.Split(tuple, " ")
	if len(parts) != 4 || parts[0] != access.Address || parts[2] != access.LocalAddress || parts[3] != strconv.Itoa(int(access.LocalPort)) {
		return ErrInventoryChanged
	}
	port, err := strconv.ParseUint(parts[1], 10, 16)
	if err != nil || port == 0 || strconv.FormatUint(port, 10) != parts[1] {
		return ErrInventoryUnsafe
	}
	if !viaJump {
		if local == nil || local.String() != net.JoinHostPort(parts[0], parts[1]) {
			return ErrInventoryChanged
		}
	}
	return nil
}

// Compile-time assertions keep the signature-counting wrapper in the algorithm
// negotiation path instead of silently falling back to the embedded signer.
var _ ssh.MultiAlgorithmSigner = (*sshAccessSigner)(nil)
