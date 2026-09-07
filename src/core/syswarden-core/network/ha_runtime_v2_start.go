package network

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"syswarden-core/firewall"
)

type haRuntimeV2Components struct {
	adapter  *haRuntimeV2Adapter
	outbound *haRuntimeV2Outbound
	identity *haV2TLSIdentity
	manager  firewall.Manager
}

func validateHARuntimeV2Config(cfg HAConfig) error {
	if !cfg.V2Enabled || cfg.Enabled != "y" || !haReplicationIDRE.MatchString(cfg.ClusterID) || cfg.Epoch == 0 ||
		!haReplicationIDRE.MatchString(cfg.NodeID) || !haReplicationIDRE.MatchString(cfg.PeerID) || cfg.NodeID == cfg.PeerID ||
		(cfg.Role != string(haRuntimeV2Writer) && cfg.Role != string(haRuntimeV2Standby)) || len(cfg.PeerIPs) != 1 ||
		cfg.PeerTLSName != cfg.PeerID || len(cfg.PeerCertSHA256) < 1 || len(cfg.PeerCertSHA256) > 2 ||
		cfg.Token == "" || strings.TrimSpace(cfg.Token) != cfg.Token || strings.ContainsAny(cfg.Token, " \t\r\n") ||
		!validHARuntimeV2Path(cfg.V2SecretFile) || !validHARuntimeV2Path(cfg.TLSCertFile) ||
		!validHARuntimeV2Path(cfg.TLSKeyFile) || !validHARuntimeV2Path(cfg.TLSCAFile) ||
		!validHARuntimeV2Path(cfg.StateFile) || !validHARuntimeV2Path(cfg.TransactionFile) || cfg.StateFile == cfg.TransactionFile ||
		cfg.TransactionFile == cfg.StateFile+".anchor.json" || cfg.TransactionFile == cfg.StateFile+".head.wal.json" ||
		cfg.TransactionFile == cfg.StateFile+".instance.lock" ||
		cfg.HeartbeatInterval < time.Second || cfg.HeartbeatInterval > time.Minute ||
		cfg.HeartbeatTimeout < cfg.HeartbeatInterval*2 || cfg.HeartbeatTimeout > 2*time.Minute ||
		cfg.RequestTimeout < time.Second || cfg.RequestTimeout > 30*time.Second {
		return fmt.Errorf("invalid HA v2 runtime configuration")
	}
	peer, err := netip.ParseAddr(cfg.PeerIPs[0])
	if err != nil {
		return fmt.Errorf("HA v2 peer must be one canonical address")
	}
	seenFingerprints := make(map[string]struct{}, len(cfg.PeerCertSHA256))
	for _, fingerprint := range cfg.PeerCertSHA256 {
		if !isLowerHexSHA256(fingerprint) {
			return fmt.Errorf("HA v2 peer certificate fingerprint is invalid")
		}
		if _, duplicate := seenFingerprints[fingerprint]; duplicate {
			return fmt.Errorf("HA v2 peer certificate fingerprints must be unique")
		}
		seenFingerprints[fingerprint] = struct{}{}
	}
	if peer.String() != cfg.PeerIPs[0] || peer.Is4In6() || peer.Zone() != "" || peer.IsUnspecified() || peer.IsMulticast() ||
		peer.IsLoopback() || peer.IsLinkLocalUnicast() {
		return fmt.Errorf("HA v2 peer must be one usable exact address")
	}
	port, err := strconv.Atoi(cfg.Port)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("HA v2 peer port is invalid")
	}
	return nil
}

func validHARuntimeV2Path(value string) bool {
	return value != "" && filepath.IsAbs(value) && filepath.Clean(value) == value
}

func prepareHARuntimeV2(ctx context.Context, cfg HAConfig, manager firewall.Manager, now func() time.Time) (*haRuntimeV2Components, error) {
	if ctx == nil || manager == nil || now == nil {
		return nil, fmt.Errorf("HA v2 runtime dependencies are unavailable")
	}
	if err := validateHARuntimeV2Config(cfg); err != nil {
		return nil, err
	}
	transactional, ok := manager.(firewall.RecoverableMutationManager)
	if !ok {
		return nil, fmt.Errorf("HA v2 requires the authoritative recoverable firewall transaction capability")
	}
	store, err := newHAV2TransactionStore(cfg.StateFile, cfg.TransactionFile, os.Geteuid())
	if err != nil {
		return nil, err
	}
	if err := store.acquireInstanceLock(); err != nil {
		return nil, err
	}
	prepared := false
	defer func() {
		if !prepared {
			store.releaseInstanceLock()
		}
	}()
	secret, err := readHARuntimeV2Secret(cfg.V2SecretFile, os.Geteuid())
	if err != nil {
		return nil, fmt.Errorf("load HA v2 message secret: %w", err)
	}
	defer func() {
		for index := range secret {
			secret[index] = 0
		}
	}()
	identity, err := loadHAV2TLSIdentity(cfg.TLSCertFile, cfg.TLSKeyFile, cfg.TLSCAFile, cfg.NodeID, cfg.PeerID, cfg.PeerCertSHA256, os.Geteuid())
	if err != nil {
		return nil, fmt.Errorf("load HA v2 mutual TLS identity: %w", err)
	}

	recoveryTime := now().UTC()
	if err := store.recoverHeadJournal(cfg.ClusterID, cfg.Epoch); err != nil {
		return nil, fmt.Errorf("recover pending HA v2 head transaction: %w", err)
	}
	model, recovered, err := store.recover(ctx, transactional, cfg.ClusterID, cfg.Epoch, cfg.NodeID, cfg.PeerID, cfg.Role, recoveryTime)
	if err != nil {
		return nil, fmt.Errorf("recover pending HA v2 firewall transaction: %w", err)
	}
	if !recovered {
		model, err = store.loadOrInitialize(cfg.ClusterID, cfg.Epoch)
		if err != nil {
			return nil, fmt.Errorf("load HA v2 replication state: %w", err)
		}
	}
	identityBound, err := model.bindRuntimeIdentity(cfg.NodeID, cfg.PeerID, cfg.Role)
	if err != nil {
		return nil, fmt.Errorf("attest HA v2 persisted runtime identity: %w", err)
	}
	if identityBound {
		if err := store.persist(model); err != nil {
			return nil, fmt.Errorf("persist HA v2 runtime identity: %w", err)
		}
	}
	coordinator, err := newHAReplicationCoordinator(cfg.ClusterID, cfg.NodeID, cfg.PeerID, secret, model)
	if err != nil {
		return nil, err
	}
	if err := model.validateStaticRole(cfg.NodeID, cfg.PeerID, cfg.Role); err != nil {
		coordinator.close()
		return nil, fmt.Errorf("attest HA v2 persisted static role: %w", err)
	}
	if err := store.reconcile(ctx, transactional, model, recoveryTime); err != nil {
		coordinator.close()
		return nil, fmt.Errorf("reconcile HA v2 restart state: %w", err)
	}
	adapter, err := newHARuntimeV2Adapter(coordinator, haRuntimeV2Role(cfg.Role), cfg.PeerIPs[0], cfg.HeartbeatTimeout)
	if err != nil {
		coordinator.close()
		return nil, err
	}
	if err := adapter.configureTransactions(ctx, transactional, store, now); err != nil {
		coordinator.close()
		return nil, err
	}
	adapter.peerCertificateVerifier = identity.verifyPeer
	transport := &http.Transport{
		Proxy: nil, TLSClientConfig: identity.clientConfig(), ForceAttemptHTTP2: false,
		MaxIdleConns: 2, MaxIdleConnsPerHost: 2, IdleConnTimeout: 30 * time.Second,
		TLSHandshakeTimeout: cfg.RequestTimeout, ResponseHeaderTimeout: cfg.RequestTimeout,
	}
	client := &http.Client{
		Transport:     transport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return fmt.Errorf("HA v2 redirects are refused") },
	}
	peerURL := "https://" + net.JoinHostPort(cfg.PeerIPs[0], strconv.Itoa(mustAtoiPort(cfg.Port)))
	outbound, err := newHARuntimeV2Outbound(adapter, client, peerURL, cfg.Token, store.persist, cfg.HeartbeatInterval, cfg.RequestTimeout)
	if err != nil {
		coordinator.close()
		transport.CloseIdleConnections()
		return nil, err
	}
	replicated, err := newHAV2ReplicatedManager(manager, adapter)
	if err != nil {
		coordinator.close()
		transport.CloseIdleConnections()
		return nil, err
	}
	go func() { <-ctx.Done(); transport.CloseIdleConnections() }()
	prepared = true
	return &haRuntimeV2Components{adapter: adapter, outbound: outbound, identity: identity, manager: replicated}, nil
}

func mustAtoiPort(value string) int {
	port, _ := strconv.Atoi(value)
	return port
}

func (components *haRuntimeV2Components) startLoops(ctx context.Context, interval time.Duration) {
	go components.outbound.run(ctx)
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-ticker.C:
				components.adapter.checkHeartbeat(now)
				if err := components.adapter.expireLocalClaims(now, maxHASweepPerPass); err != nil {
					components.adapter.markOutboundFailure("HA v2 expiry reconciliation failed")
				}
			}
		}
	}()
}

func configureHAV2ServerTLS(server *http.Server, identity *haV2TLSIdentity) error {
	if server == nil || identity == nil {
		return fmt.Errorf("HA v2 server TLS identity is unavailable")
	}
	server.TLSConfig = identity.serverConfig()
	server.TLSConfig.MinVersion = tls.VersionTLS13
	return nil
}
