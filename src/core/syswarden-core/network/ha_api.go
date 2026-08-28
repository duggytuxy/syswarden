package network

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"syswarden-core/firewall"
	corelogger "syswarden-core/logger"
	"syswarden-core/utils"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/spf13/viper"
)

type HAConfig struct {
	Enabled          string
	Token            string
	PeerIPs          []string
	Port             string
	BunkerWebEnabled bool
}

func loadHAConfig() HAConfig {
	cfg := HAConfig{
		Enabled: "n",
		Token:   "",
		PeerIPs: []string{},
		Port:    "62026", // Default HA TLS API Port
	}

	if viper.GetBool("integrations.ha.enabled") {
		cfg.Enabled = "y"
	}
	cfg.BunkerWebEnabled = viper.GetBool("integrations.bunkerweb.enabled")

	if token := viper.GetString("integrations.ha.token"); token != "" {
		cfg.Token = token
	}
	if ips := viper.GetStringSlice("integrations.ha.peer_ips"); len(ips) > 0 {
		cfg.PeerIPs = ips
	}

	port := viper.GetInt("integrations.ha.peer_port")
	if port > 0 {
		cfg.Port = fmt.Sprintf("%d", port)
	} else if portStr := viper.GetString("integrations.ha.peer_port"); portStr != "" {
		cfg.Port = portStr
	}

	return cfg
}

func generateSelfSignedCertPEM() ([]byte, []byte, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, nil, err
	}

	hostname, _ := os.Hostname()
	dnsNames := []string{"localhost"}
	if hostname != "" && hostname != "localhost" {
		dnsNames = append(dnsNames, hostname)
	}
	ipAddresses := []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
	if addresses, err := net.InterfaceAddrs(); err == nil {
		for _, address := range addresses {
			ip, _, parseErr := net.ParseCIDR(address.String())
			if parseErr == nil && ip != nil {
				ipAddresses = append(ipAddresses, ip)
			}
		}
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"SYSWARDEN HA Cluster"},
		},
		DNSNames:              dnsNames,
		IPAddresses:           ipAddresses,
		NotBefore:             time.Now().Add(-5 * time.Minute),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	if len(certPEM) == 0 || len(keyPEM) == 0 {
		return nil, nil, fmt.Errorf("failed to encode HA TLS certificate")
	}
	return certPEM, keyPEM, nil
}

type HASyncPayload struct {
	IPs        []string      `json:"ips"`
	Bans       []HAActiveBan `json:"bans,omitempty"`
	NextCursor string        `json:"next_cursor,omitempty"`
}

type HAActiveBan struct {
	IP           string `json:"ip"`
	Source       string `json:"source"`
	Reason       string `json:"reason"`
	PeerScope    string `json:"peer_scope"`
	OriginPeerIP string `json:"origin_peer_ip"`
	ExpiresAt    string `json:"expires_at"`
}

const (
	haBlacklistIPv4File  = "/etc/syswarden/lists/syswarden_blacklist.ipv4"
	haBlacklistIPv6File  = "/etc/syswarden/lists/syswarden_blacklist.ipv6"
	haTelemetryDataFile  = "/var/lib/syswarden/ui/data.json"
	haBanLedgerFile      = "/var/lib/syswarden/ha/bans.json"
	defaultHATLSDir      = "/var/lib/syswarden/ha"
	haTLSCertificateName = "server.crt"
	haTLSPrivateKeyName  = "server.key"
	maxHARequestBytes    = 2 * 1024 * 1024
	maxHATelemetryBytes  = 1024 * 1024
	maxHABlocklistBytes  = 1024 * 1024
	maxHAIPsPerRequest   = 1024
	maxHABansPerRequest  = 500
	haReadTimeout        = 5 * time.Second
	haReadHeaderTimeout  = 3 * time.Second
	haWriteTimeout       = 10 * time.Second
	haIdleTimeout        = 30 * time.Second
	maxHALedgerBytes     = 16 * 1024 * 1024
	maxHALedgerRecords   = 16_384
	maxHASweepPerPass    = 256
	haSweepInterval      = time.Second
	maxHASourceBytes     = 64
	maxHAReasonBytes     = 512
)

const (
	haLedgerVersion    = 1
	haBanPendingApply  = "pending_apply"
	haBanActive        = "active"
	haBanPendingDelete = "pending_delete"
)

var (
	haTLSDir               = defaultHATLSDir
	haRuntimeBlacklistIPv4 = haBlacklistIPv4File
	haRuntimeBlacklistIPv6 = haBlacklistIPv6File
	haRuntimeTelemetryFile = haTelemetryDataFile
	haRuntimeBanLedgerFile = haBanLedgerFile
)

func loadOrCreateHATLSCertificate(directory string) (tls.Certificate, error) {
	directory = filepath.Clean(directory)
	directoryInfo, directoryErr := os.Lstat(directory)
	if directoryErr == nil {
		return loadPersistedHATLSCertificate(directory, directoryInfo)
	}
	if !os.IsNotExist(directoryErr) {
		return tls.Certificate{}, fmt.Errorf("inspect HA TLS directory: %w", directoryErr)
	}

	parentDirectory := filepath.Clean(filepath.Dir(directory))
	if err := os.MkdirAll(parentDirectory, 0700); err != nil {
		return tls.Certificate{}, fmt.Errorf("create HA TLS parent directory: %w", err)
	}
	parentInfo, err := os.Lstat(parentDirectory)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("inspect HA TLS parent directory: %w", err)
	}
	if parentInfo.Mode()&os.ModeSymlink != 0 || !parentInfo.IsDir() {
		return tls.Certificate{}, fmt.Errorf("HA TLS parent must be a real directory, not a symbolic link")
	}

	certPEM, keyPEM, err := generateSelfSignedCertPEM()
	if err != nil {
		return tls.Certificate{}, err
	}
	certificate, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("load generated HA TLS identity: %w", err)
	}
	if err := validateHATLSCertificate(&certificate, time.Now()); err != nil {
		return tls.Certificate{}, fmt.Errorf("validate generated HA TLS identity: %w", err)
	}
	if err := persistNewHATLSIdentity(directory, certPEM, keyPEM, writePrivateTLSFile); err != nil {
		return tls.Certificate{}, err
	}
	return certificate, nil
}

func loadPersistedHATLSCertificate(directory string, directoryInfo os.FileInfo) (tls.Certificate, error) {
	if directoryInfo.Mode()&os.ModeSymlink != 0 || !directoryInfo.IsDir() {
		return tls.Certificate{}, fmt.Errorf("HA TLS identity path must be a real directory, not a symbolic link")
	}
	if directoryInfo.Mode().Perm() != 0700 {
		return tls.Certificate{}, fmt.Errorf("HA TLS identity directory permissions must be 0700, got %04o", directoryInfo.Mode().Perm())
	}

	certificateFile := filepath.Clean(filepath.Join(directory, haTLSCertificateName))
	privateKeyFile := filepath.Clean(filepath.Join(directory, haTLSPrivateKeyName))
	certificateInfo, certificateErr := os.Lstat(certificateFile)
	privateKeyInfo, privateKeyErr := os.Lstat(privateKeyFile)
	if certificateErr != nil || privateKeyErr != nil {
		return tls.Certificate{}, fmt.Errorf("incomplete HA TLS identity; certificate and key must both exist")
	}
	if !certificateInfo.Mode().IsRegular() || !privateKeyInfo.Mode().IsRegular() {
		return tls.Certificate{}, fmt.Errorf("HA TLS identity files must be regular files")
	}
	if certificateInfo.Mode().Perm()&0077 != 0 || privateKeyInfo.Mode().Perm()&0077 != 0 {
		return tls.Certificate{}, fmt.Errorf("HA TLS identity files must not be accessible by group or other users")
	}
	certificate, err := tls.LoadX509KeyPair(certificateFile, privateKeyFile)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("load persisted HA TLS identity: %w", err)
	}
	if err := validateHATLSCertificate(&certificate, time.Now()); err != nil {
		return tls.Certificate{}, fmt.Errorf("validate persisted HA TLS identity: %w", err)
	}
	return certificate, nil
}

func validateHATLSCertificate(certificate *tls.Certificate, now time.Time) error {
	if certificate == nil || len(certificate.Certificate) == 0 {
		return fmt.Errorf("HA TLS identity has no leaf certificate")
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		return fmt.Errorf("parse HA TLS leaf certificate: %w", err)
	}
	if err := validateHATLSLeaf(leaf, now); err != nil {
		return err
	}
	certificate.Leaf = leaf
	return nil
}

func validateHATLSLeaf(leaf *x509.Certificate, now time.Time) error {
	if leaf == nil {
		return fmt.Errorf("HA TLS identity has no parsed leaf certificate")
	}
	if now.Before(leaf.NotBefore) {
		return fmt.Errorf("HA TLS certificate is not valid before %s", leaf.NotBefore.UTC().Format(time.RFC3339))
	}
	if !now.Before(leaf.NotAfter) {
		return fmt.Errorf("HA TLS certificate expired at %s; replace the identity and redistribute server.crt", leaf.NotAfter.UTC().Format(time.RFC3339))
	}
	if err := leaf.CheckSignature(leaf.SignatureAlgorithm, leaf.RawTBSCertificate, leaf.Signature); err != nil {
		return fmt.Errorf("verify self-signed HA TLS certificate: %w", err)
	}
	if len(leaf.DNSNames) == 0 && len(leaf.IPAddresses) == 0 {
		return fmt.Errorf("HA TLS certificate has no DNS or IP subject alternative name")
	}
	if len(leaf.UnhandledCriticalExtensions) != 0 {
		return fmt.Errorf("HA TLS certificate contains unhandled critical extensions")
	}
	serverAuth := false
	for _, usage := range leaf.ExtKeyUsage {
		if usage == x509.ExtKeyUsageServerAuth {
			serverAuth = true
			break
		}
	}
	if !serverAuth {
		return fmt.Errorf("HA TLS certificate is not valid for server authentication")
	}
	return nil
}

type haTLSFileWriter func(path string, content []byte) error

func persistNewHATLSIdentity(directory string, certPEM, keyPEM []byte, writer haTLSFileWriter) error {
	parentDirectory := filepath.Clean(filepath.Dir(directory))
	stagingDirectory, err := os.MkdirTemp(parentDirectory, "."+filepath.Base(directory)+".tmp-")
	if err != nil {
		return fmt.Errorf("create HA TLS staging directory: %w", err)
	}
	stagingDirectory = filepath.Clean(stagingDirectory)
	published := false
	defer func() {
		if !published {
			_ = os.RemoveAll(stagingDirectory)
		}
	}()

	certificateFile := filepath.Clean(filepath.Join(stagingDirectory, haTLSCertificateName))
	privateKeyFile := filepath.Clean(filepath.Join(stagingDirectory, haTLSPrivateKeyName))
	if err := writer(certificateFile, certPEM); err != nil {
		return fmt.Errorf("persist HA TLS certificate: %w", err)
	}
	if err := writer(privateKeyFile, keyPEM); err != nil {
		return fmt.Errorf("persist HA TLS private key: %w", err)
	}
	stagingInfo, err := os.Lstat(stagingDirectory)
	if err != nil {
		return fmt.Errorf("inspect HA TLS staging directory: %w", err)
	}
	if _, err := loadPersistedHATLSCertificate(stagingDirectory, stagingInfo); err != nil {
		return fmt.Errorf("validate staged HA TLS identity: %w", err)
	}
	if err := syncDirectory(stagingDirectory); err != nil {
		return fmt.Errorf("sync staged HA TLS identity: %w", err)
	}
	if _, err := os.Lstat(directory); !os.IsNotExist(err) {
		if err == nil {
			return fmt.Errorf("HA TLS identity path appeared while publishing")
		}
		return fmt.Errorf("inspect HA TLS identity path before publishing: %w", err)
	}
	if err := os.Rename(stagingDirectory, directory); err != nil {
		return fmt.Errorf("publish HA TLS identity atomically: %w", err)
	}
	published = true
	if err := syncDirectory(parentDirectory); err != nil {
		return fmt.Errorf("sync HA TLS parent directory: %w", err)
	}
	return nil
}

func writePrivateTLSFile(path string, content []byte) (resultErr error) {
	path = filepath.Clean(path)
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := file.Close(); resultErr == nil {
			resultErr = closeErr
		}
	}()
	if _, err := file.Write(content); err != nil {
		return err
	}
	return file.Sync()
}

func syncDirectory(directory string) (resultErr error) {
	directory = filepath.Clean(directory)
	handle, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := handle.Close(); resultErr == nil {
			resultErr = closeErr
		}
	}()
	return handle.Sync()
}

type haAPI struct {
	cfg                     HAConfig
	allowedPeers            []netip.Prefix
	fwManager               firewall.Manager
	coreVersion             string
	blacklistIPv4           string
	blacklistIPv6           string
	telemetryFile           string
	banLedgerFile           string
	fence                   *haFenceController
	now                     func() time.Time
	localInterfaceAddresses func() ([]netip.Addr, error)
	isWhitelisted           func(string) (bool, error)
	mutationMu              sync.RWMutex
	sweepCursor             int
}

func newHAAPI(cfg HAConfig, fwManager firewall.Manager, coreVersion, blacklistIPv4, blacklistIPv6, telemetryFile, banLedgerFile string) (*haAPI, error) {
	if cfg.Token == "" || strings.TrimSpace(cfg.Token) != cfg.Token {
		return nil, fmt.Errorf("HA token is required")
	}
	if len(cfg.PeerIPs) == 0 {
		return nil, fmt.Errorf("at least one HA peer IP or CIDR is required")
	}
	allowedPeers := make([]netip.Prefix, 0, len(cfg.PeerIPs))
	seenPeers := make(map[string]struct{}, len(cfg.PeerIPs))
	for _, configuredPeer := range cfg.PeerIPs {
		peer, err := canonicalHAPeerPrefix(configuredPeer)
		if err != nil {
			return nil, fmt.Errorf("invalid configured HA peer: %w", err)
		}
		key := peer.String()
		if _, duplicate := seenPeers[key]; duplicate {
			continue
		}
		seenPeers[key] = struct{}{}
		allowedPeers = append(allowedPeers, peer)
	}
	sort.Slice(allowedPeers, func(i, j int) bool {
		if allowedPeers[i].Bits() != allowedPeers[j].Bits() {
			return allowedPeers[i].Bits() > allowedPeers[j].Bits()
		}
		return allowedPeers[i].String() < allowedPeers[j].String()
	})
	api := &haAPI{
		cfg:                     cfg,
		allowedPeers:            allowedPeers,
		fwManager:               fwManager,
		coreVersion:             coreVersion,
		blacklistIPv4:           filepath.Clean(blacklistIPv4),
		blacklistIPv6:           filepath.Clean(blacklistIPv6),
		telemetryFile:           filepath.Clean(telemetryFile),
		banLedgerFile:           filepath.Clean(banLedgerFile),
		now:                     time.Now,
		localInterfaceAddresses: utils.LocalInterfaceAddresses,
		isWhitelisted:           utils.IsWhitelistedStrict,
	}
	fence, err := newHAFenceController(filepath.Join(filepath.Dir(api.banLedgerFile), "fence"), os.Geteuid())
	if err != nil {
		return nil, err
	}
	api.fence = fence
	if err := api.fence.prepareForServer(); err != nil {
		return nil, fmt.Errorf("initialize HA native-sync fence: %w", err)
	}
	return api, nil
}

func (api *haAPI) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/ha/sync", api.handleSync)
	mux.HandleFunc("/ha/telemetry", api.handleTelemetry)
	mux.HandleFunc("/ha/status", api.handleStatus)
	return mux
}

func canonicalHAPeerPrefix(value string) (netip.Prefix, error) {
	value = strings.TrimSpace(value)
	if address, err := netip.ParseAddr(value); err == nil {
		if address.Is4In6() || address.Zone() != "" {
			return netip.Prefix{}, fmt.Errorf("IPv4-mapped or zoned peer addresses are not allowed")
		}
		return netip.PrefixFrom(address, address.BitLen()), nil
	}
	prefix, err := netip.ParsePrefix(value)
	if err != nil || !prefix.IsValid() {
		return netip.Prefix{}, fmt.Errorf("invalid HA peer IP or CIDR")
	}
	if prefix.Addr().Is4In6() || prefix.Addr().Zone() != "" {
		return netip.Prefix{}, fmt.Errorf("IPv4-mapped or zoned peer CIDRs are not allowed")
	}
	if prefix.Addr() != prefix.Masked().Addr() {
		return netip.Prefix{}, fmt.Errorf("HA peer CIDR contains host bits outside its mask")
	}
	minimumBits := utils.MinimumFirewallIPv6PrefixBits
	if prefix.Addr().Is4() {
		minimumBits = utils.MinimumFirewallIPv4PrefixBits
	}
	if prefix.Bits() < minimumBits {
		return netip.Prefix{}, fmt.Errorf("HA peer CIDR is broader than the /%d minimum", minimumBits)
	}
	return prefix.Masked(), nil
}

func canonicalHAAddress(value string) (string, error) {
	value = strings.TrimSpace(value)
	if address, err := netip.ParseAddr(value); err == nil {
		if address.Is4In6() || address.Zone() != "" {
			return "", fmt.Errorf("invalid HA host address %q", value)
		}
		return address.String(), nil
	}
	return "", fmt.Errorf("invalid HA host address %q", value)
}

func canonicalHAStoredEntry(value string) (string, error) {
	if address, err := canonicalHAAddress(value); err == nil {
		return address, nil
	}
	value = strings.TrimSpace(value)
	prefix, err := netip.ParsePrefix(value)
	if err != nil || !prefix.IsValid() || prefix.Addr().Is4In6() || prefix.Addr().Zone() != "" {
		return "", fmt.Errorf("invalid stored HA address or prefix %q", value)
	}
	return prefix.Masked().String(), nil
}

func (api *haAPI) canonicalHAFirewallTarget(value string) (string, error) {
	if api == nil || api.localInterfaceAddresses == nil || api.isWhitelisted == nil {
		return "", fmt.Errorf("HA firewall target policy is unavailable")
	}
	localAddresses, err := api.localInterfaceAddresses()
	if err != nil {
		return "", fmt.Errorf("load local interface addresses: %w", err)
	}
	return utils.CanonicalFirewallMutationTarget(value, utils.FirewallTargetPolicy{
		LocalAddresses:    localAddresses,
		ProtectedPrefixes: api.allowedPeers,
		IsWhitelisted:     api.isWhitelisted,
	})
}

func (api *haAPI) validateHAMutationTargets(mutation haMutationRequest) error {
	for _, address := range mutation.ips {
		if _, err := api.canonicalHAFirewallTarget(address); err != nil {
			return err
		}
	}
	for _, request := range mutation.temporaries {
		if _, err := api.canonicalHAFirewallTarget(request.IP); err != nil {
			return err
		}
	}
	return nil
}

func readHARootedFile(path string) ([]byte, error) {
	return readHARootedFileBounded(path, 0)
}

func readHARootedFileBounded(path string, limit int64) ([]byte, error) {
	path = filepath.Clean(path)
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	defer root.Close()
	return readHARegularFileBounded(root, filepath.Base(path), limit)
}

func readHARegularFileBounded(root *os.Root, name string, limit int64) ([]byte, error) {
	before, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() {
		return nil, fmt.Errorf("HA file is not a regular file: %s", name)
	}
	file, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return nil, err
	}
	current, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !opened.Mode().IsRegular() || !current.Mode().IsRegular() ||
		!os.SameFile(before, opened) || !os.SameFile(opened, current) {
		return nil, fmt.Errorf("HA file changed while opening: %s", name)
	}
	reader := io.Reader(file)
	if limit > 0 {
		reader = io.LimitReader(file, limit+1)
	}
	content, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	if limit > 0 && int64(len(content)) > limit {
		return nil, fmt.Errorf("HA file exceeds %d bytes: %s", limit, name)
	}
	return content, nil
}

type haPeerIdentity struct {
	IP    string
	Scope string
}

func (api *haAPI) authorizePeer(w http.ResponseWriter, r *http.Request) (haPeerIdentity, bool) {
	remoteHost, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return haPeerIdentity{}, false
	}
	remoteIP, err := netip.ParseAddr(remoteHost)
	if err != nil || remoteIP.Is4In6() || remoteIP.Zone() != "" {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return haPeerIdentity{}, false
	}
	matchedScope := ""
	for _, peer := range api.allowedPeers {
		if peer.Contains(remoteIP) {
			matchedScope = peer.String()
			break
		}
	}
	if matchedScope == "" {
		log.Printf("[HA Cluster] Unauthorized request dropped")
		http.Error(w, "Forbidden", http.StatusForbidden)
		return haPeerIdentity{}, false
	}
	expectedHash := sha256.Sum256([]byte("Bearer " + api.cfg.Token))
	providedHash := sha256.Sum256([]byte(r.Header.Get("Authorization")))
	if subtle.ConstantTimeCompare(providedHash[:], expectedHash[:]) != 1 {
		log.Printf("[HA Cluster] Unauthorized HA API attempt dropped")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return haPeerIdentity{}, false
	}
	return haPeerIdentity{IP: remoteIP.String(), Scope: matchedScope}, true
}

func (api *haAPI) handleSync(w http.ResponseWriter, r *http.Request) {
	peer, authorized := api.authorizePeer(w, r)
	if !authorized {
		return
	}

	switch r.Method {
	case http.MethodGet:
		if r.URL.RawQuery != "" && !api.cfg.BunkerWebEnabled {
			http.Error(w, "BunkerWeb integration is disabled; configure integrations.bunkerweb.enabled", http.StatusForbidden)
			return
		}
		api.mutationMu.RLock()
		ips, bans, err := api.readHASyncSnapshot(api.now())
		api.mutationMu.RUnlock()
		if err != nil {
			log.Printf("[HA Cluster] Failed to read synchronized blocklists: %v", err)
			http.Error(w, "Blocklist unavailable", http.StatusInternalServerError)
			return
		}
		if len(ips) == 0 {
			ips = nil // Preserve the deployed {"ips":null} empty-list contract.
		}
		payload := HASyncPayload{IPs: ips}
		if r.URL.RawQuery != "" {
			start, limit, ok := decodeHAProvenanceQuery(w, r)
			if !ok {
				return
			}
			if start > len(bans) {
				http.Error(w, "Invalid provenance cursor", http.StatusBadRequest)
				return
			}
			end := start + limit
			if end > len(bans) {
				end = len(bans)
			}
			payload.Bans = bans[start:end]
			if end < len(bans) {
				payload.NextCursor = encodeHAProvenanceCursor(end)
			}
		}
		writeHAJSON(w, http.StatusOK, payload)
	case http.MethodPost, http.MethodDelete:
		mutation, ok := decodeHAMutationPayload(w, r)
		if !ok {
			return
		}
		if len(mutation.temporaries) > 0 && !api.cfg.BunkerWebEnabled {
			http.Error(w, "BunkerWeb integration is disabled; configure integrations.bunkerweb.enabled", http.StatusForbidden)
			return
		}
		if r.Method == http.MethodPost {
			if err := api.validateHAMutationTargets(mutation); err != nil {
				log.Printf("[HA Cluster] Rejected a protected firewall mutation target: %v", err)
				http.Error(w, "Rejected firewall target", http.StatusBadRequest)
				return
			}
		}
		if len(mutation.temporaries) > 0 {
			if r.Method == http.MethodPost {
				api.applyHATemporaryBans(w, peer, mutation.temporaries)
			} else {
				api.applyHATemporaryUnbans(w, peer, mutation.temporaries)
			}
			return
		}
		fenceErr := api.fence.withLegacyMutation(r.Method, r.Header, func() {
			if r.Method == http.MethodPost {
				api.applyHABans(w, mutation.ips)
			} else {
				api.applyHAUnbans(w, mutation.ips)
			}
		})
		if fenceErr != nil {
			var protocolError *haFenceHTTPError
			if errors.As(fenceErr, &protocolError) {
				http.Error(w, protocolError.Text, protocolError.Status)
				return
			}
			http.Error(w, "HA native-sync fence is unavailable", http.StatusServiceUnavailable)
		}
	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

func decodeHAProvenanceQuery(w http.ResponseWriter, r *http.Request) (int, int, bool) {
	query := r.URL.Query()
	for key, values := range query {
		if (key != "details" && key != "limit" && key != "cursor") || len(values) != 1 {
			http.Error(w, "Invalid provenance query", http.StatusBadRequest)
			return 0, 0, false
		}
	}
	if query.Get("details") != "true" {
		http.Error(w, "Invalid provenance query", http.StatusBadRequest)
		return 0, 0, false
	}
	limit := 100
	if value := query.Get("limit"); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed < 1 || parsed > 500 {
			http.Error(w, "Invalid provenance limit", http.StatusBadRequest)
			return 0, 0, false
		}
		limit = parsed
	}
	start := 0
	if value := query.Get("cursor"); value != "" {
		decoded, err := base64.RawURLEncoding.DecodeString(value)
		if err != nil || base64.RawURLEncoding.EncodeToString(decoded) != value {
			http.Error(w, "Invalid provenance cursor", http.StatusBadRequest)
			return 0, 0, false
		}
		parsed, err := strconv.Atoi(string(decoded))
		if err != nil || parsed < 0 {
			http.Error(w, "Invalid provenance cursor", http.StatusBadRequest)
			return 0, 0, false
		}
		start = parsed
	}
	return start, limit, true
}

func encodeHAProvenanceCursor(offset int) string {
	return base64.RawURLEncoding.EncodeToString([]byte(strconv.Itoa(offset)))
}

type haTemporaryBanRequest struct {
	IP     string
	TTL    time.Duration
	Reason string
	Source string
}

type haMutationRequest struct {
	ips         []string
	temporaries []haTemporaryBanRequest
}

type haTemporaryDeleteResult struct {
	Status  string `json:"status"`
	Deleted int    `json:"deleted"`
}

func decodeHAMutationPayload(w http.ResponseWriter, r *http.Request) (haMutationRequest, bool) {
	if r.ContentLength > maxHARequestBytes {
		http.Error(w, "Payload Too Large", http.StatusRequestEntityTooLarge)
		return haMutationRequest{}, false
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxHARequestBytes)
	decoder := json.NewDecoder(r.Body)
	var raw json.RawMessage
	if err := decoder.Decode(&raw); err != nil {
		var maxBytesError *http.MaxBytesError
		if errors.As(err, &maxBytesError) {
			http.Error(w, "Payload Too Large", http.StatusRequestEntityTooLarge)
		} else {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
		}
		return haMutationRequest{}, false
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err != nil {
			var maxBytesError *http.MaxBytesError
			if errors.As(err, &maxBytesError) {
				http.Error(w, "Payload Too Large", http.StatusRequestEntityTooLarge)
			} else {
				http.Error(w, "Invalid JSON", http.StatusBadRequest)
			}
		} else {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
		}
		return haMutationRequest{}, false
	}
	fields, err := decodeHAObjectFields(raw)
	if err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return haMutationRequest{}, false
	}
	if ipsWire, legacy := fields["ips"]; legacy {
		if len(fields) != 1 {
			http.Error(w, "Ambiguous HA mutation", http.StatusBadRequest)
			return haMutationRequest{}, false
		}
		var ips []string
		if err := json.Unmarshal(ipsWire, &ips); err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return haMutationRequest{}, false
		}
		return decodeHALegacyAddresses(w, ips, r.Method == http.MethodDelete)
	}
	if bansWire, batch := fields["bans"]; batch {
		if len(fields) != 1 {
			http.Error(w, "Ambiguous HA mutation", http.StatusBadRequest)
			return haMutationRequest{}, false
		}
		return decodeHATemporaryBanBatch(w, bansWire, r.Method)
	}
	if r.Method == http.MethodDelete {
		if len(fields) != 2 {
			http.Error(w, "Invalid temporary DELETE", http.StatusBadRequest)
			return haMutationRequest{}, false
		}
		ipWire, ok := fields["ip"]
		if !ok {
			http.Error(w, "Invalid temporary DELETE", http.StatusBadRequest)
			return haMutationRequest{}, false
		}
		sourceWire, sourceOK := fields["source"]
		var ip, source string
		if !sourceOK || json.Unmarshal(ipWire, &ip) != nil || json.Unmarshal(sourceWire, &source) != nil || !validHASource(source) {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return haMutationRequest{}, false
		}
		canonical, err := canonicalHAAddress(ip)
		if err != nil {
			http.Error(w, "Invalid host address", http.StatusBadRequest)
			return haMutationRequest{}, false
		}
		return haMutationRequest{temporaries: []haTemporaryBanRequest{{IP: canonical, Source: source}}}, true
	}
	if r.Method != http.MethodPost || len(fields) != 4 {
		http.Error(w, "Invalid temporary ban", http.StatusBadRequest)
		return haMutationRequest{}, false
	}
	for _, required := range []string{"ip", "ttl", "reason", "source"} {
		if _, ok := fields[required]; !ok {
			http.Error(w, "Invalid temporary ban", http.StatusBadRequest)
			return haMutationRequest{}, false
		}
	}
	var ip, reason, source string
	var ttlSeconds int64
	if json.Unmarshal(fields["ip"], &ip) != nil || json.Unmarshal(fields["reason"], &reason) != nil ||
		json.Unmarshal(fields["source"], &source) != nil || json.Unmarshal(fields["ttl"], &ttlSeconds) != nil {
		http.Error(w, "Invalid temporary ban", http.StatusBadRequest)
		return haMutationRequest{}, false
	}
	canonical, err := canonicalHAAddress(ip)
	if err != nil || ttlSeconds < int64(firewall.MinimumBanTTL/time.Second) ||
		ttlSeconds > int64(firewall.MaximumBanTTL/time.Second) || !validHASource(source) || !validHAReason(reason) {
		http.Error(w, "Invalid temporary ban", http.StatusBadRequest)
		return haMutationRequest{}, false
	}
	return haMutationRequest{temporaries: []haTemporaryBanRequest{{
		IP: canonical, TTL: time.Duration(ttlSeconds) * time.Second, Reason: reason, Source: source,
	}}}, true
}

func decodeHAObjectFields(raw []byte) (map[string]json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') {
		return nil, fmt.Errorf("HA mutation must be an object")
	}
	fields := make(map[string]json.RawMessage)
	allowed := map[string]struct{}{"ips": {}, "bans": {}, "ip": {}, "ttl": {}, "reason": {}, "source": {}}
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		key, ok := keyToken.(string)
		if !ok {
			return nil, fmt.Errorf("invalid HA mutation field")
		}
		if _, ok := allowed[key]; !ok {
			return nil, fmt.Errorf("unknown HA mutation field")
		}
		if _, duplicate := fields[key]; duplicate {
			return nil, fmt.Errorf("duplicate HA mutation field")
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, err
		}
		fields[key] = value
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim('}') {
		return nil, fmt.Errorf("invalid HA mutation object")
	}
	if decoder.Decode(&json.RawMessage{}) != io.EOF {
		return nil, fmt.Errorf("trailing HA mutation value")
	}
	return fields, nil
}

func decodeHATemporaryBanBatch(w http.ResponseWriter, wire []byte, method string) (haMutationRequest, bool) {
	var items []json.RawMessage
	if err := json.Unmarshal(wire, &items); err != nil || len(items) == 0 {
		http.Error(w, "Invalid temporary ban batch", http.StatusBadRequest)
		return haMutationRequest{}, false
	}
	if len(items) > maxHABansPerRequest {
		http.Error(w, "Too Many Bans", http.StatusRequestEntityTooLarge)
		return haMutationRequest{}, false
	}
	requests := make([]haTemporaryBanRequest, 0, len(items))
	seen := make(map[string]struct{}, len(items))
	for _, item := range items {
		fields, err := decodeHAObjectFields(item)
		if err != nil {
			http.Error(w, "Invalid temporary ban batch", http.StatusBadRequest)
			return haMutationRequest{}, false
		}
		requiredCount := 4
		if method == http.MethodDelete {
			requiredCount = 2
		}
		if len(fields) != requiredCount {
			http.Error(w, "Invalid temporary ban batch", http.StatusBadRequest)
			return haMutationRequest{}, false
		}
		var ip, source string
		if json.Unmarshal(fields["ip"], &ip) != nil || json.Unmarshal(fields["source"], &source) != nil || !validHASource(source) {
			http.Error(w, "Invalid temporary ban batch", http.StatusBadRequest)
			return haMutationRequest{}, false
		}
		canonical, err := canonicalHAAddress(ip)
		if err != nil {
			http.Error(w, "Invalid temporary ban batch", http.StatusBadRequest)
			return haMutationRequest{}, false
		}
		request := haTemporaryBanRequest{IP: canonical, Source: source}
		if method == http.MethodPost {
			var ttlSeconds int64
			if _, ok := fields["ttl"]; !ok {
				http.Error(w, "Invalid temporary ban batch", http.StatusBadRequest)
				return haMutationRequest{}, false
			}
			if _, ok := fields["reason"]; !ok || json.Unmarshal(fields["ttl"], &ttlSeconds) != nil ||
				json.Unmarshal(fields["reason"], &request.Reason) != nil || ttlSeconds < int64(firewall.MinimumBanTTL/time.Second) ||
				ttlSeconds > int64(firewall.MaximumBanTTL/time.Second) || !validHAReason(request.Reason) {
				http.Error(w, "Invalid temporary ban batch", http.StatusBadRequest)
				return haMutationRequest{}, false
			}
			request.TTL = time.Duration(ttlSeconds) * time.Second
		} else if method != http.MethodDelete {
			http.Error(w, "Invalid temporary ban batch", http.StatusBadRequest)
			return haMutationRequest{}, false
		}
		key := request.IP + "\x00" + request.Source
		if _, duplicate := seen[key]; duplicate {
			http.Error(w, "Duplicate temporary ban", http.StatusBadRequest)
			return haMutationRequest{}, false
		}
		seen[key] = struct{}{}
		requests = append(requests, request)
	}
	sort.Slice(requests, func(i, j int) bool {
		if requests[i].IP != requests[j].IP {
			return requests[i].IP < requests[j].IP
		}
		return requests[i].Source < requests[j].Source
	})
	return haMutationRequest{temporaries: requests}, true
}

func decodeHALegacyAddresses(w http.ResponseWriter, ips []string, allowStoredPrefixes bool) (haMutationRequest, bool) {
	if len(ips) > maxHAIPsPerRequest {
		http.Error(w, "Too Many IPs", http.StatusRequestEntityTooLarge)
		return haMutationRequest{}, false
	}
	canonical := make([]string, 0, len(ips))
	seen := make(map[string]struct{}, len(ips))
	for _, value := range ips {
		ip, err := canonicalHAAddress(value)
		if allowStoredPrefixes {
			ip, err = canonicalHAStoredEntry(value)
		}
		if err != nil {
			http.Error(w, "Invalid host address", http.StatusBadRequest)
			return haMutationRequest{}, false
		}
		if _, duplicate := seen[ip]; duplicate {
			continue
		}
		seen[ip] = struct{}{}
		canonical = append(canonical, ip)
	}
	sort.Strings(canonical)
	return haMutationRequest{ips: canonical}, true
}

func validHASource(source string) bool {
	if len(source) < 1 || len(source) > maxHASourceBytes {
		return false
	}
	for _, character := range source {
		if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') &&
			(character < '0' || character > '9') && !strings.ContainsRune("._:/-", character) {
			return false
		}
	}
	return true
}

func validHAReason(reason string) bool {
	if len(reason) < 1 || len(reason) > maxHAReasonBytes || !utf8.ValidString(reason) || strings.TrimSpace(reason) == "" {
		return false
	}
	for _, character := range reason {
		if unicode.IsControl(character) || !unicode.IsPrint(character) {
			return false
		}
	}
	return true
}

func (api *haAPI) applyHABans(w http.ResponseWriter, ips []string) {
	if err := api.validateHAMutationTargets(haMutationRequest{ips: ips}); err != nil {
		http.Error(w, "Rejected firewall target", http.StatusBadRequest)
		return
	}
	api.mutationMu.Lock()
	defer api.mutationMu.Unlock()
	log.Printf("[HA Cluster] Received %d validated banned addresses from an authenticated peer", len(ips)) // #nosec G706 -- only the integer length of the validated slice is logged
	if len(ips) > 0 && api.fwManager == nil {
		http.Error(w, "Firewall unavailable", http.StatusInternalServerError)
		return
	}
	for _, ip := range ips {
		if err := api.applyPermanentHABan(ip); err != nil {
			log.Printf("[HA Cluster] Failed to apply a synchronized ban")
			http.Error(w, "Firewall mutation failed", http.StatusInternalServerError)
			return
		}
		if err := api.setStoredIP(ip, true); err != nil {
			log.Printf("[HA Cluster] Failed to persist a synchronized ban")
			http.Error(w, "Blocklist mutation failed", http.StatusInternalServerError)
			return
		}
	}
	writeHAJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (api *haAPI) applyPermanentHABan(ip string) error {
	canonical, err := api.canonicalHAFirewallTarget(ip)
	if err != nil {
		return err
	}
	manager, ok := api.fwManager.(firewall.BanPermanentManager)
	if ok {
		return manager.BanPermanent(canonical)
	}
	// Preserve mixed-version compatibility with older firewall managers. Their
	// historical Ban contract is the only available durable operation.
	return api.fwManager.Ban(canonical)
}

func (api *haAPI) applyHAUnbans(w http.ResponseWriter, ips []string) {
	api.mutationMu.Lock()
	defer api.mutationMu.Unlock()
	now := api.now().UTC().Truncate(time.Second)
	log.Printf("[HA Cluster] Received %d validated addresses to unban from an authenticated peer", len(ips)) // #nosec G706 -- only the integer length of the validated slice is logged
	if len(ips) > 0 && api.fwManager == nil {
		http.Error(w, "Firewall unavailable", http.StatusInternalServerError)
		return
	}
	for _, ip := range ips {
		if err := api.setStoredIP(ip, false); err != nil {
			log.Printf("[HA Cluster] Failed to persist a synchronized unban")
			http.Error(w, "Blocklist mutation failed", http.StatusInternalServerError)
			return
		}
		if desired, err := api.reconcileDesiredHABanAfterRemoval(ip, now); err != nil {
			log.Printf("[HA Cluster] Failed to reconcile remaining synchronized bans")
			http.Error(w, "Firewall reconciliation failed", http.StatusInternalServerError)
			return
		} else if desired {
			log.Printf("[HA Cluster] Legacy unban preserved a temporary ban")
		}
	}
	writeHAJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (api *haAPI) blacklistFile(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		parsed, _, _ = net.ParseCIDR(ip)
	}
	if parsed != nil && parsed.To4() == nil {
		return api.blacklistIPv6
	}
	return api.blacklistIPv4
}

func (api *haAPI) readStoredIPs() ([]string, error) {
	var all []string
	for _, path := range []string{api.blacklistIPv4, api.blacklistIPv6} {
		content, err := readHARootedFileBounded(path, maxHABlocklistBytes)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		for lineNumber, line := range strings.Split(string(content), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			ip, err := canonicalHAStoredEntry(line)
			if err != nil {
				return nil, fmt.Errorf("%s:%d: %w", path, lineNumber+1, err)
			}
			all = append(all, ip)
		}
	}
	seen := make(map[string]struct{}, len(all))
	unique := make([]string, 0, len(all))
	for _, ip := range all {
		if _, ok := seen[ip]; ok {
			continue
		}
		seen[ip] = struct{}{}
		unique = append(unique, ip)
	}
	sort.Strings(unique)
	return unique, nil
}

func (api *haAPI) setStoredIP(ip string, present bool) error {
	if !present {
		return api.removeStoredIPRecovery(ip)
	}
	return corelogger.UpdatePersistentBlocklist(api.blacklistFile(ip), ip, present)
}

func (api *haAPI) removeStoredIPRecovery(ip string) error {
	canonical, err := canonicalHAStoredEntry(ip)
	if err != nil {
		return err
	}
	directory, name, err := openHADataDirectory(api.blacklistFile(canonical))
	if err != nil {
		return err
	}
	defer directory.Close()
	lockFile, err := lockHADataDirectory(directory)
	if err != nil {
		return err
	}
	defer unlockHADataDirectory(lockFile)

	stored, err := readHAStoredIPSet(directory, name)
	if err != nil {
		return err
	}
	if _, exists := stored[canonical]; !exists {
		return nil
	}
	delete(stored, canonical)
	entries := make([]string, 0, len(stored))
	for entry := range stored {
		entries = append(entries, entry)
	}
	sort.Strings(entries)
	content := []byte(nil)
	if len(entries) > 0 {
		content = []byte(strings.Join(entries, "\n") + "\n")
	}
	if len(content) > maxHABlocklistBytes {
		return fmt.Errorf("HA blocklist exceeds %d bytes", maxHABlocklistBytes)
	}
	return publishHAFileAtomically(directory, name, content)
}

func openHADataDirectory(path string) (*os.Root, string, error) {
	cleanPath := filepath.Clean(path)
	if !filepath.IsAbs(cleanPath) || cleanPath != path {
		return nil, "", fmt.Errorf("HA data path must be absolute and canonical")
	}
	directoryPath := filepath.Dir(cleanPath)
	name := filepath.Base(cleanPath)
	if name == "." || name == string(filepath.Separator) || filepath.Base(name) != name {
		return nil, "", fmt.Errorf("invalid HA data file name")
	}
	directoryInfo, err := os.Lstat(directoryPath)
	if err != nil {
		return nil, "", err
	}
	if !directoryInfo.IsDir() || directoryInfo.Mode()&os.ModeSymlink != 0 {
		return nil, "", fmt.Errorf("HA data parent must be a real directory")
	}
	directory, err := os.OpenRoot(directoryPath)
	if err != nil {
		return nil, "", err
	}
	openedInfo, err := directory.Stat(".")
	if err != nil || !os.SameFile(directoryInfo, openedInfo) {
		_ = directory.Close()
		return nil, "", fmt.Errorf("HA data parent changed while opening")
	}
	return directory, name, nil
}

func lockHADataDirectory(directory *os.Root) (*os.File, error) {
	lockFile, err := directory.Open(".")
	if err != nil {
		return nil, fmt.Errorf("open HA blocklist directory lock: %w", err)
	}
	if err := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX); err != nil {
		_ = lockFile.Close()
		return nil, fmt.Errorf("lock HA blocklist directory: %w", err)
	}
	return lockFile, nil
}

func unlockHADataDirectory(lockFile *os.File) {
	_ = syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN)
	_ = lockFile.Close()
}

func readHAStoredIPSet(directory *os.Root, name string) (map[string]struct{}, error) {
	stored := make(map[string]struct{})
	content, err := readHARegularFileBounded(directory, name, maxHABlocklistBytes)
	if errors.Is(err, fs.ErrNotExist) {
		return stored, nil
	}
	if err != nil {
		return nil, err
	}
	for lineNumber, line := range strings.Split(string(content), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		storedIP, err := canonicalHAStoredEntry(line)
		if err != nil {
			return nil, fmt.Errorf("%s:%d: %w", name, lineNumber+1, err)
		}
		stored[storedIP] = struct{}{}
	}
	return stored, nil
}

func createHAStagingFile(directory *os.Root, name string) (*os.File, string, error) {
	for range 128 {
		var random [16]byte
		if _, err := rand.Read(random[:]); err != nil {
			return nil, "", fmt.Errorf("generate HA staging file name: %w", err)
		}
		stagingName := "." + name + ".syswarden-" + hex.EncodeToString(random[:]) + ".tmp"
		file, err := directory.OpenFile(stagingName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if errors.Is(err, fs.ErrExist) {
			continue
		}
		if err != nil {
			return nil, "", fmt.Errorf("create HA staging file: %w", err)
		}
		return file, stagingName, nil
	}
	return nil, "", fmt.Errorf("create HA staging file: too many name collisions")
}

func publishHAFileAtomically(directory *os.Root, name string, content []byte) (resultErr error) {
	destinationInfo, destinationErr := directory.Lstat(name)
	destinationExists := destinationErr == nil
	if destinationErr != nil && !errors.Is(destinationErr, fs.ErrNotExist) {
		return destinationErr
	}
	if destinationExists && !destinationInfo.Mode().IsRegular() {
		return fmt.Errorf("HA blocklist destination is not a regular file: %s", name)
	}

	file, stagingName, err := createHAStagingFile(directory, name)
	if err != nil {
		return err
	}
	defer func() {
		if file != nil {
			_ = file.Close()
		}
		if stagingName != "" {
			_ = directory.Remove(stagingName)
		}
	}()
	if err := file.Chmod(0600); err != nil {
		return fmt.Errorf("restrict HA staging file: %w", err)
	}
	if written, err := file.Write(content); err != nil {
		return fmt.Errorf("write HA staging file: %w", err)
	} else if written != len(content) {
		return fmt.Errorf("write HA staging file: %w", io.ErrShortWrite)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync HA staging file: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close HA staging file: %w", err)
	}
	file = nil

	currentInfo, currentErr := directory.Lstat(name)
	if destinationExists {
		if currentErr != nil || !currentInfo.Mode().IsRegular() || !os.SameFile(destinationInfo, currentInfo) {
			return fmt.Errorf("HA blocklist destination changed before publication: %s", name)
		}
	} else if !errors.Is(currentErr, fs.ErrNotExist) {
		if currentErr == nil {
			return fmt.Errorf("HA blocklist destination appeared before publication: %s", name)
		}
		return currentErr
	}
	if err := directory.Rename(stagingName, name); err != nil {
		return fmt.Errorf("publish HA blocklist atomically: %w", err)
	}
	stagingName = ""
	directoryFile, err := directory.Open(".")
	if err != nil {
		return fmt.Errorf("open HA blocklist directory for sync: %w", err)
	}
	if err := directoryFile.Sync(); err != nil {
		_ = directoryFile.Close()
		return fmt.Errorf("sync HA blocklist directory: %w", err)
	}
	if err := directoryFile.Close(); err != nil {
		return fmt.Errorf("close HA blocklist directory: %w", err)
	}
	return nil
}

type haBanLedger struct {
	Version int                 `json:"version"`
	Bans    []haBanLedgerRecord `json:"bans"`
}

type haBanLedgerRecord struct {
	IP           string `json:"ip"`
	Source       string `json:"source"`
	Reason       string `json:"reason"`
	PeerScope    string `json:"peer_scope"`
	OriginPeerIP string `json:"origin_peer_ip"`
	ExpiresAt    string `json:"expires_at"`
	CreatedAt    string `json:"created_at"`
	UpdatedAt    string `json:"updated_at"`
	State        string `json:"state"`
}

func haLedgerRecordKey(record haBanLedgerRecord) string {
	return record.IP + "\x00" + record.Source + "\x00" + record.PeerScope
}

func readHALedgerInDirectory(directory *os.Root, name string) (haBanLedger, error) {
	info, err := directory.Lstat(name)
	if errors.Is(err, fs.ErrNotExist) {
		return haBanLedger{Version: haLedgerVersion}, nil
	}
	if err != nil {
		return haBanLedger{}, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return haBanLedger{}, fmt.Errorf("HA ban ledger must be a regular 0600 file")
	}
	wire, err := readHARegularFileBounded(directory, name, maxHALedgerBytes)
	if err != nil {
		return haBanLedger{}, err
	}
	if err := rejectHADuplicateJSONKeys(wire); err != nil {
		return haBanLedger{}, fmt.Errorf("decode HA ban ledger: %w", err)
	}
	decoder := json.NewDecoder(io.LimitReader(bytes.NewReader(wire), maxHALedgerBytes+1))
	decoder.DisallowUnknownFields()
	var ledger haBanLedger
	if err := decoder.Decode(&ledger); err != nil {
		return haBanLedger{}, fmt.Errorf("decode HA ban ledger: %w", err)
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); err != io.EOF {
		return haBanLedger{}, fmt.Errorf("decode HA ban ledger: trailing JSON")
	}
	if err := validateHALedger(ledger); err != nil {
		return haBanLedger{}, err
	}
	return ledger, nil
}

func rejectHADuplicateJSONKeys(wire []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(wire))
	if err := scanHAJSONValue(decoder, 0); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return fmt.Errorf("trailing JSON value")
		}
		return err
	}
	return nil
}

func scanHAJSONValue(decoder *json.Decoder, depth int) error {
	if depth > 64 {
		return fmt.Errorf("JSON nesting exceeds 64 levels")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, compound := token.(json.Delim)
	if !compound {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return fmt.Errorf("JSON object key is not a string")
			}
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("duplicate JSON key %q", key)
			}
			seen[key] = struct{}{}
			if err := scanHAJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return fmt.Errorf("invalid JSON object")
		}
		return nil
	case '[':
		for decoder.More() {
			if err := scanHAJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return fmt.Errorf("invalid JSON array")
		}
		return nil
	default:
		return fmt.Errorf("unexpected JSON delimiter")
	}
}

func validateHALedger(ledger haBanLedger) error {
	if ledger.Version != haLedgerVersion {
		return fmt.Errorf("unsupported HA ban ledger version %d", ledger.Version)
	}
	if len(ledger.Bans) > maxHALedgerRecords {
		return fmt.Errorf("HA ban ledger exceeds %d records", maxHALedgerRecords)
	}
	seen := make(map[string]struct{}, len(ledger.Bans))
	for index, record := range ledger.Bans {
		canonicalIP, err := canonicalHAAddress(record.IP)
		if err != nil || canonicalIP != record.IP || !validHASource(record.Source) || !validHAReason(record.Reason) {
			return fmt.Errorf("invalid HA ban ledger record %d", index)
		}
		scope, err := canonicalHAPeerPrefix(record.PeerScope)
		if err != nil || scope.String() != record.PeerScope {
			return fmt.Errorf("invalid HA ban ledger peer scope at record %d", index)
		}
		origin, err := netip.ParseAddr(record.OriginPeerIP)
		if err != nil || origin.Is4In6() || origin.Zone() != "" || !scope.Contains(origin) {
			return fmt.Errorf("invalid HA ban ledger origin at record %d", index)
		}
		created, createdErr := parseCanonicalHATime(record.CreatedAt)
		updated, updatedErr := parseCanonicalHATime(record.UpdatedAt)
		expires, expiresErr := parseCanonicalHATime(record.ExpiresAt)
		if createdErr != nil || updatedErr != nil || expiresErr != nil || updated.Before(created) || !expires.After(created) {
			return fmt.Errorf("invalid HA ban ledger timestamps at record %d", index)
		}
		if record.State != haBanPendingApply && record.State != haBanActive && record.State != haBanPendingDelete {
			return fmt.Errorf("invalid HA ban ledger state at record %d", index)
		}
		key := haLedgerRecordKey(record)
		if _, duplicate := seen[key]; duplicate {
			return fmt.Errorf("duplicate HA ban ledger record %d", index)
		}
		seen[key] = struct{}{}
	}
	return nil
}

func parseCanonicalHATime(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil || parsed.UTC().Format(time.RFC3339) != value {
		return time.Time{}, fmt.Errorf("invalid canonical HA timestamp")
	}
	return parsed.UTC(), nil
}

func sortHALedger(ledger *haBanLedger) {
	sort.Slice(ledger.Bans, func(i, j int) bool {
		left, right := ledger.Bans[i], ledger.Bans[j]
		if left.IP != right.IP {
			return left.IP < right.IP
		}
		if left.Source != right.Source {
			return left.Source < right.Source
		}
		return left.PeerScope < right.PeerScope
	})
}

func (api *haAPI) readHALedger() (haBanLedger, error) {
	directory, name, err := openHADataDirectory(api.banLedgerFile)
	if err != nil {
		return haBanLedger{}, err
	}
	defer directory.Close()
	lockFile, err := lockHADataDirectory(directory)
	if err != nil {
		return haBanLedger{}, err
	}
	defer unlockHADataDirectory(lockFile)
	return readHALedgerInDirectory(directory, name)
}

func (api *haAPI) mutateHALedger(mutator func(*haBanLedger) error) error {
	return api.mutateHALedgerIfChanged(func(ledger *haBanLedger) (bool, error) {
		if err := mutator(ledger); err != nil {
			return false, err
		}
		return true, nil
	})
}

func (api *haAPI) mutateHALedgerIfChanged(mutator func(*haBanLedger) (bool, error)) error {
	directory, name, err := openHADataDirectory(api.banLedgerFile)
	if err != nil {
		return err
	}
	defer directory.Close()
	lockFile, err := lockHADataDirectory(directory)
	if err != nil {
		return err
	}
	defer unlockHADataDirectory(lockFile)
	ledger, err := readHALedgerInDirectory(directory, name)
	if err != nil {
		return err
	}
	changed, err := mutator(&ledger)
	if err != nil {
		return err
	}
	if !changed {
		return nil
	}
	sortHALedger(&ledger)
	if err := validateHALedger(ledger); err != nil {
		return err
	}
	wire, err := json.Marshal(ledger)
	if err != nil {
		return err
	}
	if len(wire) > maxHALedgerBytes {
		return fmt.Errorf("HA ban ledger exceeds %d bytes", maxHALedgerBytes)
	}
	return publishHAFileAtomically(directory, name, wire)
}

func (api *haAPI) readHASyncSnapshot(now time.Time) ([]string, []HAActiveBan, error) {
	staticIPs, err := api.readStoredIPs()
	if err != nil {
		return nil, nil, err
	}
	ledger, err := api.readHALedger()
	if err != nil {
		return nil, nil, err
	}
	now = now.UTC()
	all := append([]string(nil), staticIPs...)
	bans := make([]HAActiveBan, 0, len(ledger.Bans))
	for _, record := range ledger.Bans {
		expires, err := parseCanonicalHATime(record.ExpiresAt)
		if err != nil {
			return nil, nil, err
		}
		if record.State != haBanActive || !expires.After(now) {
			continue
		}
		all = append(all, record.IP)
		bans = append(bans, HAActiveBan{
			IP: record.IP, Source: record.Source, Reason: record.Reason, PeerScope: record.PeerScope,
			OriginPeerIP: record.OriginPeerIP, ExpiresAt: record.ExpiresAt,
		})
	}
	all = uniqueSortedHAAddresses(all)
	sort.Slice(bans, func(i, j int) bool {
		if bans[i].IP != bans[j].IP {
			return bans[i].IP < bans[j].IP
		}
		if bans[i].Source != bans[j].Source {
			return bans[i].Source < bans[j].Source
		}
		if bans[i].PeerScope != bans[j].PeerScope {
			return bans[i].PeerScope < bans[j].PeerScope
		}
		if bans[i].OriginPeerIP != bans[j].OriginPeerIP {
			return bans[i].OriginPeerIP < bans[j].OriginPeerIP
		}
		return bans[i].ExpiresAt < bans[j].ExpiresAt
	})
	return all, bans, nil
}

func uniqueSortedHAAddresses(addresses []string) []string {
	seen := make(map[string]struct{}, len(addresses))
	result := make([]string, 0, len(addresses))
	for _, address := range addresses {
		if _, duplicate := seen[address]; duplicate {
			continue
		}
		seen[address] = struct{}{}
		result = append(result, address)
	}
	sort.Strings(result)
	return result
}

var errHALedgerFull = errors.New("HA ban ledger capacity reached")

func (api *haAPI) temporaryBanMode() (firewall.BanExpiryMode, error) {
	if api.fwManager == nil {
		return "", fmt.Errorf("firewall unavailable")
	}
	reporter, ok := api.fwManager.(firewall.BanExpiryReporter)
	if !ok {
		return "", fmt.Errorf("firewall backend does not report temporary-ban semantics")
	}
	mode := reporter.BanExpiryMode()
	if mode == firewall.BanExpiryNative {
		if _, ok := api.fwManager.(firewall.BanWithTTLManager); !ok {
			return "", fmt.Errorf("native-expiry firewall lacks BanWithTTL")
		}
		return mode, nil
	}
	if mode != firewall.BanExpiryExternal {
		return "", fmt.Errorf("unsupported firewall expiry mode")
	}
	return mode, nil
}

func (api *haAPI) storedIPPresent(ip string) (bool, error) {
	directory, name, err := openHADataDirectory(api.blacklistFile(ip))
	if err != nil {
		return false, err
	}
	defer directory.Close()
	lockFile, err := lockHADataDirectory(directory)
	if err != nil {
		return false, err
	}
	defer unlockHADataDirectory(lockFile)
	stored, err := readHAStoredIPSet(directory, name)
	if err != nil {
		return false, err
	}
	_, present := stored[ip]
	return present, nil
}

func (api *haAPI) desiredHABan(ip string, now time.Time) (bool, bool, time.Time, error) {
	static, err := api.storedIPPresent(ip)
	if err != nil {
		return false, false, time.Time{}, err
	}
	ledger, err := api.readHALedger()
	if err != nil {
		return false, false, time.Time{}, err
	}
	var latest time.Time
	for _, record := range ledger.Bans {
		if record.IP != ip || record.State == haBanPendingDelete {
			continue
		}
		expires, err := parseCanonicalHATime(record.ExpiresAt)
		if err != nil {
			return false, false, time.Time{}, err
		}
		if expires.After(now) && expires.After(latest) {
			latest = expires
		}
	}
	return static || !latest.IsZero(), static, latest, nil
}

func (api *haAPI) applyDesiredHABan(ip string, now time.Time) (bool, error) {
	canonical, err := api.canonicalHAFirewallTarget(ip)
	if err != nil {
		return false, err
	}
	desired, static, latest, err := api.desiredHABan(canonical, now)
	if err != nil || !desired {
		return desired, err
	}
	if static {
		return true, api.applyPermanentHABan(canonical)
	}
	mode, err := api.temporaryBanMode()
	if err != nil {
		return true, err
	}
	if mode == firewall.BanExpiryExternal {
		return true, api.fwManager.Ban(canonical)
	}
	remaining := boundedHARemainingTTL(latest, now)
	return true, api.fwManager.(firewall.BanWithTTLManager).BanWithTTL(canonical, remaining)
}

func boundedHARemainingTTL(latest, now time.Time) time.Duration {
	remaining := latest.Sub(now)
	if remaining%time.Second != 0 {
		remaining = (remaining/time.Second + 1) * time.Second
	}
	if remaining < firewall.MinimumBanTTL {
		remaining = firewall.MinimumBanTTL
	}
	if remaining > firewall.MaximumBanTTL {
		remaining = firewall.MaximumBanTTL
	}
	return remaining
}

func (api *haAPI) reconcileDesiredHABanAfterRemoval(ip string, now time.Time) (bool, error) {
	canonical, err := canonicalHAStoredEntry(ip)
	if err != nil {
		return false, err
	}
	desired, static, latest, err := api.desiredHABan(canonical, now)
	if err != nil {
		return false, err
	}
	if !desired {
		if api.fwManager == nil {
			return false, fmt.Errorf("firewall unavailable")
		}
		return false, api.fwManager.Unban(canonical)
	}
	if _, err := api.canonicalHAFirewallTarget(canonical); err != nil {
		if api.fwManager == nil {
			return false, fmt.Errorf("firewall unavailable")
		}
		// A target that became local, peered, or whitelisted after it was
		// banned must be releasable even if another stale HA claim remains.
		return false, api.fwManager.Unban(canonical)
	}
	if static {
		return true, api.applyPermanentHABan(canonical)
	}
	mode, err := api.temporaryBanMode()
	if err != nil {
		return true, err
	}
	if mode == firewall.BanExpiryExternal {
		return true, api.fwManager.Ban(canonical)
	}
	reconciler, ok := api.fwManager.(firewall.BanTTLReconciler)
	if !ok {
		return true, fmt.Errorf("native-expiry firewall lacks exact TTL reconciliation")
	}
	return true, reconciler.ReconcileBanTTL(canonical, boundedHARemainingTTL(latest, now))
}

func (api *haAPI) stageHATemporaryBans(peer haPeerIdentity, requests []haTemporaryBanRequest, now time.Time) (map[string]struct{}, error) {
	keys := make(map[string]struct{}, len(requests))
	err := api.mutateHALedger(func(ledger *haBanLedger) error {
		existing := make(map[string]int, len(ledger.Bans))
		for index, record := range ledger.Bans {
			existing[haLedgerRecordKey(record)] = index
		}
		newRecords := 0
		for _, request := range requests {
			key := request.IP + "\x00" + request.Source + "\x00" + peer.Scope
			keys[key] = struct{}{}
			if _, found := existing[key]; !found {
				newRecords++
			}
		}
		if len(ledger.Bans)+newRecords > maxHALedgerRecords {
			return errHALedgerFull
		}
		for _, request := range requests {
			key := request.IP + "\x00" + request.Source + "\x00" + peer.Scope
			expires := now.Add(request.TTL)
			if index, found := existing[key]; found {
				record := &ledger.Bans[index]
				currentExpiry, err := parseCanonicalHATime(record.ExpiresAt)
				if err != nil {
					return err
				}
				if currentExpiry.After(expires) {
					expires = currentExpiry
				}
				record.Reason = request.Reason
				record.OriginPeerIP = peer.IP
				record.ExpiresAt = expires.Format(time.RFC3339)
				record.UpdatedAt = now.Format(time.RFC3339)
				record.State = haBanPendingApply
				continue
			}
			existing[key] = len(ledger.Bans)
			ledger.Bans = append(ledger.Bans, haBanLedgerRecord{
				IP: request.IP, Source: request.Source, Reason: request.Reason, PeerScope: peer.Scope,
				OriginPeerIP: peer.IP, ExpiresAt: expires.Format(time.RFC3339), CreatedAt: now.Format(time.RFC3339),
				UpdatedAt: now.Format(time.RFC3339), State: haBanPendingApply,
			})
		}
		return nil
	})
	return keys, err
}

func (api *haAPI) temporaryAdmissionState(peer haPeerIdentity, requests []haTemporaryBanRequest, now time.Time) (bool, bool, error) {
	ledger, err := api.readHALedger()
	if err != nil {
		return false, false, err
	}
	existing := make(map[string]struct{}, len(ledger.Bans))
	needsRecovery := false
	for _, record := range ledger.Bans {
		existing[haLedgerRecordKey(record)] = struct{}{}
		expires, err := parseCanonicalHATime(record.ExpiresAt)
		if err != nil {
			return false, false, err
		}
		if record.State != haBanActive || !expires.After(now) {
			needsRecovery = true
		}
	}
	newRecords := 0
	for _, request := range requests {
		key := request.IP + "\x00" + request.Source + "\x00" + peer.Scope
		if _, found := existing[key]; found {
			continue
		}
		existing[key] = struct{}{}
		newRecords++
	}
	return needsRecovery, len(ledger.Bans)+newRecords > maxHALedgerRecords, nil
}

func (api *haAPI) markHATemporaryBansActive(keys map[string]struct{}, successfulIPs map[string]struct{}, now time.Time) error {
	return api.mutateHALedger(func(ledger *haBanLedger) error {
		found := 0
		for index := range ledger.Bans {
			record := &ledger.Bans[index]
			if _, expected := keys[haLedgerRecordKey(*record)]; !expected {
				continue
			}
			if _, successful := successfulIPs[record.IP]; !successful {
				continue
			}
			record.State = haBanActive
			record.UpdatedAt = now.Format(time.RFC3339)
			found++
		}
		if found == 0 && len(successfulIPs) > 0 {
			return fmt.Errorf("staged HA temporary bans disappeared")
		}
		return nil
	})
}

func (api *haAPI) applyHATemporaryBans(w http.ResponseWriter, peer haPeerIdentity, requests []haTemporaryBanRequest) {
	if err := api.validateHAMutationTargets(haMutationRequest{temporaries: requests}); err != nil {
		http.Error(w, "Rejected firewall target", http.StatusBadRequest)
		return
	}
	api.mutationMu.Lock()
	defer api.mutationMu.Unlock()
	now := api.now().UTC().Truncate(time.Second)
	if _, err := api.temporaryBanMode(); err != nil {
		http.Error(w, "Temporary firewall bans unavailable", http.StatusInternalServerError)
		return
	}
	needsRecovery, ledgerFull, err := api.temporaryAdmissionState(peer, requests, now)
	if err != nil {
		http.Error(w, "HA ban ledger unavailable", http.StatusInternalServerError)
		return
	}
	if ledgerFull && !needsRecovery {
		http.Error(w, "HA ban ledger full", http.StatusInsufficientStorage)
		return
	}
	if needsRecovery {
		if err := api.reconcileHABansLocked(now, maxHALedgerRecords); err != nil {
			http.Error(w, "HA ban recovery failed", http.StatusInternalServerError)
			return
		}
	}
	keys, err := api.stageHATemporaryBans(peer, requests, now)
	if errors.Is(err, errHALedgerFull) {
		http.Error(w, "HA ban ledger full", http.StatusInsufficientStorage)
		return
	}
	if err != nil {
		http.Error(w, "HA ban ledger unavailable", http.StatusInternalServerError)
		return
	}
	uniqueIPs := make([]string, 0, len(requests))
	seenIPs := make(map[string]struct{}, len(requests))
	for _, request := range requests {
		if _, duplicate := seenIPs[request.IP]; duplicate {
			continue
		}
		seenIPs[request.IP] = struct{}{}
		uniqueIPs = append(uniqueIPs, request.IP)
	}
	successfulIPs := make(map[string]struct{}, len(uniqueIPs))
	var mutationErrors []error
	for _, ip := range uniqueIPs {
		if _, err := api.applyDesiredHABan(ip, now); err != nil {
			mutationErrors = append(mutationErrors, err)
			continue
		}
		successfulIPs[ip] = struct{}{}
	}
	if err := api.markHATemporaryBansActive(keys, successfulIPs, now); err != nil {
		http.Error(w, "HA ban ledger publication failed", http.StatusInternalServerError)
		return
	}
	if joined := errors.Join(mutationErrors...); joined != nil {
		log.Printf("[HA Cluster] temporary ban batch partially failed origin=%s count=%d", peer.IP, len(mutationErrors))
		http.Error(w, "Firewall mutation failed", http.StatusInternalServerError)
		return
	}
	log.Printf("[HA Cluster] temporary ban batch active origin=%s count=%d", peer.IP, len(requests))
	writeHAJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (api *haAPI) markHATemporaryDeletes(requests []haTemporaryBanRequest, peerScope string, now time.Time) (map[string]map[string]struct{}, error) {
	requested := make(map[string]struct{}, len(requests))
	for _, request := range requests {
		requested[request.IP+"\x00"+request.Source] = struct{}{}
	}
	matched := make(map[string]map[string]struct{}, len(requests))
	err := api.mutateHALedgerIfChanged(func(ledger *haBanLedger) (bool, error) {
		changed := false
		for index := range ledger.Bans {
			record := &ledger.Bans[index]
			_, matches := requested[record.IP+"\x00"+record.Source]
			if !matches || record.PeerScope != peerScope {
				continue
			}
			if matched[record.IP] == nil {
				matched[record.IP] = make(map[string]struct{})
			}
			matched[record.IP][record.Source] = struct{}{}
			if record.State == haBanPendingDelete {
				continue
			}
			record.State = haBanPendingDelete
			record.UpdatedAt = now.Format(time.RFC3339)
			changed = true
		}
		return changed, nil
	})
	if err != nil {
		return nil, err
	}
	return matched, nil
}

func (api *haAPI) removeHATemporaryDeletes(ip string, sources map[string]struct{}, peerScope string) error {
	return api.mutateHALedger(func(ledger *haBanLedger) error {
		remaining := ledger.Bans[:0]
		for _, record := range ledger.Bans {
			_, sourceMatches := sources[record.Source]
			if record.IP == ip && sourceMatches && record.PeerScope == peerScope && record.State == haBanPendingDelete {
				continue
			}
			remaining = append(remaining, record)
		}
		ledger.Bans = remaining
		return nil
	})
}

func (api *haAPI) applyHATemporaryUnbans(w http.ResponseWriter, peer haPeerIdentity, requests []haTemporaryBanRequest) {
	api.mutationMu.Lock()
	defer api.mutationMu.Unlock()
	now := api.now().UTC().Truncate(time.Second)
	byIP, err := api.markHATemporaryDeletes(requests, peer.Scope, now)
	if err != nil {
		http.Error(w, "HA ban ledger unavailable", http.StatusInternalServerError)
		return
	}
	if len(byIP) == 0 {
		writeHAJSON(w, http.StatusOK, haTemporaryDeleteResult{Status: "ok", Deleted: 0})
		return
	}
	if api.fwManager == nil {
		http.Error(w, "Firewall unavailable", http.StatusInternalServerError)
		return
	}
	ips := make([]string, 0, len(byIP))
	for ip := range byIP {
		ips = append(ips, ip)
	}
	sort.Strings(ips)
	var mutationErrors []error
	deleted := 0
	for _, ip := range ips {
		desired, err := api.reconcileDesiredHABanAfterRemoval(ip, now)
		if err != nil {
			mutationErrors = append(mutationErrors, err)
			continue
		}
		if err := api.removeHATemporaryDeletes(ip, byIP[ip], peer.Scope); err != nil {
			mutationErrors = append(mutationErrors, err)
			continue
		}
		deleted += len(byIP[ip])
		if desired {
			log.Printf("[HA Cluster] temporary delete preserved another desired ban origin=%s", peer.IP)
		}
	}
	if joined := errors.Join(mutationErrors...); joined != nil {
		log.Printf("[HA Cluster] temporary delete batch partially failed origin=%s count=%d", peer.IP, len(mutationErrors))
		http.Error(w, "Firewall mutation failed", http.StatusInternalServerError)
		return
	}
	writeHAJSON(w, http.StatusOK, haTemporaryDeleteResult{Status: "ok", Deleted: deleted})
}

func (api *haAPI) reconcileHABansLocked(now time.Time, limit int) error {
	ledger, err := api.readHALedger()
	if err != nil {
		return err
	}
	allIPs := make([]string, 0)
	seen := make(map[string]struct{})
	needsTransition := make(map[string]bool)
	for _, record := range ledger.Bans {
		expires, err := parseCanonicalHATime(record.ExpiresAt)
		if err != nil {
			return err
		}
		if record.State != haBanActive || !expires.After(now) {
			needsTransition[record.IP] = true
		}
		if _, duplicate := seen[record.IP]; duplicate {
			continue
		}
		seen[record.IP] = struct{}{}
		allIPs = append(allIPs, record.IP)
	}
	if len(allIPs) == 0 || limit <= 0 {
		api.sweepCursor = 0
		return nil
	}
	if limit > len(allIPs) {
		limit = len(allIPs)
	}
	start := api.sweepCursor % len(allIPs)
	candidates := make([]string, 0, limit)
	for offset := 0; offset < limit; offset++ {
		candidates = append(candidates, allIPs[(start+offset)%len(allIPs)])
	}
	api.sweepCursor = (start + limit) % len(allIPs)
	for _, ip := range candidates {
		transition := needsTransition[ip]
		if transition {
			if err := api.mutateHALedger(func(current *haBanLedger) error {
				for index := range current.Bans {
					record := &current.Bans[index]
					if record.IP != ip {
						continue
					}
					expires, err := parseCanonicalHATime(record.ExpiresAt)
					if err != nil {
						return err
					}
					if !expires.After(now) {
						record.State = haBanPendingDelete
						record.UpdatedAt = now.Format(time.RFC3339)
					}
				}
				return nil
			}); err != nil {
				return err
			}
		}
		if transition {
			_, err = api.reconcileDesiredHABanAfterRemoval(ip, now)
		} else {
			_, err = api.applyDesiredHABan(ip, now)
		}
		if err != nil {
			return err
		}
		if !transition {
			continue
		}
		if err := api.mutateHALedger(func(current *haBanLedger) error {
			remaining := current.Bans[:0]
			for _, record := range current.Bans {
				if record.IP == ip && record.State == haBanPendingDelete {
					continue
				}
				if record.IP == ip && record.State == haBanPendingApply {
					record.State = haBanActive
					record.UpdatedAt = now.Format(time.RFC3339)
				}
				remaining = append(remaining, record)
			}
			current.Bans = remaining
			return nil
		}); err != nil {
			return err
		}
	}
	return nil
}

func (api *haAPI) reconcileHABans(now time.Time, limit int) error {
	api.mutationMu.Lock()
	defer api.mutationMu.Unlock()
	return api.reconcileHABansLocked(now.UTC().Truncate(time.Second), limit)
}

func (api *haAPI) startHASweeper(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(haSweepInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-ticker.C:
				if err := api.reconcileHABans(now, maxHASweepPerPass); err != nil {
					log.Printf("[HA Cluster] temporary-ban reconciliation failed: %v", err)
				}
			}
		}
	}()
}

func writeHAJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func (api *haAPI) handleTelemetry(w http.ResponseWriter, r *http.Request) {
	if _, authorized := api.authorizePeer(w, r); !authorized {
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	content, err := readHARootedFileBounded(api.telemetryFile, maxHATelemetryBytes)
	if err != nil {
		http.Error(w, "Telemetry unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(content)
}

func (api *haAPI) handleStatus(w http.ResponseWriter, r *http.Request) {
	if _, authorized := api.authorizePeer(w, r); !authorized {
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	challenge, err := parseHAFenceChallenge(r.Header)
	if err != nil {
		http.Error(w, "Invalid HA fence challenge", http.StatusBadRequest)
		return
	}
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "unknown"
	}
	osName := "Linux"
	if osRelease, err := os.ReadFile("/etc/os-release"); err == nil {
		for _, line := range strings.Split(string(osRelease), "\n") {
			if strings.HasPrefix(line, "PRETTY_NAME=") {
				osName = strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), "\"")
				break
			}
		}
	}
	capabilities := []string{"auth_all_routes", haFenceCapability, "peer_cidr", "tls_verified_client"}
	if api.cfg.BunkerWebEnabled {
		capabilities = []string{"auth_all_routes", haFenceCapability, "peer_cidr", "sync_ttl", "sync_provenance", "tls_verified_client"}
	}
	fenceStatus, fenceErr := api.fence.status(challenge)
	if fenceErr != nil {
		log.Printf("[HA Cluster] Native-sync fence status is unavailable: %v", fenceErr)
	}
	if fenceStatus.State == haFenceStateActiveDrained && fenceStatus.Condition != "" {
		w.Header().Set(haFenceConditionHeader, fenceStatus.Condition)
	}
	writeHAJSON(w, http.StatusOK, struct {
		Hostname        string                  `json:"hostname"`
		OS              string                  `json:"os"`
		Version         string                  `json:"version"`
		Status          string                  `json:"status"`
		APIVersion      string                  `json:"api_version"`
		Capabilities    []string                `json:"capabilities"`
		NativeSyncFence haNativeSyncFenceStatus `json:"native_sync_fence"`
	}{
		Hostname: hostname, OS: osName, Version: api.coreVersion, Status: "online", APIVersion: "2",
		Capabilities: capabilities, NativeSyncFence: fenceStatus,
	})
}

func newHAServer(address string, handler http.Handler, certificate tls.Certificate) *http.Server {
	return &http.Server{
		Addr:              address,
		Handler:           handler,
		ReadTimeout:       haReadTimeout,
		ReadHeaderTimeout: haReadHeaderTimeout,
		WriteTimeout:      haWriteTimeout,
		IdleTimeout:       haIdleTimeout,
		MaxHeaderBytes:    16 * 1024,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{certificate},
			MinVersion:   tls.VersionTLS13,
		},
	}
}

func prepareHAServerAPI(api *haAPI) error {
	if api == nil {
		return fmt.Errorf("HA API is unavailable")
	}
	if api.fence == nil {
		return fmt.Errorf("HA native-sync fence is unavailable")
	}
	return api.reconcileHABans(time.Now(), maxHALedgerRecords)
}

func StartHAServer(fwManager firewall.Manager) {
	cfg := loadHAConfig()
	if (cfg.Enabled != "y" && cfg.Enabled != "true" && cfg.Enabled != "1") || len(cfg.PeerIPs) == 0 {
		return
	}
	if cfg.Token == "" || strings.TrimSpace(cfg.Token) != cfg.Token {
		log.Printf("[HA Cluster] Refusing to start: HA token is required")
		return
	}

	coreVersion := "unknown"
	cmd := exec.Command("syswarden")
	if out, err := cmd.Output(); err == nil {
		lines := strings.Split(string(out), "\n")
		if len(lines) > 0 {
			parts := strings.Split(lines[0], " ")
			if len(parts) >= 2 {
				coreVersion = parts[1]
			}
		}
	}

	cert, err := loadOrCreateHATLSCertificate(haTLSDir)
	if err != nil {
		log.Printf("[HA Cluster] Failed to load persistent TLS identity: %v", err)
		return
	}
	api, err := newHAAPI(cfg, fwManager, coreVersion, haRuntimeBlacklistIPv4, haRuntimeBlacklistIPv6, haRuntimeTelemetryFile, haRuntimeBanLedgerFile)
	if err != nil {
		log.Printf("[HA Cluster] Refusing invalid HA configuration: %v", err)
		return
	}
	if err := prepareHAServerAPI(api); err != nil {
		log.Printf("[HA Cluster] Initial temporary-ban reconciliation failed: %v", err)
		return
	}
	api.startHASweeper(context.Background())

	server := newHAServer(fmt.Sprintf(":%s", cfg.Port), api.handler(), cert)
	log.Printf("[HA Cluster] Starting bounded TLS P2P API on port %s", cfg.Port)
	go func() {
		if err := server.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("[HA Cluster] Server failed: %v", err)
		}
	}()
}
