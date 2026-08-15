package network

import (
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"syswarden-cli/config"
	"time"
)

type HASyncPayload struct {
	IPs []string `json:"ips"`
}

type HAPeerSyncStatus struct {
	Peer           string `json:"peer"`
	State          string `json:"state"`
	InSync         bool   `json:"in_sync"`
	Desynced       bool   `json:"desynced"`
	LocalIPs       int    `json:"local_ips"`
	RemoteIPs      int    `json:"remote_ips"`
	MissingOnPeer  int    `json:"missing_on_peer"`
	MissingLocally int    `json:"missing_locally"`
	Pushed         int    `json:"pushed"`
	Attempts       int    `json:"attempts"`
	LastAttempt    string `json:"last_attempt"`
	LastError      string `json:"last_error,omitempty"`
}

type HASyncStatusSnapshot struct {
	UpdatedAt string             `json:"updated_at"`
	Peers     []HAPeerSyncStatus `json:"peers"`
}

const (
	defaultHARequestTimeout    = 4 * time.Second
	defaultHARetryAttempts     = 3
	defaultHARetryBackoff      = 100 * time.Millisecond
	maxHASyncIPsPerRequest     = 1024
	maxHAResponseBytes         = 1024 * 1024
	defaultHASyncStatusFile    = "/var/lib/syswarden/ha/sync-status.json"
	defaultHACAFile            = "/etc/syswarden/ha-ca.pem"
	defaultHABlacklistIPv4File = "/etc/syswarden/lists/syswarden_blacklist.ipv4"
	defaultHABlacklistIPv6File = "/etc/syswarden/lists/syswarden_blacklist.ipv6"
	haAuthSetupErrorMessage    = "HA bearer token is required; configure integrations.ha.token and upgrade legacy HA clients"
)

type haSyncOptions struct {
	client         *http.Client
	requestTimeout time.Duration
	retryAttempts  int
	retryBackoff   time.Duration
	statusFile     string
	statusOwnerUID int
	blacklistIPv4  string
	blacklistIPv6  string
	now            func() time.Time
}

type haHTTPResult struct {
	response *http.Response
	attempts int
}

type cancelOnCloseReadCloser struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (body *cancelOnCloseReadCloser) Close() error {
	err := body.ReadCloser.Close()
	body.cancel()
	return err
}

func defaultHASyncOptions() (haSyncOptions, error) {
	client, err := newVerifiedHAHTTPClient(defaultHACAFile, defaultHARequestTimeout)
	if err != nil {
		return haSyncOptions{}, err
	}
	return haSyncOptions{
		client:         client,
		requestTimeout: defaultHARequestTimeout,
		retryAttempts:  defaultHARetryAttempts,
		retryBackoff:   defaultHARetryBackoff,
		statusFile:     defaultHASyncStatusFile,
		statusOwnerUID: 0,
		blacklistIPv4:  defaultHABlacklistIPv4File,
		blacklistIPv6:  defaultHABlacklistIPv6File,
		now:            time.Now,
	}, nil
}

func newVerifiedHAHTTPClient(caPath string, timeout time.Duration) (*http.Client, error) {
	rootCAs, err := loadHATrustPool(caPath)
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: rootCAs},
	}
	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return fmt.Errorf("HA redirects are disabled")
		},
	}, nil
}

func loadHATrustPool(path string) (*x509.CertPool, error) {
	path = filepath.Clean(path)
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		pool, systemErr := x509.SystemCertPool()
		if systemErr != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		return pool, nil
	}
	if err != nil {
		return nil, fmt.Errorf("inspect HA CA bundle: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("HA CA bundle must be a regular file")
	}
	ownerUID, err := haFileOwnerUID(info)
	if err != nil {
		return nil, err
	}
	if ownerUID != 0 && ownerUID != os.Geteuid() {
		return nil, fmt.Errorf("HA CA bundle has an unexpected owner")
	}
	if info.Mode().Perm()&0022 != 0 {
		return nil, fmt.Errorf("HA CA bundle must not be group/world writable")
	}
	parentInfo, err := os.Lstat(filepath.Dir(path))
	if err != nil || !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("HA CA bundle parent must be a real directory")
	}
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return nil, fmt.Errorf("open HA CA bundle parent: %w", err)
	}
	defer root.Close()
	openedParent, err := root.Stat(".")
	if err != nil || !os.SameFile(parentInfo, openedParent) {
		return nil, fmt.Errorf("HA CA bundle parent changed while opening")
	}
	file, err := root.Open(filepath.Base(path))
	if err != nil {
		return nil, fmt.Errorf("open HA CA bundle: %w", err)
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect opened HA CA bundle: %w", err)
	}
	currentInfo, err := root.Lstat(filepath.Base(path))
	if err != nil || !openedInfo.Mode().IsRegular() || !currentInfo.Mode().IsRegular() ||
		!os.SameFile(info, openedInfo) || !os.SameFile(openedInfo, currentInfo) {
		return nil, fmt.Errorf("HA CA bundle changed while opening")
	}
	const maxHACABytes = 1024 * 1024
	wire, err := io.ReadAll(io.LimitReader(file, maxHACABytes+1))
	if err != nil {
		return nil, fmt.Errorf("read HA CA bundle: %w", err)
	}
	pool := x509.NewCertPool()
	if len(wire) > maxHACABytes {
		return nil, fmt.Errorf("HA CA bundle is invalid")
	}
	if err := addStrictHACertificates(pool, wire); err != nil {
		return nil, fmt.Errorf("HA CA bundle is invalid: %w", err)
	}
	return pool, nil
}

func addStrictHACertificates(pool *x509.CertPool, wire []byte) error {
	if pool == nil {
		return fmt.Errorf("certificate pool is unavailable")
	}
	remaining := wire
	certificates := 0
	for {
		remaining = bytes.TrimLeft(remaining, " \t\r\n")
		if len(remaining) == 0 {
			break
		}
		if !bytes.HasPrefix(remaining, []byte("-----BEGIN CERTIFICATE-----")) {
			return fmt.Errorf("unexpected data outside a CERTIFICATE block")
		}
		block, rest := pem.Decode(remaining)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return fmt.Errorf("invalid CERTIFICATE block")
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("parse CERTIFICATE block: %w", err)
		}
		pool.AddCert(certificate)
		certificates++
		remaining = rest
	}
	if certificates == 0 {
		return fmt.Errorf("bundle contains no certificate")
	}
	return nil
}

var errNoDialableHAPeer = errors.New("no dialable exact peer configured")

func getLocalBlocklist(file string) ([]string, error) {
	content, err := os.ReadFile(file) // #nosec G304 -- callers provide fixed blocklist paths
	if errors.Is(err, os.ErrNotExist) {
		return []string{}, nil
	}
	if err != nil {
		return nil, err
	}

	lines := strings.Split(strings.TrimSpace(string(content)), "\n")
	ips := make([]string, 0, len(lines))
	for lineNumber, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		canonical, err := canonicalHAAddress(line)
		if err != nil {
			return nil, fmt.Errorf("%s:%d: %w", filepath.Clean(file), lineNumber+1, err)
		}
		ips = append(ips, canonical)
	}
	return uniqueSortedHAIPs(ips), nil
}

func canonicalHAAddress(value string) (string, error) {
	value = strings.TrimSpace(value)
	if parsed := net.ParseIP(value); parsed != nil {
		return parsed.String(), nil
	}
	_, network, err := net.ParseCIDR(value)
	if err == nil && network != nil {
		return network.String(), nil
	}
	return "", fmt.Errorf("invalid HA IP or CIDR address %q", value)
}

func uniqueSortedHAIPs(ips []string) []string {
	seen := make(map[string]struct{}, len(ips))
	unique := make([]string, 0, len(ips))
	for _, ip := range ips {
		if _, ok := seen[ip]; ok {
			continue
		}
		seen[ip] = struct{}{}
		unique = append(unique, ip)
	}
	sort.Strings(unique)
	return unique
}

func canonicalHAIPList(ips []string) ([]string, error) {
	canonical := make([]string, 0, len(ips))
	for index, value := range ips {
		ip, err := canonicalHAAddress(value)
		if err != nil {
			return nil, fmt.Errorf("HA payload IP %d: %w", index, err)
		}
		canonical = append(canonical, ip)
	}
	return uniqueSortedHAIPs(canonical), nil
}

func configuredHAPeers(value string) []string {
	return strings.Fields(strings.ReplaceAll(value, ",", " "))
}

func dialableHAPeers(value string) ([]string, error) {
	plan, err := planHAClusterPeers(value)
	if err != nil {
		return nil, err
	}
	if len(plan.Dialable) == 0 {
		return nil, errNoDialableHAPeer
	}
	return plan.Dialable, nil
}

func haPeerSyncURL(peer, port string) (string, error) {
	host := strings.TrimSpace(peer)
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	}
	address, err := netip.ParseAddr(host)
	if err != nil || address.Is4In6() || address.Zone() != "" {
		return "", fmt.Errorf("invalid HA peer address %q", peer)
	}
	host = address.String()
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return "", fmt.Errorf("invalid HA peer port %q", port)
	}
	return "https://" + net.JoinHostPort(host, strconv.Itoa(portNumber)) + "/ha/sync", nil
}

func SyncHAPeer() error {
	return SyncHAPeerContext(context.Background())
}

func SyncHAPeerContext(ctx context.Context) error {
	options, err := defaultHASyncOptions()
	if err != nil {
		return err
	}
	return syncHAPeers(ctx, config.GlobalConfig, options)
}

func syncHAPeers(ctx context.Context, cfg *config.Config, options haSyncOptions) error {
	if cfg == nil {
		return fmt.Errorf("HA configuration is unavailable")
	}
	if !cfg.HAEnabled {
		fmt.Println("[INFO] HA Sync is disabled in configuration.")
		return nil
	}
	if cfg.HAToken == "" || strings.TrimSpace(cfg.HAToken) != cfg.HAToken {
		return errors.New(haAuthSetupErrorMessage)
	}

	peers, err := dialableHAPeers(cfg.HAPeerIP)
	if err != nil {
		return err
	}
	if err := validateHASyncOptions(options); err != nil {
		return err
	}

	localIPv4, ipv4Err := getLocalBlocklist(options.blacklistIPv4)
	localIPv6, ipv6Err := getLocalBlocklist(options.blacklistIPv6)
	localErr := errors.Join(ipv4Err, ipv6Err)
	localIPs := uniqueSortedHAIPs(append(localIPv4, localIPv6...))
	localSet := haIPSet(localIPs)

	statuses := make([]HAPeerSyncStatus, 0, len(peers))
	var peerErrors []error
	for _, peer := range peers {
		status := HAPeerSyncStatus{
			Peer:        peer,
			State:       "error",
			LocalIPs:    len(localIPs),
			LastAttempt: options.now().UTC().Format(time.RFC3339),
		}
		if localErr != nil {
			status.LastError = localErr.Error()
			statuses = append(statuses, status)
			peerErrors = append(peerErrors, fmt.Errorf("HA peer %s: load local blocklists: %w", peer, localErr))
			continue
		}

		apiURL, err := haPeerSyncURL(peer, cfg.HAPeerPort)
		if err != nil {
			status.State = "invalid"
			status.LastError = err.Error()
			statuses = append(statuses, status)
			peerErrors = append(peerErrors, err)
			continue
		}

		fmt.Printf("[INFO] Starting HA Sync to Peer %s...\n", peer)
		getResult, err := doHARequest(ctx, options, cfg.HAToken, http.MethodGet, apiURL, nil)
		status.Attempts = getResult.attempts
		if err != nil {
			status.State = haFailureState(err)
			status.LastError = err.Error()
			statuses = append(statuses, status)
			peerErrors = append(peerErrors, fmt.Errorf("HA peer %s GET: %w", peer, err))
			fmt.Printf("[ERROR] HA Peer %s GET failed: %v\n", peer, err)
			continue
		}

		remoteIPs, err := decodeHAPayloadResponse(getResult.response)
		if err != nil {
			status.State = "error"
			status.LastError = err.Error()
			statuses = append(statuses, status)
			peerErrors = append(peerErrors, fmt.Errorf("HA peer %s response: %w", peer, err))
			continue
		}
		status.RemoteIPs = len(remoteIPs)
		remoteSet := haIPSet(remoteIPs)
		missingOnPeer := haSetDifference(localIPs, remoteSet)
		missingLocally := haSetDifference(remoteIPs, localSet)
		status.MissingOnPeer = len(missingOnPeer)
		status.MissingLocally = len(missingLocally)
		status.Desynced = status.MissingOnPeer > 0 || status.MissingLocally > 0

		if len(missingOnPeer) > 0 {
			fmt.Printf("[INFO] Found %d IPs missing on peer %s. Synchronizing...\n", len(missingOnPeer), peer)
			for start := 0; start < len(missingOnPeer); start += maxHASyncIPsPerRequest {
				end := start + maxHASyncIPsPerRequest
				if end > len(missingOnPeer) {
					end = len(missingOnPeer)
				}
				body, marshalErr := json.Marshal(HASyncPayload{IPs: missingOnPeer[start:end]})
				if marshalErr != nil {
					err = marshalErr
					break
				}
				postResult, postErr := doHARequest(ctx, options, cfg.HAToken, http.MethodPost, apiURL, body)
				if postResult.attempts > status.Attempts {
					status.Attempts = postResult.attempts
				}
				if postErr != nil {
					err = postErr
					break
				}
				closeHAResponse(postResult.response)
				status.Pushed += end - start
			}
			if err != nil {
				status.State = haFailureState(err)
				status.LastError = err.Error()
				status.MissingOnPeer -= status.Pushed
				statuses = append(statuses, status)
				peerErrors = append(peerErrors, fmt.Errorf("HA peer %s POST: %w", peer, err))
				fmt.Printf("[ERROR] HA Peer %s POST failed: %v\n", peer, err)
				continue
			}
			status.MissingOnPeer = 0
		}

		status.Desynced = status.MissingOnPeer > 0 || status.MissingLocally > 0
		status.InSync = !status.Desynced
		if status.InSync {
			status.State = "synced"
			fmt.Printf("[+] HA Peer %s is synchronized.\n", peer)
		} else {
			status.State = "desynced"
			fmt.Printf("[WARN] HA Peer %s remains desynchronized: missing_on_peer=%d missing_locally=%d\n", peer, status.MissingOnPeer, status.MissingLocally)
		}
		statuses = append(statuses, status)
	}

	snapshot := HASyncStatusSnapshot{
		UpdatedAt: options.now().UTC().Format(time.RFC3339),
		Peers:     statuses,
	}
	if err := persistHASyncStatus(options.statusFile, options.statusOwnerUID, snapshot); err != nil {
		peerErrors = append(peerErrors, fmt.Errorf("persist HA sync telemetry: %w", err))
	}
	return errors.Join(peerErrors...)
}

func SyncHAUnban(ips []string) error {
	return SyncHAUnbanContext(context.Background(), ips)
}

func SyncHAUnbanContext(ctx context.Context, ips []string) error {
	options, err := defaultHASyncOptions()
	if err != nil {
		return err
	}
	return syncHAUnban(ctx, config.GlobalConfig, ips, options)
}

func syncHAUnban(ctx context.Context, cfg *config.Config, ips []string, options haSyncOptions) error {
	if cfg == nil {
		return fmt.Errorf("HA configuration is unavailable")
	}
	if !cfg.HAEnabled {
		return nil
	}
	if cfg.HAToken == "" || strings.TrimSpace(cfg.HAToken) != cfg.HAToken {
		return errors.New(haAuthSetupErrorMessage)
	}
	peers, err := dialableHAPeers(cfg.HAPeerIP)
	if err != nil {
		if errors.Is(err, errNoDialableHAPeer) {
			return nil
		}
		return err
	}
	if len(ips) == 0 {
		return nil
	}
	if err := validateHASyncOptions(options); err != nil {
		return err
	}
	canonicalIPs, err := canonicalHAIPList(ips)
	if err != nil {
		return err
	}

	var peerErrors []error
	for _, peer := range peers {
		apiURL, urlErr := haPeerSyncURL(peer, cfg.HAPeerPort)
		if urlErr != nil {
			peerErrors = append(peerErrors, urlErr)
			continue
		}
		for start := 0; start < len(canonicalIPs); start += maxHASyncIPsPerRequest {
			end := start + maxHASyncIPsPerRequest
			if end > len(canonicalIPs) {
				end = len(canonicalIPs)
			}
			body, marshalErr := json.Marshal(HASyncPayload{IPs: canonicalIPs[start:end]})
			if marshalErr != nil {
				peerErrors = append(peerErrors, marshalErr)
				break
			}
			result, requestErr := doHARequest(ctx, options, cfg.HAToken, http.MethodDelete, apiURL, body)
			if requestErr != nil {
				peerErrors = append(peerErrors, fmt.Errorf("HA peer %s DELETE: %w", peer, requestErr))
				fmt.Printf("[ERROR] Failed to push UNBAN to HA Peer %s: %v\n", peer, requestErr)
				break
			}
			closeHAResponse(result.response)
		}
	}
	return errors.Join(peerErrors...)
}

func validateHASyncOptions(options haSyncOptions) error {
	if options.client == nil {
		return fmt.Errorf("HA HTTP client is unavailable")
	}
	if options.requestTimeout <= 0 || options.retryAttempts < 1 || options.retryBackoff < 0 || options.statusOwnerUID < 0 {
		return fmt.Errorf("invalid HA retry configuration")
	}
	if options.now == nil {
		return fmt.Errorf("HA clock is unavailable")
	}
	return nil
}

func doHARequest(ctx context.Context, options haSyncOptions, token, method, url string, body []byte) (haHTTPResult, error) {
	result := haHTTPResult{}
	if token == "" || strings.TrimSpace(token) != token {
		return result, errors.New(haAuthSetupErrorMessage)
	}
	for attempt := 1; attempt <= options.retryAttempts; attempt++ {
		result.attempts = attempt
		requestContext, cancel := context.WithTimeout(ctx, options.requestTimeout)
		request, err := http.NewRequestWithContext(requestContext, method, url, bytes.NewReader(body))
		if err != nil {
			cancel()
			return result, err
		}
		if len(body) > 0 {
			request.Header.Set("Content-Type", "application/json")
		}
		request.Header.Set("Authorization", "Bearer "+token)

		response, requestErr := options.client.Do(request)
		if requestErr == nil && !retryableHAStatus(response.StatusCode) {
			if response.StatusCode != http.StatusOK {
				closeHAResponse(response)
				cancel()
				return result, fmt.Errorf("HTTP status %d", response.StatusCode)
			}
			response.Body = &cancelOnCloseReadCloser{ReadCloser: response.Body, cancel: cancel}
			result.response = response
			return result, nil
		}
		if response != nil {
			closeHAResponse(response)
		}
		cancel()

		if ctx.Err() != nil {
			return result, ctx.Err()
		}
		if attempt == options.retryAttempts {
			if requestErr != nil {
				return result, requestErr
			}
			return result, fmt.Errorf("HTTP status %d after %d attempts", response.StatusCode, attempt)
		}
		if err := waitHABackoff(ctx, options.retryBackoff, attempt); err != nil {
			return result, err
		}
	}
	return result, fmt.Errorf("HA request exhausted retries")
}

func retryableHAStatus(status int) bool {
	return status == http.StatusTooManyRequests || status >= http.StatusInternalServerError
}

func waitHABackoff(ctx context.Context, base time.Duration, attempt int) error {
	if base == 0 {
		return nil
	}
	delay := base * time.Duration(1<<(attempt-1))
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func closeHAResponse(response *http.Response) {
	if response == nil || response.Body == nil {
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	_ = response.Body.Close()
}

func decodeHAPayloadResponse(response *http.Response) ([]string, error) {
	if response == nil || response.Body == nil {
		return nil, fmt.Errorf("empty HA response")
	}
	defer response.Body.Close()
	wire, err := io.ReadAll(io.LimitReader(response.Body, maxHAResponseBytes+1))
	if err != nil {
		return nil, err
	}
	if len(wire) > maxHAResponseBytes {
		return nil, fmt.Errorf("HA response exceeds %d bytes", maxHAResponseBytes)
	}
	var payload HASyncPayload
	// Deliberately tolerate unknown fields returned by newer peers.
	if err := json.Unmarshal(wire, &payload); err != nil {
		return nil, fmt.Errorf("decode HA response: %w", err)
	}
	return canonicalHAIPList(payload.IPs)
}

func haIPSet(ips []string) map[string]struct{} {
	result := make(map[string]struct{}, len(ips))
	for _, ip := range ips {
		result[ip] = struct{}{}
	}
	return result
}

func haSetDifference(values []string, other map[string]struct{}) []string {
	difference := make([]string, 0)
	for _, value := range values {
		if _, ok := other[value]; !ok {
			difference = append(difference, value)
		}
	}
	return difference
}

func haFailureState(err error) string {
	if err == nil {
		return "error"
	}
	message := err.Error()
	if strings.Contains(message, "HTTP status 401") || strings.Contains(message, "HTTP status 403") {
		return "rejected"
	}
	var networkError net.Error
	if errors.As(err, &networkError) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return "offline"
	}
	return "error"
}

func persistHASyncStatus(path string, expectedOwnerUID int, snapshot HASyncStatusSnapshot) error {
	wire, err := json.Marshal(snapshot)
	if err != nil {
		return err
	}
	directory, name, err := openSafeHAStatusDirectory(path, expectedOwnerUID)
	if err != nil {
		return err
	}
	defer directory.Close()
	lockFile, err := lockHAStatusDirectory(directory)
	if err != nil {
		return err
	}
	defer unlockHAStatusDirectory(lockFile)
	return publishHAStatusAtomically(directory, name, expectedOwnerUID, wire)
}

func openSafeHAStatusDirectory(path string, expectedOwnerUID int) (*os.Root, string, error) {
	if expectedOwnerUID < 0 {
		return nil, "", fmt.Errorf("invalid expected HA status owner UID")
	}
	cleanPath := filepath.Clean(path)
	if !filepath.IsAbs(cleanPath) || cleanPath != path {
		return nil, "", fmt.Errorf("HA status path must be absolute and canonical")
	}
	name := filepath.Base(cleanPath)
	if name == "." || name == string(filepath.Separator) || filepath.Base(name) != name {
		return nil, "", fmt.Errorf("invalid HA status file name")
	}
	directoryPath := filepath.Dir(cleanPath)
	currentRoot, err := os.OpenRoot("/")
	if err != nil {
		return nil, "", fmt.Errorf("open filesystem root for HA status: %w", err)
	}
	rootInfo, err := currentRoot.Stat(".")
	if err != nil {
		_ = currentRoot.Close()
		return nil, "", fmt.Errorf("inspect filesystem root for HA status: %w", err)
	}
	if err := validateHAStatusAncestor(rootInfo, expectedOwnerUID, false); err != nil {
		_ = currentRoot.Close()
		return nil, "", err
	}

	components := strings.Split(strings.TrimPrefix(filepath.ToSlash(directoryPath), "/"), "/")
	for index, component := range components {
		if component == "" {
			continue
		}
		info, statErr := currentRoot.Lstat(component)
		if errors.Is(statErr, fs.ErrNotExist) {
			if mkdirErr := currentRoot.Mkdir(component, 0700); mkdirErr != nil && !errors.Is(mkdirErr, fs.ErrExist) {
				_ = currentRoot.Close()
				return nil, "", fmt.Errorf("create HA status directory component %q: %w", component, mkdirErr)
			}
			info, statErr = currentRoot.Lstat(component)
		}
		if statErr != nil {
			_ = currentRoot.Close()
			return nil, "", fmt.Errorf("inspect HA status directory component %q: %w", component, statErr)
		}
		isFinal := index == len(components)-1
		if err := validateHAStatusAncestor(info, expectedOwnerUID, isFinal); err != nil {
			_ = currentRoot.Close()
			return nil, "", fmt.Errorf("unsafe HA status directory component %q: %w", component, err)
		}
		nextRoot, openErr := currentRoot.OpenRoot(component)
		if openErr != nil {
			_ = currentRoot.Close()
			return nil, "", fmt.Errorf("open HA status directory component %q: %w", component, openErr)
		}
		openedInfo, openedErr := nextRoot.Stat(".")
		if openedErr != nil || !os.SameFile(info, openedInfo) {
			_ = nextRoot.Close()
			_ = currentRoot.Close()
			return nil, "", fmt.Errorf("HA status directory component changed while opening: %q", component)
		}
		if err := validateHAStatusAncestor(openedInfo, expectedOwnerUID, isFinal); err != nil {
			_ = nextRoot.Close()
			_ = currentRoot.Close()
			return nil, "", fmt.Errorf("unsafe opened HA status directory component %q: %w", component, err)
		}
		_ = currentRoot.Close()
		currentRoot = nextRoot
	}
	return currentRoot, name, nil
}

func validateHAStatusAncestor(info fs.FileInfo, expectedOwnerUID int, final bool) error {
	if info == nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("must be a real directory")
	}
	ownerUID, err := haFileOwnerUID(info)
	if err != nil {
		return err
	}
	if ownerUID != 0 && ownerUID != expectedOwnerUID {
		return fmt.Errorf("owner UID %d is neither root nor expected UID %d", ownerUID, expectedOwnerUID)
	}
	if info.Mode().Perm()&0022 != 0 && !(ownerUID == 0 && info.Mode()&os.ModeSticky != 0) {
		return fmt.Errorf("must not be group/world writable")
	}
	if final {
		if ownerUID != expectedOwnerUID {
			return fmt.Errorf("final directory owner UID %d does not match expected UID %d", ownerUID, expectedOwnerUID)
		}
		if info.Mode().Perm()&0077 != 0 {
			return fmt.Errorf("final directory must not be accessible by group or other users")
		}
	}
	return nil
}

func haFileOwnerUID(info fs.FileInfo) (int, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return -1, fmt.Errorf("HA status file owner UID is unavailable")
	}
	return int(stat.Uid), nil
}

func lockHAStatusDirectory(directory *os.Root) (*os.File, error) {
	lockFile, err := directory.Open(".")
	if err != nil {
		return nil, fmt.Errorf("open HA status directory lock: %w", err)
	}
	if err := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX); err != nil {
		_ = lockFile.Close()
		return nil, fmt.Errorf("lock HA status directory: %w", err)
	}
	return lockFile, nil
}

func unlockHAStatusDirectory(lockFile *os.File) {
	_ = syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN)
	_ = lockFile.Close()
}

func inspectHAStatusDestination(directory *os.Root, name string, expectedOwnerUID int) (fs.FileInfo, bool, error) {
	info, err := directory.Lstat(name)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if !info.Mode().IsRegular() {
		return nil, false, fmt.Errorf("HA status destination is not a regular file")
	}
	ownerUID, err := haFileOwnerUID(info)
	if err != nil {
		return nil, false, err
	}
	if ownerUID != expectedOwnerUID {
		return nil, false, fmt.Errorf("HA status destination owner UID %d does not match expected UID %d", ownerUID, expectedOwnerUID)
	}
	if info.Mode().Perm() != 0600 {
		return nil, false, fmt.Errorf("HA status destination permissions must be 0600")
	}
	return info, true, nil
}

func createHAStatusStagingFile(directory *os.Root, name string) (*os.File, string, error) {
	for range 128 {
		var random [16]byte
		if _, err := cryptorand.Read(random[:]); err != nil {
			return nil, "", fmt.Errorf("generate HA status staging name: %w", err)
		}
		stagingName := "." + name + ".syswarden-" + hex.EncodeToString(random[:]) + ".tmp"
		file, err := directory.OpenFile(stagingName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if errors.Is(err, fs.ErrExist) {
			continue
		}
		if err != nil {
			return nil, "", fmt.Errorf("create HA status staging file: %w", err)
		}
		return file, stagingName, nil
	}
	return nil, "", fmt.Errorf("create HA status staging file: too many name collisions")
}

func publishHAStatusAtomically(directory *os.Root, name string, expectedOwnerUID int, wire []byte) error {
	destinationInfo, destinationExists, err := inspectHAStatusDestination(directory, name, expectedOwnerUID)
	if err != nil {
		return err
	}
	file, stagingName, err := createHAStatusStagingFile(directory, name)
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
		return fmt.Errorf("restrict HA status staging file: %w", err)
	}
	stagingInfo, err := file.Stat()
	if err != nil {
		return fmt.Errorf("inspect HA status staging file: %w", err)
	}
	stagingOwnerUID, err := haFileOwnerUID(stagingInfo)
	if err != nil {
		return err
	}
	if stagingOwnerUID != expectedOwnerUID {
		return fmt.Errorf("HA status staging owner UID %d does not match expected UID %d", stagingOwnerUID, expectedOwnerUID)
	}
	if written, err := file.Write(wire); err != nil {
		return fmt.Errorf("write HA status staging file: %w", err)
	} else if written != len(wire) {
		return fmt.Errorf("write HA status staging file: %w", io.ErrShortWrite)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync HA status staging file: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close HA status staging file: %w", err)
	}
	file = nil

	currentInfo, currentExists, err := inspectHAStatusDestination(directory, name, expectedOwnerUID)
	if err != nil {
		return err
	}
	if destinationExists != currentExists || (destinationExists && !os.SameFile(destinationInfo, currentInfo)) {
		return fmt.Errorf("HA status destination changed before publication")
	}
	if err := directory.Rename(stagingName, name); err != nil {
		return fmt.Errorf("publish HA status atomically: %w", err)
	}
	stagingName = ""
	directoryFile, err := directory.Open(".")
	if err != nil {
		return fmt.Errorf("open HA status directory for sync: %w", err)
	}
	if err := directoryFile.Sync(); err != nil {
		_ = directoryFile.Close()
		return fmt.Errorf("sync HA status directory: %w", err)
	}
	if err := directoryFile.Close(); err != nil {
		return fmt.Errorf("close HA status directory: %w", err)
	}
	return nil
}
