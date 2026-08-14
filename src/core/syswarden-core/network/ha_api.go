package network

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syswarden-core/firewall"
	"time"

	"github.com/spf13/viper"
)

type HAConfig struct {
	Enabled string
	Token   string
	PeerIPs []string
	Port    string
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
	IPs []string `json:"ips"`
}

const (
	haBlacklistIPv4File  = "/etc/syswarden/lists/syswarden_blacklist.ipv4"
	haBlacklistIPv6File  = "/etc/syswarden/lists/syswarden_blacklist.ipv6"
	defaultHATLSDir      = "/var/lib/syswarden/ha"
	haTLSCertificateName = "server.crt"
	haTLSPrivateKeyName  = "server.key"
)

var haTLSDir = defaultHATLSDir

type haBlacklistFamily uint8

const (
	haBlacklistIPv4 haBlacklistFamily = iota
	haBlacklistIPv6
)

func blacklistFamilyForIP(ip string) haBlacklistFamily {
	if strings.Contains(ip, ":") {
		return haBlacklistIPv6
	}
	return haBlacklistIPv4
}

func readBlacklistFileForIP(ip string) ([]byte, error) {
	if blacklistFamilyForIP(ip) == haBlacklistIPv6 {
		return os.ReadFile(haBlacklistIPv6File)
	}
	return os.ReadFile(haBlacklistIPv4File)
}

func writeBlacklistFileForIP(ip string, content []byte) error {
	if blacklistFamilyForIP(ip) == haBlacklistIPv6 {
		return os.WriteFile(haBlacklistIPv6File, content, 0600)
	}
	return os.WriteFile(haBlacklistIPv4File, content, 0600)
}

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

func StartHAServer(fwManager firewall.Manager) {
	cfg := loadHAConfig()
	if (cfg.Enabled != "y" && cfg.Enabled != "true" && cfg.Enabled != "1") || len(cfg.PeerIPs) == 0 {
		return
	}

	log.Printf("[HA Cluster] Starting TLS P2P API on port %s", cfg.Port)

	coreVersion := "unknown"
	cmd := exec.Command("syswarden") // #nosec
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

	mux := http.NewServeMux()
	mux.HandleFunc("/ha/sync", func(w http.ResponseWriter, r *http.Request) {
		// Zero-Trust: TCP IP Validation
		remoteIP, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		allowed := false
		for _, peer := range cfg.PeerIPs {
			if peer == remoteIP {
				allowed = true
				break
			}
		}

		if !allowed {
			log.Printf("[HA Cluster] Unauthorized sync attempt dropped from %s", remoteIP) // #nosec G706
			http.Error(w, "Forbidden: IP not in cluster", http.StatusForbidden)
			return
		}

		// Zero-Trust: Cryptographic Token Validation
		if cfg.Token == "" {
			log.Printf("[HA Cluster] WARNING: SYSWARDEN_HA_TOKEN is missing. Running in Legacy Mode (IP validation only). Please configure a token for maximum security.")
		} else {
			authHeader := r.Header.Get("Authorization")
			expectedHeader := "Bearer " + cfg.Token
			if subtle.ConstantTimeCompare([]byte(authHeader), []byte(expectedHeader)) != 1 {
				log.Printf("[HA Cluster] Unauthorized sync attempt dropped (invalid token)")
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
		}

		if r.Method == http.MethodGet {
			// Return current blocklists
			// IMPORTANT: syswarden_blacklist.ipv4/.ipv6 contain the WAF L7 Dynamic Bans
			// They are synchronized across the HA cluster so that all nodes can inject them into L3 (nftables @banned_ips)
			var allIPs []string
			if content, err := os.ReadFile("/etc/syswarden/lists/syswarden_blacklist.ipv4"); err == nil { // #nosec
				lines := strings.Split(strings.TrimSpace(string(content)), "\n")
				for _, l := range lines {
					if l != "" {
						allIPs = append(allIPs, strings.TrimSpace(l))
					}
				}
			}
			if content, err := os.ReadFile("/etc/syswarden/lists/syswarden_blacklist.ipv6"); err == nil { // #nosec
				lines := strings.Split(strings.TrimSpace(string(content)), "\n")
				for _, l := range lines {
					if l != "" {
						allIPs = append(allIPs, strings.TrimSpace(l))
					}
				}
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(HASyncPayload{IPs: allIPs})
			return
		}

		if r.Method == http.MethodPost {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "Bad Request", http.StatusBadRequest)
				return
			}

			var payload HASyncPayload
			if err := json.Unmarshal(body, &payload); err != nil {
				http.Error(w, "Invalid JSON", http.StatusBadRequest)
				return
			}

			log.Printf("[HA Cluster] Received %d banned IPs from peer %s", len(payload.IPs), remoteIP) // #nosec G706

			// Read current state to prevent duplicates
			existingIPs := make(map[string]bool)
			if content, err := os.ReadFile("/etc/syswarden/lists/syswarden_blacklist.ipv4"); err == nil { // #nosec
				for _, l := range strings.Split(string(content), "\n") {
					existingIPs[strings.TrimSpace(l)] = true
				}
			}
			if content, err := os.ReadFile("/etc/syswarden/lists/syswarden_blacklist.ipv6"); err == nil { // #nosec
				for _, l := range strings.Split(string(content), "\n") {
					existingIPs[strings.TrimSpace(l)] = true
				}
			}

			for _, ip := range payload.IPs {
				_ = fwManager.Ban(ip)

				if existingIPs[ip] {
					continue
				}

				// Also persist locally to blocklist
				if !strings.Contains(ip, ":") {
					f, _ := os.OpenFile("/etc/syswarden/lists/syswarden_blacklist.ipv4", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600) // #nosec
					if f != nil {
						_, _ = f.WriteString(ip + "\n")
						_ = f.Close()
					}
				} else {
					f, _ := os.OpenFile("/etc/syswarden/lists/syswarden_blacklist.ipv6", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600) // #nosec
					if f != nil {
						_, _ = f.WriteString(ip + "\n")
						_ = f.Close()
					}
				}
			}

			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"ok"}`))
			return
		}
		if r.Method == http.MethodDelete {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "Bad Request", http.StatusBadRequest)
				return
			}

			var payload HASyncPayload
			if err := json.Unmarshal(body, &payload); err != nil {
				http.Error(w, "Invalid JSON", http.StatusBadRequest)
				return
			}

			log.Printf("[HA Cluster] Received %d IPs to UNBAN from peer %s", len(payload.IPs), remoteIP) // #nosec G706

			for _, ip := range payload.IPs {
				_ = fwManager.Unban(ip)

				if content, err := readBlacklistFileForIP(ip); err == nil {
					lines := strings.Split(string(content), "\n")
					var newLines []string
					for _, l := range lines {
						if strings.TrimSpace(l) != ip && strings.TrimSpace(l) != "" {
							newLines = append(newLines, l)
						}
					}
					if len(newLines) > 0 {
						_ = writeBlacklistFileForIP(ip, []byte(strings.Join(newLines, "\n")+"\n"))
					} else {
						_ = writeBlacklistFileForIP(ip, []byte(""))
					}
				}
			}

			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"ok"}`))
			return
		}

		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	})

	mux.HandleFunc("/ha/telemetry", func(w http.ResponseWriter, r *http.Request) {
		remoteIP, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		allowed := false
		for _, peer := range cfg.PeerIPs {
			if peer == remoteIP {
				allowed = true
				break
			}
		}

		if !allowed {
			log.Printf("[HA Cluster] Unauthorized telemetry attempt dropped from %s", remoteIP) // #nosec G706
			http.Error(w, "Forbidden: IP not in cluster", http.StatusForbidden)
			return
		}

		if r.Method != http.MethodGet {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}

		content, err := os.ReadFile("/var/lib/syswarden/ui/data.json") // #nosec
		if err != nil {
			http.Error(w, "Telemetry unavailable", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(content)
	})

	mux.HandleFunc("/ha/status", func(w http.ResponseWriter, r *http.Request) {
		remoteIP, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		allowed := false
		for _, peer := range cfg.PeerIPs {
			if peer == remoteIP {
				allowed = true
				break
			}
		}

		if !allowed {
			http.Error(w, "Forbidden: IP not in cluster", http.StatusForbidden)
			return
		}

		if r.Method != http.MethodGet {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}

		hostname, _ := os.Hostname()
		if hostname == "" {
			hostname = "unknown"
		}

		// Very lightweight OS check from /etc/os-release
		osName := "Linux"
		if osRelease, err := os.ReadFile("/etc/os-release"); err == nil { // #nosec
			for _, line := range strings.Split(string(osRelease), "\n") {
				if strings.HasPrefix(line, "PRETTY_NAME=") {
					osName = strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), "\"")
					break
				}
			}
		}

		statusData := map[string]string{
			"hostname": hostname,
			"os":       osName,
			"version":  coreVersion, // syswarden current core version dynamically extracted
			"status":   "online",
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(statusData)
	})

	server := &http.Server{
		Addr:    fmt.Sprintf(":%s", cfg.Port),
		Handler: mux,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS13,
		},
		ReadHeaderTimeout: 3 * time.Second,
	}

	go func() {
		if err := server.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			log.Printf("[HA Cluster] Server failed: %v", err)
		}
	}()
}
