package network

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"syswarden-core/firewall"
	"time"
)

type HAConfig struct {
	Enabled string
	PeerIPs []string
	Port    string
}

func loadHAConfig() HAConfig {
	cfg := HAConfig{
		Enabled: "n",
		PeerIPs: []string{},
		Port:    "62026", // Default HA TLS API Port
	}

	file, err := os.Open("/opt/syswarden/syswarden-auto.conf")
	if err != nil {
		return cfg
	}
	defer func() { _ = file.Close() }()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "SYSWARDEN_HA_ENABLED=") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				cfg.Enabled = strings.ToLower(strings.TrimSpace(strings.Trim(strings.TrimSpace(parts[1]), "\"'")))
			}
		}
		if strings.HasPrefix(line, "SYSWARDEN_HA_PEER_IP=") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				ips := strings.TrimSpace(strings.Trim(strings.TrimSpace(parts[1]), "\"'"))
				ips = strings.ReplaceAll(ips, ",", " ")
				cfg.PeerIPs = append(cfg.PeerIPs, strings.Fields(ips)...)
			}
		}
		if strings.HasPrefix(line, "SYSWARDEN_HA_PEER_PORT=") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				portVal := strings.TrimSpace(strings.Trim(strings.TrimSpace(parts[1]), "\"'"))
				if portVal != "" {
					cfg.Port = portVal
				}
			}
		}
	}
	return cfg
}

// Generate self-signed TLS cert in memory
func generateSelfSignedCert() (tls.Certificate, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"SYSWARDEN HA Cluster"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	cert := tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  priv,
	}
	return cert, nil
}

type HASyncPayload struct {
	IPs []string `json:"ips"`
}

func StartHAServer(fwManager firewall.Manager) {
	cfg := loadHAConfig()
	if (cfg.Enabled != "y" && cfg.Enabled != "true" && cfg.Enabled != "1") || len(cfg.PeerIPs) == 0 {
		return
	}

	log.Printf("[HA Cluster] Starting TLS P2P API on port %s", cfg.Port)

	cert, err := generateSelfSignedCert()
	if err != nil {
		log.Printf("[HA Cluster] Failed to generate TLS cert: %v", err)
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
			log.Printf("[HA Cluster] Unauthorized sync attempt dropped from %s", remoteIP)
			http.Error(w, "Forbidden: IP not in cluster", http.StatusForbidden)
			return
		}

		if r.Method == http.MethodGet {
			// Return current blocklists
			var allIPs []string
			if content, err := os.ReadFile("/etc/syswarden/lists/syswarden_blacklist.ipv4"); err == nil {
				lines := strings.Split(strings.TrimSpace(string(content)), "\n")
				for _, l := range lines {
					if l != "" {
						allIPs = append(allIPs, strings.TrimSpace(l))
					}
				}
			}
			if content, err := os.ReadFile("/etc/syswarden/lists/syswarden_blacklist.ipv6"); err == nil {
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

			log.Printf("[HA Cluster] Received %d banned IPs from peer %s", len(payload.IPs), remoteIP)

			for _, ip := range payload.IPs {
				_ = fwManager.Ban(ip)

				// Also persist locally to blocklist
				if !strings.Contains(ip, ":") {
					f, _ := os.OpenFile("/etc/syswarden/lists/syswarden_blacklist.ipv4", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
					if f != nil {
						_, _ = f.WriteString(ip + "\n")
						_ = f.Close()
					}
				} else {
					f, _ := os.OpenFile("/etc/syswarden/lists/syswarden_blacklist.ipv6", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
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

		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	})

	server := &http.Server{
		Addr:    fmt.Sprintf(":%s", cfg.Port),
		Handler: mux,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
		},
	}

	go func() {
		if err := server.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			log.Printf("[HA Cluster] Server failed: %v", err)
		}
	}()
}
