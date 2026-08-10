package cmd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"io/fs"
	"log"
	"math/big"
	"net/http"
	"os"
	"os/exec"
	"time"

	"syswarden-cli/config"

	"github.com/creack/pty"
	"github.com/gorilla/websocket"
	"github.com/spf13/cobra"
)

var (
	bindAddr string
	webToken string
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true // Rely on token/cookie for security, not CORS
	},
}

func generateSelfSignedCert() (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"SysWarden Web-TUI"},
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

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	privBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes})

	return tls.X509KeyPair(certPEM, keyPEM)
}

type WsMsg struct {
	Type string `json:"type"`
	Data string `json:"data,omitempty"`
	Cols int    `json:"cols,omitempty"`
	Rows int    `json:"rows,omitempty"`
}

var webTuiCmd = &cobra.Command{
	Use:   "web-tui",
	Short: "Start the Web-TUI server (WebTTY)",
	Run: func(cmd *cobra.Command, args []string) {
		if webToken == "" {
			if config.GlobalConfig != nil && config.GlobalConfig.WebTUIPassword != "" {
				webToken = config.GlobalConfig.WebTUIPassword
			}
			if webToken == "" {
				// Zero Downtime Fallback: Auto-generate token if missing after upgrade
				webToken = generateSecureToken(32)
				if err := updateConfigToken(webToken); err != nil {
					log.Printf("[WARN] Failed to save auto-generated Web-TUI token: %v", err)
				} else {
					log.Printf("[Web-TUI] Generated new secure token and saved to config for backward compatibility.")
				}
			}
		}

		mux := http.NewServeMux()

		// Serve static assets from embedded FS
		subFS, err := fs.Sub(uiAssets, "ui")
		if err != nil {
			log.Fatalf("[ERROR] Failed to load UI assets: %v", err)
		}

		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			token := r.URL.Query().Get("token")

			if cookie, err := r.Cookie("syswarden_token"); err == nil && cookie.Value == webToken {
				http.FileServer(http.FS(subFS)).ServeHTTP(w, r)
				return
			}

			// Support for both Basic Auth and Legacy URL token
			user, pass, ok := r.BasicAuth()
			if ok && user == "admin" && pass == webToken {
				http.SetCookie(w, &http.Cookie{
					Name:     "syswarden_token",
					Value:    webToken,
					Path:     "/",
					HttpOnly: true,
					Secure:   true,
					SameSite: http.SameSiteStrictMode,
				})
				http.FileServer(http.FS(subFS)).ServeHTTP(w, r)
				return
			}

			// Legacy URL token support (silent login)
			if token == webToken {
				http.SetCookie(w, &http.Cookie{
					Name:     "syswarden_token",
					Value:    webToken,
					Path:     "/",
					HttpOnly: true,
					Secure:   true,
					SameSite: http.SameSiteStrictMode,
				})
				// Redirect to strip the token from the URL in the browser bar
				http.Redirect(w, r, "/", http.StatusFound)
				return
			}

			w.Header().Set("WWW-Authenticate", `Basic realm="SysWarden Web-TUI"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			log.Printf("[WebTUI] Unauthorized access attempt from IP: %s", r.RemoteAddr)
		})

		mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
			token := r.URL.Query().Get("token")
			isValid := false

			if cookie, err := r.Cookie("syswarden_token"); err == nil && cookie.Value == webToken {
				isValid = true
			} else if token == webToken {
				isValid = true
			}

			if !isValid {
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}

			conn, err := upgrader.Upgrade(w, r, nil)
			if err != nil {
				log.Printf("[ERROR] WebSocket upgrade failed: %v", err)
				return
			}
			defer func() {
				if cerr := conn.Close(); cerr != nil {
					log.Printf("[WARN] WebSocket close error: %v", cerr)
				}
			}()

			tuiPath := "/opt/syswarden/bin/syswarden-tui"
			// Check if we are running in dev mode
			if _, err := os.Stat(tuiPath); os.IsNotExist(err) {
				// Fallback to searching in PATH for dev environments
				tuiPath = "syswarden-tui"
			}

			// Secure zero-shell execution
			tuiCmd := exec.Command(tuiPath) // #nosec G204
			tuiCmd.Env = append(os.Environ(), "TERM=xterm-256color")

			ptmx, err := pty.Start(tuiCmd)
			if err != nil {
				log.Printf("[ERROR] Failed to start PTY: %v", err)
				return
			}
			defer func() { _ = ptmx.Close() }()
			defer func() { _ = tuiCmd.Process.Kill() }()

			// Handle terminal resize dynamically
			go func() {
				for {
					_, msg, err := conn.ReadMessage()
					if err != nil {
						break
					}

					var wsMsg WsMsg
					if err := json.Unmarshal(msg, &wsMsg); err == nil {
						if wsMsg.Type == "resize" && wsMsg.Cols > 0 && wsMsg.Rows > 0 {
							_ = pty.Setsize(ptmx, &pty.Winsize{
								Rows: uint16(wsMsg.Rows),
								Cols: uint16(wsMsg.Cols),
							})
						} else if wsMsg.Type == "input" {
							_, _ = ptmx.Write([]byte(wsMsg.Data))
						}
					}
				}
			}()

			// Stream output from PTY to WebSocket
			buf := make([]byte, 8192)
			for {
				n, err := ptmx.Read(buf)
				if err != nil {
					if err != io.EOF {
						log.Printf("[ERROR] PTY read error: %v", err)
					}
					break
				}
				if err := conn.WriteMessage(websocket.BinaryMessage, buf[:n]); err != nil {
					break
				}
			}
			_ = tuiCmd.Wait()
		})

		cert, err := generateSelfSignedCert()
		if err != nil {
			log.Fatalf("[ERROR] Failed to generate TLS certificate: %v", err)
		}

		server := &http.Server{
			Addr:              bindAddr,
			Handler:           mux,
			ReadHeaderTimeout: 5 * time.Second,
			TLSConfig: &tls.Config{
				Certificates: []tls.Certificate{cert},
				MinVersion:   tls.VersionTLS12,
			},
		}

		log.Printf("[SYSWARDEN] Web-TUI listening securely on https://%s/ (Token required)", bindAddr)
		if err := server.ListenAndServeTLS("", ""); err != nil { // #nosec G114
			log.Fatalf("[ERROR] Web-TUI server failed: %v", err)
		}
	},
}

func init() {
	webTuiCmd.Flags().StringVar(&bindAddr, "bind", "0.0.0.0:62027", "IP:Port to bind the Web-TUI server")
	webTuiCmd.Flags().StringVar(&webToken, "token", "", "Secure token for Web-TUI access (Required)")
	rootCmd.AddCommand(webTuiCmd)
}
