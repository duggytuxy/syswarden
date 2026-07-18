package cmd

import (
	"encoding/json"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"

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
		return true // Rely on token for security, not CORS
	},
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
			// Fallback to reading from auto.conf
			content, err := os.ReadFile("/opt/syswarden/syswarden-auto.conf")
			if err == nil {
				for _, line := range strings.Split(string(content), "\n") {
					if strings.HasPrefix(line, "SYSWARDEN_WEB_TOKEN=") {
						webToken = strings.TrimPrefix(line, "SYSWARDEN_WEB_TOKEN=")
						webToken = strings.Trim(webToken, "\"'")
						break
					}
				}
			}
			if webToken == "" {
				log.Fatal("[ERROR] A --token must be provided to secure the Web-TUI.")
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
			if token != webToken {
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}
			http.FileServer(http.FS(subFS)).ServeHTTP(w, r)
		})

		mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
			token := r.URL.Query().Get("token")
			if token != webToken {
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
				if err := conn.WriteMessage(websocket.TextMessage, buf[:n]); err != nil {
					break
				}
			}
			_ = tuiCmd.Wait()
		})

		log.Printf("[SYSWARDEN] Web-TUI listening on http://%s/?token=%s", bindAddr, webToken)
		if err := http.ListenAndServe(bindAddr, mux); err != nil { // #nosec G114
			log.Fatalf("[ERROR] Web-TUI server failed: %v", err)
		}
	},
}

func init() {
	webTuiCmd.Flags().StringVar(&bindAddr, "bind", "0.0.0.0:62027", "IP:Port to bind the Web-TUI server")
	webTuiCmd.Flags().StringVar(&webToken, "token", "", "Secure token for Web-TUI access (Required)")
	rootCmd.AddCommand(webTuiCmd)
}
