package cmd

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"syswarden-cli/config"

	"github.com/gorilla/websocket"
)

const webTUIHelperEnvironment = "SYSWARDEN_WEB_TUI_HELPER"

func TestWebTUIHTTPSAndWebSocketAuthenticationContract_SW_WEB_001(t *testing.T) {
	server := startWebTUIProcess(t)

	response := webTUIRequest(t, server, "", "", nil)
	if response.status != http.StatusUnauthorized || response.authenticate != `Basic realm="SysWarden Web-TUI"` {
		t.Fatalf("anonymous response = %#v", response)
	}
	response = webTUIRequest(t, server, "admin", "wrong", nil)
	if response.status != http.StatusUnauthorized {
		t.Fatalf("wrong Basic credentials status = %d", response.status)
	}
	response = webTUIRequest(t, server, "admin", "fixture-web-token", nil)
	if response.status != http.StatusOK || !strings.Contains(response.body, "SYSWARDEN") {
		t.Fatalf("valid Basic credentials response = %#v", response)
	}
	assertWebTUICookie(t, response.cookies)

	response = webTUIRequestPath(t, server, "/?token=fixture-web-token", "", "", nil)
	if response.status != http.StatusFound || response.location != "/" {
		t.Fatalf("legacy query token response = %#v", response)
	}
	assertWebTUICookie(t, response.cookies)

	cookie := &http.Cookie{
		Name:     "syswarden_token",
		Value:    "fixture-web-token",
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	}
	response = webTUIRequest(t, server, "", "", cookie)
	if response.status != http.StatusOK {
		t.Fatalf("valid cookie status = %d", response.status)
	}
	response = webTUIRequestPath(t, server, "/ws", "", "", nil)
	if response.status != http.StatusForbidden {
		t.Fatalf("anonymous WebSocket endpoint status = %d", response.status)
	}

	dialer := websocket.Dialer{TLSClientConfig: &tls.Config{
		InsecureSkipVerify: true, // #nosec G402 -- isolated self-signed test server
		MinVersion:         tls.VersionTLS13,
	}}
	connection, _, err := dialer.Dial("wss://"+server+"/ws?token=fixture-web-token", nil)
	if err != nil {
		t.Fatalf("authenticated WebSocket handshake: %v", err)
	}
	defer connection.Close()
	if err := connection.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	messageType, payload, err := connection.ReadMessage()
	if err != nil {
		t.Fatalf("read PTY WebSocket frame: %v", err)
	}
	if messageType != websocket.BinaryMessage || !strings.Contains(string(payload), "fixture-tui-ready") {
		t.Fatalf("PTY frame = (%d, %q)", messageType, payload)
	}
}

func TestWebTUILegacyOriginAndMessageLimitContract_SW_WEB_001(t *testing.T) {
	t.Parallel()
	request, err := http.NewRequest(http.MethodGet, "https://example.invalid/ws", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Origin", "https://untrusted.example")
	if !upgrader.CheckOrigin(request) {
		t.Fatal("v4.02.8 legacy cross-origin WebSocket behavior changed")
	}

	largeData := strings.Repeat("x", 1024*1024)
	wire, err := json.Marshal(WsMsg{Type: "input", Data: largeData})
	if err != nil {
		t.Fatal(err)
	}
	var decoded WsMsg
	if err := json.Unmarshal(wire, &decoded); err != nil {
		t.Fatalf("legacy 1 MiB message contract changed: %v", err)
	}
	if len(decoded.Data) != len(largeData) {
		t.Fatalf("decoded data length = %d, want %d", len(decoded.Data), len(largeData))
	}

	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve Web-TUI test source")
	}
	source, err := os.ReadFile(filepath.Join(filepath.Dir(currentFile), "web_tui.go")) // #nosec G304 -- fixed sibling source file
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(source), "SetReadLimit(") {
		t.Fatal("an explicit WebSocket read limit now exists; replace this legacy SW-WEB-001 assertion with bounded positive/negative tests")
	}
}

func TestWebTUIHelperProcess(t *testing.T) {
	if os.Getenv(webTUIHelperEnvironment) != "1" {
		return
	}
	bindAddr = os.Getenv("SYSWARDEN_WEB_TUI_TEST_ADDRESS")
	webToken = os.Getenv("SYSWARDEN_WEB_TUI_TEST_TOKEN")
	config.GlobalConfig = &config.Config{WebTUIPassword: webToken}
	webTuiCmd.Run(webTuiCmd, nil)
}

type webTUIResponse struct {
	status       int
	body         string
	authenticate string
	location     string
	cookies      []*http.Cookie
}

func startWebTUIProcess(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
			requireOrSkipWebTUILoopback(t, err)
		}
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}

	toolDir := t.TempDir()
	fakeTUI := filepath.Join(toolDir, "syswarden-tui")
	if err := os.WriteFile(fakeTUI, []byte("#!/bin/sh\nprintf 'fixture-tui-ready\\n'\n/bin/sleep 1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(fakeTUI, 0700); err != nil { // #nosec G302 -- the owner-only test fixture must be executable by the isolated helper
		t.Fatal(err)
	}
	command := exec.Command(os.Args[0], "-test.run=^TestWebTUIHelperProcess$") // #nosec G204 G702 -- os.Args[0] is the fixed current test binary and all arguments are static
	command.Env = append(
		os.Environ(),
		webTUIHelperEnvironment+"=1",
		"SYSWARDEN_WEB_TUI_TEST_ADDRESS="+address,
		"SYSWARDEN_WEB_TUI_TEST_TOKEN=fixture-web-token",
		"PATH="+toolDir+string(os.PathListSeparator)+os.Getenv("PATH"),
	)
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = command.Process.Kill()
		_, _ = command.Process.Wait()
	})

	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		client := webTUIHTTPClient()
		if response, err := client.Get("https://" + address + "/"); err == nil {
			_ = response.Body.Close()
			return address
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("Web-TUI helper did not become ready")
	return ""
}

func requireOrSkipWebTUILoopback(t *testing.T, err error) {
	t.Helper()
	if os.Getenv("CI") != "" || os.Getenv("ACT") == "true" || os.Getenv("SYSWARDEN_REQUIRE_LOOPBACK_TESTS") == "1" {
		t.Fatalf("Web-TUI loopback contract is mandatory in CI/Act but sockets are unavailable: %v", err)
	}
	t.Skipf("Web-TUI contract requires loopback sockets unavailable in this sandbox: %v", err)
}

func webTUIRequest(t *testing.T, server, user, password string, cookie *http.Cookie) webTUIResponse {
	t.Helper()
	return webTUIRequestPath(t, server, "/", user, password, cookie)
}

func webTUIRequestPath(t *testing.T, server, path, user, password string, cookie *http.Cookie) webTUIResponse {
	t.Helper()
	request, err := http.NewRequest(http.MethodGet, "https://"+server+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if user != "" || password != "" {
		request.SetBasicAuth(user, password)
	}
	if cookie != nil {
		request.AddCookie(cookie)
	}
	response, err := webTUIHTTPClient().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return webTUIResponse{
		status:       response.StatusCode,
		body:         string(body),
		authenticate: response.Header.Get("WWW-Authenticate"),
		location:     response.Header.Get("Location"),
		cookies:      response.Cookies(),
	}
}

func webTUIHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // #nosec G402 -- isolated self-signed test server
			MinVersion:         tls.VersionTLS13,
		}},
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func assertWebTUICookie(t *testing.T, cookies []*http.Cookie) {
	t.Helper()
	for _, cookie := range cookies {
		if cookie.Name != "syswarden_token" {
			continue
		}
		if cookie.Value != "fixture-web-token" || !cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteStrictMode || cookie.Path != "/" {
			t.Fatalf("authentication cookie = %#v", cookie)
		}
		return
	}
	t.Fatal("syswarden_token cookie is missing")
}
