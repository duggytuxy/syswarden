//go:build linux

// Command go127_protocol_probe measures one bounded, local protocol campaign.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"sync/atomic"
	"syscall"
	"time"
	"unicode/utf8"
)

const (
	exactOperations  = 2048
	maximumBodyBytes = 4096
)

type requestDocument struct {
	Epoch uint64   `json:"epoch"`
	Node  string   `json:"node"`
	IPs   []string `json:"ips"`
}

type responseDocument struct {
	Accepted int    `json:"accepted"`
	Status   string `json:"status"`
}

type probeOutput struct {
	SchemaVersion int                `json:"schema_version"`
	Operations    int                `json:"operations"`
	Protocols     map[string]string  `json:"protocols"`
	Metrics       map[string]float64 `json:"metrics"`
}

func cpuNanoseconds(usage *syscall.Rusage) int64 {
	return (usage.Utime.Sec+usage.Stime.Sec)*int64(time.Second) +
		(usage.Utime.Usec+usage.Stime.Usec)*int64(time.Microsecond)
}

func strictDecode(raw []byte, destination any) error {
	if !utf8.Valid(raw) {
		return errors.New("JSON input is not valid UTF-8")
	}
	keys := make(map[string]struct{})
	keyDecoder := json.NewDecoder(bytes.NewReader(raw))
	opening, err := keyDecoder.Token()
	if err != nil || opening != json.Delim('{') {
		return errors.New("JSON input must be one object")
	}
	for keyDecoder.More() {
		token, tokenErr := keyDecoder.Token()
		key, ok := token.(string)
		if tokenErr != nil || !ok {
			return errors.New("JSON object key is invalid")
		}
		if _, duplicate := keys[key]; duplicate {
			return errors.New("JSON object key is duplicated")
		}
		keys[key] = struct{}{}
		var value json.RawMessage
		if decodeErr := keyDecoder.Decode(&value); decodeErr != nil {
			return decodeErr
		}
	}
	closing, err := keyDecoder.Token()
	if err != nil || closing != json.Delim('}') {
		return errors.New("JSON object is incomplete")
	}
	if _, err := keyDecoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("JSON input has trailing data")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("JSON input has trailing data")
	}
	return nil
}

func main() {
	if len(os.Args) != 1 {
		fmt.Fprintln(os.Stderr, "this probe accepts no arguments")
		os.Exit(2)
	}

	protocols := map[string]string{
		"http1_keepalive":          "fail",
		"tls13":                    "fail",
		"bounded_response_headers": "fail",
		"strict_json":              "fail",
		"ed25519_manifest":         "fail",
	}

	var strict requestDocument
	invalidUTF8 := append([]byte(`{"epoch":1,"node":"`), 0xff)
	invalidUTF8 = append(invalidUTF8, []byte(`","ips":[]}`)...)
	if strictDecode([]byte(`{"epoch":1,"node":"node-a","ips":["192.0.2.10","2001:db8::10"],"unknown":true}`), &strict) == nil ||
		strictDecode([]byte(`{"epoch":1,"epoch":2,"node":"node-a","ips":[]}`), &strict) == nil ||
		strictDecode(invalidUTF8, &strict) == nil {
		fmt.Fprintln(os.Stderr, "strict JSON rejection contract failed")
		os.Exit(1)
	}
	protocols["strict_json"] = "pass"

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Fprintln(os.Stderr, "generate signing identity:", err)
		os.Exit(1)
	}
	manifest := []byte(`{"release":"v4.10.0","sha256":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}`)
	signature := ed25519.Sign(privateKey, manifest)
	if !ed25519.Verify(publicKey, manifest, signature) || ed25519.Verify(publicKey, append(manifest, '\n'), signature) {
		fmt.Fprintln(os.Stderr, "Ed25519 manifest contract failed")
		os.Exit(1)
	}
	protocols["ed25519_manifest"] = "pass"

	var newConnections atomic.Int64
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		defer request.Body.Close()
		raw, readErr := io.ReadAll(io.LimitReader(request.Body, maximumBodyBytes+1))
		var document requestDocument
		if readErr != nil || len(raw) > maximumBodyBytes || strictDecode(raw, &document) != nil ||
			document.Node != "node-a" || len(document.IPs) != 2 {
			http.Error(writer, "invalid request", http.StatusBadRequest)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(responseDocument{Accepted: 2, Status: "pass"})
	}))
	server.EnableHTTP2 = false
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			newConnections.Add(1)
		}
	}
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}
	server.StartTLS()
	defer server.Close()

	transport := server.Client().Transport.(*http.Transport).Clone()
	transport.ForceAttemptHTTP2 = false
	transport.MaxResponseHeaderBytes = 1024
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	defer transport.CloseIdleConnections()
	body, _ := json.Marshal(requestDocument{Epoch: 1, Node: "node-a", IPs: []string{"192.0.2.10", "2001:db8::10"}})
	doRequest := func() error {
		request, requestErr := http.NewRequest(http.MethodPost, server.URL+"/ha/v2/replicate", bytes.NewReader(body))
		if requestErr != nil {
			return requestErr
		}
		request.Header.Set("Content-Type", "application/json")
		response, responseErr := client.Do(request)
		if responseErr != nil {
			return responseErr
		}
		defer response.Body.Close()
		responseRaw, responseReadErr := io.ReadAll(io.LimitReader(response.Body, maximumBodyBytes+1))
		var responseDocument responseDocument
		if responseReadErr != nil || len(responseRaw) > maximumBodyBytes || strictDecode(responseRaw, &responseDocument) != nil {
			return errors.New("invalid bounded response")
		}
		if response.StatusCode != http.StatusOK || response.ProtoMajor != 1 || response.TLS == nil || response.TLS.Version != tls.VersionTLS13 ||
			responseDocument.Accepted != 2 || responseDocument.Status != "pass" {
			return errors.New("HTTP protocol result is invalid")
		}
		return nil
	}
	if err := doRequest(); err != nil {
		fmt.Fprintln(os.Stderr, "warmup request:", err)
		os.Exit(1)
	}

	oversized := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("X-SysWarden-Bound", string(bytes.Repeat([]byte{'x'}, 2048)))
		writer.WriteHeader(http.StatusNoContent)
	}))
	oversized.EnableHTTP2 = false
	oversized.TLS = &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}
	oversized.StartTLS()
	boundedTransport := oversized.Client().Transport.(*http.Transport).Clone()
	boundedTransport.ForceAttemptHTTP2 = false
	boundedTransport.MaxResponseHeaderBytes = 1024
	boundedClient := &http.Client{Transport: boundedTransport, Timeout: 10 * time.Second}
	if response, boundErr := boundedClient.Get(oversized.URL); boundErr == nil {
		response.Body.Close()
		fmt.Fprintln(os.Stderr, "oversized response headers were accepted")
		os.Exit(1)
	}
	boundedTransport.CloseIdleConnections()
	oversized.Close()
	protocols["bounded_response_headers"] = "pass"

	runtime.GC()
	var memoryBefore runtime.MemStats
	var memoryAfter runtime.MemStats
	var usageBefore syscall.Rusage
	var usageAfter syscall.Rusage
	runtime.ReadMemStats(&memoryBefore)
	if syscall.Getrusage(syscall.RUSAGE_SELF, &usageBefore) != nil {
		fmt.Fprintln(os.Stderr, "cannot read initial resource usage")
		os.Exit(1)
	}
	started := time.Now()
	for iteration := 0; iteration < exactOperations; iteration++ {
		if err := doRequest(); err != nil {
			fmt.Fprintln(os.Stderr, "measured request:", err)
			os.Exit(1)
		}
	}
	elapsed := time.Since(started)
	if syscall.Getrusage(syscall.RUSAGE_SELF, &usageAfter) != nil {
		fmt.Fprintln(os.Stderr, "cannot read final resource usage")
		os.Exit(1)
	}
	runtime.ReadMemStats(&memoryAfter)
	if newConnections.Load() != 1 {
		fmt.Fprintf(os.Stderr, "HTTP keepalive used %d connections, want 1\n", newConnections.Load())
		os.Exit(1)
	}
	protocols["http1_keepalive"] = "pass"
	protocols["tls13"] = "pass"

	cpu := cpuNanoseconds(&usageAfter) - cpuNanoseconds(&usageBefore)
	if cpu <= 0 || elapsed <= 0 || memoryAfter.Mallocs <= memoryBefore.Mallocs || memoryAfter.TotalAlloc <= memoryBefore.TotalAlloc || usageAfter.Maxrss <= 0 {
		fmt.Fprintln(os.Stderr, "resource counters are invalid")
		os.Exit(1)
	}
	operations := float64(exactOperations)
	output := probeOutput{
		SchemaVersion: 1,
		Operations:    exactOperations,
		Protocols:     protocols,
		Metrics: map[string]float64{
			"cpu_nanoseconds_per_request": float64(cpu) / operations,
			"rss_bytes":                   float64(usageAfter.Maxrss) * 1024.0,
			"allocations_per_request":     float64(memoryAfter.Mallocs-memoryBefore.Mallocs) / operations,
			"allocated_bytes_per_request": float64(memoryAfter.TotalAlloc-memoryBefore.TotalAlloc) / operations,
			"http_requests_per_second":    operations / elapsed.Seconds(),
		},
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(output); err != nil {
		fmt.Fprintln(os.Stderr, "encode probe output:", err)
		os.Exit(1)
	}
}
