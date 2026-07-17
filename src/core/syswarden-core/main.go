package main

import (
	"context"
	"io"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"syswarden-core/engine"
	"syswarden-core/firewall"
	"syswarden-core/logger"
	"syswarden-core/network"
	"syswarden-core/telemetry"
)

func main() {
	// Parity: Ensure syswarden-core standard logs go to /var/log/syswarden/core.log
	_ = os.MkdirAll("/var/log/syswarden", 0750)
	logFile, err := os.OpenFile("/var/log/syswarden/core.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600) // #nosec
	if err == nil {
		mw := io.MultiWriter(os.Stdout, logFile)
		log.SetOutput(mw)
	}

	log.Println("[SYSWARDEN-Core] Starting Next-Gen WAF Daemon...")

	// Initialize Logger (Parity: Write to /opt/syswarden/data.json for TUI)
	_ = os.MkdirAll("/opt/syswarden", 0750)
	telemetryLogger := logger.NewLogger("/var/log/syswarden/waf.json")
	telemetryLogger.Info("SYSWARDEN Core Daemon initialized")

	// Initialize Firewall Manager
	fwManager, err := firewall.NewManager()
	if err != nil {
		log.Fatalf("[SYSWARDEN-Core] Failed to initialize firewall: %v", err)
	}
	log.Printf("[SYSWARDEN-Core] Firewall backend initialized: %s", fwManager.Name())

	// Initialize Threat Engine
	threatEngine, err := engine.NewEngine("/opt/syswarden/signatures.json")
	if err != nil {
		log.Fatalf("[SYSWARDEN-Core] Failed to initialize threat engine: %v", err)
	}
	log.Printf("[SYSWARDEN-Core] Loaded %d threat signatures", threatEngine.RuleCount())

	// Initialize Unix Domain Socket
	ctx, cancel := context.WithCancel(context.Background())
	udsServer := network.NewUDSServer(ctx, "/var/run/syswarden.sock", threatEngine, fwManager, telemetryLogger)
	if err := udsServer.Start(); err != nil {
		log.Fatalf("[SYSWARDEN-Core] Failed to start UDS server: %v", err)
	}

	// Start Native Telemetry Worker
	var wg sync.WaitGroup
	telemetry.StartWorker(ctx, &wg, fwManager, telemetryLogger.LogAllowed, telemetryLogger.LogBan, telemetryLogger.LogShadowAlert)

	// Start SaaS Monitors Downloader
	saasDownloader := network.NewSaasMonitorDownloader(telemetryLogger)
	saasDownloader.Start()

	// Start L7 WAAP Analytics Engine (Heuristic & Bruteforce)
	waapEngine := network.NewWAAPEngine(fwManager, telemetryLogger)
	waapEngine.Start()

	// Start HA P2P Server (Zero-Touch TLS)
	network.StartHAServer(fwManager)

	// Handle Graceful Shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Println("[SYSWARDEN-Core] Shutting down gracefully...")
	cancel()
	udsServer.Stop()
	wg.Wait()
	telemetryLogger.Close()
}
