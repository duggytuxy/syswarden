package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"

	"syswarden-core/config"
	"syswarden-core/engine"
	"syswarden-core/firewall"
	"syswarden-core/internal/runtimepaths"
	"syswarden-core/logger"
	"syswarden-core/network"
	"syswarden-core/security"
	"syswarden-core/telemetry"

	"golang.org/x/sys/unix"
)

const (
	coreRemovalTombstonePath   = "/var/lib/syswarden/removal-in-progress-v1"
	coreRemovalTombstoneRecord = "SYSWARDEN_REMOVAL_V1\nstate=in-progress\n"
)

func inspectCoreRemovalTombstone(path string, expectedUID, expectedGID uint32) (bool, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.Base(path) != "removal-in-progress-v1" {
		return true, fmt.Errorf("removal tombstone path is not fixed, clean, and absolute")
	}
	parentPath := filepath.Dir(path)
	parent, err := os.Lstat(parentPath)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return true, fmt.Errorf("inspect removal state directory: %w", err)
	}
	parentStat, parentOK := parent.Sys().(*syscall.Stat_t)
	if !parentOK || !parent.IsDir() || parent.Mode()&os.ModeSymlink != 0 || parent.Mode().Perm()&0022 != 0 ||
		parentStat.Uid != expectedUID || parentStat.Gid != expectedGID {
		return true, fmt.Errorf("refusing unsafe or modified removal tombstone")
	}
	parentFD, err := unix.Open(parentPath, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0) // #nosec G304 -- fixed production path or isolated test fixture
	if err != nil {
		return true, fmt.Errorf("pin removal state directory: %w", err)
	}
	parentFile := os.NewFile(uintptr(parentFD), parentPath)
	if parentFile == nil {
		_ = unix.Close(parentFD)
		return true, fmt.Errorf("pin removal state directory")
	}
	defer parentFile.Close()
	openedParent, parentStatErr := parentFile.Stat()
	afterParent, afterParentErr := os.Lstat(parentPath)
	if parentStatErr != nil || afterParentErr != nil || !os.SameFile(parent, openedParent) || !os.SameFile(openedParent, afterParent) {
		return true, errors.Join(fmt.Errorf("removal state directory changed while pinning"), parentStatErr, afterParentErr)
	}
	fileFD, err := unix.Openat(parentFD, filepath.Base(path), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return false, nil
	}
	if err != nil {
		return true, fmt.Errorf("open removal tombstone without following links: %w", err)
	}
	file := os.NewFile(uintptr(fileFD), path)
	if file == nil {
		_ = unix.Close(fileFD)
		return true, fmt.Errorf("pin removal tombstone")
	}
	defer file.Close()
	opened, statErr := file.Stat()
	fileStat, fileOK := opened.Sys().(*syscall.Stat_t)
	if statErr != nil || !fileOK || opened.Mode()&os.ModeSymlink != 0 || !opened.Mode().IsRegular() ||
		opened.Mode().Perm() != 0600 || fileStat.Uid != expectedUID || fileStat.Gid != expectedGID ||
		fileStat.Nlink != 1 || opened.Size() != int64(len(coreRemovalTombstoneRecord)) {
		return true, errors.Join(fmt.Errorf("refusing unsafe or modified removal tombstone"), statErr)
	}
	content, readErr := io.ReadAll(io.LimitReader(file, int64(len(coreRemovalTombstoneRecord)+1)))
	var after unix.Stat_t
	afterErr := unix.Fstatat(parentFD, filepath.Base(path), &after, unix.AT_SYMLINK_NOFOLLOW)
	finalParent, finalParentErr := os.Lstat(parentPath)
	if readErr != nil || afterErr != nil || finalParentErr != nil ||
		!os.SameFile(openedParent, finalParent) || fileStat.Dev != uint64(after.Dev) ||
		fileStat.Ino != after.Ino || fileStat.Mode != after.Mode || fileStat.Uid != after.Uid ||
		fileStat.Gid != after.Gid || fileStat.Nlink != after.Nlink || fileStat.Size != after.Size ||
		string(content) != coreRemovalTombstoneRecord {
		return true, errors.Join(
			fmt.Errorf("removal tombstone changed during startup attestation"),
			readErr,
			afterErr,
			finalParentErr,
		)
	}
	return true, nil
}

func main() {
	removalInProgress, err := inspectCoreRemovalTombstone(coreRemovalTombstonePath, 0, 0)
	if err != nil {
		log.Fatalf("[SYSWARDEN-Core] Refusing startup while removal state is unsafe: %v", err)
	}
	if removalInProgress {
		log.Fatalf("[SYSWARDEN-Core] Refusing startup while %s is present", coreRemovalTombstonePath)
	}

	// Parity: Ensure syswarden-core standard logs go to /var/log/syswarden/core.log
	_ = os.MkdirAll("/var/log/syswarden", 0750)
	logFile, err := os.OpenFile("/var/log/syswarden/core.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600) // #nosec
	if err == nil {
		mw := io.MultiWriter(os.Stdout, logFile)
		log.SetOutput(mw)
	}

	if err := config.LoadConfig(); err != nil {
		log.Fatalf("[SYSWARDEN-Core] Refusing invalid modular config: %v", err)
	}
	firewallBackend, err := config.FirewallBackendForMutation()
	if err != nil {
		log.Fatalf("[SYSWARDEN-Core] Refusing firewall backend: %v", err)
	}

	log.Println("[SYSWARDEN-Core] Starting Next-Gen WAF Daemon...")

	// Ensure the native package root exists for runtime assets.
	_ = os.MkdirAll(runtimepaths.InstallRoot(), 0750)
	telemetryLogger := logger.NewLogger("/var/log/syswarden/waf.json")
	telemetryLogger.Info("SYSWARDEN Core Daemon initialized")

	// Initialize Firewall Manager
	fwManager, err := firewall.NewManager(firewallBackend)
	if err != nil {
		log.Fatalf("[SYSWARDEN-Core] Failed to initialize firewall: %v", err)
	}
	log.Printf("[SYSWARDEN-Core] Firewall backend initialized: %s", fwManager.Name())

	// Load WAAP Config to get global threshold defaults
	waapConfig := network.LoadWAAPConfig()

	// Initialize Threat Engine
	threatEngine, err := engine.NewEngine(runtimepaths.Signatures(), waapConfig.Threshold, int(waapConfig.Window.Seconds()))
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
	toLoggerRuleContext := func(evidence telemetry.RuleEvidence) logger.RuleContext {
		return logger.RuleContext{
			RuleID:                  evidence.RuleID,
			RiskCategory:            evidence.RiskCategory,
			RuleAction:              evidence.RuleAction,
			EffectiveThreshold:      evidence.EffectiveThreshold,
			EffectiveWindowSeconds:  evidence.EffectiveWindowSeconds,
			SignatureCatalogVersion: evidence.SignatureCatalogVersion,
			SignatureCatalogSHA256:  evidence.SignatureCatalogSHA256,
			RiskModelVersion:        evidence.RiskModelVersion,
			MetricEligible:          evidence.MetricEligible,
			ObservedAt:              evidence.ObservedAt,
			ObservationModel:        evidence.ObservationModel,
			ObservationDisposition:  evidence.ObservationDisposition,
		}
	}
	telemetry.StartWorker(
		ctx,
		&wg,
		fwManager,
		telemetryLogger.LogAllowed,
		func(ip, jail, payload string, evidence telemetry.RuleEvidence) {
			telemetryLogger.LogBanWithRule(ip, jail, payload, toLoggerRuleContext(evidence))
		},
		func(ip, jail, payload string, evidence telemetry.RuleEvidence) {
			telemetryLogger.LogShadowAlertWithRule(ip, jail, payload, toLoggerRuleContext(evidence))
		},
		func(ip, jail, payload string, evidence telemetry.RuleEvidence) {
			telemetryLogger.LogDetectedWithRule(ip, jail, payload, toLoggerRuleContext(evidence))
		},
	)

	// Start SaaS Monitors Downloader
	saasDownloader := network.NewSaasMonitorDownloader(telemetryLogger)
	saasDownloader.Start()

	// Start L7 WAAP Analytics Engine (Log Forwarder)
	waapEngine := network.NewWAAPEngine(fwManager, telemetryLogger, threatEngine)
	waapEngine.StartContext(ctx)

	// Start HA P2P Server (Zero-Touch TLS)
	network.StartHAServer(fwManager)

	// Start the selected local hardening checks. These checks are not a
	// compliance assessment.
	security.StartComplianceWatchdog(ctx, &wg, telemetryLogger)

	// Handle Graceful Shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Println("[SYSWARDEN-Core] Shutting down gracefully...")
	cancel()
	udsServer.Stop()
	wg.Wait()
	waapEngine.Wait()
	telemetryLogger.Close()
}
