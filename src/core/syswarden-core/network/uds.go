package network

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"

	"syswarden-core/engine"
	"syswarden-core/firewall"
	"syswarden-core/logger"
	"syswarden-core/utils"

	"github.com/spf13/viper"
)

type UDSServer struct {
	socketPath              string
	conn                    net.PacketConn
	engine                  *engine.Engine
	fw                      firewall.Manager
	logger                  *logger.Logger
	ctx                     context.Context
	cancel                  context.CancelFunc
	localInterfaceAddresses func() ([]netip.Addr, error)
	protectedHAPeers        func() ([]netip.Prefix, error)
	isWhitelisted           func(string) (bool, error)
	enforcementMode         func() string
	isInternalLogLine       func(string) bool
	wg                      sync.WaitGroup
}

func NewUDSServer(ctx context.Context, socketPath string, e *engine.Engine, fw firewall.Manager, l *logger.Logger) *UDSServer {
	ctx, cancel := context.WithCancel(ctx)
	return &UDSServer{
		socketPath:              socketPath,
		engine:                  e,
		fw:                      fw,
		logger:                  l,
		ctx:                     ctx,
		cancel:                  cancel,
		localInterfaceAddresses: utils.LocalInterfaceAddresses,
		protectedHAPeers:        configuredHAPeerPrefixes,
		isWhitelisted:           utils.IsWhitelistedStrict,
		enforcementMode:         configuredUDSEnforcementMode,
		isInternalLogLine:       logger.IsInternalLogLine,
	}
}

func configuredUDSEnforcementMode() string {
	mode := strings.ToLower(strings.TrimSpace(viper.GetString("waap.enforcement_mode")))
	if mode == "" {
		return "enforcing"
	}
	return mode
}

func (s *UDSServer) Start() error {
	// Remove existing socket if it exists
	if _, err := os.Stat(s.socketPath); err == nil {
		_ = os.Remove(s.socketPath)
	}

	conn, err := net.ListenPacket("unixgram", s.socketPath)
	if err != nil {
		return fmt.Errorf("failed to listen on uds socket: %w", err)
	}
	s.conn = conn

	// Ensure the socket is writable by authorized groups (0660)
	_ = os.Chmod(s.socketPath, 0660) // #nosec

	log.Printf("[UDS] Listening for unixgram zero-disk streams on %s (0660)", s.socketPath)

	s.wg.Add(1)
	go s.readLoop()
	return nil
}

func (s *UDSServer) readLoop() {
	defer s.wg.Done()

	// Implement graceful connection termination on shutdown
	go func() {
		<-s.ctx.Done()
		if s.conn != nil {
			_ = s.conn.Close()
		}
	}()

	// Buffer for massive HTTP payloads
	buf := make([]byte, 64*1024)

	for {
		n, _, err := s.conn.ReadFrom(buf)
		if err != nil {
			select {
			case <-s.ctx.Done():
				return // Graceful shutdown
			default:
				log.Printf("[UDS] Read error: %v", err)
				return // socket closed
			}
		}

		s.processLogLine(string(buf[:n]))
	}
}

func (s *UDSServer) processLogLine(line string) {
	if s.isInternalLogLine == nil || s.isInternalLogLine(line) {
		return
	}
	if s.engine == nil {
		return
	}
	match := s.engine.Scan(line)
	if match == nil || !match.Host.IsValid() {
		return
	}
	ip := match.Host.String()
	if match.Action == "detect" {
		s.logDetected(ip, match.RuleID, line)
		return
	}

	shouldBan := true
	if match.Action == "track" {
		shouldBan = s.engine.EvaluateThreshold(ip, match.RuleID, match.Threshold, match.Window)
		if !shouldBan {
			s.logShadow(ip, match.RuleID, line)
		}
	}
	if !shouldBan {
		return
	}
	canonical, err := s.canonicalUDSFirewallTarget(ip)
	if err != nil {
		if errors.Is(err, utils.ErrProtectedFirewallTarget) {
			s.logShadow(ip, match.RuleID, line)
		} else {
			s.logError("UDS firewall target policy failed closed", err)
			s.logDetected(ip, match.RuleID, line)
		}
		return
	}
	if s.enforcementMode == nil {
		s.logError("UDS enforcement mode is unavailable", errors.New("missing enforcement mode provider"))
		s.logDetected(canonical, match.RuleID, line)
		return
	}
	switch s.enforcementMode() {
	case "audit":
		s.logSimulatedBan(canonical, match.RuleID, line)
		return
	case "enforcing":
		// Continue to the only firewall mutation below.
	default:
		s.logError("UDS enforcement mode is invalid", errors.New("unsupported enforcement mode"))
		s.logDetected(canonical, match.RuleID, line)
		return
	}
	if s.fw == nil {
		s.logError("UDS firewall is unavailable", errors.New("missing firewall manager"))
		s.logDetected(canonical, match.RuleID, line)
		return
	}
	if err := s.fw.Ban(canonical); err != nil {
		s.logError("Failed to ban IP, logging as DETECTED", err)
		s.logDetected(canonical, match.RuleID, line)
		return
	}
	if s.logger != nil {
		s.logger.LogBan(canonical, match.RuleID, line)
	}
}

func (s *UDSServer) canonicalUDSFirewallTarget(value string) (string, error) {
	if s.localInterfaceAddresses == nil || s.protectedHAPeers == nil || s.isWhitelisted == nil {
		return "", fmt.Errorf("UDS firewall target policy is unavailable")
	}
	localAddresses, err := s.localInterfaceAddresses()
	if err != nil {
		return "", fmt.Errorf("load local interface addresses: %w", err)
	}
	peers, err := s.protectedHAPeers()
	if err != nil {
		return "", err
	}
	return utils.CanonicalFirewallMutationTarget(value, utils.FirewallTargetPolicy{
		LocalAddresses:    localAddresses,
		ProtectedPrefixes: peers,
		IsWhitelisted:     s.isWhitelisted,
	})
}

func (s *UDSServer) logDetected(ip, ruleID, line string) {
	if s.logger != nil {
		s.logger.LogDetected(ip, ruleID, line)
	}
}

func (s *UDSServer) logShadow(ip, ruleID, line string) {
	if s.logger != nil {
		s.logger.LogShadowAlert(ip, ruleID, line)
	}
}

func (s *UDSServer) logSimulatedBan(ip, ruleID, line string) {
	if s.logger != nil {
		s.logger.LogSimulatedBan(ip, ruleID, line)
	}
}

func (s *UDSServer) logError(message string, err error) {
	if s.logger != nil {
		s.logger.Error(message, err)
	}
}

func (s *UDSServer) Stop() {
	s.cancel()
	if s.conn != nil {
		_ = s.conn.Close()
	}
	s.wg.Wait()
}
