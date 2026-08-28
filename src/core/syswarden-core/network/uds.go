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
	"syscall"

	"syswarden-core/engine"
	"syswarden-core/firewall"
	"syswarden-core/logger"
	"syswarden-core/utils"

	"github.com/spf13/viper"
)

type UDSServer struct {
	socketPath              string
	conn                    *net.UnixConn
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

	conn, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: s.socketPath, Net: "unixgram"})
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

	// Match the direct follower's one MiB line plus a possible CRLF transport
	// terminator. ReadMsgUnix exposes MSG_TRUNC so an incomplete record is never
	// scanned or correlated as though it were authoritative.
	buf := make([]byte, maxWAAPLogLineBytes+2)

	for {
		n, _, flags, _, err := s.conn.ReadMsgUnix(buf, nil)
		if err != nil {
			select {
			case <-s.ctx.Done():
				return // Graceful shutdown
			default:
				log.Printf("[UDS] Read error: %v", err)
				return // socket closed
			}
		}
		if !completeUDSDatagram(n, flags) {
			log.Printf("[UDS] Refusing truncated or oversized datagram")
			continue
		}

		s.processLogLine(string(buf[:n]))
	}
}

func completeUDSDatagram(size, flags int) bool {
	return size >= 0 && size <= maxWAAPLogLineBytes+2 && flags&syscall.MSG_TRUNC == 0
}

func (s *UDSServer) processLogLine(line string) {
	if s.isInternalLogLine == nil || s.isInternalLogLine(line) {
		return
	}
	if s.engine == nil {
		return
	}
	match := s.engine.ScanIngress(engine.IngressSourceUDS, line)
	if match == nil || !match.Host.IsValid() {
		return
	}
	ip := match.Host.String()
	if match.Action == "detect" {
		s.logDetected(ip, match, match.Payload)
		return
	}

	shouldBan := true
	if match.Action == "track" {
		shouldBan = s.engine.EvaluateThreshold(ip, match.RuleID, match.Threshold, match.Window)
		if !shouldBan {
			s.logShadow(ip, match, match.Payload)
		}
	}
	if !shouldBan {
		return
	}
	canonical, err := s.canonicalUDSFirewallTarget(ip)
	if err != nil {
		if errors.Is(err, utils.ErrProtectedFirewallTarget) {
			s.logShadow(ip, match, match.Payload)
		} else {
			s.logError("UDS firewall target policy failed closed", err)
			s.logDetected(ip, match, match.Payload)
		}
		return
	}
	if s.enforcementMode == nil {
		s.logError("UDS enforcement mode is unavailable", errors.New("missing enforcement mode provider"))
		s.logDetected(canonical, match, match.Payload)
		return
	}
	switch s.enforcementMode() {
	case "audit":
		s.logSimulatedBan(canonical, match, match.Payload)
		return
	case "enforcing":
		// Continue to the only firewall mutation below.
	default:
		s.logError("UDS enforcement mode is invalid", errors.New("unsupported enforcement mode"))
		s.logDetected(canonical, match, match.Payload)
		return
	}
	if s.fw == nil {
		s.logError("UDS firewall is unavailable", errors.New("missing firewall manager"))
		s.logDetected(canonical, match, match.Payload)
		return
	}
	if err := s.fw.Ban(canonical); err != nil {
		s.logError("Failed to ban IP, logging as DETECTED", err)
		s.logDetected(canonical, match, match.Payload)
		return
	}
	if s.logger != nil {
		s.logger.LogBanWithRule(canonical, match.RuleID, match.Payload, loggerRuleContext(match))
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

func (s *UDSServer) logDetected(ip string, match *engine.Match, line string) {
	if s.logger != nil {
		s.logger.LogDetectedWithRule(ip, match.RuleID, line, loggerRuleContext(match))
	}
}

func (s *UDSServer) logShadow(ip string, match *engine.Match, line string) {
	if s.logger != nil {
		s.logger.LogShadowAlertWithRule(ip, match.RuleID, line, loggerRuleContext(match))
	}
}

func (s *UDSServer) logSimulatedBan(ip string, match *engine.Match, line string) {
	if s.logger != nil {
		s.logger.LogSimulatedBanWithRule(ip, match.RuleID, line, loggerRuleContext(match))
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
