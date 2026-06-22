package network

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"sync"

	"syswarden-core/engine"
	"syswarden-core/firewall"
	"syswarden-core/logger"
	"syswarden-core/webhook"
)

type UDSServer struct {
	socketPath string
	conn       net.PacketConn
	engine     *engine.Engine
	fw         firewall.Manager
	logger     *logger.Logger
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
}

func NewUDSServer(ctx context.Context, socketPath string, e *engine.Engine, fw firewall.Manager, l *logger.Logger) *UDSServer {
	ctx, cancel := context.WithCancel(ctx)
	return &UDSServer{
		socketPath: socketPath,
		engine:     e,
		fw:         fw,
		logger:     l,
		ctx:        ctx,
		cancel:     cancel,
	}
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

	// Ensure the socket is writable by Rsyslog/Vector
 _ = os.Chmod(s.socketPath, 0666)

	log.Printf("[UDS] Listening for unixgram zero-disk streams on %s", s.socketPath)

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
			s.conn.Close()
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

		line := string(buf[:n])
		
		match := s.engine.Scan(line)
		if match != nil {
			// Extract IP from the log line
			ip := engine.ExtractIP(line)
			if ip != "" {
				s.logger.LogBan(ip, match.RuleID, line)
				
				err := s.fw.Ban(ip)
				if err != nil {
					s.logger.Error("Failed to ban IP", err)
				} else {
					// Trigger Discord/Teams Webhook asynchronously
					go webhook.SendBanAlert(ip, match.RuleID, "Kernel Drop (L3)")
				}
			}
		}
	}
}

func (s *UDSServer) Stop() {
	s.cancel()
	if s.conn != nil {
		s.conn.Close()
	}
	s.wg.Wait()
}

