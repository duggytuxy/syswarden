//go:build freebsd

package firewall

import (
	"fmt"
	"log"
	"net"
	"os/exec"
)

type Manager interface {
	Ban(ip string) error
	Name() string
}

// PFManager implements FreeBSD Packet Filter dynamic banning
type PFManager struct {
}

func (m *PFManager) Name() string {
	return "pf (Packet Filter)"
}

func (m *PFManager) Ban(ip string) error {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil || parsedIP.To4() == nil {
		return fmt.Errorf("invalid IPv4 address: %s", ip)
	}

	// Add IP to the banned_ips table dynamically
	cmd := exec.Command("pfctl", "-t", "banned_ips", "-T", "add", ip)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to inject IP natively into pf: %s (err: %w)", string(out), err)
	}

	log.Printf("[Firewall-PF] Successfully injected IP: %s into banned_ips table", ip)
	return nil
}

func NewManager() (Manager, error) {
	if _, err := exec.LookPath("pfctl"); err == nil {
		return &PFManager{}, nil
	}

	return nil, fmt.Errorf("no supported firewall backend found on the system (pfctl missing)")
}
