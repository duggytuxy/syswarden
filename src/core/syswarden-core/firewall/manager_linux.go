//go:build linux

package firewall

import (
	"fmt"
	"log"
	"net"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/google/nftables"
)

type Manager interface {
	Ban(ip string) error
	Name() string
}

type FallbackManager struct {
	backend string
	cmdPath string
}

func (m *FallbackManager) Name() string {
	return m.backend
}

func (m *FallbackManager) Ban(ip string) error {
	var cmd *exec.Cmd
	switch m.backend {
	case "ufw":
		cmd = exec.Command(m.cmdPath, "insert", "1", "deny", "from", ip)
	case "firewalld":
		cmd = exec.Command(m.cmdPath, "--add-rich-rule", fmt.Sprintf("rule family=ipv4 source address=%s drop", ip), "--timeout=30d")
	case "iptables":
		cmd = exec.Command(m.cmdPath, "-I", "INPUT", "1", "-s", ip, "-j", "DROP")
	}

	if cmd != nil {
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to run firewall fallback command (%s): %w", m.backend, err)
		}
		return nil
	}
	return fmt.Errorf("unsupported fallback backend")
}

// NftablesManager implements native Netlink API zero-shell blocking
type NftablesManager struct {
	conn       *nftables.Conn
	inetSet    *nftables.Set
	netdevSet  *nftables.Set
	inetSet6   *nftables.Set
	netdevSet6 *nftables.Set
	mu         sync.Mutex
}

func (m *NftablesManager) Name() string {
	return "nftables (Native Netlink)"
}

func (m *NftablesManager) Ban(ip string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return fmt.Errorf("invalid IP address: %s", ip)
	}

	timeout := 30 * 24 * time.Hour

	var errs []string

	if parsedIP.To4() != nil {
		// Inject into inet table (L3/L4)
		if m.inetSet != nil {
			err := m.conn.SetAddElements(m.inetSet, []nftables.SetElement{
				{Key: parsedIP.To4(), Timeout: timeout},
			})
			if err != nil {
				errs = append(errs, fmt.Sprintf("inet: %v", err))
			}
		}

		// Inject into netdev table (L2 Hardware Drop)
		if m.netdevSet != nil {
			err := m.conn.SetAddElements(m.netdevSet, []nftables.SetElement{
				{Key: parsedIP.To4(), Timeout: timeout},
			})
			if err != nil {
				errs = append(errs, fmt.Sprintf("netdev: %v", err))
			}
		}
	} else {
		// Inject IPv6
		if m.inetSet6 != nil {
			err := m.conn.SetAddElements(m.inetSet6, []nftables.SetElement{
				{Key: parsedIP.To16(), Timeout: timeout},
			})
			if err != nil {
				errs = append(errs, fmt.Sprintf("inet6: %v", err))
			}
		}

		if m.netdevSet6 != nil {
			err := m.conn.SetAddElements(m.netdevSet6, []nftables.SetElement{
				{Key: parsedIP.To16(), Timeout: timeout},
			})
			if err != nil {
				errs = append(errs, fmt.Sprintf("netdev6: %v", err))
			}
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("failed to inject IP natively: %s", strings.Join(errs, ", "))
	}

	if err := m.conn.Flush(); err != nil {
		return fmt.Errorf("failed to flush netlink buffer: %w", err)
	}

	log.Printf("[Firewall-Netlink] Successfully injected IP: %s with 30d timeout", ip)
	return nil
}

func detectBackend() (string, string) {
	if path, err := exec.LookPath("nft"); err == nil {
		return "nftables", path
	}
	if path, err := exec.LookPath("ufw"); err == nil {
		return "ufw", path
	}
	if path, err := exec.LookPath("firewalld"); err == nil {
		return "firewalld", path
	}
	if path, err := exec.LookPath("iptables"); err == nil {
		return "iptables", path
	}
	return "none", ""
}

func NewManager() (Manager, error) {
	backend, path := detectBackend()
	if backend == "nftables" {
		conn := &nftables.Conn{}

		// Attempt to resolve the tables and sets immediately for O(1) injections later
		var inetSet, netdevSet, inetSet6, netdevSet6 *nftables.Set

		tables, err := conn.ListTables()
		if err == nil {
			for _, t := range tables {
				if t.Name == "syswarden" && t.Family == nftables.TableFamilyINet {
					// Retrieve inet set
					sets, err := conn.GetSets(t)
					if err == nil {
						for _, s := range sets {
							if s.Name == "banned_ips" {
								inetSet = s
							} else if s.Name == "banned_ips6" {
								inetSet6 = s
							}
						}
					}
				} else if t.Name == "syswarden_hw_drop" && t.Family == nftables.TableFamilyNetdev {
					// Retrieve netdev set
					sets, err := conn.GetSets(t)
					if err == nil {
						for _, s := range sets {
							if s.Name == "banned_ips" {
								netdevSet = s
							} else if s.Name == "banned_ips6" {
								netdevSet6 = s
							}
						}
					}
				}
			}
		}

		return &NftablesManager{
			conn:       conn,
			inetSet:    inetSet,
			netdevSet:  netdevSet,
			inetSet6:   inetSet6,
			netdevSet6: netdevSet6,
		}, nil
	}

	if backend != "none" {
		return &FallbackManager{backend: backend, cmdPath: path}, nil
	}

	return nil, fmt.Errorf("no supported firewall backend found on the system")
}
