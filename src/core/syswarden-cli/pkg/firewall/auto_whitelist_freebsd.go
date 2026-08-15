//go:build freebsd

package firewall

import (
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"strings"
)

var freeBSDNetworkInterfaces = net.Interfaces

func parseFreeBSDDefaultGateway(output string) (string, error) {
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "gateway:" {
			address, err := netip.ParseAddr(fields[1])
			if err != nil || !address.Is4() || address.IsLoopback() {
				return "", fmt.Errorf("FreeBSD default gateway is not a canonical non-loopback IPv4 address")
			}
			return address.String(), nil
		}
	}
	return "", fmt.Errorf("FreeBSD route output lacks one exact default IPv4 gateway")
}

func infraIPv4Candidates() ([]string, error) {
	dnsOutput, err := exec.Command(
		"sh",
		"-c",
		"grep '^nameserver' /etc/resolv.conf | awk '{print $2}'",
	).Output()
	if err != nil {
		return nil, fmt.Errorf("discover FreeBSD DNS resolvers: %w", err)
	}
	routeOutput, err := exec.Command("route", "-n", "get", "default").Output()
	if err != nil {
		return nil, fmt.Errorf("discover FreeBSD default route: %w", err)
	}
	gateway, err := parseFreeBSDDefaultGateway(string(routeOutput))
	if err != nil {
		return nil, err
	}
	candidates := append(strings.Fields(string(dnsOutput)), gateway)
	interfaces, err := freeBSDNetworkInterfaces()
	if err != nil {
		return nil, fmt.Errorf("enumerate FreeBSD network interfaces: %w", err)
	}
	for _, networkInterface := range interfaces {
		addresses, err := networkInterface.Addrs()
		if err != nil {
			return nil, fmt.Errorf("enumerate addresses for %s: %w", networkInterface.Name, err)
		}
		for _, candidate := range addresses {
			prefix, err := netip.ParsePrefix(candidate.String())
			if err != nil || !prefix.Addr().Is4() || prefix.Addr().IsLoopback() {
				continue
			}
			candidates = append(candidates, prefix.Addr().String())
		}
	}
	return candidates, nil
}
