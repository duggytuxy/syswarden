//go:build linux

package firewall

import (
	"os/exec"
	"strings"
)

func infraIPv4Candidates() ([]string, error) {
	var candidates []string
	for _, command := range []*exec.Cmd{
		exec.Command("sh", "-c", "grep '^nameserver' /etc/resolv.conf | awk '{print $2}'"),
		exec.Command("sh", "-c", "ip -4 route show default 2>/dev/null | grep -Eo 'via [0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+' | awk '{print $2}'"),
		exec.Command("sh", "-c", "ip -4 addr show | grep -oEo 'inet [0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+' | awk '{print $2}' | grep -v '^127\\.'"),
	} {
		output, _ := command.Output()
		candidates = append(candidates, strings.Fields(string(output))...)
	}
	return candidates, nil
}
