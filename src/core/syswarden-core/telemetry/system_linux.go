//go:build linux

package telemetry

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

func allowedEventsCommand(ctx context.Context) *exec.Cmd {
	const script = `
		{
			tail -F /var/log/auth.log /var/log/nginx/access.log /var/log/apache2/access.log /var/log/httpd/access_log /var/log/secure /var/log/messages 2>/dev/null &
			if command -v journalctl &> /dev/null; then
				journalctl -t sshd -f -n 0 2>/dev/null &
			fi
			wait
		}
	`
	return exec.CommandContext(ctx, "bash", "-c", script)
}

func kernelDropsCommand(ctx context.Context) *exec.Cmd {
	const script = `
		if command -v journalctl &> /dev/null; then
			journalctl -k -f -n 0 2>/dev/null
		elif command -v rc-service &> /dev/null; then
			tail -F /var/log/messages /var/log/kern.log 2>/dev/null
		else
			dmesg -w 2>/dev/null
		fi
	`
	return exec.CommandContext(ctx, "bash", "-c", script)
}

func collectPlatformSystemStats() platformSystemStats {
	stats := platformSystemStats{}
	proc, err := os.OpenRoot("/proc")
	if err != nil {
		return stats
	}
	defer func() { _ = proc.Close() }()
	if content, err := proc.ReadFile("uptime"); err == nil {
		parts := strings.Fields(string(content))
		if len(parts) > 0 {
			if seconds, err := strconv.ParseFloat(parts[0], 64); err == nil {
				stats.Uptime = (time.Duration(seconds) * time.Second).Round(time.Second).String()
			}
		}
	}
	if content, err := proc.ReadFile("loadavg"); err == nil {
		parts := strings.Fields(string(content))
		if len(parts) >= 3 {
			stats.LoadAverage = fmt.Sprintf("%s %s %s", parts[0], parts[1], parts[2])
		}
	}
	if content, err := proc.ReadFile("cpuinfo"); err == nil {
		for _, line := range strings.Split(string(content), "\n") {
			if strings.HasPrefix(line, "model name") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					stats.CpuModel = strings.TrimSpace(parts[1])
					break
				}
			}
		}
	}
	if content, err := proc.ReadFile("meminfo"); err == nil {
		var total, available int
		for _, line := range strings.Split(string(content), "\n") {
			if strings.HasPrefix(line, "MemTotal:") {
				_, _ = fmt.Sscanf(line, "MemTotal: %d kB", &total)
			} else if strings.HasPrefix(line, "MemAvailable:") {
				_, _ = fmt.Sscanf(line, "MemAvailable: %d kB", &available)
			}
		}
		if total > 0 {
			stats.RamTotalMb = total / 1024
			stats.RamUsedMb = (total - available) / 1024
		}
	}
	return stats
}

func serviceResult(name string, command *exec.Cmd) Service {
	status := "inactive"
	if command.Run() == nil {
		status = "active"
	}
	return Service{Name: name, Status: status}
}

func collectPlatformServices() []Service {
	if _, err := exec.LookPath("rc-service"); err == nil {
		sshName := "sshd"
		sshCommand := exec.Command("rc-service", "sshd", "status")
		if sshCommand.Run() != nil {
			sshName = "ssh"
		}
		return []Service{
			serviceResult("syswarden-core", exec.Command("rc-service", "syswarden-core", "status")),
			serviceResult("syswarden-firewall", exec.Command("rc-service", "syswarden-firewall", "status")),
			serviceResult(sshName, exec.Command("rc-service", sshName, "status")),
		}
	}
	sshName := "sshd"
	if exec.Command("systemctl", "status", "sshd").Run() != nil {
		sshName = "ssh"
	}
	sshCommand := exec.Command("systemctl", "is-active", "sshd")
	if sshName == "ssh" {
		sshCommand = exec.Command("systemctl", "is-active", "ssh")
	}
	return []Service{
		serviceResult("syswarden-core", exec.Command("systemctl", "is-active", "syswarden-core")),
		serviceResult("syswarden-firewall", exec.Command("systemctl", "is-active", "syswarden-firewall")),
		serviceResult(sshName, sshCommand),
	}
}

func collectPlatformPorts() []Port {
	ports := make([]Port, 0)
	out, err := exec.Command("ss", "-tuln").Output()
	if err != nil {
		return ports
	}
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.Contains(line, "LISTEN") && !strings.Contains(line, "UNCONN") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 5 {
			continue
		}
		localAddress := parts[4]
		lastColon := strings.LastIndex(localAddress, ":")
		if lastColon == -1 {
			continue
		}
		ports = append(ports, Port{
			IP:       localAddress[:lastColon],
			State:    parts[1],
			Port:     localAddress[lastColon+1:],
			Protocol: parts[0],
		})
	}
	return ports
}
