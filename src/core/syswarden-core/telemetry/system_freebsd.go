//go:build freebsd

package telemetry

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

func allowedEventsCommand(ctx context.Context) *exec.Cmd {
	return exec.CommandContext(
		ctx,
		"tail",
		"-F",
		"/var/log/auth.log",
		"/var/log/nginx/access.log",
		"/var/log/apache2/access.log",
		"/var/log/httpd/access_log",
		"/var/log/secure",
		"/var/log/messages",
	)
}

func kernelDropsCommand(ctx context.Context) *exec.Cmd {
	return exec.CommandContext(ctx, "tail", "-F", "/var/log/messages")
}

func sysctlValue(command *exec.Cmd) string {
	output, err := command.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(output))
}

func collectPlatformSystemStats() platformSystemStats {
	stats := platformSystemStats{
		CpuModel: sysctlValue(exec.Command("sysctl", "-n", "hw.model")),
	}
	load := strings.Trim(sysctlValue(exec.Command("sysctl", "-n", "vm.loadavg")), "{} ")
	loadParts := strings.Fields(load)
	if len(loadParts) >= 3 {
		stats.LoadAverage = fmt.Sprintf("%s %s %s", loadParts[0], loadParts[1], loadParts[2])
	}
	boot := sysctlValue(exec.Command("sysctl", "-n", "kern.boottime"))
	var bootSeconds int64
	if _, err := fmt.Sscanf(boot, "{ sec = %d,", &bootSeconds); err == nil && bootSeconds > 0 {
		stats.Uptime = time.Since(time.Unix(bootSeconds, 0)).Round(time.Second).String()
	}
	totalBytes, totalErr := strconv.ParseUint(
		sysctlValue(exec.Command("sysctl", "-n", "hw.physmem")), 10, 64,
	)
	freePages, freeErr := strconv.ParseUint(
		sysctlValue(exec.Command("sysctl", "-n", "vm.stats.vm.v_free_count")), 10, 64,
	)
	pageBytes, pageErr := strconv.ParseUint(
		sysctlValue(exec.Command("sysctl", "-n", "hw.pagesize")), 10, 64,
	)
	if totalErr == nil && freeErr == nil && pageErr == nil && totalBytes > 0 {
		freeBytes := freePages * pageBytes
		if freeBytes > totalBytes {
			freeBytes = totalBytes
		}
		stats.RamTotalMb = int(totalBytes / 1024 / 1024)
		stats.RamUsedMb = int((totalBytes - freeBytes) / 1024 / 1024)
	}
	return stats
}

func freeBSDServiceResult(name string, command *exec.Cmd) Service {
	status := "inactive"
	if command.Run() == nil {
		status = "active"
	}
	return Service{Name: name, Status: status}
}

func collectPlatformServices() []Service {
	return []Service{
		freeBSDServiceResult("syswarden", exec.Command("service", "syswarden", "onestatus")),
		freeBSDServiceResult("syswardenwebtui", exec.Command("service", "syswardenwebtui", "onestatus")),
		freeBSDServiceResult("sshd", exec.Command("service", "sshd", "onestatus")),
	}
}

func collectPlatformPorts() []Port {
	ports := make([]Port, 0)
	output, err := exec.Command("sockstat", "-46l").Output()
	if err != nil {
		return ports
	}
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 6 || fields[0] == "USER" {
			continue
		}
		protocol := fields[4]
		localAddress := fields[5]
		lastColon := strings.LastIndex(localAddress, ":")
		if lastColon == -1 {
			continue
		}
		state := "UNCONN"
		if strings.HasPrefix(protocol, "tcp") {
			state = "LISTEN"
			protocol = "tcp"
		} else if strings.HasPrefix(protocol, "udp") {
			protocol = "udp"
		}
		ports = append(ports, Port{
			IP:       localAddress[:lastColon],
			State:    state,
			Port:     localAddress[lastColon+1:],
			Protocol: protocol,
		})
	}
	return ports
}
