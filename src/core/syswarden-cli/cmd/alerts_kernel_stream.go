package cmd

import (
	"context"
	"regexp"
	"strings"
	"time"

	"github.com/gdamore/tcell/v2"
)

var (
	kernelSourceIPPattern        = regexp.MustCompile(`SRC=([0-9a-fA-F:.]+)`)
	kernelDestinationPortPattern = regexp.MustCompile(`DPT=([0-9]+)`)
	kernelProtocolPattern        = regexp.MustCompile(`PROTO=([A-Za-z0-9]+)`)
	kernelModulePattern          = regexp.MustCompile(`\[(SYSWARDEN-[A-Za-z-]+|CATCH-ALL)\]`)
)

func runKernelSource(ctx context.Context, emit func(alertStreamPhase, string) bool, report func(alertSourceStatus)) {
	runLiveAlertSource(ctx, getKernelLogCommand, emit, report)
}

func parseKernelAlertRow(line string, phase alertStreamPhase, now time.Time) (alertRow, bool) {
	if !strings.Contains(line, "SYSWARDEN-") && !strings.Contains(line, "CATCH-ALL") {
		return alertRow{}, false
	}

	module := "SYSWARDEN-DROP"
	moduleColor := tcell.ColorBlue
	if strings.Contains(line, "[CATCH-ALL]") {
		module = "SYSWARDEN-CATCH"
		moduleColor = tcell.ColorDarkCyan
	} else if match := kernelModulePattern.FindStringSubmatch(line); len(match) > 1 {
		module = match[1]
	}

	source := "N/A"
	if match := kernelSourceIPPattern.FindStringSubmatch(line); len(match) > 1 {
		source = match[1]
	}

	target := "PORT: N/A"
	if match := kernelDestinationPortPattern.FindStringSubmatch(line); len(match) > 1 {
		target = "PORT: " + match[1]
	} else if match := kernelProtocolPattern.FindStringSubmatch(line); len(match) > 1 {
		target = "PROTO: " + match[1]
	}

	return alertRow{
		Phase:       phase,
		Date:        now.Format("2006-01-02 15:04:05"),
		Module:      module,
		TextModule:  module,
		Action:      "BLOCKED",
		Source:      source,
		Target:      target,
		ModuleColor: moduleColor,
		ActionColor: tcell.ColorRed,
	}, true
}
