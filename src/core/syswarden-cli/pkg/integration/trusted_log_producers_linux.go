//go:build linux

package integration

import (
	"fmt"
	"os"
	"strings"
	"syswarden-cli/config"

	"golang.org/x/sys/unix"
)

// With explicit producer trust all bridge file inputs move to the secure core
// follower. Leaving default imfile globs enabled would bypass its rotation checks.
// Keep the historical renderer unchanged for exact legacy artifact retirement.
func renderWAFRsyslogWithProducers(raw string, siem bool, policy string) (string, int, error) {
	producers, err := config.ParseTrustedLogProducers(policy)
	if err != nil {
		return "", 0, err
	}
	if len(producers) == 0 {
		return renderWAFRsyslogConfig(raw, siem)
	}
	return renderDirectProducerBridge(raw, siem, producers, config.DirectBridgeLogPatterns(producers))
}

func renderDirectProducerBridge(raw string, siem bool, producers map[string]uint32, bridgePatterns []string) (string, int, error) {
	verify := func(path string) error {
		access := config.TrustedLogAccess{AuthorityUID: int64(os.Geteuid())}
		if uid, ok := producers[path]; ok {
			access.ProducerUID = &uid
		}
		return verifyTrustedProducerLog(path, access)
	}
	active, err := validatedLogPatternsUsing(raw, verify)
	if err != nil {
		return "", 0, err
	}
	// The core enrolls every exact grant, even outside an existing discovery glob.
	for path := range producers {
		if err := verify(path); err != nil {
			return "", 0, err
		}
	}
	if _, err := validatedLogPatternsUsing(strings.Join(bridgePatterns, " "), verify); err != nil {
		return "", 0, err
	}
	var rendered strings.Builder
	rendered.WriteString("# Explicit producer policy: file collection is owned by the secure core follower.\n")
	rendered.WriteString("module(load=\"imfile\")\nmodule(load=\"omuxsock\")\n$OMUxSockSocket /var/run/syswarden.sock\n")
	if siem {
		rendered.WriteString(rsyslogSIEMTelemetryInput)
	}
	rendered.WriteString(rsyslogWAFRuleset)
	return rendered.String(), len(active), nil
}

func verifyTrustedProducerLog(path string, access config.TrustedLogAccess) error {
	parent, name, err := access.OpenParent(path)
	if err != nil {
		return fmt.Errorf("verify producer log ancestry %q: %w", path, err)
	}
	defer unix.Close(parent)
	fd, _, err := access.OpenFile(parent, name)
	if err != nil {
		return fmt.Errorf("verify producer log %q: %w", path, err)
	}
	if err := unix.Close(fd); err != nil {
		return err
	}
	return nil
}
