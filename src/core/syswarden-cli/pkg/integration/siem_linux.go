//go:build linux

package integration

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"syswarden-cli/config"

	"golang.org/x/sys/unix"
)

func renderSIEMRsyslogConfig(ip, port, protocol, tlsCA string) (string, error) {
	target, err := rsyslogTarget(ip, port)
	if err != nil {
		return "", err
	}
	var rendered strings.Builder
	switch protocol {
	case "udp":
		fmt.Fprintf(&rendered, "*.* @%s\n", target)
	case "tcp":
		fmt.Fprintf(&rendered, "*.* @@%s\n", target)
	case "tls":
		if tlsCA == "" {
			return "", fmt.Errorf("TLS rsyslog forwarding requires a CA path")
		}
		quotedCA, err := quoteRsyslogString(tlsCA)
		if err != nil {
			return "", fmt.Errorf("encode rsyslog CA path: %w", err)
		}
		fmt.Fprintf(&rendered, "$DefaultNetstreamDriverCAFile %s\n", quotedCA)
		rendered.WriteString("$ActionSendStreamDriver gtls\n")
		rendered.WriteString("$ActionSendStreamDriverMode 1\n")
		rendered.WriteString("$ActionSendStreamDriverAuthMode anon\n")
		fmt.Fprintf(&rendered, "*.* @@%s\n", target)
	default:
		return "", fmt.Errorf("unsupported rsyslog transport %q", protocol)
	}

	rendered.WriteString("\n# SYSWARDEN WAAP Native JSON Telemetry\n")
	rendered.WriteString("module(load=\"imfile\" PollingInterval=\"10\")\n")
	rendered.WriteString("input(type=\"imfile\"\n")
	rendered.WriteString("      File=\"/var/log/syswarden/waf.json\"\n")
	rendered.WriteString("      Tag=\"syswarden-waf-json\"\n")
	rendered.WriteString("      Severity=\"alert\"\n")
	rendered.WriteString("      Facility=\"local7\")\n")
	return rendered.String(), nil
}

func reconcileSIEMRsyslogConfigAtUsing(
	parentPath string,
	uid, gid uint32,
	desired []byte,
	syncDirectory func(*os.File) error,
) (bool, error) {
	return reconcileRsyslogArtifactAtUsing(
		parentPath,
		rsyslogSIEMConfigName,
		uid,
		gid,
		desired,
		nil,
		syncDirectory,
	)
}

func disableSIEMRsyslogForwarder() error {
	var historicalExpected []byte
	if rendered, err := renderSIEMRsyslogConfig(
		config.GlobalConfig.SiemIP,
		config.GlobalConfig.SiemPort,
		config.GlobalConfig.SiemProto,
		config.GlobalConfig.SiemTLSCA,
	); err == nil {
		historicalExpected = []byte(rendered)
	}
	return disableSIEMRsyslogForwarderAtUsing(
		wafRsyslogParentDirectory,
		0,
		0,
		historicalExpected,
		defaultExactOwnedArtifactRemovalOptions(),
		reconcileWAFRsyslogService,
		requireRsyslogMutationWithoutRemovalBarrier,
	)
}

func disableSIEMRsyslogForwarderAtUsing(
	parentPath string,
	uid, gid uint32,
	historicalExpected []byte,
	options exactOwnedArtifactRemovalOptions,
	activate func(bool) error,
	preflight rsyslogMutationPreflight,
) error {
	if activate == nil || preflight == nil {
		return fmt.Errorf("rsyslog activation or mutation preflight is unavailable")
	}
	options = normalizeExactOwnedArtifactRemovalOptions(options)
	directory, err := openWAFRsyslogDirectoryAt(parentPath, uid, gid)
	if err != nil {
		return err
	}
	defer directory.Close()
	if err := unix.Flock(int(directory.Fd()), unix.LOCK_EX); err != nil {
		return fmt.Errorf("lock complete SIEM disable transaction: %w", err)
	}
	defer func() { _ = unix.Flock(int(directory.Fd()), unix.LOCK_UN) }()
	if err := preflight(); err != nil {
		return fmt.Errorf("refuse stale SIEM disable transaction: %w", err)
	}
	provenance, err := readRsyslogProvenanceRegistryInDirectory(directory, uid, gid)
	if err != nil {
		return fmt.Errorf("verify SIEM rsyslog provenance before disabling: %w", err)
	}
	record, tracked := provenance.records[rsyslogSIEMConfigName]
	var expectation exactOwnedArtifactExpectation
	if tracked {
		expectation = provenanceExpectation(
			"SysWarden SIEM rsyslog forwarder", rsyslogSIEMConfigName, record,
		)
	} else if historicalExpected != nil {
		expectation = exactContentExpectation(
			"historical SysWarden SIEM rsyslog forwarder",
			rsyslogSIEMConfigName,
			historicalExpected,
			0600,
		)
	} else {
		if err := requireOwnedArtifactAbsent(
			directory, rsyslogSIEMConfigName, "untracked SysWarden SIEM rsyslog forwarder",
		); err != nil {
			options.warn("Preserving the SIEM rsyslog forwarder because no exact SysWarden provenance is available.")
			return fmt.Errorf("cannot safely disable untracked SIEM rsyslog forwarder: %w", err)
		}
		return nil
	}
	removalOptions := options
	removalOptions.beforeCommit = func() error {
		if err := activate(true); err != nil {
			return fmt.Errorf("validate and reactivate rsyslog while disabling SIEM: %w", err)
		}
		return nil
	}
	removalOptions.afterRestore = func() error {
		if err := activate(true); err != nil {
			return fmt.Errorf("reactivate rsyslog after SIEM disable rollback: %w", err)
		}
		return nil
	}
	removed, err := removeExpectedRsyslogArtifactInDirectoryUsing(
		directory, uid, gid, expectation, removalOptions,
	)
	if err != nil {
		return err
	}
	if !removed {
		inspection, inspectErr := inspectExactOwnedArtifact(
			directory, rsyslogSIEMConfigName, expectation, uid, gid,
		)
		if inspectErr != nil {
			return errors.Join(fmt.Errorf("reinspect SIEM rsyslog forwarder after disable"), inspectErr)
		}
		if inspection.identity.exists {
			return fmt.Errorf("refusing to discard provenance for a preserved SIEM rsyslog forwarder")
		}
		if err := activate(true); err != nil {
			return fmt.Errorf("validate and reactivate rsyslog for an already absent SIEM forwarder: %w", err)
		}
	}
	if tracked {
		if err := removeRsyslogArtifactProvenanceInDirectoryUsing(
			directory, uid, gid, rsyslogSIEMConfigName, record, options,
		); err != nil {
			return fmt.Errorf("retire SIEM rsyslog provenance after disable: %w", err)
		}
	}
	return nil
}

// SetupSIEM configures Syslog forwarding natively
func SetupSIEM() error {
	fmt.Println("[INFO] Configuring SIEM Logging Integration...")

	if !config.GlobalConfig.SiemEnabled {
		if err := disableSIEMRsyslogForwarder(); err != nil {
			return err
		}
		fmt.Println("[INFO] SIEM integration disabled.")
		return nil
	}

	ip := config.GlobalConfig.SiemIP
	port := config.GlobalConfig.SiemPort
	proto := config.GlobalConfig.SiemProto
	tlsCA := config.GlobalConfig.SiemTLSCA

	if ip == "" || port == "" {
		return fmt.Errorf("SIEM IP or Port is missing in configuration")
	}

	rsyslogConf, err := renderSIEMRsyslogConfig(ip, port, proto, tlsCA)
	if err != nil {
		return fmt.Errorf("render rsyslog SIEM config: %w", err)
	}

	if err := reconcileRsyslogArtifactWithProvenanceAtUsing(
		wafRsyslogParentDirectory,
		0,
		0,
		rsyslogSIEMConfigName,
		"SIEM forwarder",
		[]byte(rsyslogConf),
		reconcileWAFRsyslogService,
		recordRsyslogArtifactProvenance,
		requireRsyslogMutationWithoutRemovalBarrier,
	); err != nil {
		return err
	}

	fmt.Printf("[+] SIEM Forwarder successfully configured (%s:%s/%s)\n", ip, port, proto)
	return nil
}
