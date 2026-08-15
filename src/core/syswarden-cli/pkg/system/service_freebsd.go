//go:build freebsd

package system

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// SetupService generates and enables the syswarden-core rc.d service natively for FreeBSD
func SetupService() error {
	fmt.Println("[INFO] Configuring rc.d Services for FreeBSD...")

	err := os.MkdirAll("/var/run", 0750)
	if err != nil {
		return fmt.Errorf("create /var/run: %w", err)
	}
	err = os.MkdirAll("/var/log/syswarden", 0750)
	if err != nil {
		return fmt.Errorf("create /var/log/syswarden: %w", err)
	}

	rcScript := `#!/bin/sh
#
# PROVIDE: syswarden
# REQUIRE: NETWORKING
# KEYWORD: shutdown

. /etc/rc.subr

name="syswarden"
rcvar="syswarden_enable"

command="/usr/local/syswarden/bin/syswarden-core"
procname="${command}"
pidfile="/var/run/${name}.pid"
required_files="${command}"

# Load configuration
load_rc_config $name
: ${syswarden_enable:="NO"}

# Hook to capture PID
start_cmd="syswarden_start"

syswarden_start() {
    running_pid="$(check_pidfile "${pidfile}" "${procname}")"
    if [ -n "${running_pid}" ]; then
        echo "SYSWARDEN is already running as ${running_pid}."
        return 0
    fi
    if [ -f "${pidfile}" ]; then
        rm -f "${pidfile}"
    fi
    echo "Starting SYSWARDEN..."
    /usr/sbin/daemon -f -p "${pidfile}" "${command}"
}

run_rc_command "$1"
`

	if err := writeExecutableAtomically("/usr/local/etc/rc.d", "syswarden", []byte(rcScript)); err != nil {
		return fmt.Errorf("failed to write syswarden rc.d script: %w", err)
	}

	// Enable service via sysrc
	if output, err := exec.Command("sysrc", "syswarden_enable=YES").CombinedOutput(); err != nil {
		return fmt.Errorf("enable syswarden in rc.conf: %s: %w", string(output), err)
	}
	if output, err := exec.Command("sysrc", "-n", "syswarden_enable").CombinedOutput(); err != nil {
		return fmt.Errorf("verify syswarden enablement: %s: %w", string(output), err)
	} else if strings.TrimSpace(string(output)) != "YES" {
		return fmt.Errorf("verify syswarden enablement: unexpected value %q", strings.TrimSpace(string(output)))
	}
	if exec.Command("service", "syswarden", "onestatus").Run() != nil {
		if output, err := exec.Command("service", "syswarden", "start").CombinedOutput(); err != nil {
			return fmt.Errorf("start syswarden service: %s: %w", string(output), err)
		}
	}
	if output, err := exec.Command("service", "syswarden", "onestatus").CombinedOutput(); err != nil {
		return fmt.Errorf("verify syswarden service: %s: %w", string(output), err)
	}

	webtuiRcScript := `#!/bin/sh
#
# PROVIDE: syswardenwebtui
# REQUIRE: NETWORKING syswarden
# KEYWORD: shutdown

. /etc/rc.subr

name="syswardenwebtui"
rcvar="syswardenwebtui_enable"

command="/usr/local/syswarden/bin/syswarden-cli"
procname="${command}"
pidfile="/var/run/${name}.pid"
required_files="${command}"

load_rc_config $name
: ${syswardenwebtui_enable:="NO"}

start_cmd="webtui_start"

webtui_start() {
    running_pid="$(check_pidfile "${pidfile}" "${procname}")"
    if [ -n "${running_pid}" ]; then
        echo "SYSWARDEN Web-TUI is already running as ${running_pid}."
        return 0
    fi
    if [ -f "${pidfile}" ]; then
        rm -f "${pidfile}"
    fi
    echo "Starting SYSWARDEN Web-TUI..."
    /usr/sbin/daemon -f -p "${pidfile}" "${command}" web-tui
}

run_rc_command "$1"
`

	if err := writeExecutableAtomically("/usr/local/etc/rc.d", "syswardenwebtui", []byte(webtuiRcScript)); err != nil {
		return fmt.Errorf("failed to write syswardenwebtui rc.d script: %w", err)
	}

	if output, err := exec.Command("sysrc", "syswardenwebtui_enable=YES").CombinedOutput(); err != nil {
		return fmt.Errorf("enable syswardenwebtui in rc.conf: %s: %w", string(output), err)
	}
	if output, err := exec.Command("sysrc", "-n", "syswardenwebtui_enable").CombinedOutput(); err != nil {
		return fmt.Errorf("verify syswardenwebtui enablement: %s: %w", string(output), err)
	} else if strings.TrimSpace(string(output)) != "YES" {
		return fmt.Errorf("verify syswardenwebtui enablement: unexpected value %q", strings.TrimSpace(string(output)))
	}
	if exec.Command("service", "syswardenwebtui", "onestatus").Run() != nil {
		if output, err := exec.Command("service", "syswardenwebtui", "start").CombinedOutput(); err != nil {
			return fmt.Errorf("start syswardenwebtui service: %s: %w", string(output), err)
		}
	}
	if output, err := exec.Command("service", "syswardenwebtui", "onestatus").CombinedOutput(); err != nil {
		return fmt.Errorf("verify syswardenwebtui service: %s: %w", string(output), err)
	}

	fmt.Println("[SUCCESS] SYSWARDEN rc.d service configured and enabled.")
	return nil
}
