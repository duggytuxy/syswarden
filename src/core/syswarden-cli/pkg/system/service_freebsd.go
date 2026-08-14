//go:build freebsd

package system

import (
	"fmt"
	"os"
	"os/exec"
)

// SetupService generates and enables the syswarden-core rc.d service natively for FreeBSD
func SetupService() error {
	fmt.Println("[INFO] Configuring rc.d Services for FreeBSD...")

	err := os.MkdirAll("/var/run", 0750)
	if err != nil {
		fmt.Printf("[WARN] Failed to create /var/run directory: %v\n", err)
	}
	err = os.MkdirAll("/var/log/syswarden", 0750)
	if err != nil {
		fmt.Printf("[WARN] Failed to create /var/log/syswarden directory: %v\n", err)
	}

	rcScript := `#!/bin/sh
#
# PROVIDE: syswarden
# REQUIRE: NETWORKING
# KEYWORD: shutdown

. /etc/rc.subr

name="syswarden"
rcvar="syswarden_enable"

command="/opt/syswarden/syswarden-core"
pidfile="/var/run/${name}.pid"

# Run in background
command_args="&"

# Load configuration
load_rc_config $name
: ${syswarden_enable:="NO"}

# Hook to capture PID
start_cmd="syswarden_start"
stop_cmd="syswarden_stop"

syswarden_start() {
    echo "Starting SYSWARDEN..."
    /usr/sbin/daemon -p ${pidfile} ${command}
}

syswarden_stop() {
    if [ -f ${pidfile} ]; then
        echo "Stopping SYSWARDEN..."
        kill $(cat ${pidfile})
        rm -f ${pidfile}
    else
        echo "SYSWARDEN is not running."
    fi
}

run_rc_command "$1"
`

	if err := writeExecutableAtomically("/usr/local/etc/rc.d", "syswarden", []byte(rcScript)); err != nil {
		return fmt.Errorf("failed to write syswarden rc.d script: %w", err)
	}

	// Enable service via sysrc
	if err := exec.Command("sysrc", "syswarden_enable=YES").Run(); err != nil { // #nosec
		fmt.Printf("[WARN] Failed to enable syswarden in rc.conf: %v\n", err)
	}

	// Start service
	if err := exec.Command("service", "syswarden", "start").Run(); err != nil { // #nosec
		fmt.Printf("[WARN] Failed to start syswarden service: %v\n", err)
	}

	webtuiRcScript := `#!/bin/sh
#
# PROVIDE: syswardenwebtui
# REQUIRE: NETWORKING syswarden
# KEYWORD: shutdown

. /etc/rc.subr

name="syswardenwebtui"
rcvar="syswardenwebtui_enable"

command="/opt/syswarden/bin/syswarden-cli"
command_args="web-tui &"
pidfile="/var/run/${name}.pid"

load_rc_config $name
: ${syswardenwebtui_enable:="NO"}

start_cmd="webtui_start"
stop_cmd="webtui_stop"

webtui_start() {
    echo "Starting SYSWARDEN Web-TUI..."
    /usr/sbin/daemon -p ${pidfile} ${command} web-tui
}

webtui_stop() {
    if [ -f ${pidfile} ]; then
        echo "Stopping SYSWARDEN Web-TUI..."
        kill $(cat ${pidfile})
        rm -f ${pidfile}
    else
        echo "SYSWARDEN Web-TUI is not running."
    fi
}

run_rc_command "$1"
`

	if err := writeExecutableAtomically("/usr/local/etc/rc.d", "syswardenwebtui", []byte(webtuiRcScript)); err != nil {
		return fmt.Errorf("failed to write syswardenwebtui rc.d script: %w", err)
	}

	if err := exec.Command("sysrc", "syswardenwebtui_enable=YES").Run(); err != nil { // #nosec
		fmt.Printf("[WARN] Failed to enable syswardenwebtui in rc.conf: %v\n", err)
	}
	if err := exec.Command("service", "syswardenwebtui", "start").Run(); err != nil { // #nosec
		fmt.Printf("[WARN] Failed to start syswardenwebtui service: %v\n", err)
	}

	fmt.Println("[SUCCESS] SYSWARDEN rc.d service configured and enabled.")
	return nil
}
