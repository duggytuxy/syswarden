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

	err := os.MkdirAll("/var/run", 0755)
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

	servicePath := "/usr/local/etc/rc.d/syswarden"
	err = os.WriteFile(servicePath, []byte(rcScript), 0755)
	if err != nil {
		return fmt.Errorf("failed to write syswarden rc.d script: %w", err)
	}

	// Enable service via sysrc
	if err := exec.Command("sysrc", "syswarden_enable=YES").Run(); err != nil {
		fmt.Printf("[WARN] Failed to enable syswarden in rc.conf: %v\n", err)
	}

	// Start service
	if err := exec.Command("service", "syswarden", "start").Run(); err != nil {
		fmt.Printf("[WARN] Failed to start syswarden service: %v\n", err)
	}

	fmt.Println("[SUCCESS] SYSWARDEN rc.d service configured and enabled.")
	return nil
}
