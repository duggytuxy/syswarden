discover_active_services() {
    log "INFO" "Scanning User-Space for actively listening TCP services..."
    local detected_ports=""

    # We use 'ss' (modern iproute2) to find all active listening TCP ports
    # Bypassing IPv6 (for now) and local-only (127.0.0.1) binds
    if command -v ss >/dev/null; then
        # Awk parses the 4th column (Local Address:Port) and extracts just the port number
        detected_ports=$(ss -tlnH 2>/dev/null | grep -v '127.0.0.1' | grep -v '::1' | awk '{print $4}' | awk -F':' '{print $NF}' | sort -nu)
    elif command -v netstat >/dev/null; then
        # Fallback for older systems using netstat
        detected_ports=$(netstat -tln 2>/dev/null | grep '^tcp' | grep -v '127.0.0.1' | grep -v '::1' | awk '{print $4}' | awk -F':' '{print $NF}' | sort -nu)
    fi

    # --- HOTFIX: TELNET HONEYPOT FAIL-SAFE ---
    # telnetd is often managed by inetd/systemd.socket and might not show up as a standard listening daemon.
    # If the binary exists, we forcefully open port 23 so the Fail2ban honeypot can trap payloads.
    if command -v telnetd >/dev/null 2>&1 || command -v in.telnetd >/dev/null 2>&1; then
        detected_ports=$(printf "%s\n23" "$detected_ports" | grep -v '^$' | sort -nu)
        log "INFO" "Telnet Honeypot binary detected. Force-whitelisting port 23."
    fi
    # ------------------------------------------------

    # Format the ports into a comma-separated list for easy firewall injection
    if [[ -n "$detected_ports" ]]; then
        ACTIVE_PORTS=$(echo "$detected_ports" | grep -v '^$' | tr '\n' ',' | sed 's/,$//')
        log "INFO" "Whitelisted active services (TCP): [$ACTIVE_PORTS]"
    else
        log "WARN" "No active external services found. Server will be locked down."
        ACTIVE_PORTS="none"
    fi
}
