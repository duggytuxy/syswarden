install_cis_dependencies() {
    log "INFO" "Checking CIS Level 2 specific dependencies..."
    local missing_cis=()

    secure_apt_cis() {
        DEBIAN_FRONTEND=noninteractive apt-get install -y \
            -o DPkg::Lock::Timeout=300 \
            -o Acquire::AllowInsecureRepositories=false \
            -o Acquire::AllowDowngradeToInsecureRepositories=false \
            -o APT::Get::AllowUnauthenticated=false "$@"
    }

    secure_dnf_cis() {
        dnf install -y \
            --setopt=gpgcheck=1 \
            --setopt=localpkg_gpgcheck=1 "$@"
    }

    if [[ -f /etc/debian_version ]]; then
        if ! dpkg -l | grep -q "libpam-pwquality"; then missing_cis+=("libpam-pwquality"); fi
        if ! command -v prelink >/dev/null 2>&1 && dpkg -l | grep -q "^ii.*prelink"; then
            # CIS 1.5.4: Ensure prelink is disabled and uninstalled (interferes with ASLR)
            log "INFO" "Removing prelink to enforce ASLR (CIS 1.5.4)..."
            prelink -ua 2>/dev/null || true
            DEBIAN_FRONTEND=noninteractive apt-get purge -y -o DPkg::Lock::Timeout=300 prelink >/dev/null 2>&1
        fi
        if [[ ${#missing_cis[@]} -gt 0 ]]; then
            secure_apt_cis "${missing_cis[@]}"
        fi
    elif [[ -f /etc/redhat-release ]]; then
        if ! rpm -q libpwquality >/dev/null 2>&1; then missing_cis+=("libpwquality"); fi
        if rpm -q prelink >/dev/null 2>&1; then
            log "INFO" "Removing prelink to enforce ASLR (CIS 1.5.4)..."
            prelink -ua 2>/dev/null || true
            dnf remove -y prelink >/dev/null 2>&1
        fi
        if [[ ${#missing_cis[@]} -gt 0 ]]; then
            secure_dnf_cis "${missing_cis[@]}"
        fi
    fi
}

# ==============================================================================
# --- CIS 1.1.1: DISABLE OBSCURE FILESYSTEMS ---
# Prevents local attack vectors via malicious image mounting.
# ==============================================================================
disable_obscure_filesystems() {
    log "INFO" "Disabling obscure filesystems (CIS 1.1.1.1 - 1.1.1.8)..."
    local FS_CONF="/etc/modprobe.d/syswarden-cis-fs.conf"

    cat <<'EOF' >"$FS_CONF"
# --- SysWarden: CIS Level 2 Filesystem Hardening ---
install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install squashfs /bin/true
install udf /bin/true
EOF
    chmod 644 "$FS_CONF"

    # Unload modules if currently loaded
    for fs in cramfs freevxfs jffs2 hfs hfsplus squashfs udf; do
        if lsmod | grep -q "^$fs"; then
            rmmod "$fs" 2>/dev/null || log "WARN" "Could not unload active module: $fs"
        fi
    done
}

# ==============================================================================
# --- CIS 3.3: DISABLE UNCOMMON NETWORK PROTOCOLS ---
# Reduces the attack surface of the network stack.
# ==============================================================================
disable_uncommon_protocols() {
    log "INFO" "Disabling uncommon network protocols (CIS 3.3.1 - 3.3.4)..."
    local NET_CONF="/etc/modprobe.d/syswarden-cis-net.conf"

    cat <<'EOF' >"$NET_CONF"
# --- SysWarden: CIS Level 2 Network Protocol Hardening ---
install dccp /bin/true
install sctp /bin/true
install rds /bin/true
install tipc /bin/true
EOF
    chmod 644 "$NET_CONF"

    for proto in dccp sctp rds tipc; do
        if lsmod | grep -q "^$proto"; then
            rmmod "$proto" 2>/dev/null || log "WARN" "Could not unload active module: $proto"
        fi
    done
}

# ==============================================================================
# --- CIS 1.5 & 3.2: KERNEL PARAMETERS (SYSCTL) LEVEL 2 ---
# Advanced defense against memory corruption, routing bypass, and BPF abuse.
# ==============================================================================
apply_cis_sysctl() {
    log "INFO" "Applying strict kernel parameters (CIS 1.5, 3.2)..."
    local SYSCTL_CONF="/etc/sysctl.d/99-syswarden-cis-level2.conf"

    cat <<'EOF' >"$SYSCTL_CONF"
# --- SysWarden: CIS Level 2 Kernel Hardening ---

# CIS 1.5.1: Restrict Core Dumps (Prevents memory exposure containing credentials)
fs.suid_dumpable = 0

# CIS 1.5.3: Enable Randomized Virtual Memory Region Placement (ASLR)
kernel.randomize_va_space = 2

# Defense-in-Depth: Restrict eBPF to root only (Mitigates local privilege escalation)
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2

# Defense-in-Depth: Restrict dmesg access (Prevents kernel memory layout leaks)
kernel.dmesg_restrict = 1

# Defense-in-Depth: Restrict access to kernel pointers
kernel.kptr_restrict = 2

# Defense-in-Depth: Restrict ptrace scope (Prevents credential theft from RAM)
kernel.yama.ptrace_scope = 1

# CIS 3.2.1: Ensure source routed packets are not accepted
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0

# CIS 3.2.2: Ensure ICMP redirects are not accepted
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0

# CIS 3.2.3: Ensure secure ICMP redirects are not accepted
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0

# CIS 3.2.4: Ensure suspicious packets are logged (Martians)
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# CIS 3.2.7: Ensure Reverse Path Filtering is strict
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# CIS 3.2.8: Ensure TCP SYN Cookies is enabled
net.ipv4.tcp_syncookies = 1
EOF
    chmod 644 "$SYSCTL_CONF"
    sysctl -p "$SYSCTL_CONF" >/dev/null 2>&1 || log "WARN" "Some sysctl parameters could not be applied depending on the environment."
}

# ==============================================================================
# --- CIS 1.5.1: RESTRICT CORE DUMPS (LIMITS) ---
# Ensures that users cannot generate core dumps via limits.conf.
# ==============================================================================
restrict_core_dumps() {
    log "INFO" "Enforcing hard limits on core dumps (CIS 1.5.1)..."
    local LIMITS_CONF="/etc/security/limits.d/99-syswarden-cis.conf"
    mkdir -p /etc/security/limits.d/

    cat <<'EOF' >"$LIMITS_CONF"
# --- SysWarden: CIS Level 2 Limits ---
* hard core 0
EOF
    chmod 644 "$LIMITS_CONF"

    # Systemd override for core dumps
    if [[ -f "/etc/systemd/coredump.conf" ]]; then
        sed -i 's/.*Storage=.*/Storage=none/' /etc/systemd/coredump.conf 2>/dev/null || true
        sed -i 's/.*ProcessSizeMax=.*/ProcessSizeMax=0/' /etc/systemd/coredump.conf 2>/dev/null || true
        systemctl daemon-reload 2>/dev/null || true
    fi
}

# ==============================================================================
# --- CIS 5.2: ADVANCED SSH HARDENING ---
# Restricts SSH features to limit attack surface without breaking modern access.
# Synergy with define_ssh_port.sh (which handles TCP Forwarding).
# ==============================================================================
apply_cis_ssh_hardening() {
    log "INFO" "Applying CIS Level 2 SSH Hardening (CIS 5.2)..."
    local SSHD_CONF="/etc/ssh/sshd_config"

    if [[ -f "$SSHD_CONF" ]]; then
        # CIS 5.2.6: Disable X11 Forwarding
        sed -i 's/^[[:space:]]*X11Forwarding.*/X11Forwarding no/' "$SSHD_CONF"
        if ! grep -q "^X11Forwarding" "$SSHD_CONF"; then echo "X11Forwarding no" >>"$SSHD_CONF"; fi

        # CIS 5.2.7: Set MaxAuthTries to 4 or less
        sed -i 's/^[[:space:]]*MaxAuthTries.*/MaxAuthTries 4/' "$SSHD_CONF"
        if ! grep -q "^MaxAuthTries" "$SSHD_CONF"; then echo "MaxAuthTries 4" >>"$SSHD_CONF"; fi

        # CIS 5.2.16 & 5.2.17: Set ClientAlive parameters (Timeout idle sessions)
        sed -i 's/^[[:space:]]*ClientAliveInterval.*/ClientAliveInterval 300/' "$SSHD_CONF"
        if ! grep -q "^ClientAliveInterval" "$SSHD_CONF"; then echo "ClientAliveInterval 300" >>"$SSHD_CONF"; fi

        sed -i 's/^[[:space:]]*ClientAliveCountMax.*/ClientAliveCountMax 3/' "$SSHD_CONF"
        if ! grep -q "^ClientAliveCountMax" "$SSHD_CONF"; then echo "ClientAliveCountMax 3" >>"$SSHD_CONF"; fi

        if command -v systemctl >/dev/null 2>&1; then
            systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || true
        fi
    fi
}

# ==============================================================================
# --- CIS 5.1: SECURE CRON PERMISSIONS ---
# Enforces strict ownership and permissions on cron directories.
# Synergy with apply_os_hardening.sh (which manages cron.allow).
# ==============================================================================
secure_cron_permissions() {
    log "INFO" "Securing cron directories permissions (CIS 5.1)..."
    local cron_dirs=("/etc/cron.d" "/etc/cron.daily" "/etc/cron.hourly" "/etc/cron.weekly" "/etc/cron.monthly")

    for dir in "${cron_dirs[@]}"; do
        if [[ -d "$dir" ]]; then
            chown root:root "$dir"
            chmod 700 "$dir"
        fi
    done

    if [[ -f "/etc/crontab" ]]; then
        chown root:root "/etc/crontab"
        chmod 600 "/etc/crontab"
    fi
}

# ==============================================================================
# --- AUTOMATIC SECURITY UPDATES (Patch Management) ---
# Ensures the system automatically installs security patches (Zero-Day defense).
# Supported: Debian, Ubuntu, Alma, Rocky, Fedora, Oracle Linux, RHEL 9+
# ==============================================================================
enable_automatic_security_updates() {
    log "INFO" "Configuring automatic security updates..."

    if [[ -f /etc/debian_version ]]; then
        # Debian / Ubuntu implementation
        if ! dpkg -l | grep -q "^ii[[:space:]]*unattended-upgrades"; then
            DEBIAN_FRONTEND=noninteractive apt-get install -y -o DPkg::Lock::Timeout=300 unattended-upgrades apt-listchanges >/dev/null 2>&1
        fi

        # Enforce daily update checks and unattended upgrades
        cat <<'EOF' >/etc/apt/apt.conf.d/20auto-upgrades
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF
        if command -v systemctl >/dev/null 2>&1; then
            systemctl enable unattended-upgrades >/dev/null 2>&1 || true
            systemctl start unattended-upgrades >/dev/null 2>&1 || true
        fi

    elif [[ -f /etc/redhat-release ]]; then
        # RHEL / Alma / Rocky / Oracle / Fedora implementation
        if ! rpm -q dnf-automatic >/dev/null 2>&1; then
            dnf install -y dnf-automatic >/dev/null 2>&1
        fi

        local DNF_AUTO_CONF="/etc/dnf/automatic.conf"
        if [[ -f "$DNF_AUTO_CONF" ]]; then
            # Restrict to security updates ONLY to prevent breaking production features
            sed -i 's/^[[:space:]]*upgrade_type[[:space:]]*=.*/upgrade_type = security/' "$DNF_AUTO_CONF"
            sed -i 's/^[[:space:]]*download_updates[[:space:]]*=.*/download_updates = yes/' "$DNF_AUTO_CONF"
            sed -i 's/^[[:space:]]*apply_updates[[:space:]]*=.*/apply_updates = yes/' "$DNF_AUTO_CONF"
        fi

        if command -v systemctl >/dev/null 2>&1; then
            # dnf-automatic relies on a systemd timer rather than a standard background daemon
            systemctl enable dnf-automatic.timer >/dev/null 2>&1 || true
            systemctl start dnf-automatic.timer >/dev/null 2>&1 || true
        fi
    else
        log "WARN" "Automatic security updates skipped: Unsupported OS family."
    fi
}

# ==============================================================================
# --- MAIN EXECUTOR ---
# ==============================================================================
apply_cis_level2_hardening() {
    # DevSecOps Fix: Load the absolute state from configuration file to prevent environment bleed
    local state_cis="n"
    if grep -q "^APPLY_CIS_L2_HARDENING='y'" "$CONF_FILE" 2>/dev/null || grep -q "^APPLY_CIS_L2_HARDENING=\"y\"" "$CONF_FILE" 2>/dev/null; then
        state_cis="y"
    elif [[ "${APPLY_CIS_L2_HARDENING:-n}" == "y" ]]; then
        state_cis="y"
    fi

    if [[ "$state_cis" != "y" ]]; then
        return
    fi

    log "INFO" "Starting CIS Benchmark Level 2 compliance routines..."

    install_cis_dependencies
    disable_obscure_filesystems
    disable_uncommon_protocols
    apply_cis_sysctl
    restrict_core_dumps
    apply_cis_ssh_hardening
    secure_cron_permissions
    enable_automatic_security_updates

    log "SUCCESS" "CIS Benchmark Level 2 Hardening successfully applied."
}
