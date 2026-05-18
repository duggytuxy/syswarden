#!/bin/bash
# ==============================================================================
# SysWarden - CIS Benchmark Level 2 Hardening
# Component: Advanced OS & Kernel Hardening (Defense-in-Depth)
# OS Support: Ubuntu, Debian, CentOS, AlmaLinux, Rocky Linux, RHEL
# ==============================================================================

# ==============================================================================
# --- SECURE DEPENDENCY MANAGER FOR CIS TOOLS ---
# ==============================================================================
install_cis_dependencies() {
    log "INFO" "Checking CIS Level 2 specific dependencies..."
    local missing_cis=()

    secure_apt_cis() {
        DEBIAN_FRONTEND=noninteractive apt-get install -y \
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
            apt-get purge -y prelink >/dev/null 2>&1
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
# --- MAIN EXECUTOR ---
# ==============================================================================
apply_cis_level2_hardening() {
    # Check configuration flag from syswarden-auto.conf
    if [[ "${APPLY_CIS_L2_HARDENING:-n}" != "y" ]]; then
        return
    fi

    log "INFO" "Starting CIS Benchmark Level 2 compliance routines..."
    
    install_cis_dependencies
    disable_obscure_filesystems
    disable_uncommon_protocols
    apply_cis_sysctl
    restrict_core_dumps
    
    log "SUCCESS" "CIS Benchmark Level 2 Hardening successfully applied."
}
