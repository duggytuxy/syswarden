apply_firewall_rules() {
    echo -e "\n${BLUE}=== Step 4: Applying Firewall Rules ($FIREWALL_BACKEND) ===${NC}"

    # --- LOCAL PERSISTENCE INJECTION ---
    mkdir -p "$SYSWARDEN_DIR"
    touch "$WHITELIST_FILE" "$BLOCKLIST_FILE"

    # 1. Inject local blocklist into the global list
    cat "$BLOCKLIST_FILE" >>"$FINAL_LIST"

    # 2. Clean duplicates to ensure firewall stability
    sort -u "$FINAL_LIST" -o "$FINAL_LIST"

    # 3. Exclude local whitelisted IPs from the final blocklist
    if [[ -s "$WHITELIST_FILE" ]]; then
        grep -vFf "$WHITELIST_FILE" "$FINAL_LIST" >"$TMP_DIR/clean_final.txt" || true
        mv "$TMP_DIR/clean_final.txt" "$FINAL_LIST"
    fi

    # --- FIX: TELEMETRY PERSISTENCE ---
    # Save the massive compiled list to disk so the telemetry engine can count it instantly
    # without running heavy queries against the kernel every minute.
    cp "$FINAL_LIST" "$SYSWARDEN_DIR/active_global_blocklist.txt"
    # -----------------------------------

    if [[ "$FIREWALL_BACKEND" == "nftables" ]]; then
        log "INFO" "Configuring Nftables via Atomic Transaction (Zero-Downtime)..."

        # --- L2 HARDWARE ACCELERATION (eBPF/XDP Alternative) ---
        # Dynamically detect the physical network interface facing the internet
        local ACTIVE_IF
        ACTIVE_IF=$(ip route get 8.8.8.8 2>/dev/null | awk '{print $5}' | head -n 1)
        [[ -z "$ACTIVE_IF" ]] && ACTIVE_IF="eth0"

        # 1. Start building the atomic configuration file
        cat <<EOF >"$TMP_DIR/syswarden.nft"
# Flush tables atomically
table inet syswarden_table
delete table inet syswarden_table
table netdev syswarden_hw_drop
delete table netdev syswarden_hw_drop

# ==============================================================
# TIER 1: HARDWARE LEVEL DROP (Layer 2 Ingress)
# Destroys packets at the NIC driver level before CPU allocates 
# memory for Conntrack. Zero-DDoS impact.
# ==============================================================
table netdev syswarden_hw_drop {
    set $SET_NAME { type ipv4_addr; flags interval; auto-merge; }
EOF

        if [[ "${GEOBLOCK_COUNTRIES:-none}" != "none" ]] && [[ -s "$GEOIP_FILE" ]]; then
            echo "    set $GEOIP_SET_NAME { type ipv4_addr; flags interval; auto-merge; }" >>"$TMP_DIR/syswarden.nft"
        fi
        if [[ "${BLOCK_ASNS:-none}" != "none" ]] && [[ -s "$ASN_FILE" ]]; then
            echo "    set $ASN_SET_NAME { type ipv4_addr; flags interval; auto-merge; }" >>"$TMP_DIR/syswarden.nft"
        fi

        cat <<EOF >>"$TMP_DIR/syswarden.nft"
    chain ingress_frontline {
        type filter hook ingress device "$ACTIVE_IF" priority -500; policy accept;
        
        # Absolute whitelist bypass at NIC level
EOF

        if [[ -s "$WHITELIST_FILE" ]]; then
            while IFS= read -r wl_ip; do
                [[ -z "$wl_ip" ]] && continue
                # Prevent syntax crash by determining IP family dynamically
                if [[ "$wl_ip" =~ : ]]; then
                    echo "        ip6 saddr $wl_ip accept" >>"$TMP_DIR/syswarden.nft"
                else
                    echo "        ip saddr $wl_ip accept" >>"$TMP_DIR/syswarden.nft"
                fi
            done <"$WHITELIST_FILE"
        fi

        cat <<EOF >>"$TMP_DIR/syswarden.nft"
        # Hardware Drops with SIEM Logging (Rate-Limited to prevent CPU/IO exhaustion)
        ip saddr @$SET_NAME limit rate 2/second log prefix "[SysWarden-BLOCK] "
        ip saddr @$SET_NAME drop
EOF
        if [[ "${GEOBLOCK_COUNTRIES:-none}" != "none" ]] && [[ -s "$GEOIP_FILE" ]]; then
            echo "        ip saddr @$GEOIP_SET_NAME limit rate 2/second log prefix \"[SysWarden-GEO] \"" >>"$TMP_DIR/syswarden.nft"
            echo "        ip saddr @$GEOIP_SET_NAME drop" >>"$TMP_DIR/syswarden.nft"
        fi
        if [[ "${BLOCK_ASNS:-none}" != "none" ]] && [[ -s "$ASN_FILE" ]]; then
            echo "        ip saddr @$ASN_SET_NAME limit rate 2/second log prefix \"[SysWarden-ASN] \"" >>"$TMP_DIR/syswarden.nft"
            echo "        ip saddr @$ASN_SET_NAME drop" >>"$TMP_DIR/syswarden.nft"
        fi

        cat <<EOF >>"$TMP_DIR/syswarden.nft"
    }
}

# ==============================================================
# TIER 2: OS KERNEL FILTERING (Layer 3/4)
# Manages complex stateful routing (WireGuard, Catch-All)
# ==============================================================
table inet syswarden_table {
    # 3. FRONTLINE CHAIN (Executes BEFORE Fail2ban at priority -10)
    chain input_frontline {
        type filter hook input priority filter - 10; policy accept;
        ct state established,related accept
EOF

        if [[ -s "$WHITELIST_FILE" ]]; then
            while IFS= read -r wl_ip; do
                [[ -z "$wl_ip" ]] && continue
                # Prevent syntax crash by determining IP family dynamically
                if [[ "$wl_ip" =~ : ]]; then
                    echo "        ip6 saddr $wl_ip accept" >>"$TMP_DIR/syswarden.nft"
                else
                    echo "        ip saddr $wl_ip accept" >>"$TMP_DIR/syswarden.nft"
                fi
            done <"$WHITELIST_FILE"
        fi

        if [[ "${USE_WIREGUARD:-n}" == "y" ]]; then
            echo "        udp dport ${WG_PORT:-51820} accept" >>"$TMP_DIR/syswarden.nft"
            echo "        iifname { \"wg0\", \"lo\" } accept comment \"SysWarden: Global Trust for VPN\"" >>"$TMP_DIR/syswarden.nft"
            echo "        tcp dport ${SSH_PORT:-22} log prefix \"[SysWarden-SSH-DROP] \" drop" >>"$TMP_DIR/syswarden.nft"
        fi

        cat <<EOF >>"$TMP_DIR/syswarden.nft"
    }

    # 4. BACKEND CHAIN (Executes AFTER Fail2ban at priority 10)
    # Serves as the Zero-Trust Catch-All, allowing legitimate traffic first.
    chain input_backend {
        type filter hook input priority filter + 10; policy drop;
        ct state established,related accept
        iifname "lo" accept
        ip protocol icmp accept
        meta l4proto ipv6-icmp accept
EOF

        # --- ZERO TRUST: DYNAMIC ALLOW & CATCH-ALL DROP ---
        if [[ -n "$ACTIVE_PORTS" ]] && [[ "$ACTIVE_PORTS" != "none" ]]; then
            echo "        tcp dport { ${SSH_PORT:-22}, 9999, $ACTIVE_PORTS } accept" >>"$TMP_DIR/syswarden.nft"
        else
            echo "        tcp dport { ${SSH_PORT:-22}, 9999 } accept" >>"$TMP_DIR/syswarden.nft"
        fi

        # --- HOTFIX: WG BACKEND SURVIVAL ---
        # WG traffic explicitly allowed in Frontline must ALSO be allowed in the Zero-Trust Backend
        if [[ "${USE_WIREGUARD:-n}" == "y" ]]; then
            echo "        udp dport ${WG_PORT:-51820} accept" >>"$TMP_DIR/syswarden.nft"
            echo "        iifname { \"wg0\", \"lo\" } accept" >>"$TMP_DIR/syswarden.nft"
        fi
        # ------------------------------------------

        cat <<EOF >>"$TMP_DIR/syswarden.nft"
        # The Catch-All Drop: Any packet surviving Frontline and Fail2ban hits this.
        limit rate 2/second log prefix "[SysWarden-BLOCK] [Catch-All] "
        drop
    }
}
EOF

        # 4. APPEND ELEMENTS IN CHUNKS (Anti-OOM Killer)
        log "INFO" "Populating Nftables sets atomically in chunks (Bypassing memory limits)..."

        # --- HOTFIX: AWK BATCH INJECTION (Anti-ARG_MAX & Anti-OOM) ---

        if [[ -s "$FINAL_LIST" ]]; then
            awk -v set_name="$SET_NAME" '
            BEGIN { c=0 }
            {
                if ($1 == "") next;
                if (c == 0) printf "add element netdev syswarden_hw_drop %s { %s", set_name, $1
                else printf ", %s", $1
                c++
                if (c >= 500) { printf " }\n"; c=0 } # Chunk reduced to 500 to prevent Netlink 64KB payload limits in LXC
            }
            END { if (c > 0) printf " }\n" }' "$FINAL_LIST" >>"$TMP_DIR/syswarden.nft"
        fi

        if [[ "${GEOBLOCK_COUNTRIES:-none}" != "none" ]] && [[ -s "$GEOIP_FILE" ]]; then
            awk -v set_name="$GEOIP_SET_NAME" '
            BEGIN { c=0 }
            {
                if ($1 == "") next;
                if (c == 0) printf "add element netdev syswarden_hw_drop %s { %s", set_name, $1
                else printf ", %s", $1
                c++
                if (c >= 500) { printf " }\n"; c=0 } # Chunk reduced to 500 to prevent Netlink 64KB payload limits in LXC
            }
            END { if (c > 0) printf " }\n" }' "$GEOIP_FILE" >>"$TMP_DIR/syswarden.nft"
        fi

        if [[ "${BLOCK_ASNS:-none}" != "none" ]] && [[ -s "$ASN_FILE" ]]; then
            awk -v set_name="$ASN_SET_NAME" '
            BEGIN { c=0 }
            {
                if ($1 == "") next;
                if (c == 0) printf "add element netdev syswarden_hw_drop %s { %s", set_name, $1
                else printf ", %s", $1
                c++
                if (c >= 500) { printf " }\n"; c=0 } # Chunk reduced to 500 to prevent Netlink 64KB payload limits in LXC
            }
            END { if (c > 0) printf " }\n" }' "$ASN_FILE" >>"$TMP_DIR/syswarden.nft"
        fi
        # --------------------------------------------------------------------

        log "INFO" "Applying Atomic Nftables Transaction to the Kernel..."
        nft -f "$TMP_DIR/syswarden.nft"
        # --------------------------------------------

        # --- FIX: KERNEL FORWARDING & OS-LEVEL BYPASS FOR WIREGUARD ---
        if [[ "${USE_WIREGUARD:-n}" == "y" ]]; then
            log "INFO" "Applying WireGuard routing bypass to native OS tables..."
            if nft list table inet filter >/dev/null 2>&1; then
                # 1. Open UDP port and allow wg0 interface in OS default input chain
                if nft list chain inet filter input >/dev/null 2>&1; then
                    # HOTFIX: grep >/dev/null prevents SIGPIPE pipefail crashes that cause ghost duplicates
                    if ! nft list chain inet filter input 2>/dev/null | grep -E "udp[[:space:]]+dport[[:space:]]+${WG_PORT:-51820}[[:space:]]+accept" >/dev/null; then
                        nft insert rule inet filter input udp dport "${WG_PORT:-51820}" accept 2>/dev/null || true
                    fi
                    if ! nft list chain inet filter input 2>/dev/null | grep -E "iifname[[:space:]]+[\"']?wg0[\"']?[[:space:]]+accept" >/dev/null; then
                        nft insert rule inet filter input iifname "wg0" accept 2>/dev/null || true
                    fi
                fi
                # 2. Allow IP Forwarding for the VPN tunnel (Idempotent)
                if nft list chain inet filter forward >/dev/null 2>&1; then
                    if ! nft list chain inet filter forward 2>/dev/null | grep -E "iifname[[:space:]]+[\"']?wg0[\"']?[[:space:]]+accept" >/dev/null; then
                        nft insert rule inet filter forward iifname "wg0" accept 2>/dev/null || true
                    fi
                    if ! nft list chain inet filter forward 2>/dev/null | grep -E "oifname[[:space:]]+[\"']?wg0[\"']?[[:space:]]+accept" >/dev/null; then
                        nft insert rule inet filter forward oifname "wg0" accept 2>/dev/null || true
                    fi
                fi

                # --- HOTFIX: SAFE OS PERSISTENCE (NO RAM DUMP) ---
                # We prevent dumping the active 'inet filter' table to avoid duplicating
                # the sysadmin's custom rules or breaking their native file structure.
                # The include directive handled later in this script is sufficient.
                # ----------------------------------------------------------
            fi
        fi
        # --------------------------------------------------------------

        # --- MODULAR PERSISTENCE (ZERO-TOUCH) ---
        log "INFO" "Saving SysWarden Nftables tables to isolated config..."
        mkdir -p /etc/syswarden
        # FIX: Export BOTH tables (Tier 1 Hardware Drop + Tier 2 Stateful)
        nft list table inet syswarden_table >/etc/syswarden/syswarden.nft
        nft list table netdev syswarden_hw_drop >>/etc/syswarden/syswarden.nft 2>/dev/null || true

        local MAIN_NFT_CONF="/etc/nftables.conf"
        if [[ -f "$MAIN_NFT_CONF" ]]; then
            # Inject include directive securely if not already present
            if ! grep -q 'include "/etc/syswarden/syswarden.nft"' "$MAIN_NFT_CONF"; then
                log "INFO" "Injecting include directive into $MAIN_NFT_CONF..."
                echo -e '\n# Added by SysWarden' >>"$MAIN_NFT_CONF"
                echo 'include "/etc/syswarden/syswarden.nft"' >>"$MAIN_NFT_CONF"
            fi
        else
            # Create a basic standard configuration if the file doesn't exist at all
            log "WARN" "$MAIN_NFT_CONF not found. Creating basic layout."
            echo '#!/usr/sbin/nft -f' >"$MAIN_NFT_CONF"
            echo 'flush ruleset' >>"$MAIN_NFT_CONF"
            echo 'include "/etc/syswarden/syswarden.nft"' >>"$MAIN_NFT_CONF"
            chmod 755 "$MAIN_NFT_CONF"
        fi

        if command -v systemctl >/dev/null; then
            systemctl enable --now nftables 2>/dev/null || true
        fi

    elif [[ "$FIREWALL_BACKEND" == "firewalld" ]]; then
        # Ensure firewalld is active and running
        if ! systemctl is-active --quiet firewalld; then systemctl enable --now firewalld; fi

        # --- WIREGUARD SSH CLOAKING & NATIVE NAT (FIXED FOR ALMA 10) ---
        if [[ "${USE_WIREGUARD:-n}" == "y" ]]; then
            log "INFO" "WireGuard: Configuring Native Firewalld Routing and Strict SSH Cloaking..."

            # 1. Native NAT for VPN Internet Access (Alma/RHEL/Fedora)
            firewall-cmd --permanent --add-masquerade >/dev/null 2>&1 || true
            firewall-cmd --permanent --zone=trusted --add-interface=wg0 >/dev/null 2>&1 || true

            # 2. Universal SSH Port Purge (Cleans lingering SSH rules from ALL zones)
            for zone in $(firewall-cmd --get-zones 2>/dev/null || echo "public"); do
                # --- FIX ALMA/RHEL: AGGRESSIVE PHANTOM SERVICE PURGE ---
                firewall-cmd --zone="$zone" --remove-service="ssh" >/dev/null 2>&1 || true
                firewall-cmd --permanent --zone="$zone" --remove-service="ssh" >/dev/null 2>&1 || true

                firewall-cmd --zone="$zone" --remove-port="${SSH_PORT:-22}/tcp" >/dev/null 2>&1 || true
                firewall-cmd --permanent --zone="$zone" --remove-port="${SSH_PORT:-22}/tcp" >/dev/null 2>&1 || true

                # Cleanup old priority rules to prevent conflicts
                firewall-cmd --permanent --zone="$zone" --remove-rich-rule="rule priority='-50' family='ipv4' source address='${WG_SUBNET}' port port='${SSH_PORT:-22}' protocol='tcp' accept" >/dev/null 2>&1 || true
                firewall-cmd --permanent --zone="$zone" --remove-rich-rule="rule priority='-50' family='ipv4' source address='${WG_SUBNET}' port port='9999' protocol='tcp' accept" >/dev/null 2>&1 || true
                firewall-cmd --permanent --zone="$zone" --remove-rich-rule="rule priority='-10' port port='${SSH_PORT:-22}' protocol='tcp' drop" >/dev/null 2>&1 || true
                firewall-cmd --permanent --zone="$zone" --remove-rich-rule="rule priority='-10' family='ipv4' port port='${SSH_PORT:-22}' protocol='tcp' drop" >/dev/null 2>&1 || true
            done

            # 3. Allow WireGuard UDP port for tunnel establishment
            firewall-cmd --permanent --add-port="${WG_PORT:-51820}/udp" >/dev/null 2>&1 || true

            # --- STRICT ZERO TRUST HIERARCHY (DEBIAN PARITY) ---

            # Priority -1000: Highest priority. Allow SSH & Dashboard strictly from VPN.
            firewall-cmd --permanent --add-rich-rule="rule priority='-1000' family='ipv4' source address='${WG_SUBNET}' port port='${SSH_PORT:-22}' protocol='tcp' accept" >/dev/null 2>&1 || true
            firewall-cmd --permanent --add-rich-rule="rule priority='-1000' family='ipv4' source address='${WG_SUBNET}' port port='9999' protocol='tcp' accept" >/dev/null 2>&1 || true

            # Priority -900: BULLETPROOF DROP. Executes BEFORE the Admin Whitelist (-100).
            # This mimics Debian: SSH is strictly dropped globally before any IP whitelists are evaluated.
            firewall-cmd --permanent --add-rich-rule="rule priority='-900' port port='${SSH_PORT:-22}' protocol='tcp' drop" >/dev/null 2>&1 || true
            # -----------------------------------

            # 4. VERIFICATION (Purple Team Check)
            if ! firewall-cmd --permanent --zone=trusted --list-interfaces | grep -q "wg0"; then
                log "WARN" "WARNING: wg0 interface not found in permanent trusted zone."
            fi

            # Note: We intentionally DO NOT reload here. We wait for the whitelist injection
            # at the end of the Firewalld section to guarantee an atomic, safe reload that keeps the admin session alive.
        fi
        # ------------------------------

        log "INFO" "Preparing Firewalld IPSets (Bypassing DBus limitations)..."

        # 1. Clean old rules quietly
        firewall-cmd --permanent --remove-rich-rule="rule source ipset='$SET_NAME' log prefix='[SysWarden-BLOCK] ' level='info' drop" >/dev/null 2>&1 || true
        firewall-cmd --permanent --remove-rich-rule="rule source ipset='$GEOIP_SET_NAME' log prefix='[SysWarden-GEO] ' level='info' drop" >/dev/null 2>&1 || true
        firewall-cmd --permanent --remove-rich-rule="rule source ipset='$ASN_SET_NAME' log prefix='[SysWarden-ASN] ' level='info' drop" >/dev/null 2>&1 || true

        firewall-cmd --permanent --delete-ipset="$SET_NAME" >/dev/null 2>&1 || true
        firewall-cmd --permanent --delete-ipset="$GEOIP_SET_NAME" >/dev/null 2>&1 || true
        firewall-cmd --permanent --delete-ipset="$ASN_SET_NAME" >/dev/null 2>&1 || true

        # 2. Create ALL empty XMLs first
        mkdir -p /etc/firewalld/ipsets
        cat <<EOF >"/etc/firewalld/ipsets/${SET_NAME}.xml"
<?xml version="1.0" encoding="utf-8"?>
<ipset type="hash:net">
  <option name="family" value="inet"/>
  <option name="maxelem" value="1000000"/>
</ipset>
EOF

        if [[ "${GEOBLOCK_COUNTRIES:-none}" != "none" ]] && [[ -s "$GEOIP_FILE" ]]; then
            cat <<EOF >"/etc/firewalld/ipsets/${GEOIP_SET_NAME}.xml"
<?xml version="1.0" encoding="utf-8"?>
<ipset type="hash:net">
  <option name="family" value="inet"/>
  <option name="maxelem" value="1000000"/>
</ipset>
EOF
        fi

        if [[ "${BLOCK_ASNS:-none}" != "none" ]] && [[ -s "$ASN_FILE" ]]; then
            cat <<EOF >"/etc/firewalld/ipsets/${ASN_SET_NAME}.xml"
<?xml version="1.0" encoding="utf-8"?>
<ipset type="hash:net">
  <option name="family" value="inet"/>
  <option name="maxelem" value="1000000"/>
</ipset>
EOF
        fi

        # 3. Fast reload to register empty sets
        firewall-cmd --reload >/dev/null 2>&1 || true

        # --- FIX: STRICT WHITELIST SYNCHRONIZATION (ANTI-GHOST RULES) ---
        log "INFO" "Synchronizing Whitelist with Firewalld memory..."

        # 1. Hunt and destroy ALL existing priority rules in permanent memory
        while IFS= read -r rule; do
            if [[ "$rule" == *"priority=\"-100\""* ]] || [[ "$rule" == *"priority=\"-32000\""* ]]; then
                firewall-cmd --permanent --remove-rich-rule="$rule" >/dev/null 2>&1 || true
            fi
        done < <(firewall-cmd --permanent --list-rich-rules 2>/dev/null || true)

        # 2. Re-inject ONLY the IPs that are currently in the text file
        if [[ -s "$WHITELIST_FILE" ]]; then
            while IFS= read -r wl_ip; do
                [[ -z "$wl_ip" ]] && continue
                # Clean up any old unprioritized legacy rule if it exists
                firewall-cmd --permanent --remove-rich-rule="rule family='ipv4' source address='$wl_ip' accept" >/dev/null 2>&1 || true

                # Inject the new prioritized rule (-32000 guarantees absolute top execution)
                firewall-cmd --permanent --add-rich-rule="rule priority='-32000' family='ipv4' source address='$wl_ip' accept" >/dev/null 2>&1 || true
            done <"$WHITELIST_FILE"
        fi
        # ----------------------------------------------------------------

        # 4. Add all Rich Rules
        firewall-cmd --permanent --add-rich-rule="rule source ipset='$SET_NAME' log prefix='[SysWarden-BLOCK] ' level='info' drop" >/dev/null 2>&1 || true

        if [[ "${GEOBLOCK_COUNTRIES:-none}" != "none" ]] && [[ -s "$GEOIP_FILE" ]]; then
            firewall-cmd --permanent --add-rich-rule="rule source ipset='$GEOIP_SET_NAME' log prefix='[SysWarden-GEO] ' level='info' drop" >/dev/null 2>&1 || true
        fi

        if [[ "${BLOCK_ASNS:-none}" != "none" ]] && [[ -s "$ASN_FILE" ]]; then
            firewall-cmd --permanent --add-rich-rule="rule source ipset='$ASN_SET_NAME' log prefix='[SysWarden-ASN] ' level='info' drop" >/dev/null 2>&1 || true
        fi

        # --- ZERO TRUST: DYNAMIC ALLOW & CATCH-ALL DROP ---
        # Firewalld uses Zones. We dynamically force the target of the active default zone to DROP.
        # This acts as our Catch-All (Priority Guillotine).
        local ACTIVE_ZONE
        ACTIVE_ZONE=$(firewall-cmd --get-default-zone 2>/dev/null || echo "public")

        firewall-cmd --permanent --zone="$ACTIVE_ZONE" --set-target=DROP >/dev/null 2>&1 || true

        # Explicitly allow discovered services to override the DROP target
        firewall-cmd --permanent --zone="$ACTIVE_ZONE" --add-port="${SSH_PORT:-22}/tcp" >/dev/null 2>&1 || true

        if [[ -n "$ACTIVE_PORTS" ]] && [[ "$ACTIVE_PORTS" != "none" ]]; then
            for port in $(echo "$ACTIVE_PORTS" | tr ',' ' '); do
                # HOTFIX: Use dynamic ACTIVE_ZONE instead of hardcoded public
                firewall-cmd --permanent --zone="$ACTIVE_ZONE" --add-port="${port}/tcp" >/dev/null 2>&1 || true
            done
        fi

        # Ensure Firewalld DenyLogs are active so Fail2ban can catch the drops
        firewall-cmd --set-log-denied=all >/dev/null 2>&1 || true

        # 5. Populate XMLs directly with data
        log "INFO" "Injecting massive IP lists into kernel..."
        sed -i '/<\/ipset>/d' "/etc/firewalld/ipsets/${SET_NAME}.xml"
        sed 's/.*/  <entry>&<\/entry>/' "$FINAL_LIST" >>"/etc/firewalld/ipsets/${SET_NAME}.xml"
        echo "</ipset>" >>"/etc/firewalld/ipsets/${SET_NAME}.xml"

        if [[ "${GEOBLOCK_COUNTRIES:-none}" != "none" ]] && [[ -s "$GEOIP_FILE" ]]; then
            sed -i '/<\/ipset>/d' "/etc/firewalld/ipsets/${GEOIP_SET_NAME}.xml"
            sed 's/.*/  <entry>&<\/entry>/' "$GEOIP_FILE" >>"/etc/firewalld/ipsets/${GEOIP_SET_NAME}.xml"
            echo "</ipset>" >>"/etc/firewalld/ipsets/${GEOIP_SET_NAME}.xml"
        fi

        if [[ "${BLOCK_ASNS:-none}" != "none" ]] && [[ -s "$ASN_FILE" ]]; then
            sed -i '/<\/ipset>/d' "/etc/firewalld/ipsets/${ASN_SET_NAME}.xml"
            sed 's/.*/  <entry>&<\/entry>/' "$ASN_FILE" >>"/etc/firewalld/ipsets/${ASN_SET_NAME}.xml"
            echo "</ipset>" >>"/etc/firewalld/ipsets/${ASN_SET_NAME}.xml"
        fi

        log "INFO" "Loading rules into kernel (This may take up to 30s)..."
        firewall-cmd --reload >/dev/null 2>&1 || true
        log "INFO" "Firewalld rules applied."

    elif [[ "$FIREWALL_BACKEND" == "ufw" ]]; then
        log "INFO" "Configuring UFW with IPSet..."

        # 1. Create IPSet (UFW uses iptables underneath)
        ipset create "$SET_NAME" hash:net maxelem 1000000 -exist
        sed "s/^/add $SET_NAME /" "$FINAL_LIST" | ipset restore -!

        # 2. Inject Rule into /etc/ufw/before.rules
        UFW_RULES="/etc/ufw/before.rules"

        # Remove old rules if present to avoid duplicates
        sed -i "/$SET_NAME/d" "$UFW_RULES"

        # Insert new rules after "# End required lines" marker
        if grep -q "# End required lines" "$UFW_RULES"; then
            sed -i "/# End required lines/a -A ufw-before-input -m set --match-set $SET_NAME src -j DROP" "$UFW_RULES"
            sed -i "/# End required lines/a -A ufw-before-input -m set --match-set $SET_NAME src -j LOG --log-prefix \"[SysWarden-BLOCK] \"" "$UFW_RULES"
        else
            log "WARN" "Standard UFW marker not found. Appending to end of file."
            echo "-A ufw-before-input -m set --match-set $SET_NAME src -j LOG --log-prefix \"[SysWarden-BLOCK] \"" >>"$UFW_RULES"
            echo "-A ufw-before-input -m set --match-set $SET_NAME src -j DROP" >>"$UFW_RULES"
        fi

        # --- GEOIP INJECTION ---
        if [[ "${GEOBLOCK_COUNTRIES:-none}" != "none" ]] && [[ -s "$GEOIP_FILE" ]]; then
            log "INFO" "Configuring UFW GeoIP Set..."
            ipset create "$GEOIP_SET_NAME" hash:net maxelem 1000000 -exist
            sed "s/^/add $GEOIP_SET_NAME /" "$GEOIP_FILE" | ipset restore -!

            sed -i "/$GEOIP_SET_NAME/d" "$UFW_RULES"
            if grep -q "# End required lines" "$UFW_RULES"; then
                sed -i "/# End required lines/a -A ufw-before-input -m set --match-set $GEOIP_SET_NAME src -j DROP" "$UFW_RULES"
                sed -i "/# End required lines/a -A ufw-before-input -m set --match-set $GEOIP_SET_NAME src -j LOG --log-prefix \"[SysWarden-GEO] \"" "$UFW_RULES"
            else
                echo "-A ufw-before-input -m set --match-set $GEOIP_SET_NAME src -j LOG --log-prefix \"[SysWarden-GEO] \"" >>"$UFW_RULES"
                echo "-A ufw-before-input -m set --match-set $GEOIP_SET_NAME src -j DROP" >>"$UFW_RULES"
            fi
        fi

        # --- ASN INJECTION ---
        if [[ "${BLOCK_ASNS:-none}" != "none" ]] && [[ -s "$ASN_FILE" ]]; then
            log "INFO" "Configuring UFW ASN Set..."
            ipset create "$ASN_SET_NAME" hash:net maxelem 1000000 -exist
            sed "s/^/add $ASN_SET_NAME /" "$ASN_FILE" | ipset restore -!

            sed -i "/$ASN_SET_NAME/d" "$UFW_RULES"
            if grep -q "# End required lines" "$UFW_RULES"; then
                sed -i "/# End required lines/a -A ufw-before-input -m set --match-set $ASN_SET_NAME src -j DROP" "$UFW_RULES"
                sed -i "/# End required lines/a -A ufw-before-input -m set --match-set $ASN_SET_NAME src -j LOG --log-prefix \"[SysWarden-ASN] \"" "$UFW_RULES"
            else
                echo "-A ufw-before-input -m set --match-set $ASN_SET_NAME src -j LOG --log-prefix \"[SysWarden-ASN] \"" >>"$UFW_RULES"
                echo "-A ufw-before-input -m set --match-set $ASN_SET_NAME src -j DROP" >>"$UFW_RULES"
            fi
        fi

        # --- STRICT WIREGUARD SSH CLOAKING & GLOBAL TRUST ---
        if [[ "${USE_WIREGUARD:-n}" == "y" ]]; then
            # Priority 4: Deny public SSH access
            ufw insert 1 deny "${SSH_PORT:-22}/tcp" >/dev/null 2>&1 || true

            # Priority 3: Allow SSH strictly from the WG Subnet
            ufw insert 1 allow from "${WG_SUBNET}" to any port "${SSH_PORT:-22}" proto tcp >/dev/null 2>&1 || true

            # Priority 2: HOTFIX - Global Trust for WireGuard Interface (Fixes Ping & UI)
            ufw insert 1 allow in on wg0 >/dev/null 2>&1 || true

            # Priority 1: Allow UDP port for WireGuard Tunnel
            ufw insert 1 allow "${WG_PORT:-51820}/udp" >/dev/null 2>&1 || true
        fi

        # --- FIX DEVSECOPS: WHITELIST MUST BE ON TOP ---
        if [[ -s "$WHITELIST_FILE" ]]; then
            while IFS= read -r wl_ip; do
                [[ -z "$wl_ip" ]] && continue
                ufw insert 1 allow from "$wl_ip" >/dev/null 2>&1 || true
            done <"$WHITELIST_FILE"
        fi

        # --- ZERO TRUST: DYNAMIC ALLOW & CATCH-ALL DROP ---
        # 1. Allow discovered ports
        ufw allow "${SSH_PORT:-22}/tcp" >/dev/null 2>&1 || true
        if [[ -n "$ACTIVE_PORTS" ]] && [[ "$ACTIVE_PORTS" != "none" ]]; then
            for port in $(echo "$ACTIVE_PORTS" | tr ',' ' '); do
                ufw allow "${port}/tcp" >/dev/null 2>&1 || true
            done
        fi

        # 2. Change UFW Default Policy to Deny (Catch-All)
        ufw default deny incoming >/dev/null 2>&1 || true
        # Enable UFW logging so Fail2ban can read the drops
        ufw logging on >/dev/null 2>&1 || true

        ufw reload
        log "INFO" "UFW rules applied."

    else
        # Fallback IPSET / IPTABLES
        ipset create "${SET_NAME}_tmp" hash:net maxelem 1000000 -exist
        sed "s/^/add ${SET_NAME}_tmp /" "$FINAL_LIST" | ipset restore -!
        ipset create "$SET_NAME" hash:net maxelem 1000000 -exist
        ipset swap "${SET_NAME}_tmp" "$SET_NAME"
        ipset destroy "${SET_NAME}_tmp"

        # --- FIX: IDEMPOTENCY ON RAW TABLE ---
        if ! iptables -t raw -C PREROUTING -m set --match-set "$SET_NAME" src -j DROP 2>/dev/null; then
            iptables -t raw -I PREROUTING 1 -m set --match-set "$SET_NAME" src -j DROP
            iptables -t raw -I PREROUTING 1 -m set --match-set "$SET_NAME" src -j LOG --log-prefix "[SysWarden-BLOCK] "

            if command -v netfilter-persistent >/dev/null; then
                netfilter-persistent save
            elif command -v service >/dev/null && [ -f /etc/init.d/iptables ]; then service iptables save; fi
        fi

        # --- ASN INJECTION (Priority 2) ---
        if [[ "${BLOCK_ASNS:-none}" != "none" ]] && [[ -s "$ASN_FILE" ]]; then
            ipset create "${ASN_SET_NAME}_tmp" hash:net maxelem 1000000 -exist
            sed "s/^/add ${ASN_SET_NAME}_tmp /" "$ASN_FILE" | ipset restore -!
            ipset create "$ASN_SET_NAME" hash:net maxelem 1000000 -exist
            ipset swap "${ASN_SET_NAME}_tmp" "$ASN_SET_NAME"
            ipset destroy "${ASN_SET_NAME}_tmp"

            if ! iptables -t raw -C PREROUTING -m set --match-set "$ASN_SET_NAME" src -j DROP 2>/dev/null; then
                # Insert at position 1 (Pushed down by GeoIP later if exists)
                iptables -t raw -I PREROUTING 1 -m set --match-set "$ASN_SET_NAME" src -j DROP
                iptables -t raw -I PREROUTING 1 -m set --match-set "$ASN_SET_NAME" src -j LOG --log-prefix "[SysWarden-ASN] "
            fi
        fi

        # --- GEOIP INJECTION (Priority 1) ---
        if [[ "${GEOBLOCK_COUNTRIES:-none}" != "none" ]] && [[ -s "$GEOIP_FILE" ]]; then
            ipset create "${GEOIP_SET_NAME}_tmp" hash:net maxelem 1000000 -exist
            # The -! flag is crucial to prevent ipset from crashing if two countries share the same CIDR
            sed "s/^/add ${GEOIP_SET_NAME}_tmp /" "$GEOIP_FILE" | ipset restore -!
            ipset create "$GEOIP_SET_NAME" hash:net maxelem 1000000 -exist
            ipset swap "${GEOIP_SET_NAME}_tmp" "$GEOIP_SET_NAME"
            ipset destroy "${GEOIP_SET_NAME}_tmp"

            if ! iptables -t raw -C PREROUTING -m set --match-set "$GEOIP_SET_NAME" src -j DROP 2>/dev/null; then
                # Insert at position 1 (Top priority, enforced before ASN and standard list)
                iptables -t raw -I PREROUTING 1 -m set --match-set "$GEOIP_SET_NAME" src -j DROP
                iptables -t raw -I PREROUTING 1 -m set --match-set "$GEOIP_SET_NAME" src -j LOG --log-prefix "[SysWarden-GEO] "
            fi
        fi

        # --- STRICT WIREGUARD SSH CLOAKING & GLOBAL TRUST ---
        if [[ "${USE_WIREGUARD:-n}" == "y" ]]; then
            # Clean existing WG rules first to prevent duplicates
            while iptables -D INPUT -p udp --dport "${WG_PORT:-51820}" -j ACCEPT 2>/dev/null; do :; done
            while iptables -D INPUT -p tcp --dport "${SSH_PORT:-22}" -j DROP 2>/dev/null; do :; done
            while iptables -D INPUT -i wg0 -j ACCEPT 2>/dev/null; do :; done
            while iptables -D INPUT -i lo -j ACCEPT 2>/dev/null; do :; done

            # Insert top-priority rules (inserted in reverse order so they stack correctly)
            iptables -I INPUT 1 -p tcp --dport "${SSH_PORT:-22}" -j DROP
            iptables -I INPUT 1 -i wg0 -j ACCEPT
            iptables -I INPUT 1 -i lo -j ACCEPT
            iptables -I INPUT 1 -p udp --dport "${WG_PORT:-51820}" -j ACCEPT
        fi

        # ==========================================================
        # >>> ZERO TRUST INJECTION (DYNAMIC ALLOW & CATCH-ALL)
        # ==========================================================

        # --- HOTFIX: IDEMPOTENCY FOR IPTABLES (ANTI-CRON DUPLICATION) ---
        # 1. Allow discovered ports explicitly
        while iptables -D INPUT -p tcp --dport "${SSH_PORT:-22}" -j ACCEPT 2>/dev/null; do :; done
        iptables -I INPUT 1 -p tcp --dport "${SSH_PORT:-22}" -j ACCEPT

        if [[ -n "$ACTIVE_PORTS" ]] && [[ "$ACTIVE_PORTS" != "none" ]]; then
            while iptables -D INPUT -p tcp -m multiport --dports "$ACTIVE_PORTS" -j ACCEPT 2>/dev/null; do :; done
            iptables -I INPUT 1 -p tcp -m multiport --dports "$ACTIVE_PORTS" -j ACCEPT
        fi
        # -----------------------------------------------------------------------

        # 2. The Catch-All Drop (Appended to the VERY END of the INPUT chain)
        # Clean old catch-all if it exists
        while iptables -D INPUT -j DROP 2>/dev/null; do :; done
        while iptables -D INPUT -j LOG --log-prefix "[SysWarden-BLOCK] [Catch-All] " 2>/dev/null; do :; done

        iptables -A INPUT -j LOG --log-prefix "[SysWarden-BLOCK] [Catch-All] "
        iptables -A INPUT -j DROP

        # ==========================================================

        # --- FIX DEVSECOPS: STRICT WHITELIST EVALUATION ---
        if [[ -s "$WHITELIST_FILE" ]]; then
            while IFS= read -r wl_ip; do
                [[ -z "$wl_ip" ]] && continue
                if ! iptables -C INPUT -s "$wl_ip" -j ACCEPT 2>/dev/null; then
                    iptables -I INPUT 1 -s "$wl_ip" -j ACCEPT
                fi
            done <"$WHITELIST_FILE"
        fi

        # --- ESSENTIAL CONNECTION TRACKING (ALWAYS ACTIVE AT TOP) ---
        while iptables -D INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null; do :; done
        iptables -I INPUT 1 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

        # Save IPtables persistence for legacy OS
        if command -v netfilter-persistent >/dev/null; then
            netfilter-persistent save
        elif command -v service >/dev/null && [ -f /etc/init.d/iptables ]; then service iptables save; fi
    fi

    # --- DOCKER HERMETIC FIREWALL BLOCK ---
    if [[ "${USE_DOCKER:-n}" == "y" ]]; then
        log "INFO" "Applying Global Rules to Docker (DOCKER-USER chain)..."

        # 1. Standard Blocklist
        if ! ipset list "$SET_NAME" >/dev/null 2>&1; then
            ipset create "$SET_NAME" hash:net maxelem 1000000 -exist
            sed "s/^/add $SET_NAME /" "$FINAL_LIST" | ipset restore -!
        fi

        # 2. Geo-Blocking Set
        if [[ "${GEOBLOCK_COUNTRIES:-none}" != "none" ]] && [[ -s "$GEOIP_FILE" ]]; then
            if ! ipset list "$GEOIP_SET_NAME" >/dev/null 2>&1; then
                ipset create "$GEOIP_SET_NAME" hash:net maxelem 1000000 -exist
                sed "s/^/add $GEOIP_SET_NAME /" "$GEOIP_FILE" | ipset restore -!
            fi
        fi

        # 3. ASN-Blocking Set
        if [[ "${BLOCK_ASNS:-none}" != "none" ]] && [[ -s "$ASN_FILE" ]]; then
            if ! ipset list "$ASN_SET_NAME" >/dev/null 2>&1; then
                ipset create "$ASN_SET_NAME" hash:net maxelem 1000000 -exist
                sed "s/^/add $ASN_SET_NAME /" "$ASN_FILE" | ipset restore -!
            fi
        fi

        if iptables -n -L DOCKER-USER >/dev/null 2>&1; then
            # Clean old rules
            iptables -D DOCKER-USER -m set --match-set "$SET_NAME" src -j DROP 2>/dev/null || true
            iptables -D DOCKER-USER -m set --match-set "$SET_NAME" src -j LOG --log-prefix "[SysWarden-DOCKER] " 2>/dev/null || true
            iptables -D DOCKER-USER -m set --match-set "$GEOIP_SET_NAME" src -j DROP 2>/dev/null || true
            iptables -D DOCKER-USER -m set --match-set "$GEOIP_SET_NAME" src -j LOG --log-prefix "[SysWarden-GEO] " 2>/dev/null || true
            iptables -D DOCKER-USER -m set --match-set "$ASN_SET_NAME" src -j DROP 2>/dev/null || true
            iptables -D DOCKER-USER -m set --match-set "$ASN_SET_NAME" src -j LOG --log-prefix "[SysWarden-ASN] " 2>/dev/null || true

            # Apply Standard Blocklist (Priority 3)
            iptables -I DOCKER-USER 1 -m set --match-set "$SET_NAME" src -j DROP
            iptables -I DOCKER-USER 1 -m set --match-set "$SET_NAME" src -j LOG --log-prefix "[SysWarden-DOCKER] "

            # Apply ASN-Blocklist (Priority 2)
            if [[ "${BLOCK_ASNS:-none}" != "none" ]] && [[ -s "$ASN_FILE" ]]; then
                iptables -I DOCKER-USER 1 -m set --match-set "$ASN_SET_NAME" src -j DROP
                iptables -I DOCKER-USER 1 -m set --match-set "$ASN_SET_NAME" src -j LOG --log-prefix "[SysWarden-ASN] "
            fi

            # Apply Geo-Blocklist (Priority 1)
            if [[ "${GEOBLOCK_COUNTRIES:-none}" != "none" ]] && [[ -s "$GEOIP_FILE" ]]; then
                iptables -I DOCKER-USER 1 -m set --match-set "$GEOIP_SET_NAME" src -j DROP
                iptables -I DOCKER-USER 1 -m set --match-set "$GEOIP_SET_NAME" src -j LOG --log-prefix "[SysWarden-GEO] "
            fi

            # ==============================================================================
            # --- HOTFIX: STATEFUL DOCKER BYPASS (Priority 0 - Absolute Top) ---
            # Ensures outbound traffic (like S3 uploads) never times out on the way back.
            # Executed LAST so it becomes Rule #1 in the DOCKER-USER chain.
            # ==============================================================================
            while iptables -D DOCKER-USER -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN 2>/dev/null; do :; done
            iptables -I DOCKER-USER 1 -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN 2>/dev/null || true
            # ==============================================================================

            if command -v netfilter-persistent >/dev/null; then
                netfilter-persistent save 2>/dev/null || true
            elif command -v service >/dev/null && [ -f /etc/init.d/iptables ]; then service iptables save 2>/dev/null || true; fi
            log "INFO" "Docker firewall rules applied successfully."
        else
            log "WARN" "DOCKER-USER chain not found. Docker might not be running yet."
        fi
    fi

    # --- UNIVERSAL IPSET PERSISTENCE (UFW / IPTABLES / DOCKER) ---
    if command -v ipset >/dev/null && [[ "$FIREWALL_BACKEND" != "firewalld" ]]; then
        log "INFO" "Configuring universal IPSet persistence for boot survival..."
        mkdir -p /etc/syswarden
        ipset save >/etc/syswarden/ipsets.save 2>/dev/null || true

        cat <<'EOF' >/etc/systemd/system/syswarden-ipset.service
[Unit]
Description=SysWarden IPSet Restorer
DefaultDependencies=no
Before=network-pre.target ufw.service netfilter-persistent.service docker.service
Wants=network-pre.target

[Service]
Type=oneshot
ExecStart=/bin/sh -c "if [ -s /etc/syswarden/ipsets.save ]; then /sbin/ipset restore -! < /etc/syswarden/ipsets.save; fi"
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
        if command -v systemctl >/dev/null; then
            systemctl daemon-reload
            systemctl enable syswarden-ipset.service 2>/dev/null || true
        fi
    fi
}
