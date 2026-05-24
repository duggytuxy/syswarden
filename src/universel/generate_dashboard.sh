generate_dashboard() {
    log "INFO" "Migrating to the Enterprise TUI Dashboard (Removing legacy Web UI)..."

    local UI_DIR="/etc/syswarden/ui"
    local TUI_BIN="/usr/local/bin/syswarden-tui"

    mkdir -p "$UI_DIR"
    chmod 750 /etc/syswarden
    chmod 750 "$UI_DIR"

    # --- 1. CLEANUP LEGACY WEB ARTIFACTS ---
    log "INFO" "Hardening: Removing Web Server dependencies and UI files..."
    rm -f /etc/nginx/conf.d/syswarden-ui.conf /etc/nginx/sites-available/syswarden-ui.conf /etc/nginx/sites-enabled/syswarden-ui.conf
    rm -f /etc/apache2/sites-available/syswarden-ui.conf /etc/apache2/sites-enabled/syswarden-ui.conf
    rm -f /etc/httpd/conf.d/syswarden-ui.conf
    rm -f "$UI_DIR/index.html"
    rm -f /etc/syswarden/ssl/syswarden.crt /etc/syswarden/ssl/syswarden.key

    # Reload web services safely without disrupting active non-syswarden sites
    if systemctl is-active --quiet nginx; then systemctl reload nginx >/dev/null 2>&1 || true; fi
    if systemctl is-active --quiet apache2; then systemctl reload apache2 >/dev/null 2>&1 || true; fi
    if systemctl is-active --quiet httpd; then systemctl reload httpd >/dev/null 2>&1 || true; fi

    # --- 2. CLOSE PORT 9999 ---
    log "INFO" "Securing perimeter: Closing UI Port 9999..."
    if command -v ufw >/dev/null 2>&1; then
        ufw delete allow 9999/tcp >/dev/null 2>&1 || true
    fi
    if command -v firewall-cmd >/dev/null 2>&1; then
        local DASH_ZONE
        DASH_ZONE=$(firewall-cmd --get-default-zone 2>/dev/null || echo "public")
        firewall-cmd --permanent --zone="$DASH_ZONE" --remove-port=9999/tcp >/dev/null 2>&1 || true
        firewall-cmd --zone="$DASH_ZONE" --remove-port=9999/tcp >/dev/null 2>&1 || true
    fi
    if command -v iptables >/dev/null 2>&1; then
        iptables -D INPUT -p tcp --dport 9999 -j ACCEPT 2>/dev/null || true
        if command -v netfilter-persistent >/dev/null; then netfilter-persistent save >/dev/null 2>&1 || true; fi
    fi

    # --- 3. GENERATE FULL-SCREEN EVENT-DRIVEN TUI ENGINE (ULTRA OPTIMIZED) ---
    log "INFO" "Compiling the advanced Event-Driven TUI Engine (Zero-CPU)..."
    cat <<'EOF' >"$TUI_BIN"
#!/bin/bash
# SysWarden Enterprise TUI Dashboard
set -euo pipefail

# --- VERSION CONFIGURATION ---
SYSWARDEN_VERSION="v0.38.2"

DATA_FILE="/etc/syswarden/ui/data.json"

# --- THEME & COLORS ---
C_R="\033[1;31m" # Red (Critical/Offline)
C_G="\033[1;32m" # Green (Safe/Online)
C_Y="\033[1;33m" # Yellow (Skipped/Warning)
C_B="\033[1;34m" # Blue (Borders)
C_C="\033[1;36m" # Cyan (Headers)
C_W="\033[1;37m" # White (Text)
C_D="\033[1;30m" # Gray (Muted)
C_0="\033[0m"    # Reset

# --- STATE INTERNALS ---
SCROLL_OFFSET=0
GH_STARS="--"
GH_RELEASE="--"
LAST_TELEMETRY_DATA=""
LAST_FETCH_TS=0
LAST_GITHUB_TS=0
COLS=0
LINES=0
NEEDS_RENDER=1
C_LOAD=$C_G

declare -a JAILS_LIST=()
declare -a TOP_LIST=()
declare -a BANNED_LIST=()

# --- HELPER: DYNAMIC ALIGNMENT PADDING ---
pad() {
    local len=${#1}
    local max=$2
    local spaces=$(( max - len ))
    [[ $spaces -lt 0 ]] && spaces=0
    printf "%*s" "$spaces" ""
}

# --- SIGNAL HANDLING (Graceful Exit) ---
trap 'tput cnorm; tput rmcup 2>/dev/null || true; echo -ne "\033[?7h"; echo -e "${C_0}"; clear; exit 0' SIGINT SIGTERM
tput smcup 2>/dev/null || true # Enter alternate screen buffer to prevent scrollback stacking
tput civis # Hide cursor
echo -ne "\033[?7l" # Disable auto-wrap immediately to prevent terminal shifting
clear

while true; do
    CURRENT_TS=$(date +%s)
    
    # --- 1. RESIZE DETECTION ---
    NEW_COLS=$(tput cols 2>/dev/null || echo 80)
    NEW_LINES=$(tput lines 2>/dev/null || echo 24)
    if [[ "$NEW_COLS" != "$COLS" || "$NEW_LINES" != "$LINES" ]]; then
        COLS=$NEW_COLS
        LINES=$NEW_LINES
        SEP_H=$(printf '%*s' "$((COLS-2))" '' | sed 's/ /─/g')
        SEP_D_H=$(printf '%*s' "$((COLS-2))" '' | sed 's/ /┈/g')
        clear # Force screen wipe to prevent artifacts during window resizing
        NEEDS_RENDER=1
    fi

    # --- 2. DATA INGESTION (ONLY EVERY 5s) ---
    if (( CURRENT_TS - LAST_FETCH_TS >= 5 )) || [[ -z "$LAST_TELEMETRY_DATA" ]]; then
        if [[ -f "$DATA_FILE" ]]; then
            NEW_DATA=$(cat "$DATA_FILE" 2>/dev/null || true)
            if [[ -n "$NEW_DATA" && "$NEW_DATA" != "$LAST_TELEMETRY_DATA" ]]; then
                LAST_TELEMETRY_DATA="$NEW_DATA"
                LAST_FETCH_TS=$CURRENT_TS

                # --- GITHUB API CACHE (10 MINUTES) ---
                if (( CURRENT_TS - LAST_GITHUB_TS >= 600 )) || [[ "$GH_STARS" == "--" ]]; then
                    GH_DATA=$(curl -s --max-time 1.2 https://api.github.com/repos/duggytuxy/syswarden || echo "")
                    GH_REL_DATA=$(curl -s --max-time 1.2 https://api.github.com/repos/duggytuxy/syswarden/releases/latest || echo "")
                    GH_STARS=$(echo "$GH_DATA" | jq -r '.stargazers_count // "--"' 2>/dev/null || echo "--")
                    GH_RELEASE=$(echo "$GH_REL_DATA" | jq -r '.tag_name // "--"' 2>/dev/null || echo "--")
                    LAST_GITHUB_TS=$CURRENT_TS
                fi

                # --- SINGLE-PASS JQ PARSING (ULTRA CPU OPTIMIZATION) ---
                mapfile -t METRICS < <(echo "$LAST_TELEMETRY_DATA" | jq -r '
                    .system.hostname // "Node",
                    .system.os // "Linux",
                    .system.cpu_model // "Unknown",
                    .system.cores // "1",
                    .system.arch // "Unknown",
                    .system.load_average // "0.00, 0.00, 0.00",
                    .system.uptime // "Unknown",
                    .system.ram_used_mb // 0,
                    .system.ram_total_mb // 0,
                    .system.disk_used_mb // 0,
                    .system.disk_total_mb // 0,
                    .layer3.global_blocked // 0,
                    .layer3.geoip_blocked // 0,
                    .layer3.asn_blocked // 0,
                    .layer7.total_banned // 0,
                    .layer7.active_jails // 0,
                    .whitelist.active_ips // 0,
                    .layer7.risk_radar[0] // 0,
                    .layer7.risk_radar[1] // 0,
                    .layer7.risk_radar[2] // 0,
                    .layer7.risk_radar[3] // 0,
                    .layer7.risk_radar[4] // 0
                ' 2>/dev/null || true)
                
                if [[ ${#METRICS[@]} -ge 22 ]]; then
                    SYS_HOST="${METRICS[0]}"; SYS_OS="${METRICS[1]}"; SYS_CPU="${METRICS[2]}"
                    SYS_CORES="${METRICS[3]}"; SYS_ARCH="${METRICS[4]}"; SYS_LOAD="${METRICS[5]}"
                    SYS_UP="${METRICS[6]}"; SYS_RAM_U="${METRICS[7]}"; SYS_RAM_T="${METRICS[8]}"
                    SYS_DISK_U="${METRICS[9]}"; SYS_DISK_T="${METRICS[10]}"
                    L3_G="${METRICS[11]}"; L3_GEO="${METRICS[12]}"; L3_ASN="${METRICS[13]}"
                    L7_BAN="${METRICS[14]}"; L7_JAIL="${METRICS[15]}"; WL_ACT="${METRICS[16]}"
                    R_EXP="${METRICS[17]}"; R_BF="${METRICS[18]}"; R_REC="${METRICS[19]}"
                    R_DOS="${METRICS[20]}"; R_ABU="${METRICS[21]}"
                fi

                # --- DYNAMIC LOAD AVERAGE COLORIZATION ---
                L1=$(echo "$SYS_LOAD" | cut -d',' -f1 | tr -d ' ')
                C_LOAD=$(awk -v l1="$L1" -v cg="$C_G" -v cy="$C_Y" -v cr="$C_R" 'BEGIN {
                    if (l1 < 0.50) print cg;
                    else if (l1 < 0.75) print cy;
                    else print cr;
                }' 2>/dev/null || echo "$C_G")

                # --- SIGNAL CALCULATION ---
                TOTAL_THREATS=$(( L3_G + L7_BAN ))
                NOISE_PCT="0.00%"
                SIGNAL_PCT="0.00%"
                if (( TOTAL_THREATS > 0 )); then
                    NOISE_PCT=$(awk "BEGIN {printf \"%.2f%%\", ($L3_G / $TOTAL_THREATS) * 100}")
                    SIGNAL_PCT=$(awk "BEGIN {printf \"%.2f%%\", ($L7_BAN / $TOTAL_THREATS) * 100}")
                fi

                # --- DYNAMIC SERVICES COLORIZATION ---
                SERVICES_STR=""
                mapfile -t RAW_SERVICES < <(echo "$LAST_TELEMETRY_DATA" | jq -r '.system.services[] | "\(.name | split(" ")[0]):\(.status)"' 2>/dev/null || true)
                for srv in "${RAW_SERVICES[@]}"; do
                    [[ -z "$srv" ]] && continue
                    srv_name=$(echo "$srv" | cut -d':' -f1 | tr 'a-z' 'A-Z')
                    srv_stat=$(echo "$srv" | cut -d':' -f2 | tr 'a-z' 'A-Z')
                    if [[ "$srv_stat" == "ACTIVE" || "$srv_stat" == "ONLINE" ]]; then
                        SERVICES_STR+=" ${C_W}${srv_name}${C_0}:${C_G}${srv_stat}${C_0} │"
                    elif [[ "$srv_stat" == "SKIPPED" ]]; then
                        SERVICES_STR+=" ${C_W}${srv_name}${C_0}:${C_Y}${srv_stat}${C_0} │"
                    else
                        SERVICES_STR+=" ${C_W}${srv_name}${C_0}:${C_R}${srv_stat}${C_0} │"
                    fi
                done
                SERVICES_STR="${SERVICES_STR% │}"

                # --- WHITELIST 3 IPs EXACT MATCH ---
                WL_IPS_STR=$(echo "$LAST_TELEMETRY_DATA" | jq -r 'if .whitelist.ips then if (.whitelist.ips | length) > 3 then (.whitelist.ips[0:3] | join(", ")) + ", ..." else .whitelist.ips | join(", ") end else "None" end' 2>/dev/null || true)
                [[ -z "$WL_IPS_STR" || "$WL_IPS_STR" == "null" ]] && WL_IPS_STR="None"

                PORTS_STR=$(echo "$LAST_TELEMETRY_DATA" | jq -r '.system.ports[] | "\(.protocol):\(.port)"' | tr '\n' ' ' | sed 's/ / │ /g' | sed 's/ │ $//')
                [[ -z "$PORTS_STR" ]] && PORTS_STR="No external ports exposed. Architecture is fully locked down."

                mapfile -t JAILS_LIST < <(echo "$LAST_TELEMETRY_DATA" | jq -r '.layer7.jails_data | sort_by(.count) | reverse | .[] | "\(.name)|\(.mitre)|\(.count)"' | head -n 5)
                mapfile -t TOP_LIST < <(echo "$LAST_TELEMETRY_DATA" | jq -r '.layer7.top_attackers[]? | "\(.ip)|\(.port)|\(.country)|\(.asn)|\(.isp)"' | head -n 5)
                mapfile -t BANNED_LIST < <(echo "$LAST_TELEMETRY_DATA" | jq -r '.layer7.banned_ips | reverse | .[] | "\(.ip)|\(.jail)|\(.mitre)|\(.payload)"')
                TOTAL_BANS=${#BANNED_LIST[@]}
                
                NEEDS_RENDER=1
            fi
            LAST_FETCH_TS=$CURRENT_TS
        fi
    fi

    # --- 3. EVENT-DRIVEN RENDERER (0.0% CPU IDLE) ---
    if (( NEEDS_RENDER == 1 )); then
        OUT=""
        add_line() { OUT+="${C_B}│${C_0}${1}\033[${COLS}G${C_B}│${C_0}\n"; }
        add_sep()  { OUT+="${C_B}├${SEP_H}┤${C_0}\n"; }
        add_sep_d(){ OUT+="${C_B}├${SEP_D_H}┤${C_0}\n"; }
        add_top()  { OUT+="${C_B}┌${SEP_H}┐${C_0}\n"; }
        add_bot()  { OUT+="${C_B}└${SEP_H}┘${C_0}"; } # Removed trailing newline to prevent terminal scrolling bug

        # --- TOP BRANDING NAVBAR ---
        add_top
        add_line "  ${C_W}SYSWARDEN ${SYSWARDEN_VERSION}${C_0}   │   Noise: ${C_G}${NOISE_PCT}${C_0}   │   Signal: ${C_R}${SIGNAL_PCT}${C_0}   │   Stars: ${C_Y}${GH_STARS}${C_0}   │   Release: ${C_C}${GH_RELEASE}${C_0}   │   Node: ${C_W}${SYS_HOST}${C_0}"
        add_sep_d
        
        # --- HARDWARE SPECS HEADER PANEL ---
        add_line "  Cores: ${C_W}${SYS_CORES}${C_0}   │   Arch: ${C_W}${SYS_ARCH}${C_0}   │   OS: ${C_W}${SYS_OS}${C_0}   │   CPU: ${C_W}${SYS_CPU}${C_0}   │   Last sync: ${C_Y}$(date -d @$LAST_FETCH_TS +'%H:%M:%S')${C_0}"
        add_line "  Uptime: ${C_C}${SYS_UP}${C_0}   │   Load Avg: ${C_LOAD}${SYS_LOAD}${C_0}   │   RAM: ${C_W}${SYS_RAM_U} / ${SYS_RAM_T} MB${C_0}   │   Storage: ${C_W}$(awk "BEGIN {printf \"%.1f\", $SYS_DISK_U/1024}") / $(awk "BEGIN {printf \"%.1f\", $SYS_DISK_T/1024}") GB${C_0}"
        add_line "  Services: ${SERVICES_STR}"
        add_line "  Ports:    ${C_B}${PORTS_STR}${C_0}"
        add_sep
        add_line ""
        
        # --- LAYER 3 & LAYER 7 GEOMETRIC ALIGNED MATRICES ---
        W3=$(( (COLS - 4) / 3 ))
        [[ $W3 -lt 30 ]] && W3=30

        T1="❖ L3 KERNEL BLOCKS (GLOBAL)"
        T2="❖ L7 ACTIVE BANS (FAIL2BAN)"
        T3="❖ TRUSTED HOSTS (WHITELIST)"
        add_line "  ${C_C}${T1}${C_0}$(pad "$T1" $((W3-2)))${C_R}${T2}${C_0}$(pad "$T2" $W3)${C_G}${T3}${C_0}"
        
        V1="Value: ${L3_G}"
        V2="Value: ${L7_BAN}"
        V3="Active IPs: ${WL_ACT}"
        add_line "  ${C_D}Value: ${C_W}${L3_G}${C_0}$(pad "$V1" $((W3-2)))${C_D}Value: ${C_W}${L7_BAN}${C_0}$(pad "$V2" $W3)${C_D}Active IPs: ${C_W}${WL_ACT}${C_0}"
        
        D1="GeoIP: ${L3_GEO} │ ASN: ${L3_ASN}"
        D2="Active Guard Jails: ${L7_JAIL}"
        D3="IPs: ${WL_IPS_STR}"
        add_line "  ${C_D}GeoIP: ${C_W}${L3_GEO}${C_D} │ ASN: ${C_W}${L3_ASN}${C_0}$(pad "$D1" $((W3-2)))${C_D}Active Guard Jails: ${C_W}${L7_JAIL}${C_0}$(pad "$D2" $W3)${C_D}IPs: ${C_G}${WL_IPS_STR}${C_0}"
        
        add_line ""
        add_sep_d
        add_line ""
        
        # --- GLOBAL RISK RADAR VECTOR MATRIX ---
        add_line "  ${C_W}❖ GLOBAL RISK VECTORS${C_0}"
        add_line "  ${C_R}Exploits:${C_0} ${R_EXP}   │   ${C_Y}Brute-Force:${C_0} ${R_BF}   │   ${C_B}Recon:${C_0} ${R_REC}   │   ${C_D}DDoS:${C_0} ${R_DOS}   │   ${C_Y}Abuse/Spam:${C_0} ${R_ABU}"
        
        add_line ""
        add_sep
        add_line ""

        # --- JAILS LOAD DISTRIBUTION & TOP ATTACKERS SPLIT MATRICES ---
        HALF_WIDTH=$(( (COLS - 4) / 2 - 2 ))
        [[ $HALF_WIDTH -lt 58 ]] && HALF_WIDTH=58

        TITLE_L="  ❖ JAILS LOAD DISTRIBUTION"
        TITLE_R="  ❖ TOP ATTACKERS (OSINT HISTORY)"
        add_line "${C_W}${TITLE_L}$(pad "$TITLE_L" $HALF_WIDTH)${TITLE_R}${C_0}"
        
        HEAD_L="  TARGET JAIL                       MITRE ATT&CK       LOAD"
        HEAD_R="  IP ADDRESS          PORT      COUNTRY   ASN       ISP"
        add_line "${C_D}${HEAD_L}$(pad "$HEAD_L" $HALF_WIDTH)${HEAD_R}${C_0}"

        for i in {0..4}; do
            J_LINE=""
            T_LINE=""
            if [[ ${#JAILS_LIST[@]} -gt $i ]]; then
                IFS='|' read -r j_name j_mitre j_count <<< "${JAILS_LIST[$i]}"
                j_mitre_short=$(echo "$j_mitre" | cut -d':' -f1)
                J_LINE=$(printf "  %-33s %-18s %-8s" "${j_name:0:32}" "${j_mitre_short:0:17}" "$j_count")
            fi
            if [[ ${#TOP_LIST[@]} -gt $i ]]; then
                IFS='|' read -r t_ip t_port t_country t_asn t_isp <<< "${TOP_LIST[$i]}"
                T_LINE=$(printf "  %-19s %-9s %-9s %-9s %s" "${t_ip:0:18}" "${t_port:0:8}" "${t_country:0:8}" "${t_asn:0:8}" "${t_isp:0:30}")
            fi
            add_line "${C_C}${J_LINE}${C_0}$(pad "$J_LINE" $HALF_WIDTH)${C_R}${T_LINE}${C_0}"
        done
        
        add_sep
        add_line ""

        # --- L7 BANNED IP REGISTRY & RAW SYSTEM LOGS STREAM ENGINE ---
        add_line "  ${C_W}❖ L7 BANNED IP REGISTRY (LIVE JAIL ALLOCATIONS)${C_0}"
        
        W_IP=22
        W_JAIL=24
        W_MITRE=22
        W_PAYLOAD=$(( COLS - W_IP - W_JAIL - W_MITRE - 6 ))
        [[ $W_PAYLOAD -lt 25 ]] && W_PAYLOAD=25

        HEAD_REG=$(printf "  %-*s %-*s %-*s %s" "$W_IP" "IP ADDRESS" "$W_JAIL" "TARGET JAIL" "$W_MITRE" "MITRE ATT&CK" "TRIGGER PAYLOAD")
        add_line "${C_D}${HEAD_REG}${C_0}"

        USED_LINES=$(echo -ne "$OUT" | wc -l)
        MAX_BANS=$(( LINES - USED_LINES - 5 ))
        [[ $MAX_BANS -lt 4 ]] && MAX_BANS=4

        # Bounds alignment
        if (( SCROLL_OFFSET > TOTAL_BANS - MAX_BANS )); then SCROLL_OFFSET=$(( TOTAL_BANS - MAX_BANS )); fi
        if (( SCROLL_OFFSET < 0 )); then SCROLL_OFFSET=0; fi

        if [[ $TOTAL_BANS -eq 0 ]]; then
            add_line "  ${C_G}Registry is empty. Architecture is secure.${C_0}"
        else
            for ((i=0; i<MAX_BANS; i++)); do
                IDX=$(( i + SCROLL_OFFSET ))
                if [[ $IDX -lt $TOTAL_BANS ]]; then
                    IFS='|' read -r b_ip b_jail b_mitre b_payload <<< "${BANNED_LIST[$IDX]}"
                    b_mitre_short=$(echo "$b_mitre" | cut -d':' -f1)
                    
                    # Parsing is now handled persistently in the backend telemetry engine
                    P_CLEAN=$(echo "$b_payload" | tr -d '\n\r' | cut -c 1-$W_PAYLOAD)
                    
                    C_VEC=${C_W}
                    if [[ "$b_jail" =~ (sqli|xss|lfi|revshell|webshell|ssti|ssrf|jndi|modsec|homoglyph) ]]; then C_VEC=${C_R}
                    elif [[ "$b_jail" =~ (ssh|auth|privesc|prestashop) ]]; then C_VEC=${C_Y}
                    elif [[ "$b_jail" =~ (scan|bot|mapper|enum|hunter|tls) ]]; then C_VEC=${C_B}
                    elif [[ "$b_jail" =~ (flood) ]]; then C_VEC=${C_D}
                    else C_VEC=${C_Y}; fi
                    
                    STR_1=$(printf "  %-*s " "$W_IP" "${b_ip:0:$W_IP}")
                    STR_2=$(printf "%-*s " "$W_JAIL" "${b_jail:0:$W_JAIL}")
                    STR_3=$(printf "%-*s " "$W_MITRE" "${b_mitre_short:0:$W_MITRE}")
                    
                    add_line "${C_W}${STR_1}${C_0}${C_VEC}${STR_2}${STR_3}${C_0}${C_W}${P_CLEAN}${C_0}"
                else
                    add_line ""
                fi
            done
        fi

        # Fill footer
        CURRENT_LINES=$(echo -ne "$OUT" | wc -l)
        REMAIN=$(( LINES - CURRENT_LINES - 3 ))
        if [[ $REMAIN -gt 0 ]]; then
            for ((i=0; i<$REMAIN; i++)); do add_line ""; done
        fi

        add_sep
        add_line "  ${C_D}Registry Index: $((SCROLL_OFFSET + 1))-${TOTAL_BANS} of ${TOTAL_BANS} │ Interval: 60s │ Navigate: Up/Down Arrows │ Press 'q' to exit.${C_0}"
        add_bot

        # --- ATOMIC FLUSH TO SCREEN ---
        echo -ne "\033[?7l\033[H\033[J${OUT}\033[H"
        NEEDS_RENDER=0
    fi

    # --- 4. NON-BLOCKING INPUT KERNEL (0% IDLE CPU) ---
    # `read` will block and idle the CPU for 0.1s natively. If no key, it fails and continues loop.
    if ! read -s -n 1 -t 0.1 key; then
        continue
    fi
    
    # If a key is pressed, process logic and set NEEDS_RENDER=1 to redraw exactly once.
    if [[ "$key" == $'\x1b' ]]; then
        # Read the rest of the escape sequence quickly (catches long mouse scroll codes)
        read -s -n 5 -t 0.05 next_keys || true
        
        if [[ "$next_keys" == "[A" || "$next_keys" == "OA" || "$next_keys" =~ "64" || "$next_keys" == "[M "* ]]; then
            if (( SCROLL_OFFSET > 0 )); then SCROLL_OFFSET=$(( SCROLL_OFFSET - 1 )); NEEDS_RENDER=1; fi
        elif [[ "$next_keys" == "[B" || "$next_keys" == "OB" || "$next_keys" =~ "65" || "$next_keys" == "[M!"* ]]; then
            if (( SCROLL_OFFSET < TOTAL_BANS - MAX_BANS )); then SCROLL_OFFSET=$(( SCROLL_OFFSET + 1 )); NEEDS_RENDER=1; fi
        fi
        
        # Aggressive flush of residual input buffer to prevent scroll artifacts
        while read -s -n 1 -t 0.01; do :; done
    elif [[ "$key" == "q" || "$key" == "Q" ]]; then
        tput cnorm; tput rmcup 2>/dev/null || true; echo -ne "\033[?7h"; echo -e "${C_0}"; clear; exit 0
    fi
done
EOF

    chmod +x "$TUI_BIN"
    ln -sf "$TUI_BIN" "/usr/local/bin/syswarden-dashboard" 2>/dev/null || true

    log "INFO" "TUI Engine successfully deployed."
}
