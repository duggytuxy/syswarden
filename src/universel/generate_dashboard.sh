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

    # --- 3. GENERATE FULL-SCREEN PRECISION TUI ENGINE ---
    log "INFO" "Compiling the advanced 5s-refresh TUI Engine (Zero-CPU Engine)..."
    cat <<'EOF' >"$TUI_BIN"
#!/bin/bash
# SysWarden Enterprise TUI Dashboard
set -euo pipefail

DATA_FILE="/etc/syswarden/ui/data.json"

# --- THEME & COLORS ---
C_R="\033[1;31m" # Red (Critical/Signal)
C_G="\033[1;32m" # Green (Safe/Noise)
C_Y="\033[1;33m" # Yellow (Warning)
C_B="\033[1;34m" # Blue (Borders)
C_C="\033[1;36m" # Cyan (Headers)
C_W="\033[1;37m" # White (Text)
C_D="\033[1;30m" # Gray (Muted)
C_0="\033[0m"    # Reset

# --- TIMING & METRICS STATE INTERNALS ---
SCROLL_OFFSET=0
GH_STARS="--"
GH_RELEASE="--"
LAST_TELEMETRY_DATA=""
LAST_FETCH_TS=0
LAST_GITHUB_TS=0

# Declare arrays to prevent uninitialized errors on first boot
declare -a JAILS_LIST=()
declare -a TOP_LIST=()
declare -a BANNED_LIST=()

# --- SIGNAL HANDLING (Graceful Exit) ---
trap 'tput cnorm; echo -e "${C_0}"; clear; exit 0' SIGINT SIGTERM
tput civis # Hide cursor
clear

while true; do
    CURRENT_TS=$(date +%s)
    COLS=$(tput cols 2>/dev/null || echo 80)
    LINES=$(tput lines 2>/dev/null || echo 24)
    
    SEP=$(printf '%*s' "$COLS" '' | tr ' ' '=')
    SEP_D=$(printf '%*s' "$COLS" '' | tr ' ' '-')

    if [[ ! -f "$DATA_FILE" ]]; then
        echo -ne "\033[H\033[K${C_R}Waiting for SysWarden telemetry data (data.json)...${C_0}"
        sleep 2
        continue
    fi

    # --- CPU OPTIMIZATION: PARSE DATA ONLY EVERY 5 SECONDS ---
    if (( CURRENT_TS - LAST_FETCH_TS >= 5 )) || [[ -z "$LAST_TELEMETRY_DATA" ]]; then
        LAST_TELEMETRY_DATA=$(cat "$DATA_FILE")
        LAST_FETCH_TS=$CURRENT_TS

        # --- APIS TIMING LIMITATION (10 Minutes Cache for GitHub) ---
        if (( CURRENT_TS - LAST_GITHUB_TS >= 600 )) || [[ "$GH_STARS" == "--" ]]; then
            GH_DATA=$(curl -s --max-time 1.2 https://api.github.com/repos/duggytuxy/syswarden || echo "")
            GH_REL_DATA=$(curl -s --max-time 1.2 https://api.github.com/repos/duggytuxy/syswarden/releases/latest || echo "")
            GH_STARS=$(echo "$GH_DATA" | jq -r '.stargazers_count // "--"' 2>/dev/null || echo "--")
            GH_RELEASE=$(echo "$GH_REL_DATA" | jq -r '.tag_name // "--"' 2>/dev/null || echo "--")
            LAST_GITHUB_TS=$CURRENT_TS
        fi

        # --- DATA PARSING FROM CACHED payload ---
        SYS_HOST=$(echo "$LAST_TELEMETRY_DATA" | jq -r '.system.hostname // "Node"')
        SYS_OS=$(echo "$LAST_TELEMETRY_DATA" | jq -r '.system.os // "Linux"')
        SYS_CPU=$(echo "$LAST_TELEMETRY_DATA" | jq -r '.system.cpu_model // "Unknown"')
        SYS_CORES=$(echo "$LAST_TELEMETRY_DATA" | jq -r '.system.cores // "1"')
        SYS_ARCH=$(echo "$LAST_TELEMETRY_DATA" | jq -r '.system.arch // "Unknown"')
        SYS_LOAD=$(echo "$LAST_TELEMETRY_DATA" | jq -r '.system.load_average // "0, 0, 0"')
        SYS_UP=$(echo "$LAST_TELEMETRY_DATA" | jq -r '.system.uptime // "Unknown"')
        SYS_RAM_U=$(echo "$LAST_TELEMETRY_DATA" | jq -r '.system.ram_used_mb // 0')
        SYS_RAM_T=$(echo "$LAST_TELEMETRY_DATA" | jq -r '.system.ram_total_mb // 0')
        SYS_DISK_U=$(echo "$LAST_TELEMETRY_DATA" | jq -r '.system.disk_used_mb // 0')
        SYS_DISK_T=$(echo "$LAST_TELEMETRY_DATA" | jq -r '.system.disk_total_mb // 0')
        
        L3_G=$(echo "$LAST_TELEMETRY_DATA" | jq -r '.layer3.global_blocked // 0')
        L3_GEO=$(echo "$LAST_TELEMETRY_DATA" | jq -r '.layer3.geoip_blocked // 0')
        L3_ASN=$(echo "$LAST_TELEMETRY_DATA" | jq -r '.layer3.asn_blocked // 0')
        L7_BAN=$(echo "$LAST_TELEMETRY_DATA" | jq -r '.layer7.total_banned // 0')
        L7_JAIL=$(echo "$LAST_TELEMETRY_DATA" | jq -r '.layer7.active_jails // 0')
        WL_ACT=$(echo "$LAST_TELEMETRY_DATA" | jq -r '.whitelist.active_ips // 0')
        
        R_EXP=$(echo "$LAST_TELEMETRY_DATA" | jq -r '.layer7.risk_radar[0] // 0')
        R_BF=$(echo "$LAST_TELEMETRY_DATA" | jq -r '.layer7.risk_radar[1] // 0')
        R_REC=$(echo "$LAST_TELEMETRY_DATA" | jq -r '.layer7.risk_radar[2] // 0')
        R_DOS=$(echo "$LAST_TELEMETRY_DATA" | jq -r '.layer7.risk_radar[3] // 0')
        R_ABU=$(echo "$LAST_TELEMETRY_DATA" | jq -r '.layer7.risk_radar[4] // 0')

        # --- PRECISION FILTRATION EFFICIENCY MATRIX ---
        TOTAL_THREATS=$(( L3_G + L7_BAN ))
        NOISE_PCT="0.00%"
        SIGNAL_PCT="0.00%"
        if (( TOTAL_THREATS > 0 )); then
            NOISE_PCT=$(awk "BEGIN {printf \"%.2f%%\", ($L3_G / $TOTAL_THREATS) * 100}")
            SIGNAL_PCT=$(awk "BEGIN {printf \"%.2f%%\", ($L7_BAN / $TOTAL_THREATS) * 100}")
        fi

        SERVICES_STR=$(echo "$LAST_TELEMETRY_DATA" | jq -r '.system.services[] | "\(.name | split(" ")[0]):\(.status)"' | tr '\n' ' ' | sed 's/ / | /g' | sed 's/ | $//' | tr 'a-z' 'A-Z')
        PORTS_STR=$(echo "$LAST_TELEMETRY_DATA" | jq -r '.system.ports[] | "\(.protocol):\(.port)"' | tr '\n' ' ' | sed 's/ / | /g' | sed 's/ | $//')
        [[ -z "$PORTS_STR" ]] && PORTS_STR="No external ports exposed. Architecture is fully locked down."

        mapfile -t JAILS_LIST < <(echo "$LAST_TELEMETRY_DATA" | jq -r '.layer7.jails_data | sort_by(.count) | reverse | .[] | "\(.name)|\(.mitre)|\(.count)"' | head -n 5)
        mapfile -t TOP_LIST < <(echo "$LAST_TELEMETRY_DATA" | jq -r '.layer7.top_attackers[] | "\(.ip)|\(.port)|\(.count)"' | head -n 5)
        mapfile -t BANNED_LIST < <(echo "$LAST_TELEMETRY_DATA" | jq -r '.layer7.banned_ips | reverse | .[] | "\(.ip)|\(.jail)|\(.mitre)|\(.payload)"')
        TOTAL_BANS=${#BANNED_LIST[@]}
    fi

    # --- RENDERING GENERATION (Pure Bash Cache Drawing) ---
    OUT=""
    add_line() { OUT+="${1}\033[K\n"; }

    # --- TOP BRANDING NAVBAR ---
    add_line "${C_B}${SEP}${C_0}"
    add_line "${C_W} SYSWARDEN v0.35.5 ${C_0}| Noise: ${C_G}${NOISE_PCT}${C_0} | Signal: ${C_R}${SIGNAL_PCT}${C_0} | Stars: ${C_Y}${GH_STARS}${C_0} | Release: ${C_C}${GH_RELEASE}${C_0} | Node: ${C_G}${SYS_HOST}${C_0}"
    add_line "${C_B}${SEP_D}${C_0}"
    
    # --- HARDWARE SPECS HEADER PANEL ---
    add_line " Cores: ${C_W}${SYS_CORES}${C_0} | Arch: ${C_W}${SYS_ARCH}${C_0} | OS: ${C_W}${SYS_OS}${C_0} | CPU: ${C_W}${SYS_CPU}${C_0} | Last sync: ${C_Y}$(date -d @$LAST_FETCH_TS +'%H:%M:%S')${C_0}"
    add_line " Uptime: ${C_C}${SYS_UP}${C_0} | Load Avg: ${C_W}${SYS_LOAD}${C_0} | RAM: ${C_W}${SYS_RAM_U} / ${SYS_RAM_T} MB${C_0} | Storage: ${C_W}$(awk "BEGIN {printf \"%.1f\", $SYS_DISK_U/1024}") / $(awk "BEGIN {printf \"%.1f\", $SYS_DISK_T/1024}") GB${C_0}"
    
    # --- FLAT SERVICES & EXPOSED NETWORK PORTS PANEL ---
    add_line " Services: [ ${C_W}${SERVICES_STR}${C_0} ]"
    add_line " Ports: [ ${C_B}${PORTS_STR}${C_0} ]"
    add_line "${C_B}${SEP}${C_0}"

    # --- LAYER 3 & LAYER 7 METRICS BLOCKS ---
    add_line " ${C_C}[ L3 KERNEL BLOCKS (GLOBAL) ]${C_0}          ${C_R}[ L7 ACTIVE BANS (FAIL2BAN) ]${C_0}          ${C_G}[ TRUSTED HOSTS (WHITELIST) ]${C_0}"
    add_line " Value: ${C_W}${L3_G}${C_0}                             Value: ${C_W}${L7_BAN}${C_0}                             Active IPs: ${C_W}${WL_ACT}${C_0}"
    add_line " GeoIP: ${L3_GEO} | ASN: ${L3_ASN}                 Active Guard Jails: ${L7_JAIL}                 Trusted Networks Matrix"
    add_line "${C_B}${SEP_D}${C_0}"

    # --- GLOBAL RISK RADAR VECTOR MATRIX ---
    add_line " ${C_W}[ GLOBAL RISK VECTORS ]${C_0}"
    add_line " Exploits: ${C_R}${R_EXP}${C_0} | Brute-Force: ${C_Y}${R_BF}${C_0} | Recon: ${C_B}${R_REC}${C_0} | DDoS: ${C_D}${R_DOS}${C_0} | Abuse/Spam: ${C_Y}${R_ABU}${C_0}"
    add_line "${C_B}${SEP}${C_0}"

    # --- JAILS LOAD DISTRIBUTION & TOP ATTACKERS SPLIT MATRICES ---
    HALF_WIDTH=$(( COLS / 2 - 2 ))
    [[ $HALF_WIDTH -lt 45 ]] && HALF_WIDTH=45

    TITLE_L=" [ JAILS LOAD DISTRIBUTION ]"
    TITLE_R=" [ TOP ATTACKERS (OSINT HISTORY) ]"
    add_line "${C_W}${TITLE_L}$(printf '%*s' $(( HALF_WIDTH - ${#TITLE_L} + 4 )) '')${TITLE_R}${C_0}"
    
    HEAD_L=" TARGET JAIL      MITRE ATT&CK         LOAD"
    HEAD_R=" IP ADDRESS           PORT       HITS"
    add_line "${C_D}${HEAD_L}$(printf '%*s' $(( HALF_WIDTH - ${#HEAD_L} + 4 )) '')${HEAD_R}${C_0}"

    for i in {0..4}; do
        J_LINE=""
        T_LINE=""
        if [[ ${#JAILS_LIST[@]} -gt $i ]]; then
            IFS='|' read -r j_name j_mitre j_count <<< "${JAILS_LIST[$i]}"
            j_mitre_short=$(echo "$j_mitre" | cut -d':' -f1)
            J_LINE=$(printf " %-16s %-20s %-8s" "${j_name:0:15}" "${j_mitre_short:0:19}" "$j_count")
        fi
        if [[ ${#TOP_LIST[@]} -gt $i ]]; then
            IFS='|' read -r t_ip t_port t_count <<< "${TOP_LIST[$i]}"
            T_LINE=$(printf " %-20s %-10s %-8s" "${t_ip:0:19}" "${t_port:0:9}" "$t_count")
        fi
        PADDING_LEN=$(( HALF_WIDTH - ${#J_LINE} + 4 ))
        [[ $PADDING_LEN -lt 1 ]] && PADDING_LEN=1
        PAD=$(printf '%*s' "$PADDING_LEN" '')
        add_line "${C_C}${J_LINE}${C_0}${PAD}${C_R}${T_LINE}${C_0}"
    done
    add_line "${C_B}${SEP}${C_0}"

    # --- L7 BANNED IP REGISTRY & RAW SYSTEM LOGS STREAM ENGINE ---
    add_line " ${C_W}[ L7 BANNED IP REGISTRY (LIVE JAIL ALLOCATIONS) ]${C_0}"
    
    W_IP=20
    W_JAIL=18
    W_MITRE=22
    W_PAYLOAD=$(( COLS - W_IP - W_JAIL - W_MITRE - 6 ))
    [[ $W_PAYLOAD -lt 25 ]] && W_PAYLOAD=25

    HEAD_REG=$(printf " %-${W_IP}s %-${W_JAIL}s %-${W_MITRE}s %s" "IP ADDRESS" "TARGET JAIL" "MITRE ATT&CK" "TRIGGER PAYLOAD")
    add_line "${C_D}${HEAD_REG}${C_0}"

    USED_LINES=$(echo -ne "$OUT" | wc -l)
    MAX_BANS=$(( LINES - USED_LINES - 4 ))
    [[ $MAX_BANS -lt 4 ]] && MAX_BANS=4

    # Bounds alignment
    if (( SCROLL_OFFSET > TOTAL_BANS - MAX_BANS )); then SCROLL_OFFSET=$(( TOTAL_BANS - MAX_BANS )); fi
    if (( SCROLL_OFFSET < 0 )); then SCROLL_OFFSET=0; fi

    if [[ $TOTAL_BANS -eq 0 ]]; then
        add_line " ${C_G}Registry is empty. Architecture is secure.${C_0}"
    else
        for ((i=0; i<MAX_BANS; i++)); do
            IDX=$(( i + SCROLL_OFFSET ))
            if [[ $IDX -lt $TOTAL_BANS ]]; then
                IFS='|' read -r b_ip b_jail b_mitre b_payload <<< "${BANNED_LIST[$IDX]}"
                b_mitre_short=$(echo "$b_mitre" | cut -d':' -f1)
                
                P_CLEAN=$(echo "$b_payload" | tr -d '\n\r' | cut -c 1-$W_PAYLOAD)
                LINE_STR=$(printf " %-${W_IP}s %-${W_JAIL}s %-${W_MITRE}s %s" "${b_ip:0:$W_IP}" "${b_jail:0:$W_JAIL}" "${b_mitre_short:0:$W_MITRE}" "$P_CLEAN")
                
                SCROLL_CHAR="│"
                if (( TOTAL_BANS > MAX_BANS )); then
                    SLIDER_START=$(( SCROLL_OFFSET * MAX_BANS / TOTAL_BANS ))
                    SLIDER_END=$(( (SCROLL_OFFSET + MAX_BANS) * MAX_BANS / TOTAL_BANS ))
                    if (( i >= SLIDER_START && i <= SLIDER_END )); then SCROLL_CHAR="█"; fi
                fi
                
                if [[ "$b_payload" =~ "kernel:" || "$b_payload" =~ "SysWarden" ]]; then
                    add_line "${C_Y}${LINE_STR:0:$((COLS-2))}${C_0}${C_B}${SCROLL_CHAR}${C_0}"
                else
                    add_line "${C_W}${LINE_STR:0:$((COLS-2))}${C_0}${C_B}${SCROLL_CHAR}${C_0}"
                fi
            else
                SCROLL_CHAR="│"
                if (( TOTAL_BANS <= MAX_BANS )); then SCROLL_CHAR=" "; fi
                add_line "$(printf '%*s' $((COLS-1)) '')${C_B}${SCROLL_CHAR}${C_0}"
            fi
        done
    fi

    # Fill footer
    CURRENT_LINES=$(echo -ne "$OUT" | wc -l)
    REMAIN=$(( LINES - CURRENT_LINES - 2 ))
    if [[ $REMAIN -gt 0 ]]; then
        for ((i=0; i<$REMAIN; i++)); do add_line ""; done
    fi

    add_line "${C_B}${SEP}${C_0}"
    OUT+=" ${C_D}Registry Index: $((SCROLL_OFFSET + 1))-${TOTAL_BANS} of ${TOTAL_BANS} | Interval: 5s | Navigate: Up/Down Arrows | Press 'q' to exit.${C_0}\033[K"

    # --- FLUSH THE INSTANT RENDERING MATRIX ---
    echo -ne "\033[H${OUT}"

    # DEVSECOPS FIX: Keyboard hook logic forces CPU idle cycle
    read -s -n 1 -t 0.1 key || sleep 0.1
    if [[ "$key" == $'\x1b' ]]; then
        read -s -n 2 -t 0.05 next_keys || sleep 0.05
        if [[ "$next_keys" == "[A" ]]; then
            if (( SCROLL_OFFSET > 0 )); then SCROLL_OFFSET=$(( SCROLL_OFFSET - 1 )); fi
        elif [[ "$next_keys" == "[B" ]]; then
            if (( SCROLL_OFFSET < TOTAL_BANS - MAX_BANS )); then SCROLL_OFFSET=$(( SCROLL_OFFSET + 1 )); fi
        fi
    elif [[ "$key" == "q" || "$key" == "Q" ]]; then
        tput cnorm; echo -e "${C_0}"; clear; exit 0
    fi
done
EOF

    chmod +x "$TUI_BIN"
    ln -sf "$TUI_BIN" "/usr/local/bin/syswarden-dashboard" 2>/dev/null || true

    log "INFO" "TUI Engine successfully deployed. Run 'syswarden-tui' to view the full-screen terminal dashboard."
}
