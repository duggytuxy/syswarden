show_alerts_dashboard() {
    # --- HTOP-STYLE TERMINAL INITIALIZATION ---
    # Use alternate screen buffer to prevent scrollback pollution
    tput smcup 2>/dev/null || clear
    tput civis 2>/dev/null || true # Hide cursor

    # Clean exit strategy: Kill multiplexers, restore cursor, and restore original screen
    trap 'tput cnorm 2>/dev/null; tput rmcup 2>/dev/null || clear; echo -e "\n\033[1;32mExiting Dashboard...\033[0m"; exit 0' INT TERM

    # --- Fetch Fail2ban IgnoreIPs for WhiteList status (IGNORED) ---
    local F2B_IGNORE=""
    if command -v fail2ban-client >/dev/null 2>&1; then
        F2B_IGNORE=$(fail2ban-client get system ignoreip 2>/dev/null | tr '\n' ' ')
    fi
    # Fallback to direct config parsing if daemon isn't responding
    if [[ -z "$F2B_IGNORE" ]] && [[ -f /etc/fail2ban/jail.local ]]; then
        F2B_IGNORE=$(grep -m 1 -E "^[[:space:]]*ignoreip" /etc/fail2ban/jail.local | awk -F'=' '{print $2}')
    fi
    if [[ -n "$SYSWARDEN_WHITELIST_IPS" ]]; then
        F2B_IGNORE="$F2B_IGNORE $SYSWARDEN_WHITELIST_IPS"
    fi
    F2B_IGNORE=$(echo "$F2B_IGNORE" | tr ',' ' ' | tr -s ' ' | sed 's/^[ \t]*//;s/[ \t]*$//')

    # HOTFIX: Mawk (Debian/Ubuntu) Input Buffering Bypass via Function Wrapper
    syswarden_awk() {
        if awk -W version 2>&1 | grep -qi "mawk"; then
            awk -W interactive "$@"
        else
            awk "$@"
        fi
    }

    # --- ASYNCHRONOUS MULTIPLEXER ---
    (
        # 1. Asynchronous Heartbeat Tick (Forces screen redraw every 2 seconds even if logs are quiet)
        while true; do
            echo "SYSWARDEN_TICK"
            sleep 2
        done &
        P0=$!

        # 2. Systemd Journal Stream
        P1=""
        if command -v journalctl >/dev/null 2>&1; then
            journalctl -k -f --no-pager 2>/dev/null &
            P1=$!
        fi

        # 3. Flat Files Stream
        P2=""
        local LOGS=()
        [[ -f /var/log/kern-firewall.log ]] && LOGS+=(/var/log/kern-firewall.log)
        [[ -f /var/log/auth-syswarden.log ]] && LOGS+=(/var/log/auth-syswarden.log)
        [[ -f /var/log/fail2ban.log ]] && LOGS+=(/var/log/fail2ban.log)
        [[ -f /var/log/kern.log ]] && LOGS+=(/var/log/kern.log)
        [[ -f /var/log/syslog ]] && LOGS+=(/var/log/syslog)
        [[ -f /var/log/messages ]] && LOGS+=(/var/log/messages)

        if [[ ${#LOGS[@]} -gt 0 ]]; then
            tail -F -q "${LOGS[@]}" 2>/dev/null &
            P2=$!
        fi

        trap '[[ -n "$P0" ]] && kill $P0 2>/dev/null; [[ -n "$P1" ]] && kill $P1 2>/dev/null; [[ -n "$P2" ]] && kill $P2 2>/dev/null' EXIT
        wait
    ) | syswarden_awk -v ignored_list="$F2B_IGNORE" '
    BEGIN {
        m["Jan"]="01"; m["Feb"]="02"; m["Mar"]="03"; m["Apr"]="04"; m["May"]="05"; m["Jun"]="06";
        m["Jul"]="07"; m["Aug"]="08"; m["Sep"]="09"; m["Oct"]="10"; m["Nov"]="11"; m["Dec"]="12";
        "date +%Y" | getline current_year; close("date +%Y")
        
        split(ignored_list, ig_arr, " ")
        for (i in ig_arr) {
            if (ig_arr[i] != "") whitelist[ig_arr[i]] = 1
        }
        
        # Ring Buffer Initialization
        hist_len = 0
        ring_size = 200
    }
    
    function ip2int(ip,   octets) {
        split(ip, octets, ".")
        return (octets[1] * 16777216) + (octets[2] * 65536) + (octets[3] * 256) + octets[4]
    }
    
    function in_cidr(ip, cidr,   parts, base_ip, mask, ip_int, base_int, shift, divisor) {
        if (cidr !~ /\//) return ip == cidr
        split(cidr, parts, "/")
        base_ip = parts[1]
        mask = parts[2]
        if (mask == "") mask = 32
        if (mask == 0) return 1
        ip_int = ip2int(ip)
        base_int = ip2int(base_ip)
        shift = 32 - mask
        divisor = 2 ^ shift
        return int(ip_int / divisor) == int(base_int / divisor)
    }

    function is_whitelisted(ip,   w) {
        for (w in whitelist) if (in_cidr(ip, w)) return 1
        return 0
    }

    function draw_dashboard() {
        # 1. Fetch Dynamic Terminal Size
        "tput lines" | getline ROWS; close("tput lines")
        if (ROWS == "" || ROWS < 15) ROWS = 24
        
        # 2. Extract Native Telemetry using POSIX Awk bounds
        uptime = "N/A"; ram_u = 0; ram_t = 0; load = "0.00"; l3 = 0; l7 = 0; jails = 0;
        while ((getline line < "/etc/syswarden/ui/data.json") > 0) {
            if (match(line, /"uptime": *"[^"]+"/)) {
                uptime = substr(line, RSTART, RLENGTH); sub(/.*"uptime": *"/, "", uptime); sub(/".*/, "", uptime)
            }
            if (match(line, /"load_average": *"[^"]+"/)) {
                load = substr(line, RSTART, RLENGTH); sub(/.*"load_average": *"/, "", load); sub(/".*/, "", load)
            }
            if (match(line, /"ram_used_mb": *[0-9]+/)) {
                ram_u = substr(line, RSTART, RLENGTH); sub(/.*"ram_used_mb": */, "", ram_u); ram_u += 0
            }
            if (match(line, /"ram_total_mb": *[0-9]+/)) {
                ram_t = substr(line, RSTART, RLENGTH); sub(/.*"ram_total_mb": */, "", ram_t); ram_t += 0
            }
            if (match(line, /"global_blocked": *[0-9]+/)) {
                l3 = substr(line, RSTART, RLENGTH); sub(/.*"global_blocked": */, "", l3); l3 += 0
            }
            if (match(line, /"total_banned": *[0-9]+/)) {
                l7 = substr(line, RSTART, RLENGTH); sub(/.*"total_banned": */, "", l7); l7 += 0
            }
            if (match(line, /"active_jails": *[0-9]+/)) {
                jails = substr(line, RSTART, RLENGTH); sub(/.*"active_jails": */, "", jails); jails += 0
            }
        }
        close("/etc/syswarden/ui/data.json")
        
        # 3. Bar Chart Mathematics
        ram_pct = (ram_t > 0) ? int((ram_u / ram_t) * 100) : 0
        fill = int((ram_pct * 15) / 100)
        empty = 15 - fill
        ram_bar = sprintf("%*s", fill, ""); gsub(/ /, "|", ram_bar)
        ram_space = sprintf("%*s", empty, "")
        
        split(load, l_arr, ",")
        l_val = l_arr[1] + 0
        l_pct = int(l_val * 10)
        if (l_pct > 15) l_pct = 15
        l_fill = l_pct
        l_empty = 15 - l_fill
        load_bar = sprintf("%*s", l_fill, ""); gsub(/ /, "|", load_bar)
        load_space = sprintf("%*s", l_empty, "")
        
        # 4. Engine Rendering (Flicker-Free Htop Layout)
        printf "\033[2J\033[H"
        printf "\033[1;34m+-----------------------------------------------------------------------------+\033[0m\n"
        printf "\033[1;34m|\033[0m \033[1;32mSYSWARDEN CLI DASHBOARD (Live HTOP Mode)\033[0m                            v0.34.5 \033[1;34m|\033[0m\n"
        printf "\033[1;34m+-----------------------------------------+-----------------------------------+\033[0m\n"
        printf "\033[1;34m|\033[0m RAM:  [\033[1;32m%-15s\033[0m] %3d%%          \033[1;34m|\033[0m Uptime:       %-20s\033[1;34m|\033[0m\n", ram_bar ram_space, ram_pct, uptime
        printf "\033[1;34m|\033[0m Load: [\033[1;33m%-15s\033[0m] %-4.2f         \033[1;34m|\033[0m Active Jails: %-20d\033[1;34m|\033[0m\n", load_bar load_space, l_val, jails
        printf "\033[1;34m|\033[0m L3 Kernel Blocks: \033[1;36m%-21d\033[0m \033[1;34m|\033[0m L7 WAF Bans:  \033[1;31m%-20d\033[0m\033[1;34m|\033[0m\n", l3, l7
        printf "\033[1;34m+-----------------------------------------+-----------------------------------+\033[0m\n"
        
        printf "\033[1m\033[36m%-19s | %-16s | %-10s | %-15s | %s\033[0m\n", "TIMESTAMP", "MODULE", "ACTION", "SOURCE IP", "TARGET (PORT/JAIL)"
        printf "\033[1;34m--------------------+------------------+------------+-----------------+--------------------\033[0m\n"
        
        # 5. Ring Buffer Dump (Last N elements fitting the screen)
        max_logs = ROWS - 10
        if (max_logs < 5) max_logs = 5
        
        start_idx = hist_len - max_logs
        if (start_idx < 0) start_idx = 0
        
        for (i = start_idx; i < hist_len; i++) {
            idx = i % ring_size
            print hist[idx]
        }
        
        system("") # Universal stdout flush
    }

    # Heartbeat Trap
    $0 ~ /^SYSWARDEN_TICK/ {
        draw_dashboard()
        next
    }

    {
        parsed = ""
        
        # --- 1. FIREWALL ALERTS PROCESSING ---
        if ($0 ~ /SysWarden-BLOCK|SysWarden-GEO|SysWarden-ASN|Catch-All/) {
            if ($1 ~ /^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T/) {
                date = substr($1, 1, 10) " " substr($1, 12, 8)
            } else if ($1 in m) {
                date = sprintf("%s-%s-%02d %s", current_year, m[$1], $2, $3)
            } else {
                date = $1 " " $2 " " $3
            }
            
            module = "SysWarden-CATCH"
            if (match($0, /\[SysWarden-[A-Za-z]+\]/)) module = substr($0, RSTART+1, RLENGTH-2)
            
            src = "N/A"
            if (match($0, /SRC=[0-9.]+/)) src = substr($0, RSTART+4, RLENGTH-4)
            
            target_info = "PORT: N/A"
            if (match($0, /DPT=[0-9]+/)) target_info = "PORT: " substr($0, RSTART+4, RLENGTH-4)
            else if (match($0, /PROTO=[A-Za-z0-9]+/)) target_info = "PROTO: " substr($0, RSTART+6, RLENGTH-6)
            
            parsed = sprintf("\033[1;30m%-19s\033[0m | \033[1;34m%-16s\033[0m | \033[1;31m%-10s\033[0m | \033[1;33m%-15s\033[0m | \033[1;36m%s\033[0m", date, module, "BLOCKED", src, target_info)
        }
        
        # --- 2. FAIL2BAN ALERTS PROCESSING ---
        else if ($0 ~ /fail2ban/i && ($0 ~ /Ban / || $0 ~ /Found /) && $0 !~ /Restore/) {
            if ($1 ~ /^[0-9]{4}-[0-9]{2}-[0-9]{2}T/) {
                date = substr($1, 1, 10) " " substr($1, 12, 8)
            } else if ($1 ~ /^[0-9]{4}-[0-9]{2}-[0-9]{2}/) {
                date = substr($1, 1, 10) " " substr($2, 1, 8)
            } else if ($1 in m) {
                date = sprintf("%s-%s-%02d %s", current_year, m[$1], $2, $3)
            } else {
                date = $1 " " $2 " " $3; sub(/,.*/, "", date)
            }
            
            jail = "Unknown"
            if (match($0, /\[[-_A-Za-z0-9]+\] (Found|Ban) /)) {
                str = substr($0, RSTART, RLENGTH)
                if (match(str, /\[[-_A-Za-z0-9]+\]/)) jail = substr(str, RSTART+1, RLENGTH-2)
            }
            
            act = ($0 ~ /Ban /) ? "BANNED" : "DETECTED"
            act_color = ($0 ~ /Ban /) ? "\033[1;31m" : "\033[1;35m"
            
            ip = "Unknown"
            if (match($0, /(Found|Ban)[ \t]+[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/)) {
                str = substr($0, RSTART, RLENGTH)
                if (match(str, /[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/)) ip = substr(str, RSTART, RLENGTH)
            }
            
            if (act == "DETECTED" && is_whitelisted(ip)) {
                act = "IGNORED"
                act_color = "\033[1;32m"
            }
            
            parsed = sprintf("\033[1;30m%-19s\033[0m | \033[1;35m%-16s\033[0m | %s%-10s\033[0m | \033[1;33m%-15s\033[0m | \033[1;36mJAIL: %s\033[0m", date, "FAIL2BAN WAF", act_color, act, ip, jail)
        }
        
        # If valid, inject into the Ring Buffer and force redraw
        if (parsed != "") {
            hist[hist_len % ring_size] = parsed
            hist_len++
            draw_dashboard()
        }
    }' || true

    # Clean Exit Trigger
    tput cnorm 2>/dev/null
    tput rmcup 2>/dev/null || clear
}
