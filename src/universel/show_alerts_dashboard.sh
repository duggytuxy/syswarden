show_alerts_dashboard() {
    # Trap Ctrl+C/Exit to restore cursor safely
    trap 'tput cnorm; echo -e "\n${GREEN}Exiting Dashboard...${NC}"; exit 0' INT TERM
    tput civis # Hide cursor for cleaner UI

    echo -e "\n${BLUE}=========================================================================================${NC}"
    echo -e "${GREEN}                        SYSWARDEN CLI DASHBOARD (Live Alerts)                            ${NC}"
    echo -e "${BLUE}=========================================================================================${NC}"
    echo -e "${YELLOW}[i] Tailing live Threat Intelligence Logs... (Press Ctrl+C to stop)${NC}\n"

    # --- TABLE HEADER ---
    printf "\033[1m\033[36m%-19s | %-16s | %-10s | %-15s | %s\033[0m\n" "TIMESTAMP" "MODULE" "ACTION" "SOURCE IP" "TARGET (PORT/JAIL)"
    echo -e "${BLUE}--------------------+------------------+------------+-----------------+--------------------${NC}"

    # HOTFIX: Mawk (Debian/Ubuntu) Input Buffering Bypass via Function Wrapper
    # Avoids IFS strict-mode word-splitting issues while injecting the '-W interactive' flag.
    syswarden_awk() {
        if awk -W version 2>&1 | grep -qi "mawk"; then
            awk -W interactive "$@"
        else
            awk "$@"
        fi
    }

    # Multiplex Systemd Journal and Flat files safely without creating orphan processes
    (
        P1=""
        if command -v journalctl >/dev/null 2>&1; then
            journalctl -k -f --no-pager 2>/dev/null &
            P1=$!
        fi

        P2=""
        local LOGS=()
        # HOTFIX: Integration of all possible log targets across Debian, Alpine, and Slackware
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

        trap '[[ -n "$P1" ]] && kill $P1 2>/dev/null; [[ -n "$P2" ]] && kill $P2 2>/dev/null' EXIT
        wait
    ) | syswarden_awk '
    BEGIN {
        # Map syslog months to ISO numbers and fetch current year
        m["Jan"]="01"; m["Feb"]="02"; m["Mar"]="03"; m["Apr"]="04"; m["May"]="05"; m["Jun"]="06";
        m["Jul"]="07"; m["Aug"]="08"; m["Sep"]="09"; m["Oct"]="10"; m["Nov"]="11"; m["Dec"]="12";
        "date +%Y" | getline current_year; close("date +%Y")
    }
    {
        # --- 1. FIREWALL ALERTS PROCESSING ---
        if ($0 ~ /SysWarden-BLOCK|SysWarden-GEO|SysWarden-ASN|Catch-All/) {
            
            # Universal Date Parsing (Supports ISO-8601 from Debian 13 and Legacy Syslog)
            if ($1 ~ /^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T/) {
                date = substr($1, 1, 10) " " substr($1, 12, 8)
            } else if ($1 in m) {
                date = sprintf("%s-%s-%02d %s", current_year, m[$1], $2, $3)
            } else {
                date = $1 " " $2 " " $3
            }
            
            module = "SysWarden-CATCH"
            if (match($0, /\[SysWarden-[A-Za-z]+\]/)) {
                module = substr($0, RSTART+1, RLENGTH-2)
            }
            
            src = "N/A"
            # IPv4 Strict Matching
            if (match($0, /SRC=[0-9.]+/)) {
                src = substr($0, RSTART+4, RLENGTH-4)
            }
            
            # --- HOTFIX: Dynamic Target Info (Port vs Protocol for ICMP/IGMP) ---
            target_info = "PORT: N/A"
            if (match($0, /DPT=[0-9]+/)) {
                # Extract port if present (TCP/UDP)
                target_info = "PORT: " substr($0, RSTART+4, RLENGTH-4)
            } else if (match($0, /PROTO=[A-Za-z0-9]+/)) {
                # Fallback to protocol if no port provided (e.g. ICMP)
                target_info = "PROTO: " substr($0, RSTART+6, RLENGTH-6)
            }
            
            printf "\033[1;30m%-19s\033[0m | \033[1;34m%-16s\033[0m | \033[1;31m%-10s\033[0m | \033[1;33m%-15s\033[0m | \033[1;36m%s\033[0m\n", date, module, "BLOCKED", src, target_info
            
            # HOTFIX: Universal stdout flush (Works on Debian mawk, Alpine busybox, RHEL gawk)
            system("")
            next
        }
        
        # --- 2. FAIL2BAN ALERTS PROCESSING ---
        if (($0 ~ /Ban / || $0 ~ /Found /) && $0 !~ /Restore/) {
            date = $1 " " $2
            sub(/,.*/, "", date)
            
            jail = "Unknown"
            if (match($0, /\[[-_A-Za-z0-9]+\] (Found|Ban)/)) {
                str = substr($0, RSTART, RLENGTH)
                if (match(str, /\[[-_A-Za-z0-9]+\]/)) {
                    jail = substr(str, RSTART+1, RLENGTH-2)
                }
            }
            
            act = ($0 ~ /Ban /) ? "BANNED" : "DETECTED"
            act_color = ($0 ~ /Ban /) ? "\033[1;31m" : "\033[1;35m"
            
            ip = "Unknown"
            # IPv4 Strict Matching
            if (match($0, /(Found|Ban) [0-9.]+/)) {
                ip = substr($0, RSTART, RLENGTH)
                sub(/(Found|Ban) /, "", ip)
            }
            
            printf "\033[1;30m%-19s\033[0m | \033[1;35m%-16s\033[0m | %s%-10s\033[0m | \033[1;33m%-15s\033[0m | \033[1;36mJAIL: %s\033[0m\n", date, "FAIL2BAN WAF", act_color, act, ip, jail
            
            # HOTFIX: Universal stdout flush
            system("")
        }
    }' || true

    tput cnorm # Restore cursor
}
