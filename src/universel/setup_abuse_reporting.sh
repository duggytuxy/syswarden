setup_abuse_reporting() {
    echo -e "\n${BLUE}=== Step 7: AbuseIPDB Reporting Setup ===${NC}"

    # --- ENTERPRISE COMPLIANCE KILL-SWITCH ---
    # Strictly prevents telemetry exfiltration regardless of other variables
    if [[ "${SYSWARDEN_ENTERPRISE_MODE:-n}" =~ ^[Yy]$ ]]; then
        log "WARN" "Enterprise Mode Active: Third-party telemetry (AbuseIPDB) is strictly DISABLED by corporate policy."
        return
    fi
    # -----------------------------------------

    # --- CI/CD AUTO MODE CHECK ---
    if [[ "${1:-}" == "auto" ]]; then
        response=${SYSWARDEN_ENABLE_ABUSE:-n}
        log "INFO" "Auto Mode: AbuseIPDB choice loaded via env var [${response}]"
    else
        echo "Would you like to automatically report blocked IPs to AbuseIPDB?"
        read -p "Enable AbuseIPDB reporting? (y/N): " response
    fi
    # -----------------------------

    if [[ "$response" =~ ^[Yy]$ ]]; then

        # --- HOTFIX: Strict Validation with CI/CD Auto-Mode support ---
        if [[ "${1:-}" == "auto" ]]; then
            USER_API_KEY=${SYSWARDEN_ABUSE_API_KEY:-""}
            if [[ -n "$USER_API_KEY" && ! "$USER_API_KEY" =~ ^[a-z0-9]{80}$ ]]; then
                log "ERROR" "Auto Mode: Invalid SYSWARDEN_ABUSE_API_KEY format. Must be exactly 80 lowercase letters/numbers. Skipping reporting setup."
                return
            fi
        else
            while true; do
                read -p "Enter your AbuseIPDB API Key: " USER_API_KEY
                if [[ -z "$USER_API_KEY" ]]; then
                    break
                elif [[ ! "$USER_API_KEY" =~ ^[a-z0-9]{80}$ ]]; then
                    echo -e "${RED}ERROR: Invalid API Key format. It must contain exactly 80 lowercase letters and numbers.${NC}"
                else
                    echo -e "${GREEN}[✔] API Key syntax validated.${NC}"
                    break
                fi
            done
        fi
        # ---------------------------------------------------------------------

        if [[ -z "$USER_API_KEY" ]]; then
            log "ERROR" "No API Key provided. Skipping reporting setup."
            return
        fi

        if [[ "${1:-}" == "auto" ]]; then
            REPORT_F2B=${SYSWARDEN_REPORT_F2B:-y}
            REPORT_FW=${SYSWARDEN_REPORT_FW:-y}
        else
            echo ""
            read -p "Report Fail2ban Bans (SSH/Web brute-force)? [Y/n]: " REPORT_F2B
            REPORT_F2B=${REPORT_F2B:-y}

            echo ""
            read -p "Report Firewall Drops (Port Scans/Blacklist)? [Y/n]: " REPORT_FW
            REPORT_FW=${REPORT_FW:-y}
        fi

        if [[ "$REPORT_F2B" =~ ^[Nn]$ ]] && [[ "$REPORT_FW" =~ ^[Nn]$ ]]; then
            log "INFO" "Both reporting options declined. Skipping."
            return
        fi

        log "INFO" "Configuring Unified SysWarden Reporter..."

        cat <<'EOF' >/usr/local/bin/syswarden_reporter.py
#!/usr/bin/env python3
import subprocess
import select
import re
import requests
import time
import ipaddress
import socket
import threading
import json
import os

# --- CONFIGURATION ---
API_KEY = "PLACEHOLDER_KEY"
REPORT_INTERVAL = 900  # 15 minutes
ENABLE_F2B = PLACEHOLDER_F2B
ENABLE_FW = PLACEHOLDER_FW
CACHE_FILE = "/var/lib/syswarden/abuse_cache.json"

# --- DEFINITIONS ---
reported_cache = {}
cache_lock = threading.Lock()

def load_cache():
    global reported_cache
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, 'r') as f:
                reported_cache = json.load(f)
        except Exception:
            reported_cache = {}

def save_cache():
    try:
        with cache_lock:
            with open(CACHE_FILE, 'w') as f:
                json.dump(reported_cache, f)
    except Exception as e:
        print(f"[WARN] Failed to write cache: {e}", flush=True)

def clean_cache():
    current_time = time.time()
    with cache_lock:
        expired = [ip for ip, ts in reported_cache.items() if current_time - ts > REPORT_INTERVAL]
        for ip in expired:
            del reported_cache[ip]
    if expired:
        save_cache()

def send_report(ip, categories, comment):
    current_time = time.time()
    
    # --- Strict IP Validation ---
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        print(f"[SKIP] Invalid IP detected by Regex: '{ip}'", flush=True)
        return

    # 1. Thread-safe cache check and update
    with cache_lock:
        if ip in reported_cache and (current_time - reported_cache[ip] < REPORT_INTERVAL):
            return 
        reported_cache[ip] = current_time
    save_cache()
    
    url = 'https://api.abuseipdb.com/api/v2/report'
    headers = {'Key': API_KEY, 'Accept': 'application/json'}
    full_comment = f"[{socket.gethostname()}] {comment}"
    params = {'ip': ip, 'categories': categories, 'comment': full_comment}

    try:
        response = requests.post(url, params=params, headers=headers)
        if response.status_code == 200:
            print(f"[SUCCESS] Reported {ip} -> Cats [{categories}]", flush=True)
            clean_cache()
        elif response.status_code == 429:
            print(f"[SKIP] IP {ip} already reported to AbuseIPDB recently (HTTP 429).", flush=True)
            clean_cache()
        else:
            print(f"[API ERROR] HTTP {response.status_code} : {response.text}", flush=True)
            with cache_lock:
                if ip in reported_cache:
                    del reported_cache[ip]
            save_cache()
    except Exception as e:
        print(f"[FAIL] Error: {e}", flush=True)
        with cache_lock:
            if ip in reported_cache:
                del reported_cache[ip]
        save_cache()

def monitor_logs():
    print("🚀 Monitoring logs (Unified SysWarden Reporter)...", flush=True)
    load_cache() # Load JSON cache on startup
    
    # --- BUG FIX: MULTIPLEXING FLAT FILES VS JOURNALCTL ---
    logs_to_tail = []
    for log_path in ['/var/log/kern-firewall.log', '/var/log/kern.log', '/var/log/syslog', '/var/log/messages', '/var/log/fail2ban.log']:
        if os.path.exists(log_path):
            logs_to_tail.append(log_path)
            
    # DEVSECOPS FIX: We route stderr to STDOUT so permission errors are caught by journalctl instead of being swallowed.
    if logs_to_tail:
        f = subprocess.Popen(['tail', '-F', '-n', '0', '-q'] + logs_to_tail, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    else:
        # Fallback if no physical logs exist
        f = subprocess.Popen(['journalctl', '-f', '-n', '0', '-o', 'cat'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    p = select.poll()
    p.register(f.stdout)

    # Logic: Universal Firewall Netfilter Regex (Matches Standard, Docker, GeoIP and ASN)
    regex_fw = re.compile(r"\[SysWarden-(BLOCK|DOCKER|GEO|ASN)\].*?SRC=([\d\.]+)")
    regex_dpt = re.compile(r"DPT=(\d+)")
    regex_f2b = re.compile(r"\[([a-zA-Z0-9_-]+)\]\s+Ban\s+([\d\.]+)")

    while True:
        if p.poll(100):
            line = f.stdout.readline().decode('utf-8', errors='ignore')
            
            # DEVSECOPS FIX: CPU Time-Bomb Prevention. 
            # If tail dies or hits EOF, it returns an empty string. We must break out.
            if not line:
                print("[FATAL] Log process died or reached EOF. Exiting to allow Systemd to restart the service.", flush=True)
                break

            # --- FIREWALL LOGIC ---
            if ENABLE_FW:
                match_fw = regex_fw.search(line)
                if match_fw:
                    fw_type = match_fw.group(1) # Extract BLOCK, DOCKER, GEO or ASN
                    ip = match_fw.group(2)
                    
                    # Dynamic port extraction (Fallback to Port 0 for ICMP/IGMP)
                    match_port = regex_dpt.search(line)
                    port = int(match_port.group(1)) if match_port else 0
                    
                    # Base: Scanning for open ports and vulnerable services (Cat 14)
                    cats = ["14"]
                    attack_type = "Port Scan / Probing"

                    # Dynamic AbuseIPDB comment customization based on L2/L3 source
                    if fw_type == "GEO":
                        attack_type = "Traffic from Blocked Country (GeoIP)"
                    elif fw_type == "ASN":
                        attack_type = "Traffic from Malicious Hoster (ASN)"
                    elif port in [80, 443, 4443, 8080, 8443]: cats.extend(["15", "21"]); attack_type = "Web Attack"
                    elif port in [22, 2222, 22222]: cats.extend(["18", "22"]); attack_type = "SSH Attack"
                    elif port == 23: cats.extend(["18", "23"]); attack_type = "Telnet IoT Attack"
                    elif port == 88: cats.extend(["15", "18"]); attack_type = "Kerberos Attack"
                    elif port in [139, 445]: cats.extend(["15", "18"]); attack_type = "SMB/Possible Ransomware Attack"
                    elif port in [389, 636]: cats.extend(["15", "18"]); attack_type = "LDAP/LDAPS Attack"
                    elif port in [1433, 3306, 5432, 27017, 6379, 9200, 11211]: cats.extend(["15", "18"]); attack_type = "Database/Cache Attack"
                    elif port in [8006, 9090, 3000, 2375, 2376]: cats.extend(["15", "21"]); attack_type = "Infra/DevOps Attack"
                    elif port == 4444: cats.extend(["15", "20"]); attack_type = "Possible C2 Host"
                    elif port in [3389, 5900]: cats.extend(["18"]); attack_type = "RDP/VNC Attack"
                    elif port == 21: cats.extend(["5", "18"]); attack_type = "FTP Attack"
                    elif port in [25, 110, 143, 465, 587, 993, 995]: cats.extend(["11", "18"]); attack_type = "Mail Service Attack"
                    elif port in [1080, 3128, 8118]: cats.extend(["9", "15"]); attack_type = "Open Proxy Probe"
                    elif port in [5060, 5061]: cats.extend(["8", "18"]); attack_type = "SIP/VoIP Attack"
                    elif port in [1194, 51820, 51821]: cats.extend(["15", "18"]); attack_type = "VPN Probe"

                    cats = list(set(cats)) # Deduplicate array before sending
                    threading.Thread(target=send_report, args=(ip, ",".join(cats), f"Blocked by SysWarden Firewall ({attack_type})")).start()
                    continue

            # --- FAIL2BAN LOGIC (Layer 7) ---
            if ENABLE_F2B:
                match_f2b = regex_f2b.search(line)
                if match_f2b and "SysWarden-BLOCK" not in line:
                    jail = match_f2b.group(1).lower()
                    ip = match_f2b.group(2)
                    
                    cats = []
                    
                    # 1. Web Vulnerability Scanners & Pentest Tools
                    if any(x in jail for x in ["badbot", "scanner", "apimapper", "secretshunter", "idor"]): cats.extend(["14", "15", "19", "21"])
                    # 2. SQLi & XSS
                    elif "sqli" in jail or "xss" in jail: cats.extend(["15", "16", "21"])
                    # 3. RCE, WebShells, LFI/RFI, SSRF, JNDI, ModSecurity, Obfuscation
                    elif any(x in jail for x in ["revshell", "webshell", "lfi", "ssrf", "jndi", "modsec", "homoglyph"]): cats.extend(["15", "21"])
                    # 4. Layer 7 DDoS (HTTP Flood)
                    elif "httpflood" in jail: cats.extend(["4", "21"])
                    # 5. AI Bots & Scrapers
                    elif "aibot" in jail: cats.extend(["19", "21"])
                    # 6. Proxy Abuse / Tunneling
                    elif any(x in jail for x in ["proxy-abuse", "squid", "haproxy"]): cats.extend(["9", "15", "21"])
                    # 7. SSH Brute-Force
                    elif "ssh" in jail: cats.extend(["18", "22"])
                    # 8. FTP Brute-Force
                    elif "vsftpd" in jail or "ftp" in jail: cats.extend(["5", "18"])
                    # 9. Mail Service Abuse
                    elif any(x in jail for x in ["postfix", "sendmail", "dovecot"]): cats.extend(["11", "18"])
                    # 10. Database & Middleware Brute-Force
                    elif any(x in jail for x in ["mariadb", "mongodb", "redis", "rabbitmq"]): cats.extend(["15", "18"])
                    # 11. Privilege Escalation & Auditd
                    elif any(x in jail for x in ["privesc", "auditd", "proxmox"]): cats.extend(["15", "18"])
                    # 12. Web App Logins (Auth/CMS/SSO/Generic)
                    elif any(x in jail for x in ["auth", "generic-auth", "wordpress", "drupal", "nextcloud", "phpmyadmin", "laravel", "grafana", "zabbix", "gitea", "cockpit", "vaultwarden", "sso", "odoo", "prestashop", "atlassian"]): cats.extend(["18", "21"])
                    # 13. TLS/SSL Layer Attacks (TLS Fuzzing & SNI Scanners)
                    elif "tls" in jail: cats.extend(["14", "15", "21"])
                    # 14. VPN
                    elif "wireguard" in jail or "openvpn" in jail: cats.extend(["15", "18"])
                    # 15. VoIP
                    elif "asterisk" in jail: cats.extend(["8", "18"])
                    # 16. Portscan
                    elif "portscan" in jail: cats.extend(["14"])
                    # 17. Persistent Attacker (Recidive) / Horizontal Movement
                    elif "recidive" in jail: cats.extend(["14", "15", "18"])
                    # 18. Fallback
                    else: cats.extend(["15", "18"])

                    cats = list(set(cats)) # Deduplicate array before sending
                    threading.Thread(target=send_report, args=(ip, ",".join(cats), f"Banned by Fail2ban (Jail: {match_f2b.group(1)})")).start()

if __name__ == "__main__":
    monitor_logs()
EOF

        # Replace placeholders based on user choices
        local PY_F2B="False"
        if [[ "$REPORT_F2B" =~ ^[Yy]$ ]]; then PY_F2B="True"; fi
        local PY_FW="False"
        if [[ "$REPORT_FW" =~ ^[Yy]$ ]]; then PY_FW="True"; fi

        sed -i "s/PLACEHOLDER_KEY/$USER_API_KEY/" /usr/local/bin/syswarden_reporter.py
        sed -i "s/PLACEHOLDER_F2B/$PY_F2B/" /usr/local/bin/syswarden_reporter.py
        sed -i "s/PLACEHOLDER_FW/$PY_FW/" /usr/local/bin/syswarden_reporter.py

        # --- SECURITY FIX: SECURE ABUSEIPDB API KEY (CWE-732: Incorrect Permission Assignment for Critical Resource) ---
        # The python script contains the API key in plain text.
        # We enforce absolute root ownership so no non-privileged user can view the code.
        chown root:root /usr/local/bin/syswarden_reporter.py
        chmod 700 /usr/local/bin/syswarden_reporter.py
        # ----------------------------------------------

        log "INFO" "Creating systemd service for Reporter..."
        cat <<EOF >/etc/systemd/system/syswarden-reporter.service
[Unit]
Description=SysWarden Unified Reporter
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/syswarden_reporter.py
Restart=always

# --- SECURITY & LEAST PRIVILEGE ---
# DEVSECOPS FIX: Removed DynamicUser=yes. The telemetry script MUST have the right 
# to read /var/log/kern-firewall.log which is strictly locked to root (600) to prevent log spoofing.
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
NoNewPrivileges=yes
# Ensure script can write its cache file securely 
StateDirectory=syswarden
# ----------------------------------

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        systemctl enable --now syswarden-reporter
        log "INFO" "AbuseIPDB Unified Reporter is ACTIVE."

    else
        log "INFO" "Skipping AbuseIPDB reporting setup."
    fi
}
