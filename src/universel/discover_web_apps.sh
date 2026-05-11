discover_web_apps() {
    log "INFO" "Discovering active Web Servers and underlying applications..."

    # Reset global state to prevent persistence across reloads
    export SYSW_RCE_LOGS=""
    export SYSW_HAS_DOLIBARR=false
    export SYSW_HAS_PRESTASHOP=false
    export SYSW_HAS_WORDPRESS=false
    export SYSW_HAS_DRUPAL=false
    export SYSW_HAS_NEXTCLOUD=false
    export SYSW_HAS_PHPMYADMIN=false
    export SYSW_HAS_LARAVEL=false

    local web_conf_dirs=""
    local raw_web_logs=""

    # 1. Native detection of active Web Servers
    if command -v nginx >/dev/null 2>&1 && systemctl is-active --quiet nginx 2>/dev/null; then
        raw_web_logs="/var/log/nginx/*access.log /var/log/nginx/*error.log"
        web_conf_dirs="/etc/nginx"
    fi

    if command -v apache2 >/dev/null 2>&1 && systemctl is-active --quiet apache2 2>/dev/null; then
        raw_web_logs="${raw_web_logs:+$raw_web_logs }/var/log/apache2/*access.log /var/log/apache2/*error.log"
        web_conf_dirs="${web_conf_dirs:+$web_conf_dirs }/etc/apache2"
    elif command -v httpd >/dev/null 2>&1 && systemctl is-active --quiet httpd 2>/dev/null; then
        raw_web_logs="${raw_web_logs:+$raw_web_logs }/var/log/httpd/*access.log /var/log/httpd/*error_log"
        web_conf_dirs="${web_conf_dirs:+$web_conf_dirs }/etc/httpd"
    fi

    # --- LOG SANITIZER ENGINE (v0.32.3 - Global Expansion Fix) ---
    local verified_logs=""
    if [[ -n "$raw_web_logs" ]]; then
        for pattern in $raw_web_logs; do
            # Use a local array to force shell globbing expansion (e.g., *.log -> access.log error.log)
            # This ensures Fail2ban receives absolute file paths instead of literal wildcards
            # shellcheck disable=SC2086
            local files=($pattern)

            # Check if the first element of the expanded array physically exists on the disk
            # If the wildcard doesn't match anything, the first element remains the literal pattern
            if [[ -e "${files[0]}" ]]; then
                # Iterate through all expanded file paths and append them to the verified list
                for file in "${files[@]}"; do
                    # Add to the string with a space separator to comply with Fail2ban's logpath syntax
                    verified_logs="${verified_logs:+$verified_logs }$file"
                done
            fi
        done
    fi

    # Export a clean, space-separated list of REAL existing files to the global environment
    # This prevents Fail2ban from crashing (Exit 255) due to missing log targets or invalid commas
    export SYSW_RCE_LOGS="${verified_logs}"
    # -------------------------------------------------------------

    # 2. Application Heuristic Discovery (Only if a Web Server runs)
    if [[ -n "$web_conf_dirs" ]]; then
        # Fast configuration parsing (Reverse lookup)
        grep -riEq 'dolibarr' $web_conf_dirs 2>/dev/null && SYSW_HAS_DOLIBARR=true || true
        grep -riEq 'prestashop' $web_conf_dirs 2>/dev/null && SYSW_HAS_PRESTASHOP=true || true
        grep -riEq 'wp-config|wordpress' $web_conf_dirs 2>/dev/null && SYSW_HAS_WORDPRESS=true || true
        grep -riEq 'drupal' $web_conf_dirs 2>/dev/null && SYSW_HAS_DRUPAL=true || true
        grep -riEq 'nextcloud' $web_conf_dirs 2>/dev/null && SYSW_HAS_NEXTCLOUD=true || true
        grep -riEq 'phpmyadmin' $web_conf_dirs 2>/dev/null && SYSW_HAS_PHPMYADMIN=true || true
        grep -riEq 'laravel|artisan' $web_conf_dirs 2>/dev/null && SYSW_HAS_LARAVEL=true || true

        # Shallow filesystem probing (Depth 4 max for strict I/O optimization)
        for root in /var/www /usr/share/nginx/html /opt; do
            if [[ -d "$root" ]]; then
                find "$root" -maxdepth 4 -type f -name "wp-config.php" 2>/dev/null | head -n 1 | grep -q . && SYSW_HAS_WORDPRESS=true || true
                find "$root" -maxdepth 4 -type f -name "artisan" 2>/dev/null | head -n 1 | grep -q . && SYSW_HAS_LARAVEL=true || true
                find "$root" -maxdepth 4 -type d -name "phpmyadmin" 2>/dev/null | head -n 1 | grep -q . && SYSW_HAS_PHPMYADMIN=true || true
                find "$root" -maxdepth 4 -type d -name "drupal" 2>/dev/null | head -n 1 | grep -q . && SYSW_HAS_DRUPAL=true || true
                find "$root" -maxdepth 4 -type f -name "status.php" -path "*/nextcloud/*" 2>/dev/null | head -n 1 | grep -q . && SYSW_HAS_NEXTCLOUD=true || true
            fi
        done
    fi

    return 0
}
