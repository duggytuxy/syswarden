detect_protected_services() {
    echo -e "\n${BLUE}=== Step 5: Service Integration Check ===${NC}"
    if command -v fail2ban-client >/dev/null && systemctl is-active --quiet fail2ban; then
        JAILS=$(fail2ban-client status | grep "Jail list" | sed 's/.*Jail list://g')
        log "INFO" "Fail2ban is ACTIVE. Jails: ${JAILS}"
    else
        log "WARN" "Fail2ban not active."
    fi
}
