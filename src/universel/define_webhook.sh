#!/usr/bin/env bash
# ==============================================================================
# SYSWARDEN - WEBHOOK DEFINITION MODULE
# ==============================================================================

define_webhook() {
    local mode="$1"

    # Bypass interactive prompts if CI/CD mode, but strictly persist the auto-config memory
    if [[ "$mode" == "auto" ]]; then
        echo -e "SYSWARDEN_ENABLE_WEBHOOK=\"${SYSWARDEN_ENABLE_WEBHOOK:-n}\"" >>"$CONF_FILE"
        if [[ -n "${SYSWARDEN_WEBHOOK_URL_DISCORD:-}" ]]; then
            echo -e "SYSWARDEN_WEBHOOK_URL_DISCORD=\"$SYSWARDEN_WEBHOOK_URL_DISCORD\"" >>"$CONF_FILE"
        fi
        if [[ -n "${SYSWARDEN_WEBHOOK_URL_TEAMS:-}" ]]; then
            echo -e "SYSWARDEN_WEBHOOK_URL_TEAMS=\"$SYSWARDEN_WEBHOOK_URL_TEAMS\"" >>"$CONF_FILE"
        fi
        return 0
    fi

    echo -e "\n${BLUE}======================================================================${NC}"
    echo -e "${GREEN}SysWarden - Webhook Notifications (Fail2ban L7)${NC}"
    echo -e "${BLUE}======================================================================${NC}"
    echo -e "Do you want to enable Webhook alerts for Fail2ban blocks?"
    echo -e "This pushes real-time alerts to Discord or MS Teams."
    read -rp "Enable Webhooks? (y/n) [n]: " enable_wh
    enable_wh=${enable_wh:-n}

    if [[ "$enable_wh" == "y" ]]; then
        echo -e "SYSWARDEN_ENABLE_WEBHOOK=\"y\"" >>"$CONF_FILE"

        echo -e "\nDiscord Webhook URL (Must be HTTPS - Leave empty to skip):"
        while true; do
            read -rp "> " wh_discord
            if [[ -z "$wh_discord" ]]; then
                break
            elif [[ "$wh_discord" =~ ^https:// ]]; then
                echo -e "SYSWARDEN_WEBHOOK_URL_DISCORD=\"$wh_discord\"" >>"$CONF_FILE"
                break
            else
                echo -e "${RED}[!] ERROR: Insecure protocol or invalid URL. Only HTTPS is permitted.${NC}"
            fi
        done

        echo -e "\nMS Teams Webhook URL (Must be HTTPS - Leave empty to skip):"
        while true; do
            read -rp "> " wh_teams
            if [[ -z "$wh_teams" ]]; then
                break
            elif [[ "$wh_teams" =~ ^https:// ]]; then
                echo -e "SYSWARDEN_WEBHOOK_URL_TEAMS=\"$wh_teams\"" >>"$CONF_FILE"
                break
            else
                echo -e "${RED}[!] ERROR: Insecure protocol or invalid URL. Only HTTPS is permitted.${NC}"
            fi
        done
    else
        echo -e "SYSWARDEN_ENABLE_WEBHOOK=\"n\"" >>"$CONF_FILE"
    fi
}
