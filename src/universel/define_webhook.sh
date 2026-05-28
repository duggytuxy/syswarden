#!/usr/bin/env bash
# ==============================================================================
# SYSWARDEN - WEBHOOK DEFINITION MODULE
# ==============================================================================

define_webhook() {
    local mode="$1"

    # Bypass if CI/CD mode
    if [[ "$mode" == "auto" ]]; then
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

        echo -e "\nDiscord Webhook URL (Leave empty to skip):"
        read -rp "> " wh_discord
        if [[ -n "$wh_discord" ]]; then
            echo -e "SYSWARDEN_WEBHOOK_URL_DISCORD=\"$wh_discord\"" >>"$CONF_FILE"
        fi

        echo -e "\nMS Teams Webhook URL (Leave empty to skip):"
        read -rp "> " wh_teams
        if [[ -n "$wh_teams" ]]; then
            echo -e "SYSWARDEN_WEBHOOK_URL_TEAMS=\"$wh_teams\"" >>"$CONF_FILE"
        fi
    else
        echo -e "SYSWARDEN_ENABLE_WEBHOOK=\"n\"" >>"$CONF_FILE"
    fi
}
