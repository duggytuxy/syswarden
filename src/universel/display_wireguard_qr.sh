display_wireguard_qr() {
    # This runs at the VERY END to display the QR code cleanly without interrupting logs
    if [[ "${USE_WIREGUARD:-n}" == "y" ]] && [[ -f "/etc/wireguard/clients/admin-pc.conf" ]]; then
        echo -e "\n${RED}========================================================================${NC}"
        echo -e "${YELLOW}           WIREGUARD MANAGEMENT VPN - SCAN TO CONNECT${NC}"
        echo -e "${RED}========================================================================${NC}\n"

        # Generates a high-contrast ANSI UTF-8 QR Code directly in the terminal
        qrencode -t ansiutf8 </etc/wireguard/clients/admin-pc.conf

        echo -e "\n${GREEN}[✔] Client Configuration File Saved At:${NC} /etc/wireguard/clients/admin-pc.conf"
        echo -e "${YELLOW}Keep this secure! Scan this code with the WireGuard App to connect.${NC}"
    fi
}
