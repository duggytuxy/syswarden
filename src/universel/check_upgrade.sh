check_upgrade() {
    echo -e "\n${BLUE}=== SysWarden Upgrade Checker (Universal) ===${NC}"

    # --- DEVSECOPS FIX: CAPTURE ABSOLUTE PATH EARLY ---
    # We must resolve $0 before any 'cd' commands alter the current working directory,
    # otherwise realpath resolves relative to the temp folder, causing a cp self-collision.
    local current_script
    current_script=$(realpath "$0" 2>/dev/null || readlink -f "$0" 2>/dev/null || echo "${PWD}/${0#./}")

    log "INFO" "Checking for updates on GitHub API..."

    local api_url="https://api.github.com/repos/duggytuxy/syswarden/releases/latest"
    local response

    response=$(curl -sS --connect-timeout 5 "$api_url") || {
        log "ERROR" "Failed to connect to GitHub API."
        exit 1
    }

    local download_url
    download_url=$(echo "$response" | grep -o '"browser_download_url": "[^"]*/install-syswarden\.sh"' | head -n 1 | cut -d'"' -f4)

    local hash_url
    hash_url=$(echo "$response" | grep -o '"browser_download_url": "[^"]*/install-syswarden\.sh\.sha256"' | head -n 1 | cut -d'"' -f4)

    if [[ -z "$download_url" ]]; then
        echo -e "${GREEN}No specific update found for the Universal version in the latest release. You are up to date!${NC}"
        return
    fi

    local latest_version
    latest_version=$(echo "$response" | grep -o '"tag_name": "[^"]*"' | head -n 1 | cut -d'"' -f4)

    echo -e "Current Version : ${YELLOW}${VERSION}${NC}"
    echo -e "Latest Version  : ${GREEN}${latest_version}${NC}\n"

    if [[ "$VERSION" == "$latest_version" ]]; then
        echo -e "${GREEN}You are already using the latest version of SysWarden!${NC}"
    else
        echo -e "${YELLOW}A new Universal version ($latest_version) is available!${NC}"

        # --- DEVSECOPS: INTERACTIVE CONFIRMATION ---
        read -p "Do you want to proceed with the automated in-place upgrade now? (y/N): " proceed_upgrade
        if [[ ! "$proceed_upgrade" =~ ^[Yy]$ ]]; then
            echo -e "${YELLOW}Upgrade aborted by user. System remains on $VERSION.${NC}"
            return
        fi

        # --- SECURITY FIX: MITM PROTECTION & SECURE UPDATE (CWE-494: Download of Code Without Integrity Check) ---
        echo -e "${YELLOW}Downloading and verifying update securely...${NC}"

        # --- HOTFIX: SAME-FILE COLLISION PREVENTION ---
        # Create an isolated sub-directory for the update payload to guarantee
        # it never collides with the script's current execution path.
        local UPGRADE_DIR="$TMP_DIR/syswarden_upgrade_payload"
        mkdir -p "$UPGRADE_DIR"

        wget --https-only --secure-protocol=TLSv1_2 --max-redirect=2 --no-hsts -qO "$UPGRADE_DIR/install-syswarden.sh" "$download_url"
        wget --https-only --secure-protocol=TLSv1_2 --max-redirect=2 --no-hsts -qO "$UPGRADE_DIR/install-syswarden.sh.sha256" "$hash_url"

        cd "$UPGRADE_DIR" || exit 1

        if ! sha256sum -c install-syswarden.sh.sha256 --status; then
            echo -e "${RED}[ CRITICAL ALERT ]${NC}"
            echo -e "${RED}The downloaded script failed cryptographic validation!${NC}"
            echo -e "${RED}Possible causes: Man-In-The-Middle (MITM) attack, DNS poisoning, or incomplete download.${NC}"
            echo -e "${RED}Update aborted to protect system integrity.${NC}"
            rm -rf "$UPGRADE_DIR"
            exit 1
        fi

        echo -e "${GREEN}Checksum validated successfully. Preparing in-place upgrade...${NC}"

        # --- PRE-UPGRADE: SURGICAL PROCESS TERMINATION ---
        # We must kill background telemetry and UI processes to avoid zombie orphans
        # or file locking issues during the transition to the new script version.
        log "INFO" "Terminating existing SysWarden background processes safely..."
        pkill -9 -f syswarden-telemetry 2>/dev/null || true
        pkill -9 -f syswarden_reporter 2>/dev/null || true

        if command -v systemctl >/dev/null; then
            systemctl stop syswarden-ui 2>/dev/null || true
            systemctl stop syswarden-reporter 2>/dev/null || true
        fi

        # --- IN-PLACE SCRIPT REPLACEMENT ---
        log "INFO" "Replacing current orchestrator at $current_script..."

        # We explicitly copy instead of move in case the OS locks the executing file
        cp -f "$UPGRADE_DIR/install-syswarden.sh" "$current_script"
        chmod 700 "$current_script"

        # Configuration sanity check
        if [[ ! -f "$CONF_FILE" ]]; then
            log "WARN" "Configuration file $CONF_FILE missing! The upgrade will behave as a fresh install."
        else
            log "INFO" "Configuration file $CONF_FILE found. User settings will be strictly preserved."
        fi

        echo -e "${GREEN}In-place upgrade sequence initiated. Handing over to the new version...${NC}"

        # --- EXECUTE NEW VERSION (PROCESS HANDOFF) ---
        exec bash "$current_script" update
    fi
}
