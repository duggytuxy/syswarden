check_upgrade() {
    echo -e "\n${BLUE}=== SysWarden Upgrade Checker (Enterprise) ===${NC}"

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

    # DEVSECOPS FIX: Append '|| true' to prevent silent crashes from 'set -e'
    local latest_version
    latest_version=$(echo "$response" | grep -o '"tag_name": "[^"]*"' | head -n 1 | cut -d'"' -f4 || true)

    if [[ -z "$latest_version" ]]; then
        echo -e "${RED}Failed to parse the latest version from GitHub API. Upgrade aborted.${NC}"
        return
    fi

    echo -e "Current Version : ${YELLOW}${VERSION}${NC}"
    echo -e "Latest Version  : ${GREEN}${latest_version}${NC}\n"

    if [[ "$VERSION" == "$latest_version" ]]; then
        echo -e "${GREEN}You are already using the latest version of SysWarden!${NC}"
    else
        echo -e "${YELLOW}A new Enterprise version ($latest_version) is available!${NC}"

        # --- DEVSECOPS: PREREQUISITE CHECK ---
        # Git is now mandatory for the local build process
        if ! command -v git >/dev/null 2>&1; then
            echo -e "${RED}[ CRITICAL ALERT ] 'git' is not installed. Required for compilation.${NC}"
            echo -e "${YELLOW}Please run: apt install git (or equivalent)${NC}"
            return
        fi

        # --- DEVSECOPS: INTERACTIVE CONFIRMATION ---
        read -p "Do you want to proceed with the automated in-place upgrade now? (y/N): " proceed_upgrade
        if [[ ! "$proceed_upgrade" =~ ^[Yy]$ ]]; then
            echo -e "${YELLOW}Upgrade aborted by user. System remains on $VERSION.${NC}"
            return
        fi

        echo -e "${YELLOW}Cloning and compiling update securely...${NC}"

        # --- HOTFIX: ISOLATED BUILD ENVIRONMENT ---
        # Create an isolated sub-directory for the source code to guarantee
        # it never collides with the script's current execution path.
        local UPGRADE_DIR="$TMP_DIR/syswarden_upgrade_payload"
        rm -rf "$UPGRADE_DIR" # Enforce clean state
        mkdir -p "$UPGRADE_DIR"

        # --- SURGICAL CLONE: SPECIFIC RELEASE TAG ---
        # We clone the exact tag to ensure stability, rather than the main branch
        # [DEVSECOPS FIX] Enforce non-interactive mode to prevent terminal hangs if the repository status changes
        if ! env GIT_TERMINAL_PROMPT=0 git clone -c core.askpass=true --branch "$latest_version" --depth 1 https://github.com/duggytuxy/syswarden.git "$UPGRADE_DIR" >/dev/null 2>&1; then
            echo -e "${RED}[ CRITICAL ALERT ] Failed to clone the repository. Update aborted.${NC}"
            rm -rf "$UPGRADE_DIR"
            exit 1
        fi

        cd "$UPGRADE_DIR" || exit 1

        # --- COMPILATION STAGE ---
        log "INFO" "Executing SysWarden Universal Build..."
        # [DEVSECOPS FIX] Explicit bash invocation physically bypasses 'noexec' mount restrictions on /tmp (CIS/ANSSI compliance).
        # The previous 'chmod +x' was removed as it is logically redundant and generates unnecessary syscalls on locked partitions.
        bash ./build.sh >/dev/null 2>&1 || {
            echo -e "${RED}[ CRITICAL ALERT ] Compilation failed. Update aborted.${NC}"
            cd /
            rm -rf "$UPGRADE_DIR"
            exit 1
        }

        local compiled_artifact="dist/install-syswarden.sh"

        # --- SECURITY FIX: BASIC INTEGRITY CHECK ---
        # Ensure the file compiled correctly and is a valid bash script
        if [[ ! -f "$compiled_artifact" ]] || ! head -n 1 "$compiled_artifact" | grep -q "#!/bin/bash"; then
            echo -e "${RED}[ CRITICAL ALERT ]${NC}"
            echo -e "${RED}The compiled artifact is invalid or corrupted!${NC}"
            echo -e "${RED}Update aborted to protect system integrity.${NC}"
            cd /
            rm -rf "$UPGRADE_DIR"
            exit 1
        fi

        echo -e "${GREEN}Artifact compiled and validated successfully. Preparing in-place upgrade...${NC}"

        # --- PRE-UPGRADE: SURGICAL PROCESS TERMINATION ---
        # We must kill background telemetry and UI processes to avoid zombie orphans
        # or file locking issues during the transition to the new script version.
        log "INFO" "Terminating existing SysWarden background processes safely..."
        # [DEVSECOPS FIX] Graceful degradation: SIGTERM first to allow file descriptor sync, then SIGKILL to prevent DB corruption
        pkill -15 -f syswarden-telemetry 2>/dev/null || true
        pkill -15 -f syswarden_reporter 2>/dev/null || true
        sleep 1
        pkill -9 -f syswarden-telemetry 2>/dev/null || true
        pkill -9 -f syswarden_reporter 2>/dev/null || true

        if command -v systemctl >/dev/null; then
            systemctl stop syswarden-ui 2>/dev/null || true
            systemctl stop syswarden-reporter 2>/dev/null || true
        fi

        # --- IN-PLACE SCRIPT REPLACEMENT ---
        log "INFO" "Replacing current orchestrator at $current_script..."

        # We explicitly copy instead of move in case the OS locks the executing file
        cp -f "$compiled_artifact" "$current_script"
        chmod 700 "$current_script"

        # Configuration sanity check
        if [[ ! -f "$CONF_FILE" ]]; then
            log "WARN" "Configuration file $CONF_FILE missing! The upgrade will behave as a fresh install."
        else
            log "INFO" "Configuration file $CONF_FILE found. User settings will be strictly preserved."
        fi

        # --- CLEANUP ---
        cd /
        rm -rf "$UPGRADE_DIR"

        # --- DEVSECOPS FIX: TELEMETRY STATE BACKUP ---
        # Safeguards historical payloads and OSINT cache from being wiped during upgrade reinitialization
        local STATE_BACKUP_DIR="/tmp/syswarden_state_backup"
        rm -rf "$STATE_BACKUP_DIR"
        mkdir -p "$STATE_BACKUP_DIR"

        if [[ -f "/etc/syswarden/ui/data.json" ]]; then
            cp -f "/etc/syswarden/ui/data.json" "$STATE_BACKUP_DIR/data.json.bak"
        fi
        if [[ -f "/etc/syswarden/ui/osint_cache.txt" ]]; then
            cp -f "/etc/syswarden/ui/osint_cache.txt" "$STATE_BACKUP_DIR/osint_cache.txt.bak"
        fi

        echo -e "${GREEN}In-place upgrade sequence initiated. Executing the new version...${NC}"

        # --- EXECUTE NEW VERSION (WAITING FOR COMPLETION) ---
        # We remove 'exec' so the current script waits for the update to finish before restoring state.
        bash "$current_script" update

        # --- DEVSECOPS FIX: TELEMETRY STATE RESTORE ---
        if [[ -d "$STATE_BACKUP_DIR" ]]; then
            mkdir -p /etc/syswarden/ui
            [[ -f "$STATE_BACKUP_DIR/data.json.bak" ]] && cp -f "$STATE_BACKUP_DIR/data.json.bak" /etc/syswarden/ui/data.json
            [[ -f "$STATE_BACKUP_DIR/osint_cache.txt.bak" ]] && cp -f "$STATE_BACKUP_DIR/osint_cache.txt.bak" /etc/syswarden/ui/osint_cache.txt
            rm -rf "$STATE_BACKUP_DIR"

            chown www-data:www-data /etc/syswarden/ui/data.json 2>/dev/null || chown nginx:nginx /etc/syswarden/ui/data.json 2>/dev/null || true
            chmod 640 /etc/syswarden/ui/data.json 2>/dev/null || true
        fi
    fi
}
