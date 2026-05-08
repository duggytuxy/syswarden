#!/usr/bin/env bash
#
# SysWarden Micro-Modular Compiler
# Compiles individual function scripts into a single universal deployment artifact.

set -euo pipefail

DIST_DIR="dist"
OUTPUT="${DIST_DIR}/install-syswarden.sh"

echo "[*] Initializing SysWarden Universal Build..."
mkdir -p "${DIST_DIR}"
: > "${OUTPUT}"

# ==========================================
# 1. BASE SECURITY HEADERS
# ==========================================
cat << 'EOF' > "${OUTPUT}"
#!/bin/bash
# SysWarden - Enterprise Compiled Build
# Copyright (C) 2026 duggytuxy - Laurent M.
#
# --- STRICT RUNTIME ENVIRONMENT ---
set -euo pipefail
IFS=$'\n\t'
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

EOF

# ==========================================
# 2. INJECT CORE CONFIGURATION
# ==========================================
echo "[*] Injecting core configurations..."
for file in src/core/*.sh; do
    if [[ -f "$file" ]]; then
        cat "$file" >> "${OUTPUT}"
        echo -e "\n" >> "${OUTPUT}"
    fi
done

# ==========================================
# 3. INJECT UNIVERSAL FUNCTIONS
# ==========================================
echo "[*] Injecting universal modules..."
for file in src/universel/*.sh; do
    if [[ -f "$file" ]]; then
        echo "# --- SOURCE: $(basename "$file") ---" >> "${OUTPUT}"
        cat "$file" >> "${OUTPUT}"
        echo -e "\n" >> "${OUTPUT}"
    fi
done

# ==========================================
# 4. INJECT MAIN ORCHESTRATOR
# ==========================================
echo "[*] Injecting main orchestrator..."
if [[ -f "src/main.sh" ]]; then
    echo "# --- SOURCE: main.sh ---" >> "${OUTPUT}"
    cat "src/main.sh" >> "${OUTPUT}"
else
    echo "[-] CRITICAL: src/main.sh not found. Build aborted." >&2
    exit 1
fi

chmod +x "${OUTPUT}"
echo "[+] Build complete. Artifact generated at: ${OUTPUT}"
