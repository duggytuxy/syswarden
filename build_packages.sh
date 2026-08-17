#!/bin/bash
# SysWarden Local Builder & Packager for Beta Testers
# Supported OS: Debian/Ubuntu & RHEL/CentOS/AlmaLinux
# This script compiles the Native Go binaries and generates the .deb / .rpm packages locally.

set -e
echo "[*] Initializing SysWarden Local Package Builder..."

# 1. Detect OS and Install FPM / Go Dependencies
if [ -f /etc/debian_version ]; then
    echo "[*] Debian/Ubuntu detected. Installing requirements..."
elif [ -f /etc/redhat-release ] || [ -f /etc/fedora-release ]; then
    echo "[*] RHEL/CentOS/Fedora/AlmaLinux detected. Installing requirements..."
else
    echo "[-] Unsupported OS for local package building."
    exit 1
fi

echo "[*] Installing FPM (Effing Package Management)..."

echo "[*] Checking Golang..."
if ! command -v go &> /dev/null; then
    echo "[*] Golang not found. Downloading Go 1.26..."
    wget https://go.dev/dl/go1.26.4.linux-amd64.tar.gz -O /tmp/go.tar.gz
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf /tmp/go.tar.gz
    rm /tmp/go.tar.gz
fi
export PATH=$PATH:/usr/local/go/bin

# Extract Version from Go Code
VERSION=$(grep -oP 'Version = "v\K[0-9\.]+' src/core/syswarden-cli/pkg/system/upgrade.go || echo "2.00.0")
echo "[+] Detected SysWarden Version: v${VERSION}"

# 2. Compile Go Binaries
echo "[*] Compiling SysWarden Native Go Modules..."
export GOOS=linux
export GOARCH=amd64
export CGO_ENABLED=0

mkdir -p dist/bin

echo " -> Compiling syswarden-cli..."
cd src/core/syswarden-cli
go mod tidy && go build -buildmode=pie -ldflags="-s -w" -o ../../../dist/bin/syswarden-cli .
cd ../../../

echo " -> Compiling syswarden-core..."
cd src/core/syswarden-core
go mod tidy && go build -buildmode=pie -ldflags="-s -w" -o ../../../dist/bin/syswarden-core .
cd ../../../

echo " -> Compiling syswarden-tui..."
cd src/core/syswarden-tui
go mod tidy && go build -buildmode=pie -ldflags="-s -w" -o ../../../dist/bin/syswarden-tui .
cd ../../../

echo "[+] Linux Compilation successful."

echo "[*] Compiling SysWarden Native Go Modules for FreeBSD..."
export GOOS=freebsd
export GOARCH=amd64
export CGO_ENABLED=0

mkdir -p dist/freebsd/bin

echo " -> Compiling syswarden-cli (FreeBSD)..."
cd src/core/syswarden-cli
go build -ldflags="-s -w" -o ../../../dist/freebsd/bin/syswarden-cli .
cd ../../../

echo " -> Compiling syswarden-core (FreeBSD)..."
cd src/core/syswarden-core
go build -ldflags="-s -w" -o ../../../dist/freebsd/bin/syswarden-core .
cd ../../../

echo " -> Compiling syswarden-tui (FreeBSD)..."
cd src/core/syswarden-tui
go build -ldflags="-s -w" -o ../../../dist/freebsd/bin/syswarden-tui .
cd ../../../

echo "[+] FreeBSD Compilation successful."
# 3. Prepare Staging Environment
echo "[*] Preparing File Hierarchy for Packaging..."
rm -rf staging
mkdir -p staging/opt/syswarden/bin

# Copy files
cp src/core/syswarden-core/signatures.json staging/opt/syswarden/
cp dist/bin/* staging/opt/syswarden/bin/

# Permissions
chmod 750 staging/opt/syswarden/bin/*
chmod 640 staging/opt/syswarden/signatures.json

# Pre-Install / Pre-Upgrade script
cat << 'EOF' > preinst.sh
#!/bin/sh
if [ -f /opt/syswarden/syswarden-auto.conf ]; then
    mv /opt/syswarden/syswarden-auto.conf /opt/syswarden/syswarden-auto.conf.migration_backup
fi
EOF

# Global Execution Symlink handled via postinst script
cat << 'EOF' > postinst.sh
#!/bin/sh
export SYSWARDEN_PKG_INSTALL=1
ln -sf /opt/syswarden/bin/syswarden-cli /usr/local/bin/syswarden
ln -sf /opt/syswarden/bin/syswarden-tui /usr/local/bin/syswarden-tui

# Generate Bash Autocompletion
if [ -d /etc/bash_completion.d ]; then
    /opt/syswarden/bin/syswarden-cli completion bash > /etc/bash_completion.d/syswarden || true
fi

# RPM Upgrade ($1 = 2) or DEB Upgrade ($1 = configure && $2 != "")
if [ "$1" = "2" ] || [ "$1" = "configure" -a -n "$2" ]; then
    if [ -f /opt/syswarden/syswarden-auto.conf.migration_backup ]; then
        if [ ! -d /etc/syswarden/config/modules ] || [ -z "$(ls -A /etc/syswarden/config/modules 2>/dev/null)" ]; then
            /opt/syswarden/bin/syswarden-cli migrate-config --source /opt/syswarden/syswarden-auto.conf.migration_backup --output /etc/syswarden/config || true
        fi
        mv /opt/syswarden/syswarden-auto.conf.migration_backup /opt/syswarden/syswarden-auto.conf.bak || true
    fi
    /opt/syswarden/bin/syswarden-cli install
    if command -v systemctl >/dev/null 2>&1; then
        systemctl daemon-reload
        /opt/syswarden/bin/syswarden-cli reload
        systemctl enable syswarden-firewall || true
        systemctl restart syswarden-firewall || true
        systemctl restart syswarden-core || true
        systemctl restart syswarden-webtui || true
    elif command -v rc-service >/dev/null 2>&1; then
        /opt/syswarden/bin/syswarden-cli reload || true
        rc-service syswarden-firewall restart || true
        rc-service syswarden-core restart || true
        rc-service syswarden-webtui restart || true
    fi
# RPM Install ($1 = 1) or DEB Install ($1 = configure && $2 == "")
elif [ "$1" = "1" ] || [ "$1" = "configure" ]; then
    /opt/syswarden/bin/syswarden-cli install
    if command -v systemctl >/dev/null 2>&1; then
        systemctl restart syswarden-core || true
        systemctl restart syswarden-webtui || true
    elif command -v rc-service >/dev/null 2>&1; then
        rc-service syswarden-core restart || true
        rc-service syswarden-webtui restart || true
    fi
# Alpine APK Install/Upgrade (APK passes version string in $1)
elif [ -f /etc/alpine-release ]; then
    if [ -f /opt/syswarden/syswarden-auto.conf.migration_backup ]; then
        if [ ! -d /etc/syswarden/config/modules ] || [ -z "$(ls -A /etc/syswarden/config/modules 2>/dev/null)" ]; then
            /opt/syswarden/bin/syswarden-cli migrate-config --source /opt/syswarden/syswarden-auto.conf.migration_backup --output /etc/syswarden/config || true
        fi
        mv /opt/syswarden/syswarden-auto.conf.migration_backup /opt/syswarden/syswarden-auto.conf.bak || true
    fi
    /opt/syswarden/bin/syswarden-cli install
    # syswarden update handles the daemon restart in Alpine, so we just reload.
    /opt/syswarden/bin/syswarden-cli reload || true
fi
EOF

cat << 'EOF' > postrm.sh
#!/bin/sh
# RPM Uninstall ($1 = 0) or DEB Uninstall/Purge
if [ "$1" = "0" ] || [ "$1" = "purge" ]; then
  rm -f /usr/local/bin/syswarden
  rm -f /usr/local/bin/syswarden-tui
  rm -f /etc/bash_completion.d/syswarden
  rm -rf /opt/syswarden
  rm -rf /etc/syswarden
fi
EOF

cat << 'EOF' > prerm.sh
#!/bin/sh
syswarden_managed_cron_line() {
    syswarden_cron_candidate="$1"
    shift
    syswarden_cron_minute="$(printf '%s\n' "${syswarden_cron_candidate}" | awk 'NR == 1 { print $1; exit }')"
    for syswarden_cron_cli do
        if [ "${syswarden_cron_candidate}" = "*/30 * * * * ${syswarden_cron_cli} ha-sync >/dev/null 2>&1" ]; then
            return 0
        fi
        case "${syswarden_cron_minute}" in
            [1-9]|[1-5][0-9])
                if [ "${syswarden_cron_candidate}" = "${syswarden_cron_minute} * * * * ${syswarden_cron_cli} update-feeds >/dev/null 2>&1" ]; then
                    return 0
                fi
                ;;
        esac
    done
    return 1
}
syswarden_filter_crontab() {
    syswarden_cron_input="$1"
    syswarden_cron_output="$2"
    shift 2
    {
        while :; do
            syswarden_cron_candidate=
            if IFS= read -r syswarden_cron_candidate; then
                syswarden_cron_terminated=1
            else
                syswarden_cron_terminated=0
                [ -n "${syswarden_cron_candidate}" ] || break
            fi
            if ! syswarden_managed_cron_line "${syswarden_cron_candidate}" "$@"; then
                if [ "${syswarden_cron_terminated}" -eq 1 ]; then
                    printf '%s\n' "${syswarden_cron_candidate}" || return 1
                else
                    printf '%s' "${syswarden_cron_candidate}" || return 1
                fi
            fi
        done
    } < "${syswarden_cron_input}" > "${syswarden_cron_output}"
}
syswarden_read_crontab() {
    syswarden_cron_backup="$1"
    syswarden_cron_error="$2"
    syswarden_cron_present=0
    if LC_ALL=C crontab -l > "${syswarden_cron_backup}" 2> "${syswarden_cron_error}"; then
        syswarden_cron_present=1
        return 0
    else
        syswarden_cron_rc=$?
    fi
    [ "${syswarden_cron_rc}" -eq 1 ] || {
        printf 'crontab -l failed with exit %s\n' "${syswarden_cron_rc}" >&2
        return 1
    }
    [ ! -s "${syswarden_cron_backup}" ] || {
        printf '%s\n' 'crontab -l emitted partial stdout while reporting absence' >&2
        return 1
    }
    syswarden_cron_message="$(cat "${syswarden_cron_error}")"
    syswarden_cron_lines="$(LC_ALL=C awk 'END { print NR + 0 }' "${syswarden_cron_error}")"
    case "${syswarden_cron_lines}:${syswarden_cron_message}" in
        "1:no crontab for root"|\
        "1:crontab: no crontab for root"|\
        "1:crontab: can't open 'root': No such file or directory")
            if [ -n "${SYSWARDEN_CRON_ABSENCE_SPOOL:-}" ] && \
               { [ -e "${SYSWARDEN_CRON_ABSENCE_SPOOL}" ] || [ -L "${SYSWARDEN_CRON_ABSENCE_SPOOL}" ]; }; then
                printf '%s\n' 'crontab reported absence while the configured spool path still exists' >&2
                return 1
            fi
            : > "${syswarden_cron_backup}"
            return 0
            ;;
    esac
    printf '%s\n' "${syswarden_cron_message}" >&2
    return 1
}
syswarden_cleanup_cron_work() {
    [ -n "${cron_work:-}" ] || return 0
    syswarden_cron_cleanup_target="${cron_work}"
    if [ "${XDG_CACHE_HOME:-}" = "${syswarden_cron_cleanup_target}/cache" ]; then
        unset XDG_CACHE_HOME
    fi
    cron_cache=
    rm -rf -- "${syswarden_cron_cleanup_target}" || return 1
    if [ -e "${syswarden_cron_cleanup_target}" ] || [ -L "${syswarden_cron_cleanup_target}" ]; then
        printf '%s\n' 'private cron work directory remains after cleanup' >&2
        return 1
    fi
    cron_work=
}
syswarden_prepare_cron_work() {
    cron_work="$(mktemp -d /var/tmp/syswarden-cron.XXXXXX)" || return 1
    chmod 0700 "${cron_work}" || return 1
    cron_cache="${cron_work}/cache"
    mkdir "${cron_cache}" || return 1
    chmod 0700 "${cron_cache}" || return 1
    XDG_CACHE_HOME="${cron_cache}"
    export XDG_CACHE_HOME
    cron_backup="${cron_work}/backup"
    cron_error="${cron_work}/error"
    cron_filtered="${cron_work}/filtered"
}
syswarden_cleanup_crontab() {
    syswarden_cron_backup="$1"
    syswarden_cron_error="$2"
    syswarden_cron_filtered="$3"
    shift 3
    syswarden_read_crontab "${syswarden_cron_backup}" "${syswarden_cron_error}" || return 1
    [ "${syswarden_cron_present}" -eq 1 ] || return 0
    syswarden_filter_crontab "${syswarden_cron_backup}" "${syswarden_cron_filtered}" "$@" || return 1
    if cmp -s "${syswarden_cron_backup}" "${syswarden_cron_filtered}"; then
        return 0
    else
        syswarden_cron_cmp_rc=$?
    fi
    [ "${syswarden_cron_cmp_rc}" -eq 1 ] || return 1
    if [ ! -s "${syswarden_cron_filtered}" ]; then
        LC_ALL=C crontab -r || return 1
        syswarden_read_crontab "${syswarden_cron_backup}" "${syswarden_cron_error}" || return 1
        [ "${syswarden_cron_present}" -eq 0 ] || {
            printf '%s\n' 'crontab -r returned success but the root crontab is still present' >&2
            return 1
        }
        return 0
    fi
    crontab - < "${syswarden_cron_filtered}" || return 1
}

# RPM Uninstall ($1 = 0) or DEB Uninstall/Purge
if [ "$1" = "0" ] || [ "$1" = "remove" ] || [ "$1" = "purge" ]; then
    if command -v systemctl >/dev/null 2>&1; then
        systemctl stop syswarden-core.service || true
        systemctl disable syswarden-core.service || true
        systemctl stop syswarden-firewall.service || true
        systemctl disable syswarden-firewall.service || true
        systemctl stop syswarden-webtui.service || true
        systemctl disable syswarden-webtui.service || true
        systemctl restart rsyslog || true
    elif command -v rc-service >/dev/null 2>&1; then
        rc-service syswarden-core stop || true
        rc-update del syswarden-core default || true
        rc-service syswarden-firewall stop || true
        rc-update del syswarden-firewall default || true
        rc-service syswarden-webtui stop || true
        rc-update del syswarden-webtui default || true
        rc-service rsyslog restart || true
    fi
    nft delete table netdev syswarden_hw_drop || true
    nft delete table inet syswarden || true
    umask 077
    SYSWARDEN_CRON_ABSENCE_SPOOL=
    cron_work=
    trap 'syswarden_cleanup_cron_work' 0
    trap 'syswarden_cleanup_cron_work; exit 129' 1
    trap 'syswarden_cleanup_cron_work; exit 130' 2
    trap 'syswarden_cleanup_cron_work; exit 143' 15
    syswarden_prepare_cron_work || exit 1
    syswarden_cleanup_crontab \
        "${cron_backup}" "${cron_error}" "${cron_filtered}" \
        /opt/syswarden/bin/syswarden-cli || exit 1
    syswarden_cleanup_cron_work || exit 1
    trap - 0 1 2 15
    rm -f /etc/rsyslog.d/99-syswarden-waf-bridge.conf || true
fi
EOF

chmod +x preinst.sh postinst.sh postrm.sh prerm.sh

# 4. Generate Packages
echo "[*] Generating .deb and .rpm packages via FPM..."

# Generate DEB
fpm -f -s dir -t deb \
    -n syswarden \
    -v "${VERSION}" \
    --vendor "SysWarden Security" \
    --maintainer "SysWarden Engineering" \
    --description "SysWarden Host-based Security Orchestrator for Linux" \
    -d "nftables" -d "ipset" -d "curl" -d "wget" -d "rsyslog" -d "bash-completion" \
    --before-install preinst.sh \
    --after-install postinst.sh \
    --before-remove prerm.sh \
    --after-remove postrm.sh \
    -C staging .

# Generate RPM
fpm -f -s dir -t rpm \
    -n syswarden \
    -v "${VERSION}" \
    --vendor "SysWarden Security" \
    --maintainer "SysWarden Engineering" \
    --description "SysWarden Host-based Security Orchestrator for Linux" \
    -d "nftables" -d "ipset" -d "curl" -d "wget" -d "rsyslog" -d "bash-completion" \
    --before-install preinst.sh \
    --after-install postinst.sh \
    --before-remove prerm.sh \
    --after-remove postrm.sh \
    -C staging .

# Generate Alpine APK via nfpm
echo "[*] Generating .apk package via nfpm..."
go install github.com/goreleaser/nfpm/v2/cmd/nfpm@v2.43.0
cat << EOF > nfpm_alpine_amd64.yaml
name: "syswarden"
arch: "amd64"
platform: "linux"
version: "${VERSION}"
maintainer: "SysWarden Engineering"
description: "SysWarden Host-based Security Orchestrator for Alpine Linux"
vendor: "SysWarden Security"
homepage: "https://github.com/duggytuxy/syswarden"
depends:
  - nftables
  - openrc
  - curl
  - wget
  - rsyslog
  - rsyslog-uxsock
  - bash-completion
contents:
  - src: "./staging/opt"
    dst: "/opt"
  - src: "./staging/usr"
    dst: "/usr"
scripts:
  preinstall: "./preinst.sh"
  postinstall: "./postinst.sh"
  preremove: "./prerm.sh"
  postremove: "./postrm.sh"
apk:
  scripts:
    preupgrade: "./preinst.sh"
    postupgrade: "./postinst.sh"
EOF
"$(go env GOPATH)/bin/nfpm" pkg --config nfpm_alpine_amd64.yaml --packager apk --target .
rm -f nfpm_alpine_amd64.yaml

# Generate FreeBSD PKG
echo "[*] Preparing FreeBSD Staging..."
rm -rf staging_fbsd
mkdir -p staging_fbsd/usr/local/syswarden/bin
cp src/core/syswarden-core/signatures.json staging_fbsd/usr/local/syswarden/
cp dist/freebsd/bin/* staging_fbsd/usr/local/syswarden/bin/
chmod 750 staging_fbsd/usr/local/syswarden/bin/*
chmod 640 staging_fbsd/usr/local/syswarden/signatures.json

cat << 'EOF' > preinst_fbsd.sh
#!/bin/sh
if [ -f /usr/local/syswarden/syswarden-auto.conf ]; then
    mv /usr/local/syswarden/syswarden-auto.conf /usr/local/syswarden/syswarden-auto.conf.migration_backup
fi
EOF

cat << 'EOF' > postinst_fbsd.sh
#!/bin/sh
export SYSWARDEN_PKG_INSTALL=1
ln -sf /usr/local/syswarden/bin/syswarden-cli /usr/local/bin/syswarden
ln -sf /usr/local/syswarden/bin/syswarden-tui /usr/local/bin/syswarden-tui
if [ -f /usr/local/syswarden/syswarden-auto.conf.migration_backup ]; then
    if [ ! -d /etc/syswarden/config/modules ] || [ -z "$(ls -A /etc/syswarden/config/modules 2>/dev/null)" ]; then
        /usr/local/syswarden/bin/syswarden-cli migrate-config --source /usr/local/syswarden/syswarden-auto.conf.migration_backup --output /etc/syswarden/config || true
    fi
    mv /usr/local/syswarden/syswarden-auto.conf.migration_backup /usr/local/syswarden/syswarden-auto.conf.bak || true
fi
/usr/local/bin/syswarden install
service syswarden restart || true
EOF

cat << 'EOF' > postrm_fbsd.sh
#!/bin/sh
rm -f /usr/local/bin/syswarden
rm -f /usr/local/bin/syswarden-tui
rm -rf /usr/local/syswarden
EOF

cat << 'EOF' > prerm_fbsd.sh
#!/bin/sh
service syswarden stop || true
sysrc -x syswarden_enable || true
pfctl -t syswarden_blacklist -T kill || true
pfctl -t syswarden_whitelist -T kill || true
pfctl -t banned_ips -T kill || true
EOF
chmod +x preinst_fbsd.sh postinst_fbsd.sh postrm_fbsd.sh prerm_fbsd.sh

fpm -f -s dir -t freebsd \
    -n syswarden \
    -v "${VERSION}" \
    --vendor "SysWarden Security" \
    --maintainer "SysWarden Engineering" \
    --description "SysWarden Host-based Security Orchestrator for FreeBSD" \
    --before-install preinst_fbsd.sh \
    --after-install postinst_fbsd.sh \
    --before-remove prerm_fbsd.sh \
    --after-remove postrm_fbsd.sh \
    -C staging_fbsd .

# Clean Staging
rm -rf staging staging_fbsd dist preinst*.sh postinst*.sh postrm*.sh prerm*.sh

echo "[SUCCESS] Packages have been successfully generated in your current directory!"
ls -lh ./*.deb ./*.rpm ./*.pkg || true
