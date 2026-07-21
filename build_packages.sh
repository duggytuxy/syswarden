#!/bin/bash
# SysWarden Local Builder & Packager for Beta Testers
# Supported OS: Debian/Ubuntu & RHEL/CentOS/AlmaLinux
# This script compiles the Native Go binaries and generates the .deb / .rpm packages locally.

set -e
echo "[*] Initializing SysWarden Local Package Builder..."

# 1. Detect OS and Install FPM / Go Dependencies
if [ -f /etc/debian_version ]; then
    echo "[*] Debian/Ubuntu detected. Installing requirements..."
    sudo apt-get update
    sudo apt-get install -y ruby ruby-dev rubygems build-essential rpm wget curl git
elif [ -f /etc/redhat-release ]; then
    echo "[*] RHEL/CentOS/AlmaLinux detected. Installing requirements..."
    sudo dnf install -y ruby ruby-devel rubygems gcc make rpm-build wget curl git
else
    echo "[-] Unsupported OS for local package building."
    exit 1
fi

echo "[*] Installing FPM (Effing Package Management)..."
sudo gem install --no-document fpm

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
go mod tidy && go build -ldflags="-s -w" -o ../../../dist/bin/syswarden-cli .
cd ../../../

echo " -> Compiling syswarden-core..."
cd src/core/syswarden-core
go mod tidy && go build -ldflags="-s -w" -o ../../../dist/bin/syswarden-core .
cd ../../../

echo " -> Compiling syswarden-tui..."
cd src/core/syswarden-tui
go mod tidy && go build -ldflags="-s -w" -o ../../../dist/bin/syswarden-tui .
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
    sed -i 's|ReadWritePaths=/var/lib/syswarden /var/log/syswarden /run /opt/syswarden$|ReadWritePaths=/var/lib/syswarden /var/log/syswarden /run /opt/syswarden /etc/syswarden/lists|g' /etc/systemd/system/syswarden-core.service || true
    if command -v systemctl >/dev/null 2>&1; then
        systemctl daemon-reload
        systemctl restart syswarden-core || true
        systemctl restart syswarden-firewall || true
        systemctl restart syswarden-webtui || true
    elif command -v rc-service >/dev/null 2>&1; then
        rc-service syswarden-core restart || true
        rc-service syswarden-firewall restart || true
        rc-service syswarden-webtui restart || true
    fi
fi

# Ensure Web-TUI service exists regardless of Upgrade or Fresh Install
if command -v systemctl >/dev/null 2>&1; then
    if [ ! -f /etc/systemd/system/syswarden-webtui.service ]; then
        cat << 'SVC' > /etc/systemd/system/syswarden-webtui.service
[Unit]
Description=SYSWARDEN Web-TUI (WebTTY)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=/opt/syswarden/bin/syswarden-cli web-tui
Restart=on-failure
RestartSec=5s

# Security Hardening
ProtectSystem=full
ProtectHome=yes
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
SVC
        systemctl daemon-reload
        systemctl enable --now syswarden-webtui.service || true
    fi
elif command -v rc-service >/dev/null 2>&1; then
    if [ ! -f /etc/init.d/syswarden-webtui ]; then
        cat << 'SVC' > /etc/init.d/syswarden-webtui

#!/sbin/openrc-run

name="syswarden-webtui"
description="SYSWARDEN Web-TUI (WebTTY)"
command="/opt/syswarden/bin/syswarden-cli"
command_args="web-tui"
command_background=true
pidfile="/run/syswarden-webtui.pid"

depend() {
	need net
}
SVC
            chmod +x /etc/init.d/syswarden-webtui
            rc-update add syswarden-webtui default || true
            rc-service syswarden-webtui start || true
        fi
        rc-service syswarden-webtui restart || true
    fi

    if ! grep -q "SYSWARDEN_WEB_TOKEN" /opt/syswarden/syswarden-auto.conf 2>/dev/null; then
        echo "[INFO] Upgrading SysWarden: Initializing Web-TUI..."
        /usr/local/bin/syswarden web-token --rotate
    fi
# RPM Install ($1 = 1) or DEB Install ($1 = configure && $2 == "")
    /opt/syswarden/bin/syswarden-cli install
    if command -v systemctl >/dev/null 2>&1; then
        systemctl restart syswarden-core || true
    elif command -v rc-service >/dev/null 2>&1; then
        rc-service syswarden-core restart || true
    fi
fi
EOF

cat << 'EOF' > postrm.sh
#!/bin/sh
# RPM Uninstall ($1 = 0) or DEB Uninstall/Purge
if [ "$1" = "0" ] || [ "$1" = "remove" ] || [ "$1" = "purge" ]; then
  rm -f /usr/local/bin/syswarden
  rm -f /usr/local/bin/syswarden-tui
  rm -f /etc/bash_completion.d/syswarden
  rm -rf /opt/syswarden
  rm -rf /etc/syswarden
fi
EOF

cat << 'EOF' > prerm.sh
#!/bin/sh
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
    crontab -l | grep -v 'syswarden-cli' | crontab - || true
    rm -f /etc/rsyslog.d/99-syswarden-waf-bridge.conf || true
fi
EOF

chmod +x postinst.sh postrm.sh prerm.sh

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
    --after-install postinst.sh \
    --before-remove prerm.sh \
    --after-remove postrm.sh \
    -C staging .

# Generate FreeBSD PKG
echo "[*] Preparing FreeBSD Staging..."
rm -rf staging_fbsd
mkdir -p staging_fbsd/usr/local/syswarden/bin
cp src/core/syswarden-core/signatures.json staging_fbsd/usr/local/syswarden/
cp dist/freebsd/bin/* staging_fbsd/usr/local/syswarden/bin/
chmod 750 staging_fbsd/usr/local/syswarden/bin/*
chmod 640 staging_fbsd/usr/local/syswarden/signatures.json

cat << 'EOF' > postinst_fbsd.sh
#!/bin/sh
export SYSWARDEN_PKG_INSTALL=1
ln -sf /usr/local/syswarden/bin/syswarden-cli /usr/local/bin/syswarden
ln -sf /usr/local/syswarden/bin/syswarden-tui /usr/local/bin/syswarden-tui
/usr/local/bin/syswarden install
service syswarden restart || true
EOF

cat << 'EOF' > postrm_fbsd.sh
#!/bin/sh
rm -f /usr/local/bin/syswarden
rm -f /usr/local/bin/syswarden-tui
rm -rf /usr/local/syswarden
rm -rf /etc/syswarden
EOF

cat << 'EOF' > prerm_fbsd.sh
#!/bin/sh
service syswarden stop || true
sysrc -x syswarden_enable || true
pfctl -t syswarden_blacklist -T kill || true
pfctl -t syswarden_whitelist -T kill || true
pfctl -t banned_ips -T kill || true
EOF
chmod +x postinst_fbsd.sh postrm_fbsd.sh prerm_fbsd.sh

fpm -f -s dir -t freebsd \
    -n syswarden \
    -v "${VERSION}" \
    --vendor "SysWarden Security" \
    --maintainer "SysWarden Engineering" \
    --description "SysWarden Host-based Security Orchestrator for FreeBSD" \
    --after-install postinst_fbsd.sh \
    --before-remove prerm_fbsd.sh \
    --after-remove postrm_fbsd.sh \
    -C staging_fbsd .

# Clean Staging
rm -rf staging staging_fbsd dist postinst*.sh postrm*.sh prerm*.sh

echo "[SUCCESS] Packages have been successfully generated in your current directory!"
ls -lh *.deb *.rpm *.pkg || true
