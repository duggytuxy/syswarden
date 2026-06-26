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

# RPM Upgrade ($1 = 2) or DEB Upgrade ($1 = configure && $2 != "")
if [ "$1" = "2" ] || [ "$1" = "configure" -a -n "$2" ]; then
    systemctl daemon-reload
    systemctl restart syswarden-core || true
    systemctl restart syswarden-firewall || true
# RPM Install ($1 = 1) or DEB Install ($1 = configure && $2 == "")
elif [ "$1" = "1" ] || [ "$1" = "configure" ]; then
    /opt/syswarden/bin/syswarden-cli install
    systemctl restart syswarden-core || true
fi
EOF

cat << 'EOF' > postrm.sh
#!/bin/sh
# RPM Uninstall ($1 = 0) or DEB Uninstall/Purge
if [ "$1" = "0" ] || [ "$1" = "remove" ] || [ "$1" = "purge" ]; then
  rm -f /usr/local/bin/syswarden
  rm -f /usr/local/bin/syswarden-tui
  rm -rf /opt/syswarden
  rm -rf /etc/syswarden
fi
EOF

cat << 'EOF' > prerm.sh
#!/bin/sh
# RPM Uninstall ($1 = 0) or DEB Uninstall/Purge
if [ "$1" = "0" ] || [ "$1" = "remove" ] || [ "$1" = "purge" ]; then
    systemctl stop syswarden-core.service || true
    systemctl disable syswarden-core.service || true
    systemctl stop syswarden-firewall.service || true
    systemctl disable syswarden-firewall.service || true
    nft delete table netdev syswarden_hw_drop || true
    nft delete table inet syswarden || true
    crontab -l | grep -v 'syswarden-cli' | crontab - || true
    rm -f /etc/rsyslog.d/99-syswarden-waf-bridge.conf || true
    systemctl restart rsyslog || true
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
    -d "nftables" -d "ipset" -d "curl" -d "wget" -d "rsyslog" \
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
    -d "nftables" -d "ipset" -d "curl" -d "wget" -d "rsyslog" \
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
