#!/bin/sh
set -eu
[ "$(id -u)" = 0 ]
[ "$(cat /proc/1/comm)" = systemd ]
awk 'NR==1 {exit !($1==0 && $2>0)}' /proc/self/uid_map
install -d -m 0700 /run/syswarden-ssh-native-oracle
install -d -m 0755 /run/sshd /etc/ssh/sshd_config.d
[ ! -e /etc/ssh/sshd_config.d/00-syswarden-hardening.conf ]
rm -f /etc/ssh/ssh_host_ed25519_key /etc/ssh/ssh_host_ed25519_key.pub
ssh-keygen -q -t ed25519 -N '' -f /etc/ssh/ssh_host_ed25519_key
ssh-keygen -q -t ed25519 -N '' -f /run/syswarden-ssh-native-oracle/client
cp /run/syswarden-ssh-native-oracle/client.pub /run/syswarden-ssh-native-oracle/authorized_keys
chmod 0600 /run/syswarden-ssh-native-oracle/authorized_keys
cat > /etc/ssh/sshd_config <<'CONFIG'
# SYSWARDEN-ISOLATED-SSH-BINDER-V1
Include /etc/ssh/sshd_config.d/*.conf
Port 22222
ListenAddress 127.0.0.1
HostKey /etc/ssh/ssh_host_ed25519_key
AuthorizedKeysFile /run/syswarden-ssh-native-oracle/authorized_keys
PermitRootLogin prohibit-password
UsePAM no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
AuthenticationMethods publickey
StrictModes yes
UseDNS no
LogLevel VERBOSE
CONFIG
systemctl unmask ssh.service ssh.socket
cat > /etc/systemd/system/ssh.service <<'UNIT'
[Unit]
Description=Isolated SSH production binder oracle
After=dbus.service
[Service]
Type=simple
ExecStart=/usr/sbin/sshd -D -e
RuntimeDirectory=sshd
[Install]
WantedBy=multi-user.target
UNIT
chmod 0644 /etc/ssh/sshd_config /etc/systemd/system/ssh.service
systemctl daemon-reload
systemctl start dbus.service ssh.service
systemctl is-active ssh.service
printf 'SYSWARDEN-ISOLATED-SSH-BINDER-V1\n' > /run/syswarden-ssh-native-oracle/ready
