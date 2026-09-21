# BunkerWeb log configuration

SysWarden reads existing security logs out of band. This optional configuration
selects BunkerWeb log files on a Debian host with rsyslog. It changes only the
WAAP log paths, leaving the enforcement mode, thresholds and time window intact.

## Automatic discovery

With `waap.bruteforce_logs = "auto"`, SysWarden discovers existing BunkerWeb
access, error and ModSecurity audit logs under `/var/log/bunkerweb`, as well as
existing system and supported web server logs. On Debian with rsyslog this
includes `/var/log/auth.log` and `/var/log/syslog`; on Red Hat systems it includes
`/var/log/secure` and `/var/log/messages` when present. Absent optional defaults
are skipped. Discovered files still pass the normal secure log validation.

This discovery fix is included in the v4.10.0 candidate; it is not available in
v4.04.3. The explicit override below can also be used with v4.04.3.

## Explicit BunkerWeb override

1. Review [90-waap-logs-debian.toml](90-waap-logs-debian.toml). Verify each path
   exists on the host running SysWarden and contains the intended logs. For
   containers, use the actual host-mounted paths. Remove unavailable inputs;
   do not create empty files to hide missing logs. A journald-only host does not
   acquire rsyslog files simply by installing this example.
2. From the repository root, install the reviewed example as root:

   ```sh
   sudo test ! -e /etc/syswarden/config/modules/90-waap-logs-debian.toml &&
     sudo install -o root -g root -m 0600 examples/bunkerweb/90-waap-logs-debian.toml /etc/syswarden/config/modules/90-waap-logs-debian.toml
   ```

   If this override already exists, review and back it up before editing it.
   Module filenames are loaded in lexical order, so this file overrides the
   two paths in `30-waap.toml`. Check for later modules or environment settings
   that override the same keys.
3. Verify the effective paths, then restart the collector:

   ```sh
   sudo syswarden config-get waap.bruteforce_logs
   sudo syswarden config-get waap.modsec_logs
   sudo systemctl restart syswarden-core
   sudo journalctl -u syswarden-core -n 50 --no-pager
   ```

   Confirm the expected monitored files and investigate any rejected input.
   Keep the normal ownership and permissions checks; do not loosen log access
   permissions to bypass a rejection.

Explicit paths remain authoritative. This example avoids monitoring unrelated
Nginx logs, preserves the listed SSH/system inputs, and replaces the generic
`/var/log/modsec/*.log` setting with BunkerWeb's audit path. It does not change
BunkerWeb's logging configuration or enable an otherwise disabled audit log.
