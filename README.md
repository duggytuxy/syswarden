<p align="center">
  <img src="assets/syswarden_hero.svg" alt="SysWarden">
  <br><br>
  <a href="https://github.com/duggytuxy/syswarden/actions/workflows/package.yml">
    <img src="https://img.shields.io/github/actions/workflow/status/duggytuxy/syswarden/package.yml?style=flat&logo=githubactions&logoColor=white" alt="SysWarden Builder and Packager">
  </a>
  <a href="https://github.com/duggytuxy/syswarden/actions/workflows/security-audit.yml">
    <img src="https://img.shields.io/github/actions/workflow/status/duggytuxy/syswarden/security-audit.yml?style=flat&logo=githubactions&logoColor=white&label=SysWarden%20Security%20Audit" alt="SysWarden Security Audit">
  </a>
  <a href="https://github.com/duggytuxy/syswarden/actions/workflows/scorecard.yml">
    <img src="https://img.shields.io/github/actions/workflow/status/duggytuxy/syswarden/scorecard.yml?style=flat&logo=githubactions&logoColor=white&label=OSSF%20Scorecard" alt="OpenSSF Scorecard">
  </a>
  <a href="https://github.com/duggytuxy/syswarden/blob/main/LICENSE">
    <img src="https://img.shields.io/github/license/duggytuxy/syswarden?style=flat&logo=opensourceinitiative&logoColor=white" alt="GitHub License">
  </a>
</p>

# SysWarden v4

Current source version: **v4.02.8**.

SysWarden is a host firewall orchestrator and an out-of-band security-log
analysis toolkit implemented primarily in Go. Its CLI manages configuration,
threat-intelligence lists, firewall rules, system services and optional
integrations. `syswarden-core` reads logs that another service has already
written and can add addresses to kernel firewall sets. It does not proxy,
terminate, inspect or sanitize live HTTP traffic.

This README describes the current repository state. A package being produced
by the build workflow is not, by itself, evidence that installation, upgrade,
restart and rollback have passed on the target operating system.

## Validation status

| Target | What the repository currently proves | Release qualification |
| :--- | :--- | :--- |
| Linux amd64 | The CLI, core and TUI compile; unit, contract and golden-rule tests run in CI | Privileged virtual-machine install, firewall, upgrade and rollback cycles have not passed in this repository state |
| Linux arm64 | The three binaries cross-compile and package metadata is generated | Native arm64 lifecycle evidence is still required |
| Debian/Ubuntu `.deb` | amd64 and arm64 package recipes exist | Not release-qualified by a complete VM lifecycle gate |
| RHEL-family `.rpm` | x86_64 and aarch64 package recipes exist | Not release-qualified by a complete VM lifecycle gate |
| Alpine `.apk` | x86_64 and aarch64 package recipes exist | **Known blocker:** the current Linux binaries request the glibc ELF interpreter and do not run on a standard musl-only Alpine installation |
| FreeBSD `.txz` | amd64 binaries cross-compile and a package recipe exists | **Known blocker:** the package stages binaries below `/usr/local/syswarden/bin`, while current service/runtime paths still reference `/opt/syswarden`; do not install this package |

The Linux distribution names previously listed here were build intentions, not
per-distribution lifecycle results. Until the corresponding VM gates pass, use
SysWarden only in an isolated laboratory with console access and a tested host
snapshot or rollback path.

## Components and data flow

- `syswarden-cli` is the privileged operator interface.
- `syswarden-core` tails configured access or security logs, evaluates WAAP
  signatures and brute-force thresholds, and writes telemetry.
- `syswarden-tui` displays local telemetry in a terminal and opens no network
  listener itself. The current TUI implements a responsive layout, an ASCII
  24-hour rolling timeline whose buckets are stored in UTC while the current
  axis labels are rendered from local time, and profile-aware header tagging.
- `syswarden web-tui` exposes the terminal UI through HTTPS and WebSocket. It
  is a separate, network-facing mode with different risks.

```text
application or reverse-proxy logs
              |
              v
       syswarden-core
       |            |
       v            v
local telemetry   requested bans
       |            |
       v            v
syswarden-tui   nftables or pf
```

The WAAP engine is out-of-band log analysis. A detection can lead to a later
firewall update, but SysWarden is not in the HTTP request path and cannot clean
or rewrite a request before an application receives it.

## Implemented capabilities and limits

### Firewall and threat intelligence

The Linux implementation generates nftables rules and maintains IPv4 and IPv6
list files under `/etc/syswarden/lists`. The FreeBSD implementation generates
PF rules. GeoIP, ASN, custom feeds, whitelists, SSH exceptions, honeyports,
WireGuard and L2 options are configuration-controlled.

These controls can disconnect an administrator. Keep an out-of-band console,
back up the active configuration and firewall rules, and test rollback before
enabling strict allow lists, changing SSH access, or applying rules remotely.
The current reload path removes and reapplies SysWarden rules and can restart
`syswarden-core`; it is not an atomic or connection-preserving operation.

### WAAP log analysis

`syswarden-core` can tail configured Nginx, Apache, Traefik, Caddy or other log
paths and evaluate signatures for SQL injection, XSS, LFI, RCE, scanners and
HTTP failure thresholds. Detection depends on the log format, log availability,
permissions and signature coverage. It does not replace an inline WAF, and the
repository does not establish a fixed service-count, false-positive rate,
latency or resource bound.

### Native TUI and Web-TUI

The native TUI is local and does not require an open port. The Web-TUI is
different: its default bind is `0.0.0.0:62027`, its service is enabled by the
current install path, it creates an in-memory self-signed certificate, and it
accepts a token through Basic authentication, a cookie or a legacy URL query
parameter. Restrict the listener with `--bind`, protect the port with a trusted
network control, and do not place tokens in URLs or logs.

### High availability

When enabled, the HA API listens on configurable TCP port `62026` by default.
It uses TLS 1.3 with a newly generated self-signed certificate. The current CLI
client sets `InsecureSkipVerify`, so it encrypts traffic but does not verify the
peer certificate. A bearer token is optional and an empty token enables a
legacy IP-only mode. Use a strong shared token and an isolated trusted network.

`syswarden ha-sync` compares the local blocklist with each configured peer and
pushes locally recorded entries that the peer does not report. The installer
also adds a one-way HA push cron entry every 30 minutes. This is not
bidirectional reconciliation or instantaneous event replication. Current HA
HTTP clients lack bounded request timeouts, and the unban request does not
attach the bearer token; treat mixed-version and failure recovery as
unvalidated.

### SIEM and webhooks

SIEM forwarding is implemented through rsyslog. UDP and cleartext TCP are
available. When a CA path is configured, the current rsyslog template uses
anonymous TLS authentication, so the documentation does not classify it as
strict authenticated TLS. Webhook URLs are operator-supplied destinations; the
current implementation has no destination allowlist or private-network
filtering. One setup request has a timeout, while another alert path uses the
default HTTP client without an explicit timeout.

## Network listeners

| Component | Default | Condition | Current security note |
| :--- | :--- | :--- | :--- |
| Native TUI | No listener | Launched with `syswarden tui` | Local terminal process |
| Web-TUI | `0.0.0.0:62027` | Service or `syswarden web-tui` is running | Self-signed TLS and bearer-style token; restrict the bind address |
| HA API | all interfaces on TCP `62026` | HA is enabled with at least one peer | Self-signed TLS; CLI certificate verification is disabled |
| WireGuard | Configurable; legacy default `51820` | WireGuard is enabled | Verify the configured port and firewall rules on the host |

## Files and services on Linux

| Purpose | Current path or name |
| :--- | :--- |
| Binaries | `/opt/syswarden/bin/syswarden-cli`, `/opt/syswarden/bin/syswarden-core`, `/opt/syswarden/bin/syswarden-tui` |
| CLI links | `/usr/local/bin/syswarden`, `/usr/local/bin/syswarden-tui` |
| Master configuration | `/etc/syswarden/config/config.toml` |
| Ordered modules | `/etc/syswarden/config/modules/00-core.toml` through `99-user.toml` |
| Firewall and intelligence lists | `/etc/syswarden/lists` |
| Telemetry | `/var/lib/syswarden/ui/data.json` |
| Logs | `/var/log/syswarden` |
| systemd services | `syswarden-core.service`, `syswarden-firewall.service`, `syswarden-webtui.service` |

The current FreeBSD package and runtime paths are inconsistent, as described in
the validation table. Linux paths must not be assumed to describe a working
FreeBSD installation.

## Build verification

The repository build script requires Go and PowerShell. The audited Lot 0
environment uses the official PowerShell 7.6.4 release. The script builds the
three components for linux/amd64, linux/arm64 and freebsd/amd64 and validates
the resulting executable inventory.

```bash
pwsh -File ./build.ps1
```

Building does not install or start SysWarden.

## Installation safety

The package workflow is configured to generate two DEB, two RPM, two APK and
one FreeBSD package plus `SHA256SUMS.txt`. Check the assets actually attached to
the selected GitHub release before using any filename or command.

> [!CAUTION]
> The current package post-install script invokes `syswarden-cli install`
> automatically. That operation can install dependencies, change SSH and host
> hardening, replace or modify firewall services, download feeds, create cron
> jobs, enable the Web-TUI, and restart services. Do not run it on a remotely
> administered host without console access, backups and a tested rollback.

Do not install the current Alpine or FreeBSD package. Do not use
`apk --allow-untrusted`. For a Linux laboratory test, download only the package
matching the host architecture and its release checksum file, verify the exact
package entry, inspect the package scripts, and take a snapshot before invoking
the package manager. Attestations, an SBOM or a checksum should be relied upon
only when that exact artifact is present and verifies for the selected release.

## Configuration

Configuration is loaded from `/etc/syswarden/config/config.toml` and ordered
TOML files below `/etc/syswarden/config/modules`. Later filenames override
earlier modules; `99-user.toml` is reserved for operator overrides. The legacy
`/opt/syswarden/syswarden-auto.conf` format remains available for migration.

Use the interactive editor or place a small override in `99-user.toml`:

```toml
[core]
ssh_port = "22"

[waap]
enforcement_mode = "audit"
bruteforce_logs = "/var/log/nginx/access.log"
bruteforce_threshold = 5
bruteforce_window_seconds = 60

[integrations.ha]
enabled = false
peer_ips = []
peer_port = 62026
token = ""

[user]
webtui_password = ""
```

Back up the complete configuration directory before editing. Validate the
result locally before applying it. An empty HA token selects the legacy mode;
it is shown above only because HA is disabled.

## Operator commands

Use `syswarden --help` and command-specific help as the command contract. The
main commands include:

```text
alerts             Stream the alert dashboard.
allow-ssh          Add an SSH exception registry entry; verify the kernel rule.
audit              Run a local operational diagnostic, not a compliance audit.
block              Add addresses or CIDRs to the persistent blocklist.
check              Inspect one address.
config             Open the configuration editor.
config-get         Read one modular configuration key.
ha-sync            Push missing local blocklist entries to configured HA peers.
install            Apply the installation pipeline; this is host-mutating.
list               Show manual registries.
manual             Display the embedded operator reference.
migrate-config     Convert a legacy configuration.
reload             Reapply policy and normally restart the core.
revoke-ssh         Remove an SSH exception registry entry.
tui                Launch the local terminal dashboard.
unblock            Remove addresses or CIDRs from the blocklist.
uninstall          Delete SysWarden services, rules, configuration, data and logs.
unwhitelist        Remove addresses or CIDRs from the whitelist.
update             Run the current in-place updater; see the warning below.
update-feeds       Refresh feeds and reapply firewall policy.
web-token          Display the configured token or persist a replacement and request a Web-TUI restart.
web-tui            Start the network-facing Web-TUI server.
whitelist          Add addresses or CIDRs to the whitelist.
whitelist-infra    Detect and add local infrastructure addresses.
```

If no token is configured, `syswarden web-token` generates and persists one
even without `--rotate`, then requests a `syswarden-webtui.service` restart.
`--rotate` persists a replacement token and requests the same restart. If that
restart fails, a running Web-TUI process may continue accepting the previous
token.

The port-specific bypass semantics of `allow-ssh` and `revoke-ssh` have not
passed a privileged kernel contract test. Do not depend on them for remote
access recovery.

## Lifecycle warnings

- `syswarden reload` reapplies firewall policy, repairs cron entries and
  normally restarts `syswarden-core.service`. Take a ruleset snapshot and keep
  console access before running it.
- `syswarden audit` is a local operational diagnostic. Its output is not an
  ISO 27001, NIS2, CRA or CIS certification.
- `syswarden update` currently downloads a package without verifying a release
  checksum or signature, uses fixed temporary filenames, and selects amd64 or
  x86_64 for DEB/RPM even on other architectures. Do not use this updater until
  those issues are corrected; perform a separately verified package upgrade in
  a laboratory instead.
- `syswarden uninstall` is destructive. It deletes SysWarden configuration,
  data, logs, services and firewall tables. It does not restore every previous
  host setting. Back up `/etc/syswarden`, `/var/lib/syswarden`, relevant logs,
  firewall state, SSH configuration and hardening files before considering it.

## Security posture and limitations

- SysWarden runs privileged operations and can cause network lockout or service
  interruption. An out-of-band recovery path is a prerequisite.
- Current firewall reload is not transactional.
- Current ban paths can report success without independently proving the final
  kernel state in every failure mode.
- WAAP is based on previously written logs and cannot stop a request before it
  reaches the logging application.
- HA certificate identity is not verified by the CLI client, legacy tokenless
  mode exists, unban authentication is incomplete, and request sizes and
  timeouts are not fully bounded.
- Web-TUI listens on all interfaces by default and uses a self-signed
  certificate plus a shared token.
- SIEM TLS currently uses anonymous authentication.
- Webhook destinations are not protected by a complete SSRF policy.
- The updater does not verify downloaded packages and uses unsafe fixed
  temporary paths.
- Complete install, upgrade, restart and rollback evidence is still required
  for every claimed operating-system and architecture combination.
- SysWarden provides controls and audit evidence that may assist a security
  program; it is not a regulatory certification or a substitute for an
  independent assessment.

Security issues should be reported according to [SECURITY.md](SECURITY.md).

## Documentation

The separate [SysWarden wiki](https://github.com/duggytuxy/syswarden/wiki)
contains deployment notes and use cases. Wiki changes use a separate review and
maintainer-controlled publication gate; a wiki page may lag the source until
that gate is completed. When the wiki and this README disagree, prefer tested
behavior in the source candidate and report the inconsistency.

## Target and support

> Goal: 37% reached/year (Goal) to fund continuous DevSecOps improvements and infrastructure.

Developing SysWarden and maintaining the Data-Shield IPv4 blocklists requires
server infrastructure and ongoing monitoring. Contributions and support help
fund that work.

[![Support on Ko-Fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/laurentmduggytuxy)

## License

SysWarden is free and open-source software distributed under the
[GNU General Public License v3.0](LICENSE).

*Developed and maintained by DuggyTuxy (Laurent M.).*
