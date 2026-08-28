<div align="center">
  <img src="assets/syswarden_hero.svg" alt="Official SysWarden logo" width="100%">
</div>

<br>

<div align="center">
  <a href="https://github.com/duggytuxy/syswarden/actions/workflows/package.yml">
    <img src="https://img.shields.io/github/actions/workflow/status/duggytuxy/syswarden/package.yml?branch=main&amp;style=flat-square&amp;logo=githubactions&amp;logoColor=white&amp;label=Package" alt="SysWarden package workflow">
  </a>
  <a href="https://github.com/duggytuxy/syswarden/actions/workflows/security-audit.yml">
    <img src="https://img.shields.io/github/actions/workflow/status/duggytuxy/syswarden/security-audit.yml?branch=main&amp;style=flat-square&amp;logo=githubactions&amp;logoColor=white&amp;label=Security%20Audit" alt="SysWarden security audit">
  </a>
  <a href="https://github.com/duggytuxy/syswarden/actions/workflows/compliance.yml">
    <img src="https://img.shields.io/github/actions/workflow/status/duggytuxy/syswarden/compliance.yml?branch=main&amp;style=flat-square&amp;logo=githubactions&amp;logoColor=white&amp;label=Plumber%20Compliance" alt="Plumber compliance">
  </a>
  <a href="https://score.getplumber.io/github.com/duggytuxy/syswarden">
    <img src="https://score.getplumber.io/github.com/duggytuxy/syswarden.svg" alt="Plumber Score">
  </a>
  <a href="https://github.com/duggytuxy/syswarden/actions/workflows/scorecard.yml">
    <img src="https://img.shields.io/github/actions/workflow/status/duggytuxy/syswarden/scorecard.yml?branch=main&amp;style=flat-square&amp;logo=githubactions&amp;logoColor=white&amp;label=OpenSSF%20Scorecard" alt="OpenSSF Scorecard">
  </a>
  <a href="https://github.com/duggytuxy/syswarden/blob/main/LICENSE">
    <img src="https://img.shields.io/github/license/duggytuxy/syswarden?style=flat-square&amp;logo=opensourceinitiative&amp;logoColor=white" alt="GitHub license">
  </a>
</div>

# SysWarden

**Host-local Linux defense with auditable, fail-closed enforcement.**

SysWarden is an open-source Linux security orchestrator that combines an
authoritative nftables policy, host telemetry, threat-intelligence lists,
out-of-band WAAP log analysis, authenticated high availability and a native
terminal dashboard. It is designed for operators who want one reviewable host
defense layer without placing another proxy in the application data path.

SysWarden is not an inline HTTP proxy, a traffic sanitizer or a regulatory
certification product.

Current source version: **v4.04.0**.

The latest qualified, stable public release is
[v4.03.3](https://github.com/duggytuxy/syswarden/releases/tag/v4.03.3).

## Features

- Authoritative nftables enforcement with bounded firewalld and UFW
  compatibility when exactly one supported frontend is already active.
- Persistent blocklists, whitelists and SSH exceptions with canonical IP,
  CIDR and service-scoped entries.
- Host telemetry and out-of-band WAAP log analysis for local detection and
  response workflows.
- Bounded threat-intelligence feeds with last-known-good publication behavior.
- Native local terminal dashboard with no browser service or listening port.
- Authenticated HA synchronization over TLS 1.3 with explicit ownership and
  migration-fence controls.
- Optional BunkerWeb integration with authenticated HA and provenance-aware
  cleanup.
- Native DEB, RPM and APK packaging for supported amd64 Linux hosts.

## Capabilities

| Area | What SysWarden provides |
| --- | --- |
| HIDS | Host-local telemetry, security-log analysis and alert visibility |
| HIPS | Validated policy decisions enforced through authoritative nftables rules |
| WAAP | Out-of-band analysis of logs written by a supported upstream service |
| Threat intelligence | Canonical local lists and bounded external feed updates |
| High availability | TLS 1.3, bearer authentication and peer-scoped synchronization |
| Operations | Local CLI and TUI, modular configuration, audit and lifecycle controls |
| Supply chain | Checksummed Linux packages, signed update metadata and release evidence |

## Intelligence Sources

| Source | Use and trust boundary |
| --- | --- |
| [Data-Shield](https://github.com/duggytuxy/Data-Shield_IPv4_Blocklist) | Official maintainer-curated IPv4 feed for the standard and critical profiles; SysWarden accepts it locally only after canonical validation and quorum controls |
| [IPverse country IP blocks](https://github.com/ipverse/country-ip-blocks) | Pinned CC0-1.0 RIR allocation snapshot embedded in the release-bound CLI; allocation country is not physical or current operational geolocation |
| [CINS Score](https://cinsscore.com/list/ci-badguys.txt) and [blocklist.de](https://lists.blocklist.de/lists/all.txt) | Only exact entries found at both independent origins are published |
| [Spamhaus](https://www.spamhaus.org/) and [RADB](https://www.radb.net/) | Signals may be operator-provisioned; neither source is accepted as firewall authority by itself |
| Custom HTTPS feed | Choice 3 requires an HTTPS URL and its exact SHA-256 digest for each configured address family |

## Why Choose SysWarden

- **Host-local by design.** Security decisions stay close to the protected
  Linux host, without an inline proxy or remote terminal listener.
- **Fail-closed boundaries.** Ambiguous configuration, identity, feed or HA
  state is rejected before security policy is published.
- **Operator control.** Existing firewall service ownership is preserved, and
  host mutation remains explicit and reviewable.
- **Auditable delivery.** Source, package, security, compliance and release
  qualification gates expose the evidence behind each release decision.
- **Open source.** The implementation and its operational boundaries can be
  inspected, tested and improved by the community.

## Documentation

Operational procedures are centralized in the
[SysWarden wiki](https://github.com/duggytuxy/syswarden/wiki).

| Goal | Documentation |
| --- | --- |
| Verify and install a package | [Installation procedure](https://github.com/duggytuxy/syswarden/wiki/Deployment-Tutorial#4-verify-and-install-one-package) |
| Upgrade from historical v4.02.8 to v4.03.2 | [Migration procedure](https://github.com/duggytuxy/syswarden/wiki/Migration-v4.02.8-to-v4.03.2) |
| Configure SysWarden | [Configuration guide](https://github.com/duggytuxy/syswarden/wiki/Deployment-Tutorial#7-configuration-layout) |
| Integrate SysWarden into RHEL 9+ images | [RHEL 9+ image integration](https://github.com/duggytuxy/syswarden/wiki/RHEL-9-Image-Extensions) |
| Operate, audit or remove SysWarden | [Command and lifecycle reference](https://github.com/duggytuxy/syswarden/wiki/Deployment-Tutorial#11-command-inventory) |
| Review bounded deployment scenarios | [Use cases](https://github.com/duggytuxy/syswarden/wiki/Use-cases) |
| Configure the BunkerWeb integration | [BunkerWeb integration](https://github.com/duggytuxy/syswarden/wiki/BunkerWeb-Integration) |

## Project

[Security policy](SECURITY.md) | [Contributing](CONTRIBUTING.md) |
[Releases](https://github.com/duggytuxy/syswarden/releases) | [License](LICENSE)

Developing and maintaining SysWarden requires infrastructure, testing and
ongoing security work. Community support helps sustain the project.

[![Support on Ko-Fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/laurentmduggytuxy)
