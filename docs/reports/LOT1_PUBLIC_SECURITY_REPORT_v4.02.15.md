# SysWarden Lot 1 Public Security Delivery Report

| Field | Value |
| :--- | :--- |
| Lot 1 source status | FAILED QUALIFICATION |
| Product release decision | NO-GO, publication stopped |
| Candidate | v4.02.15 |
| Historical public baseline | v4.02.8 |
| Prior source candidate | v4.02.14, merged but never tagged or published |
| Report date | 17 August 2026 |
| Final FreeBSD evidence | `099015d7d7433235b50a2d3cff76782553536af2fe2357dfb5ebf5f999e085` |
| Final statuses | `harness_status=pass`, `product_status=fail`, `release_ready=false` |
| Tag and public Release | Not created |
| Scope | Lot 1 source, package and release-qualification closure |
| Audience | Public, anonymized |

## 1. Executive outcome

This report describes the v4.02.15 repository candidate. It does not claim
that an untagged build is a public release, that every environment is
supported, or that a package is safe merely because a workflow produced it.

The v4.02.14 source candidate was merged, but it was never tagged or published.
Protected qualification run `31993252784` completed the native amd64 and ARM64
package lifecycle shards. The FreeBSD laboratory stopped before sealed package
inputs because its preflight interpreted `%Lp=777` as a missing sticky bit even
though FreeBSD exposes that bit separately as `%Mp=1`. The nftables laboratory
stopped before product evaluation because the Bubblewrap child inherited a
runner temporary path through its read-only root bind. FreeBSD and nftables
product behavior was therefore not evaluated by that run.

No sealed v4.02.14 qualification artifact, release signature, tag, public
Release or Release asset was created. v4.02.15 superseded that unpublished
candidate and entered a final disposable FreeBSD VM qualification.

The final report was generated at `2026-08-17T11:52:09.684249+00:00`. Its
SHA-256 is
`099015d7d7433235b50a2d3cff76782553536af2fe2357dfb5ebf5f999e085`. It binds
`syswarden-4.02.15.txz` at SHA-256
`e3ff75d5961092ca1ab0ec752e8dd70d4121f9bf2cbb26957dc339cdd276bf65`.
The harness passed, but the product failed: `harness_status=pass`,
`product_status=fail` and `release_ready=false`. The report contains 75 checks,
68 with status `pass` and seven unexpected checks with status `blocker`.

Publication is stopped. No v4.02.15 tag, public Release, Release signature or
public asset is authorized or created. The last public Release remains
v4.02.8. Work resumes on 20 August 2026 at 13:00 CEST with the recorded plan to
remove FreeBSD support completely.

## 2. Candidate corrections and delivered controls

The v4.02.15 source candidate gives the nftables parent harness a real,
owner-controlled 0700 temporary directory below the qualification root and
passes it only to that laboratory as `TMPDIR` and `GOTMPDIR`. The firewall test
re-executed inside Bubblewrap resets `TMPDIR` to `/tmp`, which is the child's
private tmpfs, rather than inheriting a path behind the read-only root bind.
Cleanup is bounded to the validated qualification path and rejects symlink,
ownership, mode and path-escape mutations.

The FreeBSD VM and updater probes now verify `/tmp` with both `%Mp` and `%Lp`.
The VM laboratory also forces a bounded, fail-closed `pkg update -f` before it
installs standalone TXZ prerequisites. Both probes preserve a redacted primary
laboratory error when bounded transport cleanup also fails and report the
cleanup failure separately. A valid primary result advances only if cleanup
succeeds within the three 60-second attempts separated by one-second backoff.
If cleanup is exhausted, the overall verdict remains fail-closed, status 92 is
returned, and the otherwise successful result is not published. Qualification
diagnostics enumerate all nonzero laboratory coordinates while exposing only
allowlisted summaries; raw reports and transport secrets remain private.

A subsequent real disposable-VM probe exposed a harness-only stdin defect.
Both FreeBSD `script` TUI probes inherited file descriptor 0 from the remote
`/bin/sh -s` control stream. This consumed unread shell source, returned status
2 and prevented trusted completion; it was not a product TUI result. The
corrected harness makes both TUI probes and all eleven noninteractive package
commands read from `/dev/null`, for exactly 13 explicit stdin boundaries. All
six lifecycle `pkg add -f` and two evidence-bearing `pkg delete -fy` commands
also use bounded FreeBSD `timeout -f`, which preserves successfully detached
service children. Its EXIT trap passes the original status to one final cleanup
invocation, while HUP, INT and TERM map to 129, 130 and 143 before that same
cleanup path runs.

The VM laboratory now writes `root` and `nobody` as separate lines in
`/var/cron/allow`. It verifies that `/var/cron/allow` and `/var/cron/deny` are
nonsymlink regular files with exact `root:wheel` ownership, mode 0600 and
expected bytes. Before candidate upgrade it requires a byte-exact root crontab
write, readback and restoration round trip. Before package removal it also
refuses to proceed unless the seeded crontab installs successfully and its
readback matches byte for byte. A combined `root,nobody` line, a missing root
entry, an ignored write status or a mismatched readback fails closed. Once the
probe command has run, restoration of the original present or absent state is
mandatory even when installation diagnostics, readback or comparison already
failed. Both the primary probe result and the restoration with its byte-exact
readback are fail-closed, and adversarial tests cover each failure path.

FreeBSD 14.4 PF accepts the singular `fragment` keyword for the fragment-drop
rule. Both the product generator and the frozen v4.02.8 fixture now use that
form, and the regression contract rejects the plural `fragments` form. This
keeps the immutable transition fixture and candidate policy on the same native
parser contract.

The FreeBSD PF recovery snapshot uses schema v2. It is published before any
`kldload` or policy mutation and records `initial_kernel_state=module_absent`
when the module and control device were initially absent. Its bounded live view
includes the state table captured through `pfctl -ss`. After candidate syntax
validation, `mutation_started=true` is persisted immediately before the
validated policy is applied. Restore unloads PF only when the snapshot recorded
an initially absent module. If PF was initially present, restore does not force
an unload. The VM qualification includes a real candidate install and removal
from the initially absent state, verifies an empty disabled policy during the
recovery proof, and returns the guest to module and control-device absence.

When normalization produces a byte-identical `sshd_config`, the FreeBSD SSH
path performs zero backup, temporary-file write, candidate validation, rename,
directory sync or `sshd` restart. The clean temporary and rollback path guards
still run before this decision. Changed content retains the existing validated
compare-and-swap transaction and rollback behavior. The candidate no-op path
therefore avoids an unnecessary qualification transport interruption without
weakening a real configuration change. It does not alter the immutable
v4.02.8 behavior, which may still restart `sshd` during historical installation.

Every FreeBSD TXZ member is normalized to UID/GID 0 and `root:wheel`.
The finalizer removes PAX `uid`, `gid`, `uname` and `gname` overrides before
writing the archive.
Package verification rejects any numeric or named owner or group drift across
payloads and package manifests. The ownership contract
also covers the manifest that carries the embedded lifecycle hooks, without
claiming that those hooks are separate archive members.

| Area | Candidate behavior | Security boundary |
| :--- | :--- | :--- |
| Configuration | Transactional migration, strict validation, durable recovery phases, concurrency controls and preservation of operator overrides | Mutating commands stop when the active configuration is unavailable or degraded |
| Linux firewall | Validated nftables candidate, shared lock, atomic commit, post-commit verification, TTL preservation and bounded compatibility wrappers | A policy change can still interrupt remote access; console recovery remains mandatory |
| nftables qualification | Parent temporary state is qualification-owned and writable; the Bubblewrap child uses its own `/tmp` tmpfs | Any failed type, owner, mode, write or cleanup proof keeps product status unknown and the release closed |
| Scheduling | Feed and HA cron entries are reconciled independently; exact managed entries are removed without RPM-sensitive parsing; the FreeBSD root crontab seed and readback are byte-exact | Invalid cron access policy, failed writes or mismatched readback stop the lifecycle before evidence can advance |
| Linux packages | Separate native amd64 and ARM64 shards cover exact DEB, RPM and APK coordinates with binding and lifecycle checks | Both shards must rerun for the exact v4.02.15 bytes; successful v4.02.14 evidence is not reusable |
| FreeBSD qualification | Sticky-bit fields use native semantics; package catalog refresh is bounded; eleven package commands and two TUI probes isolate stdin; six adds and two measured deletes use `timeout -f`; PF uses schema v2 with initial module state and live states plus the FreeBSD 14.4 singular fragment grammar; byte-identical SSH normalization has no transaction side effects | Neither source tests nor a repaired harness replaces the required protected VM lifecycle and signed updater transition |
| High availability | TLS 1.3, bearer authentication, bounded payloads, canonical peer scope, durable ledgers and bidirectional persistent-ban exchange | CIDRs authorize inbound peers only and are never dialed as outbound destinations |
| BunkerWeb integration | Additive TTL, provenance and batch extensions behind an explicit gate | Durable node-to-node L7 and WAAP ban exchange remains active with the partner gate false or true |
| Signed updates | Canonical manifest, detached Ed25519 signature, exact platform binding, private staging and final size and SHA-256 verification before installation | The historical v4.02.8 binary predates this trust root and requires one separately verified manual first hop |
| Release governance | Exact tag ruleset, non-bypassable protected environments, byte-bound qualification evidence and independent publisher revalidation | A public tag and Release remain blocked until protected qualification succeeds |

## 3. Upgrade contract

The candidate signed update protocol applies to v4.02.9 and later source
candidates. The planned v4.02.15 manifest would have bound seven package
identities: two DEB, two RPM, two APK and one FreeBSD TXZ. A package would have
been selected by exact operating system, architecture, name, size and SHA-256,
then rehashed immediately before its package manager was invoked.

The immutable v4.02.8 binary has no embedded signed-manifest verifier. No
qualified v4.02.15 Release exists, so no first hop to v4.02.15 is authorized.
The local candidate package and its final failed VM evidence are not a public
update channel.

## 4. Package and platform boundaries

| Platform | Candidate evidence | Final state |
| :--- | :--- | :--- |
| DEB amd64 and arm64 | Contents, dependencies, maintainer scripts and lifecycle contracts | No v4.02.15 package is published |
| RPM x86_64 and aarch64 | Exact payload, scriptlet, build-id and lifecycle contracts | No v4.02.15 package is published |
| APK x86_64 and aarch64 | Static package executables, OpenRC dependency, preparation and fresh/upgrade hooks | No v4.02.15 package is published |
| FreeBSD amd64 | Final disposable VM report passed its harness and failed its product verdict with seven unexpected blockers | Publication stopped; complete FreeBSD support removal is planned for the 20 August 2026 resumption |

Raw `pkg delete` is not the supported FreeBSD cleanup path because the package
manager does not guarantee that a failing pre-deinstall script aborts payload
removal, and its no-script mode bypasses recovery hooks. Operators must use
`syswarden uninstall` with backups and console access.

The Web-TUI is enabled by the current package path. A package-level disabled
default and conditional TCP 62027 ownership remain Lot 2 work.

## 5. Qualification state

Protected qualification run `31993252784` remains diagnostic evidence for the
unpublished v4.02.14 candidate only. Its native package results are SHA-bound
and do not authorize v4.02.15.

The final v4.02.15 FreeBSD evidence is byte-bound by report SHA-256
`099015d7d7433235b50a2d3cff76782553536af2fe2357dfb5ebf5f999e085`. The report
records `harness_status=pass`, `product_status=fail` and
`release_ready=false`. Its 75 checks contain 68 passes and these seven exact
unexpected blockers:

| Exact check ID | Exact observed result relevant to the blocker |
| :--- | :--- |
| `SW-PKG-FBSD-CANDIDATE-UPGRADE-POSTINSTALL-001` | `diagnostics_clean=0`; marker absent; complete modular configuration inventory present |
| `SW-PKG-FBSD-CANDIDATE-REINSTALL-POSTINSTALL-001` | `diagnostics_clean=0`; marker absent; complete modular configuration inventory present |
| `SW-PKG-FBSD-CANDIDATE-RESTART-IDEMPOTENCE-POSTINSTALL-001` | `diagnostics_clean=0`; marker absent; complete modular configuration inventory present |
| `SW-PKG-FBSD-RCD-ENABLE-001` | core enable value empty; web enable value empty |
| `SW-PKG-FBSD-UPGRADE-RCD-001` | core and web enable values empty; core and web status return codes both 1 |
| `SW-PKG-FBSD-PF-MODULE-ABSENT-INSTALL-001` | schema version 2; exact-live provenance; safe snapshot; `initial_kernel_state=module_absent`; package return code 0; module present and control device ready; `diagnostics_clean=0`; `mutation_started=false`; policy `Disabled`; rule count 0; marker absent |
| `SW-PKG-FBSD-RSYSLOG-001` | validation return code 0; enable value empty; status return code 1; `base_syslogd_inactive=0` |

These are the report observations. This document does not infer a root cause
beyond them. The failed product verdict keeps every publication action closed.
No v4.02.15 tag or public Release exists.

## 6. Planned inventory that was not published

The planned v4.02.15 Release contract contained exactly these 14 public assets:

1. `syswarden_4.02.15_amd64.deb`;
2. `syswarden_4.02.15_arm64.deb`;
3. `syswarden-4.02.15-1.x86_64.rpm`;
4. `syswarden-4.02.15-1.aarch64.rpm`;
5. `syswarden_4.02.15_x86_64.apk`;
6. `syswarden_4.02.15_aarch64.apk`;
7. `syswarden-4.02.15.txz`;
8. `SHA256SUMS.txt`;
9. `RELEASE_SHA256SUMS.txt`;
10. `syswarden-release.tar.gz`;
11. `syswarden-sbom.spdx.json`;
12. `plumber-report.zip`;
13. `syswarden-update-manifest-v1.json`;
14. `syswarden-update-manifest-v1.json.sig`.

This planned inventory contains seven packages plus seven evidence and update
assets. None was published for v4.02.15. No PDF is part of the public Release
inventory. The local `output/` directory is private operator evidence and is
excluded from the repository candidate and public Release. A successful source
merge or a local report alone does not create a tag or any of these assets.

## 7. Release notes contract

The complete v4.02.15 changelog section records the candidate corrections and
the final failed qualification. No public v4.02.15 Release notes are authorized
under this decision. The failed v4.02.14 and v4.02.15 histories remain intact.

## 8. Resumption and FreeBSD withdrawal plan

Publication remains stopped. Work resumes on 20 August 2026 at 13:00 CEST.
The recorded plan for that resumption is complete removal of FreeBSD support.
This removal is planned work and is not represented as already implemented.
No FreeBSD support or release claim may rely on the failed v4.02.15 candidate.

## 9. Deferred Lot 2 work

The following items remain outside this Lot 1 closure:

- a package-level `[webtui] enabled = false` default and conditional TCP 62027
  ownership;
- an external BunkerWeb plugin, UI and end-to-end partner qualification;
- per-client HA tokens and remote whitelist mutation privileges;
- additional product UX and policy controls that do not alter the v4.02.15
  upgrade safety boundary.

## 10. Final decision

v4.02.15 is NO-GO and publication is stopped. The final FreeBSD harness passed,
the product failed and `release_ready` is false. No v4.02.15 tag, public Release,
Release signature or public asset is created. The last public Release remains
v4.02.8. The next authorized work is the complete FreeBSD support removal plan
at the 20 August 2026, 13:00 CEST resumption.
