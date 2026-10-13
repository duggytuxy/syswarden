# Unprivileged local attack assurance

Status: incremental v5 implementation and acceptance plan, tracked in
[WP19](https://github.com/duggytuxy/syswarden/issues/337). A passed component
check is evidence for its declared boundary, not a guarantee that no vulnerability
exists. Preserve the distinction between security testing, independent review and
a professional penetration test. Do not describe automated checks as an external
pentest or as complete native acceptance.

## Threat model

The principal attacker is an ordinary local Linux account, distinct from every
SysWarden service identity, without sudo, capabilities, privileged supplementary
groups, inherited trusted descriptors or administrator-approved credentials. It
can run programs, create its own files, submit untrusted observations where
permitted and contact reachable interfaces. Add explicit cases for an unrelated
service account and an unintended group member when those boundaries exist.

An internal network, a local process, a claimed username or a path bearing the
product name does not confer authority. Separate observation from verified
provenance and authoritative decisions. A hash beside an attacker-controlled file
is not independent authentication. Keep root compromise, service-UID compromise,
kernel vulnerabilities, physical access and malicious administrators outside this
ordinary-user claim, with separate documented threat and recovery treatment.

## First mandatory component gate

`TestLocalUnprivilegedBoundary` runs against the real v5 journal storage and
`LocalAuthority` dispatcher with synthetic signed fixtures. The parent uses an
identity able to start a child as UID/GID 65534; this creates no system account.
Before probing, the child verifies its distinct identity, empty supplementary
groups, zero effective/permitted/inheritable/ambient capabilities, and
`no_new_privs` on its locked probe thread. Acquiring UID 0 must fail. A writable private canary proves the
child can perform ordinary I/O, rather than accepting a globally broken process
as proof of security.

The 80 cases cover:

- Reading, opening for overwrite/append/truncation, unlinking, replacement by
  rename, hard-linking, chmod and chown against policy, custody, anchor, segment
  and checkpoint files: 45 cases.
- File creation, symlink insertion and directory substitution against the four
  protected resource directories: 12 cases.
- Connection to a private test socket: one case.
- All six dispatcher routes with a real ungranted kernel peer, after deliberately
  making only the disposable test socket reachable: six cases. Claimed root and
  administrator labels are ignored; they are not authentication inputs. Policy
  administration has no configured identity provider and must deny.
- Mutation attempts against the actual listener endpoint: eight cases covering
  unlink, rename, hardlink, chmod, chown, entry creation, symlink insertion and
  directory substitution. The child belongs to the endpoint group but cannot write
  its directory or become its owner.
- Actual listener denial of all six framed operations for that ungranted group
  member, plus one connection refusal with a different primary group and no
  supplementary groups: seven cases. The socket remains `0660`, directory `0750`;
  no test-only public permission is needed for this listener.
- Authorized resume, commit and independently reopened resume after the attacks:
  one case.

The test exposes its harness ancestors so their permissions cannot accidentally
provide the protection attributed to product resource directories. Access probes
must fail with an actual permission error, not a missing file or unrelated error.
Protected bytes, inode identity, modes, owner/group, link counts, modification and
change times, and directory inventories are compared after each mutation attempt.
Access times are excluded because verification itself reads the files.

The existing required **Code Hygiene** job executes this dedicated gate, feeding
its result into **Security Audit**. The report verifier requires every named case
and package completion exactly once. Missing, skipped, duplicate, failed or
truncated evidence fails. Ordinary Go test runs explicitly skip this privileged
harness; that skip is not its mandatory CI result. A missing credential-changing
capability in the dedicated job is an error, never a green skip.

The CI parent runs on a disposable runner. Local verification can use the existing
rootless `podman unshare` namespace instead, with no new image or container cache.
Both modes test kernel identity separation. The actual
[listener component](LOCAL_AUTHORITY_SERVER.md) uses the production framing and
permission checks with synthetic authority resources. The earlier deliberately
reachable dispatcher probe remains a harness-only socket. Neither test establishes
deployed package ownership, SELinux/AppArmor policy, feed pipeline, process
isolation, boot behavior or distribution support. Production provisioning and
identity/approval providers remain separate work.

## Remaining mandatory coverage

| Surface | Adversarial probes | Required evidence |
| --- | --- | --- |
| Installed code and services | Replace binaries, modules, helpers, units/drop-ins, scheduled jobs; PATH/environment or writable-parent substitution; unauthorized lifecycle commands. | Original content, metadata and effective service command preserved; legitimate health and lifecycle operations still work. |
| Configuration and ownership | Edit options, manifests, removal barriers and trust roots; symlink/hardlink/rename races; altered ACLs, group access or inherited descriptors. | Rejection before privileged mutation; independently trusted ownership retained; explicit diagnosis of unsafe provisioning. |
| Feed lists and update cache | Replace downloaded bytes, lists, signatures, sidecars, provenance, temporary files and cached results; replay stale valid data; exploit writable staging. | Only independently verified current data is promoted atomically; prior valid protection survives rejection; updater remains usable. |
| Results and evidence | Forge alerts, journal frames, checkpoints, counters, KPI inputs, health status and exports; spoof source or identity; terminal/control and CSV formula injection. | Untrusted observations never become verified origin, successful action or authoritative verdict; output remains inert and uncertainty visible. |
| Local and remote interfaces | Connect as wrong UID/group, reuse credentials or descriptors, inject ancillary data, attempt privilege escalation and cross-scope access. | Explicit authorization for each operation, independent approval for mutations, no confidential response on denial. |
| Availability | Bounded socket floods, slow peers, input/file growth, signal/ptrace attempts, lock contention and queue exhaustion. | Frozen CPU/RAM/disk/FD/time budgets, visible loss/refusal, no unlimited retries; authorized recovery and access remain possible. |
| Lifecycle and integrations | Repeat relevant attacks after installation, supported migration, restart, reload and reboot; test uninstall/remove/purge independently. | Active product ownership and unrelated administrator protection remain correct. BunkerWeb source-owned bans, TTL, retries and HA behavior remain independent of the dashboard and journal. |

Implement probes against the actual delivered path, not just a mock returning
permission denied. Include a positive control and an authorized recovery/health
check, retain failures, and bind results to the exact source and signed packages.
A failed prerequisite, timed-out child, unsupported probe or absent result is
incomplete evidence. It cannot count as a passing security assertion. Do not
relax SELinux, AppArmor, firewall ownership or host namespace restrictions to make
a product assertion pass.

## Native review matrix

These are the inherited v5 review targets from the
[scope contract](SCOPE_AND_AUTHORITY.md), not a newly declared support matrix.
Their unprivileged installed-product evidence remains pending.

| Target | Init/package boundary | Unprivileged native campaign |
| --- | --- | --- |
| Debian 13 | systemd / DEB | Pending |
| Ubuntu 24.04 and 26.04 | systemd / DEB, AppArmor profile recorded | Pending for each version |
| Fedora 44 | systemd / RPM, SELinux enforcing | Pending |
| AlmaLinux 9 and 10 | systemd / RPM, SELinux enforcing | Pending for each version |
| Alpine 3.22 and 3.24 | OpenRC / APK | Pending for each version |

Freeze the supported matrix through WP01 and bind its mandatory cases into the
v5 release verifier through WP14 before acceptance. This follow-up is not yet
implemented in the v5 publisher. A container using the host kernel is component
or userspace evidence, not a native reboot test. Existing v4 native evidence keeps
its original scope. Do not silently drop a target, accept an unrun profile, or
label a cross-UID test as coverage of every distribution.

Use existing hardware and simulated accounts/workloads. No paid test service,
additional infrastructure or new machine purchase is required by this plan.
If existing capacity prevents a required campaign, record the gap for review.
Never convert a resource limitation into a passed result.

## Reporting and completion

For every case record the attack identity and capabilities, protection under test,
expected refusal, observed status, before/after integrity, authorized postcondition,
candidate and environment, resources, timestamps and limitations. Keep operational
logs, identifying metadata and genuine secrets private. Public fixtures and CI
reports contain synthetic data only. Use the private vulnerability-reporting path
for a newly discovered exploitable issue; do not publish exploit details in an
ordinary tracking comment before coordinated handling.

This work complements the [validation plan](VALIDATION_PLAN.md), the file-integrity
work packages and the [BunkerWeb compatibility contract](BUNKERWEB_COMPATIBILITY.md).
Keep implementation, CI success, native acceptance and residual risk explicit.
An open coverage item stays open until the matching behavior and evidence exist.
